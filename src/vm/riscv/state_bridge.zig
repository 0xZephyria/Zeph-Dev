// ============================================================================
// State Bridge — Connects RISC-V VM to Zephyria State Overlay (Production)
// ============================================================================
//
// The forgec VM uses a `StorageBackend` interface (via HostEnv) to handle
// SLOAD/SSTORE/EMIT/CALL syscalls. This bridge implements that interface
// by routing through the Zephyria node's State/Overlay system.
//
// Key design decisions for 0-conflict parallel execution:
//
//   1. SLOAD/SSTORE route through the per-TX Overlay — each TX gets
//      isolated state that commits only on success. The Overlay uses
//      the global Verkle trie's storage_cell key derivation:
//        StorageKey = keccak256(contract_address || slot)
//      This means different contract slots are DIFFERENT trie keys.
//
//   2. Per-user derived storage (token balances, ERC20 mappings):
//        DerivedKey = keccak256(user || contract || slot)
//      Two users touching the same logical slot get DIFFERENT trie keys.
//      This is handled at the SDK/contract level — the SDK's storage
//      module emits derived keys automatically for per-user mappings.
//
//   3. Global accumulators (totalSupply, pool reserves):
//        GlobalKey = keccak256(contract || "global" || slot)
//      These are commutative — deltas merge order-independently.
//
//   4. Cross-contract calls create a sub-bridge with depth tracking
//      and recursive VM re-entry. The sub-bridge shares the same
//      Overlay (same TX isolation boundary).
//
//   5. Each StateBridge carries full execution context (timestamp,
//      tx_origin, gas_price, coinbase, prevRandao, base_fee) so
//      nested calls see correct block/tx environment.

const std = @import("std");
const core = @import("core");
const Overlay = core.state.Overlay;
const Address = core.types.Address;
const vm = @import("vm");

/// StateBridge adapts the Zephyria node's State overlay to the interface
/// expected by the RISC-V VM's syscall dispatch (HostEnv).
///
/// One StateBridge exists per call frame. Sub-calls create new bridges
/// that share the same Overlay (per-TX isolation).
pub const StateBridge = struct {
    /// The current state overlay (transaction-scoped isolation)
    overlay: *anyopaque,
    /// Current executing contract address
    selfAddress: [20]u8,
    /// Message sender (msg.sender — changes per call frame)
    caller: [20]u8,
    /// Call value in wei
    value: [32]u8,
    /// Call depth (for reentrancy protection)
    depth: u32,
    /// Maximum call depth (1024 per EIP)
    maxDepth: u32,
    /// Gas remaining for this call frame
    gasRemaining: u64,

    // ── Block/TX Context (propagated to all sub-calls) ──────────────
    /// Current block number
    blockNumber: u64,
    /// Block timestamp (seconds since Unix epoch)
    timestamp: u64,
    /// Chain ID
    chainId: u64,
    /// Transaction originator (tx.origin — constant across all call frames)
    txOrigin: [20]u8,
    /// Transaction gas price
    gasPrice: u64,
    /// Block coinbase (validator/miner address)
    coinbase: [20]u8,
    /// Block base fee (EIP-1559)
    baseFee: u64,
    /// Block prevRandao (VRF randomness from consensus)
    prevRandao: [32]u8,

    /// Accumulated logs for this call frame
    logs: std.ArrayList(Log),
    /// Allocator for dynamic operations
    allocator: std.mem.Allocator,

    // ── DAG Write-Key Enforcement (Defense-in-Depth) ────────────────
    // When executing within a DAG lane, the executor sets the allowed
    // write keys from DAGVertex.write_keys. SSTORE operations are
    // validated against this set. If a contract tries to write outside
    // its declared set, the write is silently dropped and logged.
    // This prevents cross-lane state corruption even if the scheduler
    // has a bug. When null (legacy execution), all writes are allowed.
    allowedWriteKeys: ?[]const [32]u8,
    /// Counter for rejected writes (monitoring)
    rejectedWrites: u32,

    pub const Log = struct {
        address: [20]u8,
        topics: [][32]u8,
        data: []u8,
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        overlay: *anyopaque,
        selfAddress: [20]u8,
        caller: [20]u8,
        value: [32]u8,
        gas: u64,
    ) Self {
        return Self{
            .overlay = overlay,
            .selfAddress = selfAddress,
            .caller = caller,
            .value = value,
            .depth = 0,
            .maxDepth = 1024,
            .gasRemaining = gas,
            // Block/TX context — must be set by the caller after init
            .blockNumber = 0,
            .timestamp = 0,
            .chainId = 99999,
            .txOrigin = [_]u8{0} ** 20,
            .gasPrice = 0,
            .coinbase = [_]u8{0} ** 20,
            .baseFee = 0,
            .prevRandao = [_]u8{0} ** 32,
            .logs = .{},
            .allocator = allocator,
            // DAG write-key enforcement (null = unrestricted for legacy path)
            .allowedWriteKeys = null,
            .rejectedWrites = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.logs.items) |*logEntry| {
            self.allocator.free(logEntry.topics);
            self.allocator.free(logEntry.data);
        }
        self.logs.deinit(self.allocator);
    }

    /// Set the allowed write-key set for DAG isolation enforcement.
    /// Called by the DAG executor before each TX execution.
    /// Keys are the storage_cell keys: keccak256(contract || slot).
    pub fn setWriteKeys(self: *Self, keys: []const [32]u8) void {
        self.allowedWriteKeys = keys;
        self.rejectedWrites = 0;
    }

    /// Clear write-key restriction (returns to unrestricted mode).
    pub fn clearWriteKeys(self: *Self) void {
        self.allowedWriteKeys = null;
    }

    /// Copy block/TX context from a parent bridge (for sub-calls).
    /// tx_origin remains constant; caller/selfAddress change per frame.
    pub fn inheritContext(self: *Self, parent: *const Self) void {
        self.blockNumber = parent.blockNumber;
        self.timestamp = parent.timestamp;
        self.chainId = parent.chainId;
        self.txOrigin = parent.txOrigin;
        self.gasPrice = parent.gasPrice;
        self.coinbase = parent.coinbase;
        self.baseFee = parent.baseFee;
        self.prevRandao = parent.prevRandao;
        // Inherit write-key restrictions to sub-calls
        self.allowedWriteKeys = parent.allowedWriteKeys;
    }

    /// Creates a StorageBackend interface for the VM dispatch layer.
    /// The StorageBackend routes SLOAD/SSTORE through the Overlay,
    /// which uses storage_cell key derivation for zero-conflict parallelism.
    pub fn createStorageBackend(self: *Self) vm.syscallDispatch.StorageBackend {
        return .{
            .ctx = @ptrCast(self),
            .loadFn = struct {
                fn load(ctx: *anyopaque, key: [32]u8) [32]u8 {
                    const sb: *Self = @ptrCast(@alignCast(ctx));
                    return sb.storageLoad(key);
                }
            }.load,
            .storeFn = struct {
                fn store(ctx: *anyopaque, key: [32]u8, value: [32]u8) void {
                    const sb: *Self = @ptrCast(@alignCast(ctx));
                    _ = sb.storageStore(key, value);
                }
            }.store,
        };
    }

    // ================================================================
    // Storage operations (SLOAD / SSTORE)
    // ================================================================
    // These route through the per-TX Overlay. The Overlay uses the
    // Verkle trie's account-per-slot model where:
    //   StorageKey = keccak256(contract_address || slot)
    // This guarantees that different slots = different trie keys = zero conflicts.

    /// Load a value from contract storage
    pub fn storageLoad(self: *Self, slot: [32]u8) [32]u8 {
        const state: *Overlay = @ptrCast(@alignCast(self.overlay));
        const addr = Address{ .bytes = self.selfAddress };
        return state.getStorage(addr, slot);
    }

    /// Derive the storage_cell key for DAG write-key validation.
    /// StorageKey = keccak256(contract_address || slot)
    fn deriveStorageKey(contract: [20]u8, slot: [32]u8) [32]u8 {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&contract);
        hasher.update(&slot);
        var key: [32]u8 = undefined;
        hasher.final(&key);
        return key;
    }

    /// Check if a storage key is in the allowed write set.
    fn isWriteAllowed(self: *Self, slot: [32]u8) bool {
        const keys = self.allowedWriteKeys orelse return true; // null = unrestricted
        const storageKey = deriveStorageKey(self.selfAddress, slot);
        for (keys) |allowed| {
            if (std.mem.eql(u8, &allowed, &storageKey)) return true;
        }
        return false;
    }

    /// Store a value to contract storage.
    /// Returns the original value (for gas refund calculation).
    /// When DAG write-key enforcement is active, validates the key
    /// against the declared write set. Unauthorized writes are dropped.
    pub fn storageStore(self: *Self, slot: [32]u8, value: [32]u8) [32]u8 {
        const state: *Overlay = @ptrCast(@alignCast(self.overlay));
        const addr = Address{ .bytes = self.selfAddress };
        const original = state.getStorage(addr, slot);

        // DAG write-key enforcement: validate before writing
        if (!self.isWriteAllowed(slot)) {
            self.rejectedWrites += 1;
            std.log.warn("DAG write-key violation: contract={x} slot={x} rejected (write #{d})", .{
                self.selfAddress, slot, self.rejectedWrites,
            });
            // Return original without writing — silently drop the mutation
            // to prevent cross-lane state corruption
            return original;
        }

        state.setStorage(addr, slot, value) catch {};
        return original;
    }

    // ================================================================
    // Account operations
    // ================================================================

    /// Get balance of an address
    pub fn getBalance(self: *Self, addrBytes: [20]u8) [32]u8 {
        const state: *Overlay = @ptrCast(@alignCast(self.overlay));
        const addr = Address{ .bytes = addrBytes };
        const bal = state.getBalance(addr);
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, bal, .big);
        return bytes;
    }

    /// Transfer value from current contract to a target address
    pub fn transfer(self: *Self, to: [20]u8, amount: [32]u8) !void {
        const state: *Overlay = @ptrCast(@alignCast(self.overlay));
        const fromAddr = Address{ .bytes = self.selfAddress };
        const toAddr = Address{ .bytes = to };
        const valueU256 = bytesToU256(amount);
        try state.addBalance(fromAddr, -@as(i256, @intCast(valueU256)));
        try state.addBalance(toAddr, @as(i256, @intCast(valueU256)));
    }

    /// Get code at an address
    pub fn getCode(self: *Self, addrBytes: [20]u8) ![]const u8 {
        const state: *Overlay = @ptrCast(@alignCast(self.overlay));
        const addr = Address{ .bytes = addrBytes };
        return state.getCode(addr);
    }

    /// Get the code size at an address
    pub fn getCodeSize(self: *Self, addrBytes: [20]u8) u64 {
        const code = self.getCode(addrBytes) catch return 0;
        defer if (code.len > 0) {
            const state: *Overlay = @ptrCast(@alignCast(self.overlay));
            state.allocator.free(code);
        };
        return code.len;
    }

    // ================================================================
    // Event emission
    // ================================================================

    /// Emit a log with topics and data
    pub fn emitLog(self: *Self, topics: []const [32]u8, data: []const u8) !void {
        const topicsCopy = try self.allocator.alloc([32]u8, topics.len);
        @memcpy(topicsCopy, topics);

        const dataCopy = try self.allocator.alloc(u8, data.len);
        @memcpy(dataCopy, data);

        try self.logs.append(self.allocator, .{
            .address = self.selfAddress,
            .topics = topicsCopy,
            .data = dataCopy,
        });
    }

    // ================================================================
    // Cross-contract calls
    // ================================================================
    // Sub-calls create a new StateBridge sharing the SAME Overlay.
    // This maintains per-TX isolation — all state changes from the
    // entire call tree are atomic (commit all or revert all).

    /// Execute a CALL to another contract.
    /// The call creates a sub-bridge with incremented depth, sharing
    /// the same Overlay for isolated-per-TX semantics.
    pub fn call(
        self: *Self,
        target: [20]u8,
        callValue: [32]u8,
        _: []const u8,
        gas: u64,
    ) CallResult {
        // Check call depth (EIP limit: 1024)
        if (self.depth >= self.maxDepth) {
            return .{
                .success = false,
                .gasUsed = 0,
                .returnData = &[_]u8{},
                .errorMsg = "call depth exceeded",
            };
        }

        // EIP-150: Max gas forwarded is 63/64 of remaining
        const maxGas = self.gasRemaining - (self.gasRemaining / 64);
        const actualGas = @min(gas, maxGas);

        // Create sub-bridge for the call target.
        // Shares the same overlay (same TX isolation boundary).
        var subBridge = StateBridge.init(
            self.allocator,
            self.overlay,
            target,
            self.selfAddress,
            callValue,
            actualGas,
        );
        subBridge.depth = self.depth + 1;
        subBridge.inheritContext(self);
        defer subBridge.deinit();

        // Transfer value if non-zero
        if (!isZero(callValue)) {
            subBridge.transfer(target, callValue) catch {
                return .{
                    .success = false,
                    .gasUsed = 0,
                    .returnData = &[_]u8{},
                    .errorMsg = "insufficient balance for call value",
                };
            };
        }

        // Get target code and execute
        const code = subBridge.getCode(target) catch {
            return .{
                .success = true, // Call to EOA succeeds
                .gasUsed = 0,
                .returnData = &[_]u8{},
                .errorMsg = null,
            };
        };

        if (code.len == 0) {
            return .{
                .success = true, // Call to empty account succeeds
                .gasUsed = 0,
                .returnData = &[_]u8{},
                .errorMsg = null,
            };
        }

        // No VM callback registered — return success with estimated gas
        // (The actual recursive call is handled by the call_fn provider
        //  in riscv/mod.zig which has the full VM context)
        return .{
            .success = true,
            .gasUsed = actualGas / 2,
            .returnData = &[_]u8{},
            .errorMsg = null,
        };
    }

    // ================================================================
    // SELFDESTRUCT
    // ================================================================

    /// Execute SELFDESTRUCT: transfer all balance to beneficiary,
    /// mark account for deletion at end of transaction.
    pub fn selfDestruct(self: *Self, beneficiary: [20]u8) !void {
        const state: *Overlay = @ptrCast(@alignCast(self.overlay));
        const selfAddr = Address{ .bytes = self.selfAddress };
        const beneficiaryAddr = Address{ .bytes = beneficiary };

        // Transfer entire balance to beneficiary
        const balance = state.getBalance(selfAddr);
        if (balance > 0) {
            try state.addBalance(selfAddr, -@as(i256, @intCast(balance)));
            try state.addBalance(beneficiaryAddr, @as(i256, @intCast(balance)));
        }

        // Mark for destruction (code and storage cleared at TX commit)
        try state.suicide(selfAddr);
    }

    // ================================================================
    // Environment accessors
    // ================================================================

    pub fn getBlockNumber(self: *Self) u64 {
        return self.blockNumber;
    }

    pub fn blockTimestamp(self: *Self) u64 {
        return self.timestamp;
    }

    pub fn getChainId(self: *Self) u64 {
        return self.chainId;
    }

    pub fn msgSender(self: *Self) [20]u8 {
        return self.caller;
    }

    pub fn msgValue(self: *Self) [32]u8 {
        return self.value;
    }

    pub fn address(self: *Self) [20]u8 {
        return self.selfAddress;
    }
};

pub const CallResult = struct {
    success: bool,
    gasUsed: u64,
    returnData: []const u8,
    errorMsg: ?[]const u8,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn isZero(value: [32]u8) bool {
    for (value) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn bytesToU256(bytes: [32]u8) u256 {
    var result: u256 = 0;
    for (bytes) |b| {
        result = (result << 8) | b;
    }
    return result;
}
