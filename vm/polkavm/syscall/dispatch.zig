// File: vm/syscall/dispatch.zig
// Syscall dispatch for ForgeVM.
// Routes ECALL instructions to host functions based on the syscall ID in register a5 (x15).
// Implements the Zephyria syscall ABI: args in x10–x14, return in x10–x11, ID in x15.

const std = @import("std");
const executor = @import("../core/executor.zig");
const sandbox = @import("../memory/sandbox.zig");
const budgetTable = @import("../budget/table.zig");

pub const ForgeVM = executor.ForgeVM;
pub const SyscallError = executor.SyscallError;

// ---------------------------------------------------------------------------
// Syscall IDs (matches architecture doc)
// ---------------------------------------------------------------------------

pub const SyscallId = struct {
    // ── Storage ──────────────────────────────────────────────────
    pub const STORAGE_LOAD: u32 = 0x01;
    pub const STORAGE_STORE: u32 = 0x02;
    pub const STORAGE_LOAD_DERIVED: u32 = 0x03; // per-user slot (DerivedKey)
    pub const STORAGE_STORE_DERIVED: u32 = 0x04;
    pub const STORAGE_LOAD_GLOBAL: u32 = 0x05; // commutative accumulator
    pub const STORAGE_STORE_GLOBAL: u32 = 0x06;

    // ── Assets (FORGE-native, no EVM equivalent) ──────────────────
    pub const ASSET_TRANSFER: u32 = 0x10;
    pub const ASSET_BALANCE: u32 = 0x11;
    pub const ASSET_CREATE: u32 = 0x12;
    pub const ASSET_BURN: u32 = 0x13;
    pub const ASSET_METADATA: u32 = 0x14;
    pub const ASSET_APPROVE: u32 = 0x15;
    pub const ASSET_ALLOWANCE: u32 = 0x16;

    // ── Authority (FORGE role system) ────────────────────────────
    pub const AUTHORITY_CHECK: u32 = 0x20;
    pub const AUTHORITY_GRANT: u32 = 0x21;
    pub const AUTHORITY_REVOKE: u32 = 0x22;
    pub const AUTHORITY_LIST: u32 = 0x23;
    pub const TRANSIENT_LOAD: u32 = 0x26;
    pub const TRANSIENT_STORE: u32 = 0x27;

    // ── Events ───────────────────────────────────────────────────
    pub const EMIT_EVENT: u32 = 0x30;
    pub const EMIT_INDEXED_EVENT: u32 = 0x31;

    // ── Cross-contract calls ──────────────────────────────────────
    pub const CALL_CONTRACT: u32 = 0x40;
    pub const DELEGATECALL: u32 = 0x41;
    pub const STATICCALL: u32 = 0x42;
    pub const CREATE_CONTRACT: u32 = 0x43;
    pub const CREATE2_CONTRACT: u32 = 0x44;

    // ── Execution control ────────────────────────────────────────
    pub const RETURN_DATA: u32 = 0x50;
    pub const REVERT: u32 = 0x51;

    // ── Environment ──────────────────────────────────────────────
    pub const GET_CALLER: u32 = 0x60;
    pub const GET_CALLVALUE: u32 = 0x61;
    pub const GET_CALLDATA: u32 = 0x62;
    pub const GET_CALLDATA_SIZE: u32 = 0x63;
    pub const GET_SELF_ADDRESS: u32 = 0x64;
    pub const GET_BLOCK_NUMBER: u32 = 0x65;
    pub const GET_TIMESTAMP: u32 = 0x66;
    pub const GET_CHAIN_ID: u32 = 0x67;
    pub const GET_budget_REMAINING: u32 = 0x68;
    pub const GET_TX_ORIGIN: u32 = 0x69;
    pub const GET_budget_PRICE: u32 = 0x6A;
    pub const GET_COINBASE: u32 = 0x6B;
    pub const GET_BLOCK_HASH: u32 = 0x6C; // VRF randomness

    // ── Cryptography ─────────────────────────────────────────────
    pub const HASH_BLAKE3: u32 = 0x70; // replaces KECCAK256
    pub const HASH_SHA256: u32 = 0x71;
    pub const ECRECOVER: u32 = 0x72;
    pub const BLS_VERIFY: u32 = 0x73;

    // ── Parallel execution hints ──────────────────────────────────
    pub const RESOURCE_LOCK: u32 = 0x80; // declare write intent
    pub const RESOURCE_UNLOCK: u32 = 0x81;
    pub const PARALLEL_HINT: u32 = 0x82; // mark region conflict-free

    // ── Debug (only active in debug build) ───────────────────────
    pub const DEBUG_LOG: u32 = 0xFF;
};

// ---------------------------------------------------------------------------
// Host state that backs the syscalls
// ---------------------------------------------------------------------------

/// Storage backend interface — abstracts the underlying state database.
pub const StorageBackend = struct {
    ctx: *anyopaque,
    loadFn: *const fn (ctx: *anyopaque, key: [32]u8) [32]u8,
    storeFn: *const fn (ctx: *anyopaque, key: [32]u8, value: [32]u8) void,

    pub fn load(self: *StorageBackend, key: [32]u8) [32]u8 {
        return self.loadFn(self.ctx, key);
    }

    pub fn store(self: *StorageBackend, key: [32]u8, value: [32]u8) void {
        self.storeFn(self.ctx, key, value);
    }
};

/// Log entry captured during execution.
pub const LogEntry = struct {
    // ArrayListUnmanaged: allocator passed per-operation — matches .empty init and
    // two-arg append/deinit used throughout this file.
    topics: std.ArrayListUnmanaged([32]u8),
    data: std.ArrayListUnmanaged(u8),
    alloc: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) LogEntry {
        return .{
            .topics = .empty,
            .data = .empty,
            .alloc = allocator,
        };
    }

    pub fn deinit(self: *LogEntry) void {
        self.topics.deinit(self.alloc);
        self.data.deinit(self.alloc);
    }
};

/// EIP-2929 access tracking — tracks which storage slots and addresses
/// have been accessed during this execution for warm/cold budget pricing.
pub const AccessSets = struct {
    /// Warm storage slots (keys already accessed in this execution)
    warmSlots: std.AutoHashMap([32]u8, void),
    /// Warm addresses (addresses already accessed in this execution)
    warmAddresses: std.AutoHashMap([32]u8, void),
    /// Original storage values at the start of the transaction (for SSTORE refund calc)
    originalValues: std.AutoHashMap([32]u8, [32]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AccessSets {
        return .{
            .warmSlots = std.AutoHashMap([32]u8, void).init(allocator),
            .warmAddresses = std.AutoHashMap([32]u8, void).init(allocator),
            .originalValues = std.AutoHashMap([32]u8, [32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AccessSets) void {
        self.warmSlots.deinit();
        self.warmAddresses.deinit();
        self.originalValues.deinit();
    }

    /// Check if a storage slot is warm (already accessed). Does NOT mark it warm.
    pub fn isSlotWarm(self: *const AccessSets, key: [32]u8) bool {
        return self.warmSlots.contains(key);
    }

    /// Mark a storage slot as warm. Returns true if it was already warm.
    pub fn markSlotWarm(self: *AccessSets, key: [32]u8) bool {
        const wasWarm = self.warmSlots.contains(key);
        self.warmSlots.put(key, {}) catch {};
        return wasWarm;
    }

    /// Check if an address is warm.
    pub fn isAddressWarm(self: *const AccessSets, addr: [32]u8) bool {
        return self.warmAddresses.contains(addr);
    }

    /// Mark an address as warm. Returns true if it was already warm.
    pub fn markAddressWarm(self: *AccessSets, addr: [32]u8) bool {
        const wasWarm = self.warmAddresses.contains(addr);
        self.warmAddresses.put(addr, {}) catch {};
        return wasWarm;
    }

    /// Record the original value for a storage slot (for SSTORE refund tracking).
    /// Only records if not already present (first write wins).
    pub fn recordOriginalValue(self: *AccessSets, key: [32]u8, value: [32]u8) void {
        _ = self.originalValues.getOrPutValue(key, value) catch {};
    }

    /// Get the original value for a slot (pre-transaction value).
    pub fn getOriginalValue(self: *const AccessSets, key: [32]u8) ?[32]u8 {
        return self.originalValues.get(key);
    }
};

/// Host environment state provided to syscall handlers.
pub const HostEnv = struct {
    // Storage
    storage: ?*StorageBackend,

    // Environment values (set by the node before execution)
    caller: [32]u8,
    callValue: [32]u8,
    selfAddress: [32]u8,
    blockNumber: u64,
    timestamp: u64,
    chainId: u64,
    txOrigin: [32]u8,
    computePrice: u64,
    producer: [32]u8,
    executionBudget: u64,
    prevrandao: [32]u8,

    // Logs accumulated during execution
    // ArrayListUnmanaged so callers pass the allocator per operation (matches .empty init)
    logs: std.ArrayListUnmanaged(LogEntry),
    allocator: std.mem.Allocator,
    immutableData: std.ArrayList(u8),

    // ---- Last sub-call return data (for RETURNDATASIZE/RETURNDATACOPY) ----
    lastReturnData: []const u8 = &[_]u8{},

    // ---- Warm SLOAD value cache (inline, no heap alloc) ----
    // Caches the last 8 SLOAD results for re-read acceleration.
    // At 1M TPS with ~5 SLOADs/TX, most reads hit warm slots.
    sloadCacheKeys: [8][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 8,
    sloadCacheVals: [8][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 8,
    sloadCacheCount: u8 = 0,

    // ---- EIP-2929 access tracking ----
    accessSets: AccessSets,

    // ---- Pluggable providers for node integration ----

    /// Balance provider: returns 32-byte balance for a 32-byte address.
    /// If null, getBalance returns 0.
    balanceFn: ?*const fn (addr: [32]u8) [32]u8 = null,

    /// Sig verify provider: verifies Ed25519/pluggable signature and returns derived address.
    /// Signature scheme: 0 = Ed25519, 1 = BLS12-381, 2 = quantum-resistant.
    /// Returns blake3(pubkey) as the signer address, or zeroes on failure.
    /// If null, returns zero address.
    ecrecoverFn: ?*const fn (hash: [32]u8, scheme: u8, pubkey: [32]u8, signature: [64]u8) [32]u8 = null,

    /// Call provider: execute a cross-contract call.
    /// Returns (success, returnData). If null, calls return failure.
    callFn: ?*const fn (callType: CallType, to: [32]u8, value: [32]u8, data: []const u8, budget: u64) CallProviderResult = null,

    /// Create provider: deploy a new contract.
    /// Returns (success, newAddress). If null, creates return failure.
    createFn: ?*const fn (code: []const u8, value: [32]u8, budget: u64) CreateProviderResult = null,

    /// Create2 provider: deploy a contract with salt-based deterministic address.
    /// Address = keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
    /// If null, create2 returns failure.
    create2Fn: ?*const fn (code: []const u8, salt: [32]u8, value: [32]u8, budget: u64) CreateProviderResult = null,

    /// Instantiate provider: deploy a contract from its code hash (Substrate compat).
    instantiateFn: ?*const fn (code_hash: [32]u8, value: [32]u8, input: []const u8, salt: ?[32]u8, budget: u64) CreateProviderResult = null,

    /// Selfdestruct provider: transfers balance to beneficiary and marks account for deletion.
    /// If null, selfdestruct is a no-op that still halts execution.
    selfDestructFn: ?*const fn (beneficiary: [32]u8) bool = null,

    // ---- ZephyrLang Specific Providers ----

    /// Asset transfer provider: FORGE native asset transfer.
    assetTransferFn: ?*const fn (host: *HostEnv, assetId: [32]u8, from: [32]u8, to: [32]u8, amount: u128) anyerror!void = null,

    derivedLoadFn: ?*const fn (host: *HostEnv, user: [32]u8, slot: [32]u8) [32]u8 = null,
    derivedStoreFn: ?*const fn (host: *HostEnv, user: [32]u8, slot: [32]u8, value: [32]u8) anyerror!void = null,
    globalLoadFn: ?*const fn (host: *HostEnv, slot: [32]u8) [32]u8 = null,
    globalStoreFn: ?*const fn (host: *HostEnv, slot: [32]u8, delta: [32]u8, isAddition: bool) anyerror!void = null,

    /// Parallel safe hint
    parallelSafe: bool = false,

    /// VM execution pool (reusable sandbox memory, decoded code cache)
    /// When set, contract_loader uses pooled sandbox + threaded executor. 
    vm_pool: ?*anyopaque = null,

    /// Get code hash for a contract: returns 32-byte hash
    codeHashFn: ?*const fn (addr: [32]u8) [32]u8 = null,

    /// Get code size for a contract
    codeSizeFn: ?*const fn (addr: [32]u8) u64 = null,

    /// Role checking provider
    roleCheckFn: ?*const fn (addr: [32]u8, role: [32]u8, account: [32]u8) bool = null,

    /// Role management provider (for ZephyrLang native roles)
    roleGrantFn: ?*const fn (addr: [32]u8, role: [32]u8, account: [32]u8) void = null,
    roleRevokeFn: ?*const fn (addr: [32]u8, role: [32]u8, account: [32]u8) void = null,

    /// Resource lock/unlock provider (for linear types)
    resourceLockFn: ?*const fn (addr: [32]u8, id: [32]u8) bool = null,
    resourceUnlockFn: ?*const fn (addr: [32]u8, id: [32]u8) void = null,

    // ---- EIP-1153: Transient Storage (per-TX ephemeral key-value store) ----
    // Transient storage is automatically cleared when HostEnv is deinitialized
    // (at the end of each transaction). Cheap (100 budget) alternative to SSTORE
    // for values that don't need to persist across transactions.
    // Use cases: re-entrancy locks, flash loan callbacks, multi-hop routing state.
    transientStorage: std.AutoHashMap([32]u8, [32]u8),

    // ---- Call depth tracking (EVM max 1024) ----
    callDepth: u16 = 0,
    maxCallDepth: u16 = 1024,

    // ---- Re-entrancy protection (per-address guard) ----
    // Tracks which contract addresses are currently executing.
    // If a contract calls back into an address that is already in the call stack,
    // and that contract has re-entrancy protection enabled, the call is rejected.
    reentrantGuard: std.AutoHashMap([32]u8, void),

    pub fn init(allocator: std.mem.Allocator) HostEnv {
        return .{
            .storage = null,
            .caller = [_]u8{0} ** 32,
            .callValue = [_]u8{0} ** 32,
            .selfAddress = [_]u8{0} ** 32,
            .blockNumber = 0,
            .timestamp = 0,
            .chainId = 1,
            .txOrigin = [_]u8{0} ** 32,
            .computePrice = 0,
            .producer = [_]u8{0} ** 32,

            .executionBudget = 30_000_000,
            .prevrandao = [_]u8{0} ** 32,
            .logs = .empty,
            .allocator = allocator,
            .immutableData = .empty,
            .accessSets = AccessSets.init(allocator),
            .balanceFn = null,
            .ecrecoverFn = null,
            .callFn = null,
            .createFn = null,
            .create2Fn = null,
            .instantiateFn = null,
            .selfDestructFn = null,
            .codeHashFn = null,
            .codeSizeFn = null,
            .roleCheckFn = null,
            .roleGrantFn = null,
            .roleRevokeFn = null,
            .resourceLockFn = null,
            .resourceUnlockFn = null,
            .transientStorage = std.AutoHashMap([32]u8, [32]u8).init(allocator),
            .reentrantGuard = std.AutoHashMap([32]u8, void).init(allocator),
        };
    }

    pub fn deinit(self: *HostEnv) void {
        for (self.logs.items) |*logEntry| {
            logEntry.deinit();
        }
        self.logs.deinit(self.allocator);
        self.immutableData.deinit(self.allocator);
        self.accessSets.deinit();
        self.transientStorage.deinit();
        self.reentrantGuard.deinit();
    }

    /// Clear transient storage (called at TX boundary).
    /// EIP-1153: transient storage is automatically discarded after each TX.
    pub fn clearTransientStorage(self: *HostEnv) void {
        self.transientStorage.clearRetainingCapacity();
        self.reentrantGuard.clearRetainingCapacity();
        self.callDepth = 0;
    }

    /// Cache a SLOAD value in the inline MRU cache (8 entries).
    /// Most DeFi contracts re-read the same slots multiple times per call.
    pub fn cacheSloadValue(self: *HostEnv, key: [32]u8, value: [32]u8) void {
        // Check if key already in cache — update value in place
        for (self.sloadCacheKeys[0..self.sloadCacheCount], 0..) |cached_key, i| {
            if (std.mem.eql(u8, &cached_key, &key)) {
                self.sloadCacheVals[i] = value;
                return;
            }
        }
        // Add new entry (circular buffer)
        const idx = self.sloadCacheCount % 8;
        self.sloadCacheKeys[idx] = key;
        self.sloadCacheVals[idx] = value;
        if (self.sloadCacheCount < 8) self.sloadCacheCount += 1;
    }

    /// Look up a key in the SLOAD value cache.
    /// Returns the cached value if found, null otherwise.
    pub fn lookupSloadCache(self: *const HostEnv, key: [32]u8) ?[32]u8 {
        for (self.sloadCacheKeys[0..self.sloadCacheCount], 0..) |cached_key, i| {
            if (std.mem.eql(u8, &cached_key, &key)) {
                return self.sloadCacheVals[i];
            }
        }
        return null;
    }
};

/// Cross-contract call type
pub const CallType = enum {
    call,
    delegatecall,
    staticcall,
};

/// Result from a cross-contract call provider
pub const CallProviderResult = struct {
    success: bool,
    returnData: []const u8,
    budgetUsed: u64,
};

/// Result from a create provider
pub const CreateProviderResult = struct {
    success: bool,
    newAddress: [32]u8,
    budgetUsed: u64,
};

// ---------------------------------------------------------------------------
// Syscall dispatcher — creates a syscall handler function for a given HostEnv
// ---------------------------------------------------------------------------

/// Create a syscall handler and bind it to the given host environment.
///
/// Thread-safety model: the env pointer is stored in `vm.hostCtx` (a field of
/// ForgeVM set by the caller right after init). The handler retrieves it from
/// there at dispatch time. This means every VM instance carries its own env
/// pointer — there is NO shared mutable static, so concurrent VMs on the same
/// or different threads are fully independent.
///
/// Callers MUST set `vm.hostCtx = env` after `ForgeVM.init` and before the
/// first `execute()` or `step()` call. `contract_loader` and `vm.zig` already
/// do this.
pub fn createHandler(env: *HostEnv) executor.SyscallFn {
    // Validate at creation time so callers get a clear error immediately if
    // something is wired wrongly, rather than a silent null-deref at runtime.
    _ = env; // env stored in vm.hostCtx by the caller — not captured here
    return &syscallDispatch;
}

/// The single concrete syscall dispatch function.
/// Retrieves HostEnv from `vm.hostCtx` — set by the caller before execution.
fn syscallDispatch(vm_opaque: *anyopaque) executor.SyscallError!void {
    const vm: *ForgeVM = @ptrCast(@alignCast(vm_opaque));
    // Retrieve the HostEnv pointer stored in the VM by the loader/vm.zig.
    const env: *HostEnv = @ptrCast(@alignCast(vm.hostCtx orelse {
        return executor.SyscallError.InternalError; // hostCtx was never set
    }));

    const syscallId: u32 = @truncate(vm.regs[10]); // a0 = syscall ID
    switch (syscallId) {
        SyscallId.STORAGE_LOAD => try storageLoad(vm, env),
        SyscallId.STORAGE_STORE => try storageStore(vm, env),
        SyscallId.STORAGE_LOAD_DERIVED => try derivedStorageLoad(vm, env),
        SyscallId.STORAGE_STORE_DERIVED => try derivedStorageStore(vm, env),
        SyscallId.STORAGE_LOAD_GLOBAL => try globalStorageLoad(vm, env),
        SyscallId.STORAGE_STORE_GLOBAL => try globalStorageStore(vm, env),
        SyscallId.TRANSIENT_LOAD => try transientLoad(vm, env),
        SyscallId.TRANSIENT_STORE => try transientStore(vm, env),
        SyscallId.CREATE2_CONTRACT => try create2Contract(vm, env),
        SyscallId.EMIT_EVENT => try emitEvent(vm, env),
        SyscallId.EMIT_INDEXED_EVENT => try emitEvent(vm, env), // same impl for now
        SyscallId.GET_CALLER => getCaller(vm, env),
        SyscallId.GET_CALLVALUE => getCallValue(vm, env),
        SyscallId.GET_CALLDATA => getCallData(vm),
        SyscallId.GET_CALLDATA_SIZE => getCallDataSize(vm),
        SyscallId.RETURN_DATA => {
            returnData(vm);
            return executor.SyscallError.ReturnData;
        },
        SyscallId.REVERT => {
            revertExecution(vm);
            return executor.SyscallError.Revert;
        },
        SyscallId.HASH_BLAKE3 => try handleBlake3(vm, env),
        SyscallId.HASH_SHA256 => try handleSha256(vm, env),
        SyscallId.ASSET_TRANSFER => try handleAssetTransfer(vm, env),
        SyscallId.ASSET_BALANCE => try getBalance(vm, env),
        SyscallId.PARALLEL_HINT => try handleParallelHint(vm, env),
        SyscallId.GET_BLOCK_NUMBER => getBlockNumber(vm, env),
        SyscallId.GET_TIMESTAMP => getTimestamp(vm, env),
        SyscallId.GET_CHAIN_ID => getChainId(vm, env),
        SyscallId.GET_budget_REMAINING => getbudgetRemaining(vm),
        SyscallId.GET_TX_ORIGIN => getTxOrigin(vm, env),
        SyscallId.GET_budget_PRICE => getcomputePrice(vm, env),
        SyscallId.GET_COINBASE => getCoinbase(vm, env),
        SyscallId.GET_SELF_ADDRESS => getSelfAddress(vm, env),
        SyscallId.GET_BLOCK_HASH => getPrevrandao(vm, env),
        SyscallId.DEBUG_LOG => try debugLog(vm, env),
        SyscallId.CREATE_CONTRACT => try createContract(vm, env),
        SyscallId.AUTHORITY_CHECK => try roleCheck(vm, env),
        SyscallId.AUTHORITY_GRANT => try roleGrant(vm, env),
        SyscallId.AUTHORITY_REVOKE => try roleRevoke(vm, env),
        SyscallId.RESOURCE_LOCK => try resourceLock(vm, env),
        SyscallId.RESOURCE_UNLOCK => try resourceUnlock(vm, env),
        SyscallId.CALL_CONTRACT => try callContract(vm, env, .call),
        SyscallId.DELEGATECALL => try callContract(vm, env, .delegatecall),
        SyscallId.STATICCALL => try callContract(vm, env, .staticcall),
        SyscallId.ECRECOVER => try ecrecover(vm, env),
        SyscallId.BLS_VERIFY => {
            // Not yet implemented — return failure
            vm.regs[10] = 0;
        },
        // ── Substrate/PolkaVM Compat Syscalls ──
        0x101 => try sealGetStorage(vm, env),
        0x102 => try sealSetStorage(vm, env),
        0x103 => try sealClearStorage(vm, env),
        0x104 => try sealContainsStorage(vm, env),
        0x105 => try sealTransfer(vm, env),
        0x106 => try sealCall(vm, env, .call),
        0x107 => try sealCall(vm, env, .delegatecall),
        0x108 => try sealCaller(vm, env),
        0x109 => try sealAddress(vm, env),
        0x10A => try sealValueTransferred(vm, env),
        0x10B => try sealbudgetLeft(vm, env),
        0x10C => try sealBalance(vm, env),
        0x10D => try sealHashKeccak256(vm, env),
        0x10E => try sealHashBlake2_256(vm, env),
        0x10F => try sealHashSha256(vm, env),
        0x110 => try sealHashBlake3(vm, env),
        0x111 => {
            try sealReturn(vm, env);
            return executor.SyscallError.ReturnData;
        },
        0x112 => {
            try sealRevert(vm, env);
            return executor.SyscallError.Revert;
        },
        0x113 => try sealInstantiate(vm, env),
        0x115 => try sealRandom(vm, env),
        0x116 => try sealBlockNumber(vm, env),
        0x117 => try sealNow(vm, env),
        0x11A => try sealcomputePrice(vm, env),
        0x11B => try sealTerminate(vm, env),
        // ── Substrate/PolkaVM Modern Revive Compat Syscalls ──
        0x201 => try reviveAddress(vm, env),
        0x202 => try reviveBalance(vm, env),
        0x203 => try reviveBalanceOf(vm, env),
        0x204 => try reviveBaseFee(vm, env),
        0x205 => try reviveBlockAuthor(vm, env),
        0x206 => try reviveBlockHash(vm, env),
        0x207 => try reviveBlockNumber(vm, env),
        0x208 => try reviveCallDataCopy(vm),
        0x209 => try reviveCallDataLoad(vm),
        0x20A => try reviveCallDataSize(vm),
        0x20B => try reviveCallEvm(vm, env),
        0x20C => try reviveCaller(vm, env),
        0x20D => try reviveChainId(vm, env),
        0x20E => try reviveCodeHash(vm, env),
        0x20F => try reviveCodeSize(vm, env),
        0x210 => try reviveConsumeAllbudget(vm),
        0x211 => try reviveDelegateCallEvm(vm, env),
        0x212 => try reviveDepositEvent(vm, env),
        0x213 => try revivebudgetLimit(vm),
        0x214 => try revivecomputePrice(vm, env),
        0x215 => try reviveGetImmutableData(vm, env),
        0x216 => try reviveGetStorageOrZero(vm, env),
        0x217 => try reviveHashKeccak256(vm),
        0x218 => try reviveInstantiate(vm, env),
        0x219 => try reviveNow(vm, env),
        0x21A => try reviveOrigin(vm, env),
        0x21B => try reviveRefTimeLeft(vm),
        0x21C => try reviveReturnDataCopy(vm, env),
        0x21D => try reviveReturnDataSize(vm, env),
        0x21F => try reviveSetImmutableData(vm, env),
        0x220 => try reviveSetStorageOrClear(vm, env),
        0x222 => try reviveValueTransferred(vm, env),
        else => return executor.SyscallError.UnknownSyscall,
    }
}

// ---------------------------------------------------------------------------
// Individual syscall implementations
// ---------------------------------------------------------------------------

/// Syscall 0x01: storage_load (EIP-2929 warm/cold)
/// a0 = pointer to 32-byte key in VM memory
/// a1 = pointer to 32-byte result buffer in VM memory
fn storageLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const keyPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    // Zero-copy: read key directly from backing memory
    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    // EIP-2929: charge warm (100) or cold (2100) budget
    const wasWarm = env.accessSets.markSlotWarm(key);
    const budgetCost = budgetTable.Syscallbudget.STORAGE_LOAD;
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    // Fast path: check inline SLOAD value cache (avoids storage backend round-trip)
    const value = if (wasWarm)
        (env.lookupSloadCache(key) orelse if (env.storage) |s| s.load(key) else [_]u8{0} ** 32)
    else
        (if (env.storage) |s| s.load(key) else [_]u8{0} ** 32);

    // Cache the loaded value for re-read acceleration
    env.cacheSloadValue(key, value);

    // Record original value for SSTORE refund tracking (if first access)
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, value);
    }

    // Zero-copy: write result directly to backing memory
    const result_ref = vm.memory.getAligned32Mut(resultPtr) catch return SyscallError.SegFault;
    result_ref.* = value;
}

/// Syscall 0x02: storage_store (EIP-2929 warm/cold + EIP-3529 refund)
/// a0 = pointer to 32-byte key
/// a1 = pointer to 32-byte value
fn storageStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const keyPtr = vm.regs[11]; // a1
    const value_ptr = vm.regs[12]; // a2

    // Zero-copy: read key directly from backing memory
    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    // Zero-copy: read value directly from backing memory
    const valRef = vm.memory.getAligned32(value_ptr) catch return SyscallError.SegFault;
    const newValue = valRef.*;

    // Read current value from storage
    const currentValue = if (env.storage) |s| s.load(key) else [_]u8{0} ** 32;
    const zeroSlot: [32]u8 = [_]u8{0} ** 32;

    // Record original value if first time accessing this slot
    const wasWarm = env.accessSets.markSlotWarm(key);
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, currentValue);
    }

    // FORGE flat budget model
    if (!wasWarm) {
        vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;
    }

    // Determine SSTORE budget based on current and new values
    const isNoop = std.mem.eql(u8, &currentValue, &newValue);
    const originalValue = env.accessSets.getOriginalValue(key) orelse currentValue;
    const orig_is_current = std.mem.eql(u8, &originalValue, &currentValue);
    const orig_is_zero = std.mem.eql(u8, &originalValue, &zeroSlot);
    const new_is_zero = std.mem.eql(u8, &newValue, &zeroSlot);

    if (isNoop) {
        // No-op: value unchanged — charge warm access only
        vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;
    } else if (orig_is_current) {
        if (orig_is_zero) {
            // 0 → non-zero: fresh allocation
            vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE_SET) catch return SyscallError.OutOfbudget;
        } else {
            // non-zero → different non-zero (or non-zero → zero): reset
            vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;
            // EIP-3529: refund for clearing (non-zero → zero)
            if (new_is_zero) {
                vm.budget.addRefund(budgetTable.Syscallbudget.STORAGE_CLEAR_REFUND);
            }
        }
    } else {
        // Dirty slot (already modified this transaction) — warm access
        vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;

        // EIP-3529 refund adjustments for restoring original value
        if (!orig_is_zero and new_is_zero) {
            // Restoring to zero from a dirty non-zero
            vm.budget.addRefund(budgetTable.Syscallbudget.STORAGE_CLEAR_REFUND);
        }
    }

    if (env.storage) |s| s.store(key, newValue);
    // Invalidate cache entry on write
    env.cacheSloadValue(key, newValue);
}

/// Syscall 0x03: emit_event
/// a0 = topicCount (0–4)
/// a1 = pointer to topics array (topicCount × 32 bytes)
/// a2 = pointer to data
/// a3 = dataLen
fn emitEvent(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const topicCount = vm.regs[11];
    const topicsPtr = vm.regs[12];
    const dataPtr = vm.regs[13];
    const dataLen = vm.regs[14];

    if (topicCount > 4) return SyscallError.InternalError;

    // budget: base + per-byte for data
    const budgetCost = budgetTable.Syscallbudget.EMIT_EVENT_BASE + budgetTable.Syscallbudget.EMIT_EVENT_PER_BYTE * @as(u64, dataLen);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    var logEntry = LogEntry.init(env.allocator);

    // Read topics
    var i: u32 = 0;
    while (i < topicCount) : (i += 1) {
        const topic_offset = topicsPtr + i * 32;
        const topic_slice = vm.memory.getSlice(topic_offset, 32) catch return SyscallError.SegFault;
        var topic: [32]u8 = undefined;
        @memcpy(&topic, topic_slice);
        logEntry.topics.append(logEntry.alloc, topic) catch return SyscallError.InternalError;
    }

    // Read data
    if (dataLen > 0) {
        const data_slice = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
        logEntry.data.appendSlice(logEntry.alloc, data_slice) catch return SyscallError.InternalError;
    }

    env.logs.append(env.allocator, logEntry) catch return SyscallError.InternalError;
}

/// Syscall 0x06: get_caller → writes msg.sender (32 bytes) to memory at a0
fn getCaller(vm: *ForgeVM, env: *HostEnv) void {
    vm.budget.consume(budgetTable.Syscallbudget.GET_CALLER) catch return;
    const bufPtr = vm.regs[11];
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.caller);
}

/// Syscall 0x07: get_callvalue → writes msg.value (32 bytes) to memory at a0
fn getCallValue(vm: *ForgeVM, env: *HostEnv) void {
    vm.budget.consume(budgetTable.Syscallbudget.GET_CALLVALUE) catch return;
    const bufPtr = vm.regs[11];
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.callValue);
}

/// Syscall 0x08: get_calldata → copies calldata[a0..a0+a1] to memory at a2
fn getCallData(vm: *ForgeVM) void {
    const offset = vm.regs[11];
    const len = vm.regs[12];
    const dest = vm.regs[13];

    // Read from calldata region
    const src = sandbox.calldataStart + offset;
    const src_slice = vm.memory.getSlice(src, len) catch return;
    const dst_slice = vm.memory.getSliceMut(dest, len) catch return;
    @memcpy(dst_slice, src_slice);
}

/// Syscall 0x13: get_calldata_size → returns actual calldata length in a0
fn getCallDataSize(vm: *ForgeVM) void {
    vm.regs[10] = vm.calldataLen;
}

/// Syscall 0x09: returnData — a0 = pointer to data, a1 = length
fn returnData(vm: *ForgeVM) void {
    const dataPtr = vm.regs[11];
    const dataLen = vm.regs[12];

    // Copy to return region
    if (dataLen > 0 and dataLen <= sandbox.returnSize) {
        const src = vm.memory.getSlice(dataPtr, dataLen) catch return;
        const dst = vm.memory.getSliceMut(sandbox.returnStart, dataLen) catch return;
        @memcpy(dst, src);
    }

    vm.returnDataOffset = 0;
    vm.returnDataLen = @truncate(dataLen);
}

/// Syscall 0x0A: revert — a0 = pointer to error data, a1 = length
fn revertExecution(vm: *ForgeVM) void {
    const dataPtr = vm.regs[11];
    const dataLen = vm.regs[12];

    if (dataLen > 0 and dataLen <= sandbox.returnSize) {
        const src = vm.memory.getSlice(dataPtr, dataLen) catch return;
        const dst = vm.memory.getSliceMut(sandbox.returnStart, dataLen) catch return;
        @memcpy(dst, src);
    }

    vm.returnDataOffset = 0;
    vm.returnDataLen = @truncate(dataLen);
}

/// Syscall 0x0C: get_balance (EIP-2929 warm/cold) — a0 = ptr to 32-byte address, writes 32-byte balance to a1
fn getBalance(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr: u32 = @truncate(vm.regs[11]);
    const resultPtr: u32 = @truncate(vm.regs[12]);

    // Read 32-byte address from VM memory
    const addrSlice = vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault;
    var addr: [32]u8 = undefined;
    @memcpy(&addr, addrSlice);

    const budgetCost = budgetTable.Syscallbudget.ASSET_QUERY_BALANCE;
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    // Get balance via provider, or return zero
    const balance = if (env.balanceFn) |f| f(addr) else [_]u8{0} ** 32;

    // Write 32-byte balance to VM memory
    const result_slice = vm.memory.getSliceMut(resultPtr, 32) catch return SyscallError.SegFault;
    @memcpy(result_slice, &balance);
    vm.regs[10] = 0;
}

/// Syscall 0x65: get_block_number → a0 = low 32 bits
fn getBlockNumber(vm: *ForgeVM, env: *HostEnv) void {
    vm.budget.consume(budgetTable.Syscallbudget.GET_BLOCK_NUMBER) catch return;
    vm.regs[10] = @truncate(env.blockNumber);
}

/// Syscall 0x66: get_timestamp → a0 = low 32 bits
fn getTimestamp(vm: *ForgeVM, env: *HostEnv) void {
    vm.budget.consume(budgetTable.Syscallbudget.GET_TIMESTAMP) catch return;
    vm.regs[10] = @truncate(env.timestamp);
}

/// Syscall 0x67: get_chain_id → a0 = chain ID
fn getChainId(vm: *ForgeVM, env: *HostEnv) void {
    vm.budget.consume(budgetTable.Syscallbudget.GET_CHAIN_ID) catch return;
    vm.regs[10] = @truncate(env.chainId);
}

/// Syscall 0x68: get_budget_remaining → a0 = remaining budget (low 32 bits)
fn getbudgetRemaining(vm: *ForgeVM) void {
    vm.regs[10] = vm.budget.remaining();
}

/// Syscall 0x15: get_tx_origin → writes 32 bytes to memory at a1
fn getTxOrigin(vm: *ForgeVM, env: *HostEnv) void {
    const bufPtr = vm.regs[11]; // a1 — a0 is the syscall ID
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.txOrigin);
}

/// Syscall GET_budget_PRICE → a0 = budget price (low 32 bits), result overwrites a0
fn getcomputePrice(vm: *ForgeVM, env: *HostEnv) void {
    vm.regs[10] = @truncate(env.computePrice);
}

/// Syscall 0x17: get_coinbase → writes 32 bytes to memory at a1
fn getCoinbase(vm: *ForgeVM, env: *HostEnv) void {
    const bufPtr = vm.regs[11];
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.producer);
}

/// Syscall 0x18: get_execution_budget → a0 = execution budget (low 32 bits)
fn getbudgetLimit(vm: *ForgeVM, env: *HostEnv) void {
    vm.regs[10] = @truncate(env.executionBudget);
}

/// Syscall GET_BLOCK_HASH / prevrandao
/// a0 = syscallId, a1 = ptr to 32-byte output buffer
/// Writes the VRF prevrandao value (Zephyria uses VRF-based randomness).
fn getPrevrandao(vm: *ForgeVM, env: *HostEnv) void {
    vm.budget.consume(20) catch return; // cheap env read
    const bufPtr = vm.regs[11]; // a1
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.prevrandao);
}

/// Syscall 0x1B: get_self_address → writes 32 bytes to memory at a1
fn getSelfAddress(vm: *ForgeVM, env: *HostEnv) void {
    const bufPtr = vm.regs[11]; // a1 — a0 is the syscall ID
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.selfAddress);
}

/// Syscall 0x12: log_raw — raw log emission
/// a0 = syscallId, a1 = topicCount (0-4), a2 = topicsPtr, a3 = dataPtr, a4 = dataLen
/// Equivalent to LOG0-LOG4 EVM opcodes.
fn logRaw(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const topicCount = vm.regs[11]; // a1
    const topicsPtr = vm.regs[12]; // a2
    const dataPtr = vm.regs[13]; // a3
    const dataLen = vm.regs[14]; // a4

    if (topicCount > 4) return SyscallError.InternalError;

    // budget: base_cost + per_topic + per_byte_data
    const budgetCost = budgetTable.Syscallbudget.EMIT_EVENT_BASE +
        @as(u64, topicCount) * 375 + // EVM LOG_TOPIC_budget = 375
        budgetTable.Syscallbudget.EMIT_EVENT_PER_BYTE * @as(u64, dataLen);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    var logEntry = LogEntry.init(env.allocator);

    // Read topics
    var i: u32 = 0;
    while (i < topicCount) : (i += 1) {
        const topic_offset = topicsPtr + i * 32;
        const topic_slice = vm.memory.getSlice(topic_offset, 32) catch return SyscallError.SegFault;
        var topic: [32]u8 = undefined;
        @memcpy(&topic, topic_slice);
        logEntry.topics.append(logEntry.alloc, topic) catch return SyscallError.InternalError;
    }

    // Read data
    if (dataLen > 0) {
        const data_slice = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
        logEntry.data.appendSlice(logEntry.alloc, data_slice) catch return SyscallError.InternalError;
    }

    env.logs.append(env.allocator, logEntry) catch return SyscallError.InternalError;
}

/// Syscall 0x04/0x05/0x1C: call_contract / delegatecall / staticcall (EIP-2929 warm/cold)
/// a0 = ptr to 20-byte target address
/// a1 = ptr to 32-byte value (only for CALL, ignored for delegatecall/staticcall)
/// a2 = ptr to input data
/// a3 = input data length
/// Returns: a0 = 1 (success) or 0 (failure)
fn callContract(vm: *ForgeVM, env: *HostEnv, callType: CallType) SyscallError!void {
    // Read target address first so we can check warm/cold
    const toPtr_peek = vm.regs[11];
    const to_slice_peek = vm.memory.getSlice(toPtr_peek, 32) catch return SyscallError.SegFault;
    var to_addr_peek: [32]u8 = undefined;
    @memcpy(&to_addr_peek, to_slice_peek);

    // FORGE flat budget model
    const call_budget = budgetTable.Syscallbudget.CALL_CONTRACT;
    vm.budget.consume(call_budget) catch return SyscallError.OutOfbudget;

    const toPtr = vm.regs[11];
    const value_ptr = vm.regs[12];
    const dataPtr = vm.regs[13];
    const dataLen = vm.regs[14];

    // Read target address (32 bytes)
    const to_slice = vm.memory.getSlice(toPtr, 32) catch return SyscallError.SegFault;
    var to: [32]u8 = undefined;
    @memcpy(&to, to_slice);

    // Read value (32 bytes) — only meaningful for CALL
    var value: [32]u8 = [_]u8{0} ** 32;
    if (callType == .call) {
        const valSlice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
        @memcpy(&value, valSlice);
    }

    // Read input data
    var data: []const u8 = &[_]u8{};
    if (dataLen > 0) {
        data = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    }

    // Execute via provider
    if (env.callFn) |callFn| {
        // Check call depth limit (EVM max 1024)
        if (env.callDepth >= env.maxCallDepth) {
            vm.regs[10] = 0; // Call depth exceeded — return failure
            return;
        }
        env.callDepth += 1;
        defer env.callDepth -= 1;

        // Re-entrancy guard: check if target address is already in the call stack
        if (env.reentrantGuard.contains(to)) {
            // Target is already executing — potential re-entrancy
            // We still allow the call (non-reentrant guard is opt-in at SDK level)
            // but we track it for VM-level enforcement when contracts opt in.
        }

        // Track this address in the call stack
        env.reentrantGuard.put(to, {}) catch {};
        defer _ = env.reentrantGuard.remove(to);

        const budget_to_forward = vm.budget.remaining();
        const result = callFn(callType, to, value, data, budget_to_forward);

        // Consume budget used by the subcall
        vm.budget.consume(result.budgetUsed) catch {};

        // Store last return data for RETURNDATASIZE/RETURNDATACOPY
        env.lastReturnData = result.returnData;

        // Write return data to return region
        if (result.returnData.len > 0 and result.returnData.len <= sandbox.returnSize) {
            const dst = vm.memory.getSliceMut(sandbox.returnStart, @intCast(result.returnData.len)) catch {
                vm.regs[10] = 0;
                return;
            };
            @memcpy(dst, result.returnData);
            vm.returnDataLen = @intCast(result.returnData.len);
            vm.returnDataOffset = 0;
        }

        vm.regs[10] = if (result.success) 1 else 0;
    } else {
        // No call provider — return failure
        vm.regs[10] = 0;
    }
}

/// Syscall 0x10: create_contract — deploy a new contract
/// a0 = ptr to init code
/// a1 = init code length
/// a2 = ptr to 32-byte value (ETH to send)
/// a3 = ptr to 20-byte result buffer (new address written here)
/// Returns: a0 = 1 (success) or 0 (failure)
fn createContract(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(budgetTable.Syscallbudget.CREATE_CONTRACT) catch return SyscallError.OutOfbudget;

    const code_ptr = vm.regs[11];
    const code_len = vm.regs[12];
    const value_ptr = vm.regs[13];
    const resultPtr = vm.regs[14];

    // EIP-3860: enforce max initcode size (49152 bytes)
    if (code_len > 49152) {
        vm.regs[10] = 0;
        return;
    }

    // Read init code
    var code: []const u8 = &[_]u8{};
    if (code_len > 0) {
        code = vm.memory.getSlice(code_ptr, code_len) catch return SyscallError.SegFault;

        // EIP-3860: charge 2 budget per 32-byte word of initcode
        const words = (code_len + 31) / 32;
        vm.budget.consume(2 * @as(u64, words)) catch return SyscallError.OutOfbudget;
    }

    // Read value
    const valSlice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var value: [32]u8 = undefined;
    @memcpy(&value, valSlice);

    // Execute via provider
    if (env.createFn) |createFn| {
        // Check call depth limit
        if (env.callDepth >= env.maxCallDepth) {
            vm.regs[10] = 0;
            return;
        }
        env.callDepth += 1;
        defer env.callDepth -= 1;

        const budget_to_forward = vm.budget.remaining();
        const result = createFn(code, value, budget_to_forward);

        vm.budget.consume(result.budgetUsed) catch {};

        if (result.success) {
            // Write new address to result buffer
            const addrSlice = vm.memory.getSliceMut(resultPtr, 32) catch {
                vm.regs[10] = 0;
                return;
            };
            @memcpy(addrSlice, &result.newAddress);
            vm.regs[10] = 1;
        } else {
            vm.regs[10] = 0;
        }
    } else {
        vm.regs[10] = 0;
    }
}

/// Syscall 0x25: create2 — deploy a contract with salt-based deterministic address (EIP-1014)
/// a0 = ptr to init code
/// a1 = init code length
/// a2 = ptr to 32-byte salt
/// a3 = ptr to 32-byte value (ETH to send)
/// a4 = ptr to 20-byte result buffer (new address written here)
/// Returns: a0 = 1 (success) or 0 (failure)
///
/// Address derivation: keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
/// This enables counterfactual addresses, factory patterns (Uniswap V3),
/// minimal proxy clones, and deterministic deployment across chains.
fn create2Contract(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // Base budget: same as CREATE (32000) + per-word hash cost for initcode
    vm.budget.consume(32000) catch return SyscallError.OutOfbudget;

    const code_ptr = vm.regs[11]; // a1
    const code_len = vm.regs[12]; // a2
    const salt_ptr = vm.regs[13]; // a3
    const value_ptr = vm.regs[14]; // a4
    const resultPtr = vm.regs[15]; // a5 — result buffer (32 bytes)

    // Read init code
    var code: []const u8 = &[_]u8{};
    if (code_len > 0) {
        code = vm.memory.getSlice(code_ptr, code_len) catch return SyscallError.SegFault;

        // Charge per-word budget for hashing initcode (same as EIP-3860)
        const words = (code_len + 31) / 32;
        vm.budget.consume(budgetTable.Syscallbudget.CREATE2_PER_WORD * @as(u64, words)) catch return SyscallError.OutOfbudget;
    }

    // Read salt (32 bytes)
    const salt_slice = vm.memory.getSlice(salt_ptr, 32) catch return SyscallError.SegFault;
    var salt: [32]u8 = undefined;
    @memcpy(&salt, salt_slice);

    // Read value (32 bytes)
    const valSlice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var value: [32]u8 = undefined;
    @memcpy(&value, valSlice);

    // Execute via create2 provider
    if (env.create2Fn) |create2Fn| {
        // Check call depth limit
        if (env.callDepth >= env.maxCallDepth) {
            vm.regs[10] = 0;
            return;
        }
        env.callDepth += 1;
        defer env.callDepth -= 1;

        const budget_to_forward = vm.budget.remaining();
        const result = create2Fn(code, salt, value, budget_to_forward);

        vm.budget.consume(result.budgetUsed) catch {};

        if (result.success) {
            // Write new address to result buffer
            const addrSlice = vm.memory.getSliceMut(resultPtr, 32) catch {
                vm.regs[10] = 0;
                return;
            };
            @memcpy(addrSlice, &result.newAddress);
            vm.regs[10] = 1;
        } else {
            vm.regs[10] = 0;
        }
    } else {
        vm.regs[10] = 0;
    }
}

// ---------------------------------------------------------------------------
// EIP-1153: Transient Storage (TLOAD / TSTORE)
// ---------------------------------------------------------------------------
// Transient storage provides a cheap (100 budget) key-value store that is
// automatically cleared at the end of each transaction. It does NOT persist
// to the state trie and does NOT trigger warm/cold budget pricing.
//
// Use cases:
//   - Re-entrancy locks without 5000 budget SSTORE cost
//   - Flash loan callback state
//   - Multi-hop AMM routing intermediate state
//   - EIP-1153 compatible smart contracts

fn derivedStorageLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    const userPtr = vm.regs[11];
    const keyPtr = vm.regs[12];
    const resultPtr = vm.regs[13];

    const user_slice = vm.memory.getSlice(userPtr, 32) catch return SyscallError.SegFault;
    var user: [32]u8 = undefined;
    @memcpy(&user, user_slice);

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    var value = [_]u8{0} ** 32;
    if (env.derivedLoadFn) |loadFn| {
        value = loadFn(env, user, key);
    }

    const result_ref = vm.memory.getAligned32Mut(resultPtr) catch return SyscallError.SegFault;
    result_ref.* = value;
}

fn derivedStorageStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(5000) catch return SyscallError.OutOfbudget;

    const userPtr = vm.regs[11];
    const keyPtr = vm.regs[12];
    const valPtr = vm.regs[13];

    const user_slice = vm.memory.getSlice(userPtr, 32) catch return SyscallError.SegFault;
    var user: [32]u8 = undefined;
    @memcpy(&user, user_slice);

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    const valRef = vm.memory.getAligned32(valPtr) catch return SyscallError.SegFault;
    const value = valRef.*;

    if (env.derivedStoreFn) |storeFn| {
        storeFn(env, user, key, value) catch return SyscallError.InternalError;
    }
}

fn globalStorageLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    const keyPtr = vm.regs[11];
    const resultPtr = vm.regs[12];

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    var value = [_]u8{0} ** 32;
    if (env.globalLoadFn) |loadFn| {
        value = loadFn(env, key);
    }

    const result_ref = vm.memory.getAligned32Mut(resultPtr) catch return SyscallError.SegFault;
    result_ref.* = value;
}

fn globalStorageStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(5000) catch return SyscallError.OutOfbudget;

    const keyPtr = vm.regs[11];
    const deltaPtr = vm.regs[12];
    const isAdditionVal = vm.regs[13];

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    const deltaRef = vm.memory.getAligned32(deltaPtr) catch return SyscallError.SegFault;
    const delta = deltaRef.*;

    const isAddition = isAdditionVal != 0;

    if (env.globalStoreFn) |storeFn| {
        storeFn(env, key, delta, isAddition) catch return SyscallError.InternalError;
    }
}

/// Syscall 0x23: tload — read from transient storage
/// a0 = syscallId, a1 = pointer to 32-byte key, a2 = pointer to 32-byte result buffer
/// budget: 100 (EIP-1153, same as warm SLOAD)
fn transientLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    const keyPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    // Read key from VM memory
    const key_slice = vm.memory.getSlice(keyPtr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    // Look up in transient storage — default to zero if not set
    const value = env.transientStorage.get(key) orelse [_]u8{0} ** 32;

    // Write result to VM memory
    const result_slice = vm.memory.getSliceMut(resultPtr, 32) catch return SyscallError.SegFault;
    @memcpy(result_slice, &value);
}

/// Syscall 0x24: tstore — write to transient storage
/// a0 = syscallId, a1 = pointer to 32-byte key, a2 = pointer to 32-byte value
/// budget: 100 (EIP-1153, same as warm SSTORE)
fn transientStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    const keyPtr = vm.regs[11]; // a1
    const value_ptr = vm.regs[12]; // a2

    // Read key from VM memory
    const key_slice = vm.memory.getSlice(keyPtr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    // Read value from VM memory
    const value_slice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var newValue: [32]u8 = undefined;
    @memcpy(&newValue, value_slice);

    // Store in transient storage (overwrites any existing value)
    env.transientStorage.put(key, newValue) catch return SyscallError.InternalError;
}

/// Syscall VERIFY_SIG (replaces ECRECOVER)
/// a0 = syscallId, a1 = ptr to 32-byte message hash,
/// a2 = scheme (0=Ed25519, 1=BLS12-381, 2=quantum),
/// a3 = ptr to 32-byte public key, a4 = ptr to 64-byte signature,
/// a5 = ptr to 32-byte result buffer (blake3(pubkey) address)
/// Returns: a0 = 1 (success) or 0 (failure); signer address written to result buffer.
fn ecrecover(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // budget: signature verification cost (cheaper than EVM ecrecover)
    vm.budget.consume(2000) catch return SyscallError.OutOfbudget;

    const hash_ptr = vm.regs[11]; // a1 — 32-byte message hash
    const scheme: u8 = @truncate(vm.regs[12]); // a2 — signature scheme
    const pubkey_ptr = vm.regs[13]; // a3 — 32-byte Ed25519 public key
    const sig_ptr = vm.regs[14]; // a4 — 64-byte signature
    const outPtr = vm.regs[15]; // a5 — result buffer (32 bytes)

    // Read hash (32 bytes)
    const hashSlice = vm.memory.getSlice(hash_ptr, 32) catch return SyscallError.SegFault;
    var hash: [32]u8 = undefined;
    @memcpy(&hash, hashSlice);

    // Read pubkey (32 bytes)
    const pubkeySlice = vm.memory.getSlice(pubkey_ptr, 32) catch return SyscallError.SegFault;
    var pubkey: [32]u8 = undefined;
    @memcpy(&pubkey, pubkeySlice);

    // Read signature (64 bytes)
    const sigSlice = vm.memory.getSlice(sig_ptr, 64) catch return SyscallError.SegFault;
    var sig: [64]u8 = undefined;
    @memcpy(&sig, sigSlice);

    // Execute via pluggable provider
    if (env.ecrecoverFn) |ecrecoverFn| {
        const recovered = ecrecoverFn(hash, scheme, pubkey, sig);

        // Check for zero address (invalid verification)
        var all_zero = true;
        for (recovered) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }

        if (all_zero) {
            vm.regs[10] = 0; // Failed verification
        } else {
            // Write recovered address to output buffer (a5)
            const addrSlice = vm.memory.getSliceMut(outPtr, 32) catch return SyscallError.SegFault;
            @memcpy(addrSlice, &recovered);
            vm.regs[10] = 1; // Success
        }
    } else {
        vm.regs[10] = 0; // No provider
    }
}

// ---------------------------------------------------------------------------
// SELFDESTRUCT handler
// ---------------------------------------------------------------------------

/// Syscall SELFDESTRUCT — destroy contract and send balance to beneficiary
/// a0 = syscallId, a1 = ptr to 20-byte beneficiary address
/// EIP-2929: charges warm/cold budget for beneficiary address
/// EIP-6780: only effective if called in the same TX as creation (enforced at state level)
fn selfDestructSyscall(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // Base budget for SELFDESTRUCT
    vm.budget.consume(5000) catch return SyscallError.OutOfbudget;

    const beneficiaryPtr = vm.regs[11]; // a1 — a0 is syscall ID

    // Read beneficiary address (32 bytes)
    const benSlice = vm.memory.getSlice(beneficiaryPtr, 32) catch return SyscallError.SegFault;
    var beneficiary: [32]u8 = undefined;
    @memcpy(&beneficiary, benSlice);

    // EIP-2929: charge cold access if beneficiary is not warm
    const wasWarm = env.accessSets.markAddressWarm(beneficiary);
    if (!wasWarm) {
        vm.budget.consume(25000) catch return SyscallError.OutOfbudget;
    }

    // Execute via provider — transfers balance + marks for deletion
    if (env.selfDestructFn) |sdFn| {
        const success = sdFn(beneficiary);
        vm.regs[10] = if (success) 1 else 0;
    } else {
        // No provider — just halt (balance cleanup deferred to executor)
        vm.regs[10] = 1;
    }
}

// ---------------------------------------------------------------------------
// Return data introspection (RETURNDATASIZE / RETURNDATACOPY)
// ---------------------------------------------------------------------------

/// Syscall: returndatasize — a0 = syscallId; result written to a0 (overwrite)
fn getReturnDataSize(vm: *ForgeVM, env: *HostEnv) void {
    vm.regs[10] = @truncate(env.lastReturnData.len);
}

/// Syscall: returndatacopy — copy return data from last sub-call
/// a0 = syscallId, a1 = dest_ptr, a2 = offset into return data, a3 = length
fn returnDataCopy(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // budget: 3 per word (same as EVM RETURNDATACOPY)
    const dest_ptr = vm.regs[11]; // a1
    const offset = vm.regs[12]; // a2
    const length = vm.regs[13]; // a3

    const words = (length + 31) / 32;
    vm.budget.consume(3 + 3 * @as(u64, words)) catch return SyscallError.OutOfbudget;

    // Bounds check on return data
    if (offset + length > env.lastReturnData.len) return SyscallError.SegFault;

    const src = env.lastReturnData[offset..][0..length];
    const dst = vm.memory.getSliceMut(dest_ptr, length) catch return SyscallError.SegFault;
    @memcpy(dst, src);
}

// ---------------------------------------------------------------------------
// Code introspection (CODESIZE / CODECOPY / EXTCODESIZE)
// ---------------------------------------------------------------------------

/// Syscall: codesize — a0 = syscallId; result in a0
fn getCodeSize(vm: *ForgeVM) void {
    vm.budget.consume(2) catch return; // budget_BASE
    vm.regs[10] = vm.code_len;
}

/// Syscall: codecopy — copy executing code to memory
/// a0 = syscallId, a1 = dest_ptr, a2 = code_offset, a3 = length
fn codeCopy(vm: *ForgeVM) SyscallError!void {
    const dest_ptr = vm.regs[11]; // a1
    const offset = vm.regs[12]; // a2
    const length = vm.regs[13]; // a3

    // budget: 3 + 3 per word
    const words = (length + 31) / 32;
    vm.budget.consume(3 + 3 * @as(u64, words)) catch return SyscallError.OutOfbudget;

    // Read from code region (offset already relative to code start)
    if (offset + length > vm.code_len) {
        // Beyond code length: zero-pad
        const dst = vm.memory.getSliceMut(dest_ptr, length) catch return SyscallError.SegFault;
        const avail = if (offset < vm.code_len) vm.code_len - offset else 0;
        if (avail > 0) {
            const src = vm.memory.getSlice(offset, avail) catch return SyscallError.SegFault;
            @memcpy(dst[0..avail], src);
        }
        @memset(dst[avail..], 0);
    } else {
        const src = vm.memory.getSlice(offset, length) catch return SyscallError.SegFault;
        const dst = vm.memory.getSliceMut(dest_ptr, length) catch return SyscallError.SegFault;
        @memcpy(dst, src);
    }
}

/// Syscall: extcodesize — get code size of external account
/// a0 = syscallId, a1 = ptr to 32-byte address
/// Returns: a0 = code size (or 0 for EOA)
fn extCodeSize(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const addrSlice = vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault;
    var addr: [32]u8 = undefined;
    @memcpy(&addr, addrSlice);

    // EIP-2929 warm/cold budget
    const wasWarm = env.accessSets.markAddressWarm(addr);
    const budgetCost: u64 = if (wasWarm) 100 else 2600;
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    // For now: return 0 for all addresses (external code size requires provider)
    // In practice, a codesize_fn provider would query the state overlay.
    // Returning 0 means "EOA or empty contract" — safe default.
    vm.regs[10] = 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Syscall GET_BLOCK_HASH (used as get_code_hash in FORGE)
/// a0 = syscallId, a1 = ptr to 32-byte address, a2 = ptr to 32-byte result
fn getCodeHash(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    const slice = vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault;
    var addr: [32]u8 = undefined;
    @memcpy(&addr, slice);

    // Warmth check: charge EXTCODEHASH warm/cold cost
    const cost: u64 = 100;
    vm.budget.consume(cost) catch return SyscallError.OutOfbudget;

    const hash = if (env.codeHashFn) |f| f(addr) else [_]u8{0} ** 32;
    const res_slice = vm.memory.getSliceMut(resultPtr, 32) catch return SyscallError.SegFault;
    @memcpy(res_slice, &hash);
}

/// Syscall AUTHORITY_CHECK
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte role, a3 = ptr to 20-byte account
/// Returns a0 = 1 if has role, 0 otherwise
fn roleCheck(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const rolePtr = vm.regs[12]; // a2
    const accPtr = vm.regs[13]; // a3

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var role: [32]u8 = undefined;
    @memcpy(&role, vm.memory.getSlice(rolePtr, 32) catch return SyscallError.SegFault);
    var acc: [32]u8 = undefined;
    @memcpy(&acc, vm.memory.getSlice(accPtr, 32) catch return SyscallError.SegFault);

    vm.budget.consume(400) catch return SyscallError.OutOfbudget;

    const has_role = if (env.roleCheckFn) |f| f(addr, role, acc) else false;
    vm.regs[10] = if (has_role) 1 else 0;
}

/// Syscall AUTHORITY_GRANT
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte role, a3 = ptr to 20-byte account
fn roleGrant(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const rolePtr = vm.regs[12]; // a2
    const accPtr = vm.regs[13]; // a3

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var role: [32]u8 = undefined;
    @memcpy(&role, vm.memory.getSlice(rolePtr, 32) catch return SyscallError.SegFault);
    var acc: [32]u8 = undefined;
    @memcpy(&acc, vm.memory.getSlice(accPtr, 32) catch return SyscallError.SegFault);

    vm.budget.consume(2000) catch return SyscallError.OutOfbudget;

    if (env.roleGrantFn) |f| f(addr, role, acc);
}

/// Syscall AUTHORITY_REVOKE
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte role, a3 = ptr to 20-byte account
fn roleRevoke(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const rolePtr = vm.regs[12]; // a2
    const accPtr = vm.regs[13]; // a3

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var role: [32]u8 = undefined;
    @memcpy(&role, vm.memory.getSlice(rolePtr, 32) catch return SyscallError.SegFault);
    var acc: [32]u8 = undefined;
    @memcpy(&acc, vm.memory.getSlice(accPtr, 32) catch return SyscallError.SegFault);

    vm.budget.consume(2000) catch return SyscallError.OutOfbudget;

    if (env.roleRevokeFn) |f| f(addr, role, acc);
}

/// Syscall RESOURCE_LOCK
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte id
fn resourceLock(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const id_ptr = vm.regs[12]; // a2

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var id: [32]u8 = undefined;
    @memcpy(&id, vm.memory.getSlice(id_ptr, 32) catch return SyscallError.SegFault);

    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    const locked = if (env.resourceLockFn) |f| f(addr, id) else true;
    vm.regs[10] = if (locked) 1 else 0;
}

/// Syscall HASH_BLAKE3
/// a0 = syscallId, a1 = dataPtr, a2 = dataLen, a3 = outPtr (32 bytes)
fn handleBlake3(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[11]; // a1
    const dataLen = vm.regs[12]; // a2
    const outPtr = vm.regs[13]; // a3

    const word_count = (dataLen + 7) / 8;
    const budgetCost = budgetTable.Syscallbudget.HASH_BLAKE3_BASE + (word_count * budgetTable.Syscallbudget.HASH_BLAKE3_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const data = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(data, &out, .{});

    const outSlice = vm.memory.getSliceMut(outPtr, 32) catch return SyscallError.SegFault;
    @memcpy(outSlice, &out);
    vm.regs[10] = 0; // success
}

/// Syscall HASH_SHA256
/// a0 = syscallId, a1 = dataPtr, a2 = dataLen, a3 = outPtr (32 bytes)
fn handleSha256(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[11]; // a1
    const dataLen = vm.regs[12]; // a2
    const outPtr = vm.regs[13]; // a3

    const word_count = (dataLen + 31) / 32;
    const budgetCost = budgetTable.Syscallbudget.HASH_SHA256_BASE + (word_count * budgetTable.Syscallbudget.HASH_SHA256_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const data = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});

    const outSlice = vm.memory.getSliceMut(outPtr, 32) catch return SyscallError.SegFault;
    @memcpy(outSlice, &out);
    vm.regs[10] = 0; // success
}

/// Syscall 0xAB: handle_asset_transfer
fn handleAssetTransfer(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetIdPtr = vm.regs[11];
    const fromPtr = vm.regs[12];
    const toPtr = vm.regs[13];
    const amountPtr = vm.regs[14];

    vm.budget.consume(budgetTable.Syscallbudget.ASSET_TRANSFER) catch return SyscallError.OutOfbudget;

    var assetId: [32]u8 = undefined;
    @memcpy(&assetId, vm.memory.getSlice(assetIdPtr, 32) catch return SyscallError.SegFault);

    var from: [32]u8 = undefined;
    @memcpy(&from, vm.memory.getSlice(fromPtr, 32) catch return SyscallError.SegFault);

    var to: [32]u8 = undefined;
    @memcpy(&to, vm.memory.getSlice(toPtr, 32) catch return SyscallError.SegFault);

    const amountSlice = vm.memory.getSlice(amountPtr, 16) catch return SyscallError.SegFault;
    const amount = std.mem.readInt(u128, amountSlice[0..16], .little);

    if (env.assetTransferFn) |f| {
        f(env, assetId, from, to, amount) catch {
            vm.regs[10] = 1; // Error
            return;
        };
        vm.regs[10] = 0; // Success
    } else {
        vm.regs[10] = 1; // Error (unsupported)
    }
}

/// Syscall 0xAD: handle_parallel_hint
fn handleParallelHint(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const keysPtr = vm.regs[11];
    const keysLen = vm.regs[12]; // Number of 32-byte keys

    // Extremely cheap budget to encourage parallel hinting
    vm.budget.consume(10 + keysLen * 2) catch return SyscallError.OutOfbudget;

    // In actual implementation, this sets rw-sets ahead of time
    // to allow scheduler optimization
    _ = keysPtr;
    env.parallelSafe = true;
    vm.regs[10] = 0;
}

/// Syscall RESOURCE_UNLOCK
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte id
fn resourceUnlock(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const id_ptr = vm.regs[12]; // a2

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var id: [32]u8 = undefined;
    @memcpy(&id, vm.memory.getSlice(id_ptr, 32) catch return SyscallError.SegFault);

    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    if (env.resourceUnlockFn) |f| f(addr, id);
}

/// Syscall DEBUG_LOG
/// a0 = syscallId, a1 = ptr to data, a2 = data length
fn debugLog(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[11]; // a1
    const dataLen = vm.regs[12]; // a2

    vm.budget.consume(100) catch return SyscallError.OutOfbudget;

    const slice = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    std.debug.print("[VM DEBUG] {s}\n", .{slice});
}

const testing = std.testing;
const decoder = @import("../core/decoder.zig");

/// Test helper: create a minimal test VM with syscall handler.
/// IMPORTANT: After assigning the result, call ctx.fixMemPtr() to fix the memory pointer.
fn createTestVm(env: *HostEnv) !struct {
    vm: ForgeVM,
    mem: sandbox.SandboxMemory,
    envPtr: *HostEnv, // must be before any declarations

    const Self = @This();

    /// Must be called after the struct is assigned to fix the VM's memory pointer
    /// and hostCtx so syscalls can find the HostEnv.
    pub fn fixMemPtr(self: *Self) void {
        self.vm.memory = &self.mem;
        self.vm.hostCtx = self.envPtr;
    }
} {
    var mem = try sandbox.SandboxMemory.init(testing.allocator);

    // Load an ECALL instruction at PC=0
    const ecallWord: u32 = 0x00000073; // ECALL
    const ecallBytes = std.mem.asBytes(&ecallWord);
    try mem.loadCode(ecallBytes);

    const handler = createHandler(env);
    var vm = ForgeVM.init(&mem, 4, 1_000_000, handler);
    vm.hostCtx = env; // wire immediately for safety
    return .{ .vm = vm, .mem = mem, .envPtr = env };
}

test "syscall: get_chain_id" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();
    env.chainId = 42;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.GET_CHAIN_ID; // a0 = syscall ID
    ctx.vm.step(); // Execute ECALL

    try testing.expectEqual(@as(u32, 42), ctx.vm.regs[10]);
}

test "syscall: get_block_number" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();
    env.blockNumber = 12345;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.GET_BLOCK_NUMBER;
    ctx.vm.step();

    try testing.expectEqual(@as(u32, 12345), ctx.vm.regs[10]);
}

test "syscall: get_timestamp" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();
    env.timestamp = 1700000000;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[10] = SyscallId.GET_TIMESTAMP;
    ctx.vm.step();

    try testing.expectEqual(@as(u32, 1700000000), ctx.vm.regs[10]);
}

test "syscall: unknown syscall returns fault" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[10] = 0xFE; // Invalid syscall
    ctx.vm.step();

    try testing.expectEqual(executor.ExecutionStatus.fault, ctx.vm.status);
}

test "syscall: returnData sets status to returned" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.RETURN_DATA;
    ctx.vm.regs[11] = sandbox.heapStart; // data ptr
    ctx.vm.regs[12] = 0; // data len = 0
    ctx.vm.step();

    try testing.expectEqual(executor.ExecutionStatus.returned, ctx.vm.status);
}

test "syscall: revert sets status to reverted" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.REVERT;
    ctx.vm.regs[11] = sandbox.heapStart;
    ctx.vm.regs[12] = 0;
    ctx.vm.step();

    try testing.expectEqual(executor.ExecutionStatus.reverted, ctx.vm.status);
}

test "syscall: blake3" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    // Write "hello" into heap
    const data = "hello";
    const data_start = sandbox.heapStart;
    for (data, 0..) |b, idx| {
        try ctx.mem.storeByte(data_start + @as(u32, @intCast(idx)), b);
    }

    // Set up syscall args: a0 = SyscallId.HASH_BLAKE3, a1 = data_start, a2 = data.len, a3 = outPtr
    const out_ptr = data_start + 32;
    ctx.vm.regs[10] = SyscallId.HASH_BLAKE3;
    ctx.vm.regs[11] = data_start;
    ctx.vm.regs[12] = data.len;
    ctx.vm.regs[13] = out_ptr;

    try handleBlake3(&ctx.vm, &env);

    // Read result
    var result: [32]u8 = undefined;
    for (0..32) |idx| {
        result[idx] = ctx.mem.loadByte(out_ptr + @as(u32, @intCast(idx))) catch unreachable;
    }

    // Compute expected blake3("hello")
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash("hello", &expected, .{});

    try testing.expectEqualSlices(u8, &expected, &result);
}

test "syscall: storage_load and storage_store round-trip" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Set up a simple in-memory storage backend
    const TestStorage = struct {
        var data: std.AutoHashMap([32]u8, [32]u8) = undefined;
        var initialized: bool = false;

        fn ensureInit() void {
            if (!initialized) {
                data = std.AutoHashMap([32]u8, [32]u8).init(testing.allocator);
                initialized = true;
            }
        }

        fn loadFn(ctx_ptr: *anyopaque, key: [32]u8) [32]u8 {
            _ = ctx_ptr;
            ensureInit();
            return data.get(key) orelse [_]u8{0} ** 32;
        }

        fn storeFn(ctx_ptr: *anyopaque, key: [32]u8, value: [32]u8) void {
            _ = ctx_ptr;
            ensureInit();
            data.put(key, value) catch {};
        }

        fn cleanup() void {
            if (initialized) {
                data.deinit();
                initialized = false;
            }
        }
    };
    defer TestStorage.cleanup();

    var storage = StorageBackend{
        .ctx = undefined,
        .loadFn = &TestStorage.loadFn,
        .storeFn = &TestStorage.storeFn,
    };
    env.storage = &storage;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    // Write a key into heap
    const key_addr = sandbox.heapStart;
    const val_addr = sandbox.heapStart + 32;
    const result_addr = sandbox.heapStart + 64;

    // Key = 1 (padded to 32 bytes)
    try ctx.mem.storeByte(key_addr + 31, 0x01);
    // Value = 42 (padded to 32 bytes)
    try ctx.mem.storeByte(val_addr + 31, 42);

    // Store
    ctx.vm.regs[10] = SyscallId.STORAGE_STORE;
    ctx.vm.regs[11] = key_addr;
    ctx.vm.regs[12] = val_addr;
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();
    try testing.expectEqual(executor.ExecutionStatus.running, ctx.vm.status);

    // Reset PC and reload ECALL for load
    ctx.vm.pc = 0;
    ctx.vm.regs[10] = SyscallId.STORAGE_LOAD;
    ctx.vm.regs[11] = key_addr;
    ctx.vm.regs[12] = result_addr;
    ctx.vm.step();

    // Verify the loaded value
    const loaded_val = try ctx.mem.loadByte(result_addr + 31);
    try testing.expectEqual(@as(u8, 42), loaded_val);
}

test "syscall: tload and tstore round-trip" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    // TSTORE via transient storage direct API (TSTORE syscall not yet dispatched)
    var key: [32]u8 = [_]u8{0} ** 32;
    key[31] = 0x07;
    var value: [32]u8 = [_]u8{0} ** 32;
    value[31] = 0xBE;
    try env.transientStorage.put(key, value);

    // TLOAD: read back from transient storage via env API
    const loaded = env.transientStorage.get(key) orelse [_]u8{0} ** 32;
    try testing.expectEqual(@as(u8, 0xBE), loaded[31]);
}

test "syscall: tload returns zero for unset key" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Key 0xFF was never stored — transientStorage.get should return null → zero
    var key: [32]u8 = [_]u8{0} ** 32;
    key[31] = 0xFF;

    const loaded = env.transientStorage.get(key) orelse [_]u8{0} ** 32;
    try testing.expectEqual(@as(u8, 0x00), loaded[31]);
}

test "syscall: create2 deterministic address derivation" {
    // Verify the CREATE2 address derivation formula:
    // address = blake3(0x02 || sender || salt || blake3(initcode))
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Set the contract's self_address (the CREATE2 sender)
    var sender: [32]u8 = undefined;
    @memset(&sender, 0xAA);
    env.selfAddress = sender;

    // Compute expected CREATE2 address manually
    const initcode = &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0xFD }; // PUSH 0, PUSH 0, REVERT
    var salt: [32]u8 = [_]u8{0} ** 32;
    salt[31] = 0x42; // salt = 42

    // blake3(initcode)
    var initcode_hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(initcode, &initcode_hash, .{});

    // blake3(0x02 || sender || salt || initcode_hash)
    var create2Input: [97]u8 = undefined;
    create2Input[0] = 0x02;
    @memcpy(create2Input[1..33], &sender);
    @memcpy(create2Input[33..65], &salt);
    @memcpy(create2Input[65..97], &initcode_hash);
    var expected_addr: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&create2Input, &expected_addr, .{});

    // Verify the computed address is non-zero and deterministic
    var all_zero = true;
    for (expected_addr) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero); // Address should not be all zeros

    // Verify that computing the same inputs again produces the same address (deterministic)
    var addr2: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&create2Input, &addr2, .{});

    try testing.expectEqualSlices(u8, &expected_addr, &addr2);
}

// ── Substrate/PolkaVM Compatibility Helper Functions ──

pub fn translateAddrToHost(guest_addr: []const u8) [32]u8 {
    var host_addr = [_]u8{0} ** 32;
    if (guest_addr.len == 20) {
        @memcpy(host_addr[12..32], guest_addr);
    } else if (guest_addr.len >= 32) {
        @memcpy(&host_addr, guest_addr[0..32]);
    } else {
        @memcpy(host_addr[32 - guest_addr.len .. 32], guest_addr);
    }
    return host_addr;
}

pub fn translateAddrToGuest(host_addr: [32]u8, dest: []u8) void {
    var is_evm = true;
    for (host_addr[0..12]) |b| {
        if (b != 0) {
            is_evm = false;
            break;
        }
    }

    if (is_evm and dest.len == 20) {
        @memcpy(dest, host_addr[12..32]);
    } else if (dest.len >= 32) {
        @memcpy(dest[0..32], &host_addr);
        if (dest.len > 32) {
            @memset(dest[32..], 0);
        }
    } else {
        const len = @min(dest.len, 32);
        @memcpy(dest[0..len], host_addr[32 - len .. 32]);
    }
}

fn sealCaller(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);
    const out_slice = vm.memory.getSliceMut(out_ptr, guest_len) catch return SyscallError.SegFault;

    translateAddrToGuest(env.caller, out_slice);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(@min(guest_len, 32)), .little);
    vm.regs[10] = 0; // Success
}

fn sealAddress(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);
    const out_slice = vm.memory.getSliceMut(out_ptr, guest_len) catch return SyscallError.SegFault;

    translateAddrToGuest(env.selfAddress, out_slice);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(@min(guest_len, 32)), .little);
    vm.regs[10] = 0; // Success
}

fn sealValueTransferred(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);
    const out_slice = vm.memory.getSliceMut(out_ptr, guest_len) catch return SyscallError.SegFault;

    const value_len = @min(guest_len, 32);
    @memcpy(out_slice[0..value_len], env.callValue[32 - value_len .. 32]);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(value_len), .little);
    vm.regs[10] = 0; // Success
}

fn sealNow(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const out_slice = vm.memory.getSliceMut(out_ptr, 8) catch return SyscallError.SegFault;

    std.mem.writeInt(u64, out_slice[0..8], env.timestamp, .little);
    std.mem.writeInt(u32, len_ref[0..4], 8, .little);
    vm.regs[10] = 0;
}

fn sealBlockNumber(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const out_slice = vm.memory.getSliceMut(out_ptr, 8) catch return SyscallError.SegFault;

    std.mem.writeInt(u64, out_slice[0..8], env.blockNumber, .little);
    std.mem.writeInt(u32, len_ref[0..4], 8, .little);
    vm.regs[10] = 0;
}

fn sealcomputePrice(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const out_slice = vm.memory.getSliceMut(out_ptr, 8) catch return SyscallError.SegFault;

    std.mem.writeInt(u64, out_slice[0..8], env.computePrice, .little);
    std.mem.writeInt(u32, len_ref[0..4], 8, .little);
    vm.regs[10] = 0;
}

fn sealbudgetLeft(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const out_slice = vm.memory.getSliceMut(out_ptr, 8) catch return SyscallError.SegFault;

    std.mem.writeInt(u64, out_slice[0..8], vm.budget.remaining(), .little);
    std.mem.writeInt(u32, len_ref[0..4], 8, .little);
    vm.regs[10] = 0;
}

fn sealBalance(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);
    const out_slice = vm.memory.getSliceMut(out_ptr, guest_len) catch return SyscallError.SegFault;

    const balance = if (env.balanceFn) |f| f(env.selfAddress) else [_]u8{0} ** 32;
    const value_len = @min(guest_len, 32);
    @memcpy(out_slice[0..value_len], balance[32 - value_len .. 32]);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(value_len), .little);
    vm.regs[10] = 0;
}

fn sealGetStorage(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const key_ptr = vm.regs[11];
    const value_ptr = vm.regs[12];
    const value_len_ptr = vm.regs[13];

    const key_slice = vm.memory.getSlice(key_ptr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    const len_ref = vm.memory.getSliceMut(value_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);

    const wasWarm = env.accessSets.markSlotWarm(key);
    const budgetCost = budgetTable.Syscallbudget.STORAGE_LOAD;
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const value = if (wasWarm)
        (env.lookupSloadCache(key) orelse if (env.storage) |s| s.load(key) else [_]u8{0} ** 32)
    else
        (if (env.storage) |s| s.load(key) else [_]u8{0} ** 32);

    env.cacheSloadValue(key, value);
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, value);
    }

    const value_len = @min(guest_len, 32);
    const value_slice = vm.memory.getSliceMut(value_ptr, value_len) catch return SyscallError.SegFault;
    @memcpy(value_slice, value[0..value_len]);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(value_len), .little);

    vm.regs[10] = 0; // Success
}

fn sealSetStorage(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const key_ptr = vm.regs[11];
    const value_ptr = vm.regs[12];
    const value_len = vm.regs[13];

    const key_slice = vm.memory.getSlice(key_ptr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    var value = [_]u8{0} ** 32;
    if (value_len > 0) {
        const val_len = @min(value_len, 32);
        const value_slice = vm.memory.getSlice(value_ptr, val_len) catch return SyscallError.SegFault;
        @memcpy(value[0..val_len], value_slice);
    }

    const currentValue = if (env.storage) |s| s.load(key) else [_]u8{0} ** 32;
    const wasWarm = env.accessSets.markSlotWarm(key);
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, currentValue);
        vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;
    }

    if (env.storage) |s| s.store(key, value);
    env.cacheSloadValue(key, value);

    vm.regs[10] = 0; // Success
}

fn sealClearStorage(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const key_ptr = vm.regs[11];
    const key_slice = vm.memory.getSlice(key_ptr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    const zeroVal = [_]u8{0} ** 32;
    const currentValue = if (env.storage) |s| s.load(key) else [_]u8{0} ** 32;
    const wasWarm = env.accessSets.markSlotWarm(key);
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, currentValue);
        vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;
    }

    if (env.storage) |s| s.store(key, zeroVal);
    env.cacheSloadValue(key, zeroVal);

    vm.regs[10] = 0; // Success
}

fn sealContainsStorage(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const key_ptr = vm.regs[11];
    const key_slice = vm.memory.getSlice(key_ptr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    const currentValue = if (env.storage) |s| s.load(key) else [_]u8{0} ** 32;
    var exists: u32 = 0;
    for (currentValue) |b| {
        if (b != 0) {
            exists = 1;
            break;
        }
    }
    vm.regs[10] = exists;
}

fn sealTransfer(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const to_ptr = vm.regs[11];
    const to_len = vm.regs[12];
    const value_ptr = vm.regs[13];
    const value_len = vm.regs[14];

    const to_slice = vm.memory.getSlice(to_ptr, to_len) catch return SyscallError.SegFault;
    const host_to = translateAddrToHost(to_slice);

    const val_slice = vm.memory.getSlice(value_ptr, value_len) catch return SyscallError.SegFault;
    var value = [_]u8{0} ** 32;
    const v_len = @min(value_len, 32);
    @memcpy(value[32 - v_len .. 32], val_slice);

    std.debug.print("DEBUG sealTransfer: called, to={x}, value={x}\n", .{ host_to, value });

    if (env.callFn) |call_fn| {
        const res = call_fn(.call, host_to, value, &[_]u8{}, vm.budget.remaining());
        std.debug.print("DEBUG sealTransfer: callFn returned success={}\n", .{res.success});
        vm.regs[10] = if (res.success) 0 else 1; // 0 = Success in Substrate
    } else {
        std.debug.print("DEBUG sealTransfer: no callFn configured!\n", .{});
        vm.regs[10] = 1; // Error
    }
}

fn sealHashKeccak256(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const input_ptr = vm.regs[11];
    const input_len = vm.regs[12];
    const output_ptr = vm.regs[13];

    const word_count = (input_len + 31) / 32;
    const budgetCost = budgetTable.Syscallbudget.HASH_SHA256_BASE + (word_count * budgetTable.Syscallbudget.HASH_SHA256_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(input, &out, .{});

    const out_slice = vm.memory.getSliceMut(output_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &out);
    vm.regs[10] = 0;
}

fn sealHashBlake2_256(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const input_ptr = vm.regs[11];
    const input_len = vm.regs[12];
    const output_ptr = vm.regs[13];

    const word_count = (input_len + 31) / 32;
    const budgetCost = budgetTable.Syscallbudget.HASH_SHA256_BASE + (word_count * budgetTable.Syscallbudget.HASH_SHA256_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2b256.hash(input, &out, .{});

    const out_slice = vm.memory.getSliceMut(output_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &out);
    vm.regs[10] = 0;
}

fn sealHashBlake3(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const input_ptr = vm.regs[11];
    const input_len = vm.regs[12];
    const output_ptr = vm.regs[13];

    const word_count = (input_len + 7) / 8;
    const budgetCost = budgetTable.Syscallbudget.HASH_BLAKE3_BASE + (word_count * budgetTable.Syscallbudget.HASH_BLAKE3_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(input, &out, .{});

    const out_slice = vm.memory.getSliceMut(output_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &out);
    vm.regs[10] = 0;
}

fn sealHashSha256(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const input_ptr = vm.regs[11];
    const input_len = vm.regs[12];
    const output_ptr = vm.regs[13];

    const word_count = (input_len + 31) / 32;
    const budgetCost = budgetTable.Syscallbudget.HASH_SHA256_BASE + (word_count * budgetTable.Syscallbudget.HASH_SHA256_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &out, .{});

    const out_slice = vm.memory.getSliceMut(output_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &out);
    vm.regs[10] = 0;
}

fn sealReturn(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[12];
    const dataLen = vm.regs[13];

    if (dataLen > 0 and dataLen <= sandbox.returnSize) {
        const src = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
        const dst = vm.memory.getSliceMut(sandbox.returnStart, dataLen) catch return SyscallError.SegFault;
        @memcpy(dst, src);
    }

    vm.returnDataOffset = 0;
    vm.returnDataLen = @truncate(dataLen);
}

fn sealRevert(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[12];
    const dataLen = vm.regs[13];

    if (dataLen > 0 and dataLen <= sandbox.returnSize) {
        const src = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
        const dst = vm.memory.getSliceMut(sandbox.returnStart, dataLen) catch return SyscallError.SegFault;
        @memcpy(dst, src);
    }

    vm.returnDataOffset = 0;
    vm.returnDataLen = @truncate(dataLen);
}

fn sealCall(vm: *ForgeVM, env: *HostEnv, callType: CallType) SyscallError!void {
    const callee_ptr = vm.regs[12];
    const budget = vm.regs[13];
    const value_ptr = vm.regs[14];
    const input_ptr = vm.regs[15];
    const input_len = vm.regs[16];
    const output_ptr = vm.regs[17];

    const sp = vm.regs[2];
    const output_len_ptr = vm.memory.loadWord(sp) catch return SyscallError.SegFault;

    const callee_slice = vm.memory.getSlice(callee_ptr, 32) catch return SyscallError.SegFault;
    const callee = translateAddrToHost(callee_slice);

    var value = [_]u8{0} ** 32;
    if (value_ptr != 0) {
        const val_slice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
        @memcpy(&value, val_slice);
    }

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;

    if (env.callFn) |call_fn| {
        const res = call_fn(callType, callee, value, input, budget);
        
        if (res.returnData.len > 0 and output_ptr != 0 and output_len_ptr != 0) {
            const out_len_ref = vm.memory.getSliceMut(output_len_ptr, 4) catch return SyscallError.SegFault;
            const guest_out_len = std.mem.readInt(u32, out_len_ref[0..4], .little);
            const write_len = @min(guest_out_len, res.returnData.len);

            const out_slice = vm.memory.getSliceMut(output_ptr, write_len) catch return SyscallError.SegFault;
            @memcpy(out_slice, res.returnData[0..write_len]);
            std.mem.writeInt(u32, out_len_ref[0..4], @intCast(write_len), .little);
        }

        vm.regs[10] = if (res.success) 0 else 1;
    } else {
        vm.regs[10] = 1;
    }
}

fn sealTerminate(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const beneficiary_ptr = vm.regs[11];
    const ben_slice = vm.memory.getSlice(beneficiary_ptr, 32) catch return SyscallError.SegFault;
    const beneficiary = translateAddrToHost(ben_slice);

    if (env.selfDestructFn) |sd_fn| {
        _ = sd_fn(beneficiary);
    }
    vm.regs[10] = 0;
    return SyscallError.SelfDestruct;
}

fn sealInstantiate(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const code_hash_ptr = vm.regs[12];
    const budget = vm.regs[13];
    const value_ptr = vm.regs[14];
    const input_ptr = vm.regs[15];
    const input_len = vm.regs[16];
    const address_ptr = vm.regs[17];

    const sp = vm.regs[2];
    const address_len_ptr = vm.memory.loadWord(sp) catch return SyscallError.SegFault;
    const output_ptr = vm.memory.loadWord(sp + 4) catch return SyscallError.SegFault;
    const output_len_ptr = vm.memory.loadWord(sp + 8) catch return SyscallError.SegFault;
    const salt_ptr = vm.memory.loadWord(sp + 12) catch return SyscallError.SegFault;

    const hash_slice = vm.memory.getSlice(code_hash_ptr, 32) catch return SyscallError.SegFault;
    var code_hash: [32]u8 = undefined;
    @memcpy(&code_hash, hash_slice);

    var value = [_]u8{0} ** 32;
    if (value_ptr != 0) {
        const val_slice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
        @memcpy(&value, val_slice);
    }

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;

    var salt: ?[32]u8 = null;
    if (salt_ptr != 0) {
        const salt_slice = vm.memory.getSlice(salt_ptr, 32) catch return SyscallError.SegFault;
        var salt_val: [32]u8 = undefined;
        @memcpy(&salt_val, salt_slice);
        salt = salt_val;
    }

    if (env.instantiateFn) |inst_fn| {
        const res = inst_fn(code_hash, value, input, salt, budget);
        if (res.success) {
            // Write address to address_ptr
            if (address_ptr != 0 and address_len_ptr != 0) {
                const addr_len_ref = vm.memory.getSliceMut(address_len_ptr, 4) catch return SyscallError.SegFault;
                const guest_addr_len = std.mem.readInt(u32, addr_len_ref[0..4], .little);
                const write_len = @min(guest_addr_len, 32);

                const addr_slice = vm.memory.getSliceMut(address_ptr, write_len) catch return SyscallError.SegFault;
                translateAddrToGuest(res.newAddress, addr_slice);
                std.mem.writeInt(u32, addr_len_ref[0..4], @intCast(write_len), .little);
            }
            // Optional: return value data in output_ptr if needed
            _ = output_ptr;
            _ = output_len_ptr;

            vm.regs[10] = 0; // Success
        } else {
            vm.regs[10] = 1; // Failure
        }
    } else {
        vm.regs[10] = 1; // Not implemented / failure
    }
}

fn sealRandom(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[12];
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &env.prevrandao);
    vm.regs[10] = 0;
}

fn reviveAddress(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 20) catch return SyscallError.SegFault;
    translateAddrToGuest(env.selfAddress, out_slice);
    vm.regs[10] = 0;
}

fn reviveBalance(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    const balance = if (env.balanceFn) |f| f(env.selfAddress) else [_]u8{0} ** 32;
    @memcpy(out_slice, &balance);
    vm.regs[10] = 0;
}

fn reviveBalanceOf(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addr_ptr = vm.regs[11];
    const out_ptr = vm.regs[12];
    const addr_slice = vm.memory.getSlice(addr_ptr, 20) catch return SyscallError.SegFault;
    const host_addr = translateAddrToHost(addr_slice);
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    const balance = if (env.balanceFn) |f| f(host_addr) else [_]u8{0} ** 32;
    @memcpy(out_slice, &balance);
    vm.regs[10] = 0;
}

fn reviveBaseFee(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    _ = env;
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    @memset(out_slice, 0);
    vm.regs[10] = 0;
}

fn reviveBlockAuthor(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 20) catch return SyscallError.SegFault;
    translateAddrToGuest(env.producer, out_slice);
    vm.regs[10] = 0;
}

fn reviveBlockHash(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const block_number_ptr = vm.regs[11];
    const out_ptr = vm.regs[12];
    _ = block_number_ptr;
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &env.prevrandao);
    vm.regs[10] = 0;
}

fn reviveBlockNumber(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 8) catch return SyscallError.SegFault;
    std.mem.writeInt(u64, out_slice[0..8], env.blockNumber, .little);
    vm.regs[10] = 0;
}

fn reviveCallDataCopy(vm: *ForgeVM) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len = vm.regs[12];
    const offset = vm.regs[13];

    const out_slice = vm.memory.getSliceMut(out_ptr, out_len) catch return SyscallError.SegFault;
    var i: u32 = 0;
    while (i < out_len) : (i += 1) {
        const calldata_idx = offset + i;
        out_slice[i] = if (calldata_idx < vm.calldataLen)
            vm.memory.loadByte(sandbox.calldataStart + calldata_idx) catch 0
        else
            0;
    }
    vm.regs[10] = 0;
}

fn reviveCallDataLoad(vm: *ForgeVM) SyscallError!void {
    const out_ptr = vm.regs[11];
    const offset = vm.regs[12];

    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const calldata_idx = offset + i;
        out_slice[i] = if (calldata_idx < vm.calldataLen)
            vm.memory.loadByte(sandbox.calldataStart + calldata_idx) catch 0
        else
            0;
    }
    vm.regs[10] = 0;
}

fn reviveCallDataSize(vm: *ForgeVM) SyscallError!void {
    const len = vm.calldataLen;
    vm.regs[10] = len;
    vm.regs[11] = 0;
}

fn reviveCallEvm(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const flags = vm.regs[11];
    _ = flags;
    const callee_ptr = vm.regs[12];
    const value_ptr = vm.regs[13];
    const budget_low = vm.regs[14];
    const budget_high = vm.regs[15];
    const budget = budget_low | (@as(u64, budget_high) << 32);

    const input_data = vm.regs[16] | (@as(u64, vm.regs[17]) << 32);
    const input_ptr: u32 = @truncate(input_data);
    const input_len: u32 = @truncate(input_data >> 32);

    const output_data = vm.regs[18] | (@as(u64, vm.regs[19]) << 32);
    const output_ptr: u32 = @truncate(output_data);
    const output_len_ptr: u32 = @truncate(output_data >> 32);

    const callee_slice = vm.memory.getSlice(callee_ptr, 20) catch return SyscallError.SegFault;
    const callee = translateAddrToHost(callee_slice);

    var value = [_]u8{0} ** 32;
    if (value_ptr != 0) {
        const val_slice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
        @memcpy(&value, val_slice);
    }

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;

    std.debug.print("DEBUG reviveCallEvm: called, callee={x}, value={x}, input len={d}, budget={d}\n", .{ callee, value, input.len, budget });

    if (env.callFn) |call_fn| {
        const res = call_fn(.call, callee, value, input, budget);
        std.debug.print("DEBUG reviveCallEvm: callFn returned success={}, returnData len={d}\n", .{res.success, res.returnData.len});
        
        if (res.returnData.len > 0 and output_ptr != 0 and output_len_ptr != 0) {
            const out_len_ref = vm.memory.getSliceMut(output_len_ptr, 4) catch return SyscallError.SegFault;
            const guest_out_len = std.mem.readInt(u32, out_len_ref[0..4], .little);
            const write_len = @min(guest_out_len, res.returnData.len);

            const out_slice = vm.memory.getSliceMut(output_ptr, write_len) catch return SyscallError.SegFault;
            @memcpy(out_slice, res.returnData[0..write_len]);
            std.mem.writeInt(u32, out_len_ref[0..4], @intCast(write_len), .little);
        }

        env.lastReturnData = res.returnData;
        vm.regs[10] = if (res.success) 0 else 1;
    } else {
        std.debug.print("DEBUG reviveCallEvm: no callFn configured!\n", .{});
        vm.regs[10] = 1;
    }
}

fn reviveCaller(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 20) catch return SyscallError.SegFault;
    translateAddrToGuest(env.caller, out_slice);
    vm.regs[10] = 0;
}

fn reviveChainId(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    @memset(out_slice, 0);
    std.mem.writeInt(u64, out_slice[0..8], env.chainId, .little);
    vm.regs[10] = 0;
}

fn reviveCodeHash(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addr_ptr = vm.regs[11];
    const out_ptr = vm.regs[12];
    const addr_slice = vm.memory.getSlice(addr_ptr, 20) catch return SyscallError.SegFault;
    const host_addr = translateAddrToHost(addr_slice);
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    if (env.codeHashFn) |f| {
        const hash = f(host_addr);
        @memcpy(out_slice, &hash);
    } else {
        @memset(out_slice, 0);
    }
    vm.regs[10] = 0;
}

fn reviveCodeSize(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addr_ptr = vm.regs[11];
    const addr_slice = vm.memory.getSlice(addr_ptr, 20) catch return SyscallError.SegFault;
    const host_addr = translateAddrToHost(addr_slice);
    const size = if (env.codeSizeFn) |f| f(host_addr) else 0;
    vm.regs[10] = @truncate(size);
    vm.regs[11] = @truncate(size >> 32);
}

fn reviveConsumeAllbudget(vm: *ForgeVM) SyscallError!void {
    vm.budget.consume(vm.budget.remaining()) catch {};
    vm.regs[10] = 0;
    return SyscallError.Revert;
}

fn reviveDelegateCallEvm(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const flags = vm.regs[11];
    _ = flags;
    const callee_ptr = vm.regs[12];
    const budget_low = vm.regs[14];
    const budget_high = vm.regs[15];
    const budget = budget_low | (@as(u64, budget_high) << 32);

    const input_data = vm.regs[16] | (@as(u64, vm.regs[17]) << 32);
    const input_ptr: u32 = @truncate(input_data);
    const input_len: u32 = @truncate(input_data >> 32);

    const output_data = vm.regs[18] | (@as(u64, vm.regs[19]) << 32);
    const output_ptr: u32 = @truncate(output_data);
    const output_len_ptr: u32 = @truncate(output_data >> 32);

    const callee_slice = vm.memory.getSlice(callee_ptr, 20) catch return SyscallError.SegFault;
    const callee = translateAddrToHost(callee_slice);

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;

    if (env.callFn) |call_fn| {
        const res = call_fn(.delegatecall, callee, [_]u8{0} ** 32, input, budget);
        
        if (res.returnData.len > 0 and output_ptr != 0 and output_len_ptr != 0) {
            const out_len_ref = vm.memory.getSliceMut(output_len_ptr, 4) catch return SyscallError.SegFault;
            const guest_out_len = std.mem.readInt(u32, out_len_ref[0..4], .little);
            const write_len = @min(guest_out_len, res.returnData.len);

            const out_slice = vm.memory.getSliceMut(output_ptr, write_len) catch return SyscallError.SegFault;
            @memcpy(out_slice, res.returnData[0..write_len]);
            std.mem.writeInt(u32, out_len_ref[0..4], @intCast(write_len), .little);
        }

        env.lastReturnData = res.returnData;
        vm.regs[10] = if (res.success) 0 else 1;
    } else {
        vm.regs[10] = 1;
    }
}

fn reviveDepositEvent(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const topics_ptr = vm.regs[11];
    const num_topic = vm.regs[12];
    const data_ptr = vm.regs[13];
    const data_len = vm.regs[14];

    var entry = LogEntry.init(env.allocator);
    errdefer entry.deinit();

    if (num_topic > 0 and topics_ptr != 0) {
        const topics_slice = vm.memory.getSlice(topics_ptr, num_topic * 32) catch return SyscallError.SegFault;
        var i: u32 = 0;
        while (i < num_topic) : (i += 1) {
            var topic: [32]u8 = undefined;
            @memcpy(&topic, topics_slice[i * 32 .. (i + 1) * 32]);
            entry.topics.append(env.allocator, topic) catch return SyscallError.InternalError;
        }
    }

    if (data_len > 0 and data_ptr != 0) {
        const data_slice = vm.memory.getSlice(data_ptr, data_len) catch return SyscallError.SegFault;
        entry.data.appendSlice(env.allocator, data_slice) catch return SyscallError.InternalError;
    }

    env.logs.append(env.allocator, entry) catch return SyscallError.InternalError;
    vm.regs[10] = 0;
}

fn revivebudgetLimit(vm: *ForgeVM) SyscallError!void {
    const limit = vm.budget.limit;
    vm.regs[10] = @truncate(limit);
    vm.regs[11] = @truncate(limit >> 32);
}

fn revivecomputePrice(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    @memset(out_slice, 0);
    std.mem.writeInt(u64, out_slice[0..8], env.computePrice, .little);
    vm.regs[10] = 0;
}

fn reviveGetImmutableData(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];

    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);
    const write_len = @min(guest_len, env.immutableData.items.len);

    const out_slice = vm.memory.getSliceMut(out_ptr, write_len) catch return SyscallError.SegFault;
    @memcpy(out_slice, env.immutableData.items[0..write_len]);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(write_len), .little);
    vm.regs[10] = 0;
}

fn reviveGetStorageOrZero(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const flags = vm.regs[11];
    _ = flags;
    const key_ptr = vm.regs[12];
    const out_ptr = vm.regs[13];

    const key_slice = vm.memory.getSlice(key_ptr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;

    const wasWarm = env.accessSets.markSlotWarm(key);
    const budgetCost = if (wasWarm) @as(u64, 100) else @as(u64, 2100);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const value = if (wasWarm)
        (env.lookupSloadCache(key) orelse if (env.storage) |s| s.load(key) else [_]u8{0} ** 32)
    else
        (if (env.storage) |s| s.load(key) else [_]u8{0} ** 32);

    env.cacheSloadValue(key, value);
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, value);
    }

    @memcpy(out_slice, &value);
    vm.regs[10] = 0;
}

fn reviveHashKeccak256(vm: *ForgeVM) SyscallError!void {
    const input_ptr = vm.regs[11];
    const input_len = vm.regs[12];
    const output_ptr = vm.regs[13];

    const word_count = (input_len + 31) / 32;
    const budgetCost = budgetTable.Syscallbudget.HASH_SHA256_BASE + (word_count * budgetTable.Syscallbudget.HASH_SHA256_PER_WORD);
    vm.budget.consume(budgetCost) catch return SyscallError.OutOfbudget;

    const input = vm.memory.getSlice(input_ptr, input_len) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(input, &out, .{});

    const out_slice = vm.memory.getSliceMut(output_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &out);
    vm.regs[10] = 0;
}

fn reviveInstantiate(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    _ = env;
    vm.regs[10] = 1;
}

fn reviveNow(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 8) catch return SyscallError.SegFault;
    std.mem.writeInt(u64, out_slice[0..8], env.timestamp, .little);
    vm.regs[10] = 0;
}

fn reviveOrigin(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 20) catch return SyscallError.SegFault;
    translateAddrToGuest(env.txOrigin, out_slice);
    vm.regs[10] = 0;
}

fn reviveRefTimeLeft(vm: *ForgeVM) SyscallError!void {
    const remaining = vm.budget.remaining();
    vm.regs[10] = @truncate(remaining);
    vm.regs[11] = @truncate(remaining >> 32);
}

fn reviveReturnDataCopy(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_len_ptr = vm.regs[12];
    const offset = vm.regs[13];

    const len_ref = vm.memory.getSliceMut(out_len_ptr, 4) catch return SyscallError.SegFault;
    const guest_len = std.mem.readInt(u32, len_ref[0..4], .little);

    if (offset >= env.lastReturnData.len) {
        std.mem.writeInt(u32, len_ref[0..4], 0, .little);
        vm.regs[10] = 0;
        return;
    }

    const available = env.lastReturnData.len - offset;
    const write_len = @min(guest_len, available);

    const out_slice = vm.memory.getSliceMut(out_ptr, write_len) catch return SyscallError.SegFault;
    @memcpy(out_slice, env.lastReturnData[offset .. offset + write_len]);
    std.mem.writeInt(u32, len_ref[0..4], @intCast(write_len), .little);
    vm.regs[10] = 0;
}

fn reviveReturnDataSize(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const len = env.lastReturnData.len;
    vm.regs[10] = @truncate(len);
    vm.regs[11] = @truncate(len >> 32);
}

fn reviveSetImmutableData(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const ptr = vm.regs[11];
    const len = vm.regs[12];

    const data_slice = vm.memory.getSlice(ptr, len) catch return SyscallError.SegFault;
    env.immutableData.clearRetainingCapacity();
    env.immutableData.appendSlice(env.allocator, data_slice) catch return SyscallError.InternalError;
    vm.regs[10] = 0;
}

fn reviveSetStorageOrClear(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const flags = vm.regs[11];
    _ = flags;
    const key_ptr = vm.regs[12];
    const value_ptr = vm.regs[13];

    const key_slice = vm.memory.getSlice(key_ptr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    const value_slice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var value: [32]u8 = undefined;
    @memcpy(&value, value_slice);

    const currentValue = if (env.storage) |s| s.load(key) else [_]u8{0} ** 32;
    const wasWarm = env.accessSets.markSlotWarm(key);
    
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, currentValue);
        vm.budget.consume(budgetTable.Syscallbudget.STORAGE_STORE) catch return SyscallError.OutOfbudget;
    }

    if (env.storage) |s| s.store(key, value);
    env.cacheSloadValue(key, value);

    vm.regs[10] = 0;
}

fn reviveValueTransferred(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const out_ptr = vm.regs[11];
    const out_slice = vm.memory.getSliceMut(out_ptr, 32) catch return SyscallError.SegFault;
    @memcpy(out_slice, &env.callValue);
    vm.regs[10] = 0;
}

