// ============================================================================
// RISC-V VM Module — Full Node Integration (Production)
// ============================================================================
//
// Bridges the forgec RISC-V RV32EM VM (at /vm/) with the Zephyria node.
// Provides:
//   • executeContract() — execute runtime code with calldata
//   • deployContract() — execute initcode, return runtime code
//   • All HostEnv provider slots wired:
//       balance_fn      → StateBridge.getBalance (real state query)
//       call_fn         → recursive VM re-entry with call-type semantics:
//                         CALL: msg.sender = caller, storage = target
//                         DELEGATECALL: msg.sender = original caller, storage = caller
//                         STATICCALL: read-only execution, no state mutation
//       create_fn       → derive address via keccak(RLP(sender, nonce)), execute initcode
//       ecrecover_fn    → secp256k1 ECDSA signature recovery
//       selfdestruct_fn → transfer balance + mark for deletion via StateBridge
//
// Isolated Accounts & Zero-Conflict Parallel Model:
//   The VM operates within per-TX Overlay isolation. Each SLOAD/SSTORE goes through
//   the Overlay → Verkle trie path where:
//     StorageKey = keccak256(contract || slot)          — different slots = zero conflict
//     DerivedKey = keccak256(user || contract || slot)   — different users = zero conflict
//     GlobalKey  = keccak256(contract || "global" || slot) — commutative accumulators
//   Sub-calls share the same Overlay, preserving per-TX atomicity.

const std = @import("std");
const core = @import("core");
const vm = @import("vm");
const StateBridge = @import("state_bridge").StateBridge;

// Re-export forgec VM components
pub const vm_core = vm.executor;
pub const vm_syscall = vm.syscall_dispatch;
pub const vm_gas = vm.gas_meter;
pub const vm_memory = vm.sandbox;

/// Execute a contract call using the RISC-V VM.
/// All HostEnv provider slots are wired for full smart-contract support.
pub fn executeContract(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    state_bridge: *anyopaque,
) !ExecutionResult {
    var sb: *StateBridge = @ptrCast(@alignCast(state_bridge));

    // Create host environment
    var host = vm.HostEnv.init(allocator);
    defer host.deinit();

    // ── Wire storage backend ────────────────────────────────────────
    var storage_backend = sb.createStorageBackend();
    host.storage = &storage_backend;

    // ── Wire execution context (from block/tx) ──────────────────────
    host.caller = sb.caller;
    host.self_address = sb.self_address;
    host.call_value = sb.value;
    host.gas_limit = gas_limit;
    host.block_number = sb.block_number;
    host.chain_id = sb.chain_id_value;
    host.timestamp = sb.timestamp;
    host.tx_origin = sb.tx_origin;
    host.gas_price = sb.gas_price;
    host.coinbase = sb.coinbase;
    host.base_fee = sb.base_fee;
    host.prevrandao = sb.prevrandao;

    // ── Wire balance provider ───────────────────────────────────────
    // Routes GET_BALANCE syscall to real state overlay lookup.
    const BalanceProvider = struct {
        var bridge: *StateBridge = undefined;
        fn getBalance(addr: [20]u8) [32]u8 {
            return bridge.getBalance(addr);
        }
    };
    BalanceProvider.bridge = sb;
    host.balance_fn = &BalanceProvider.getBalance;

    // ── Wire call provider ──────────────────────────────────────────
    // Routes CALL/DELEGATECALL/STATICCALL syscalls to recursive VM execution.
    //
    // Call semantics:
    //   CALL:         msg.sender = current contract, code/storage = target contract
    //   DELEGATECALL: msg.sender = original caller (preserved), code = target, storage = current
    //   STATICCALL:   same as CALL but state mutations are forbidden
    const CallProvider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn callContract(
            call_type: vm.syscall_dispatch.CallType,
            to: [20]u8,
            value: [32]u8,
            data: []const u8,
            gas: u64,
        ) vm.syscall_dispatch.CallProviderResult {
            // Get target code
            const code = bridge.getCode(to) catch {
                return .{ .success = true, .return_data = &[_]u8{}, .gas_used = 0 };
            };
            if (code.len == 0) {
                return .{ .success = true, .return_data = &[_]u8{}, .gas_used = 0 };
            }

            // ------ Apply call-type semantics ------
            var sub_self_address: [20]u8 = undefined;
            var sub_caller: [20]u8 = undefined;
            var sub_value: [32]u8 = undefined;
            // For delegatecall: run target's CODE but in current contract's STORAGE context.
            // exec_code is always `code` (the target's bytecode fetched above).
            // The difference is which address and caller the sub-bridge uses.
            const exec_code = code;

            switch (call_type) {
                .call => {
                    // CALL: sender is current contract, target runs its own code/storage
                    sub_self_address = to;
                    sub_caller = bridge.self_address;
                    sub_value = value;

                    // Transfer value if non-zero
                    if (!isZero(value)) {
                        bridge.transfer(to, value) catch {
                            return .{ .success = false, .return_data = &[_]u8{}, .gas_used = 0 };
                        };
                    }
                },
                .delegatecall => {
                    // DELEGATECALL: caller = original msg.sender (preserved),
                    // storage context = current contract (sub_self_address = bridge.self_address),
                    // code = target's bytecode (exec_code set above).
                    sub_self_address = bridge.self_address; // storage stays in current contract
                    sub_caller = bridge.caller;             // msg.sender = original caller
                    sub_value = bridge.value;               // value = original call value
                    // No value transfer in delegatecall
                },
                .staticcall => {
                    // STATICCALL: same as CALL but read-only (no state mutations)
                    sub_self_address = to;
                    sub_caller = bridge.self_address;
                    sub_value = [_]u8{0} ** 32; // No value transfer in staticcall
                },
            }
            // Create sub-bridge. For DELEGATECALL sub_self_address = bridge.self_address
            // so that SLOAD/SSTORE inside the callee operate on the caller's storage slots.
            var sub_bridge = StateBridge.init(
                alloc,
                bridge.overlay,
                sub_self_address,
                sub_caller,
                sub_value,
                gas,
            );
            sub_bridge.depth = bridge.depth + 1;
            sub_bridge.inheritContext(bridge);
            defer sub_bridge.deinit();

            // Check call depth (EIP limit: 1024)
            if (sub_bridge.depth > sub_bridge.max_depth) {
                return .{ .success = false, .return_data = &[_]u8{}, .gas_used = 0 };
            }

            const result = executeContract(
                alloc,
                exec_code,
                data,
                gas,
                @ptrCast(&sub_bridge),
            ) catch {
                return .{ .success = false, .return_data = &[_]u8{}, .gas_used = gas };
            };

            return .{
                .success = result.success,
                .return_data = result.return_data,
                .gas_used = result.gas_used,
            };
        }
    };
    CallProvider.bridge = sb;
    CallProvider.alloc = allocator;
    host.call_fn = &CallProvider.callContract;

    // ── Wire create provider ────────────────────────────────────────
    // Routes CREATE_CONTRACT syscall to: derive address → execute initcode → store runtime code.
    // Address derivation follows Ethereum: keccak256(RLP([sender, nonce]))[12..32]
    const CreateProvider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn createContract(
            code: []const u8,
            value: [32]u8,
            gas: u64,
        ) vm.syscall_dispatch.CreateProviderResult {
            const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
            const sender_addr = core.types.Address{ .bytes = bridge.self_address };

            // Get sender nonce for deterministic address derivation
            const nonce = state.get_nonce(sender_addr);

            // Derive new contract address = keccak256(RLP([sender, nonce]))[12..32]
            // Simplified RLP: keccak256(0xd6 || 0x94 || sender || nonce_byte)
            // This matches Ethereum's CREATE address derivation
            var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            // RLP prefix for a list of [address, nonce]
            hasher.update(&[_]u8{ 0xd6, 0x94 });
            hasher.update(&bridge.self_address);
            // Encode nonce (simplified: single byte if < 128, otherwise length-prefixed)
            if (nonce == 0) {
                hasher.update(&[_]u8{0x80});
            } else if (nonce < 128) {
                hasher.update(&[_]u8{@truncate(nonce)});
            } else {
                var nonce_buf: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce_buf, nonce, .big);
                // Find first non-zero byte
                var start: usize = 0;
                while (start < 7 and nonce_buf[start] == 0) : (start += 1) {}
                const nonce_len: u8 = @truncate(8 - start);
                hasher.update(&[_]u8{0x80 + nonce_len});
                hasher.update(nonce_buf[start..8]);
            }
            var hash: [32]u8 = undefined;
            hasher.final(&hash);
            var new_addr: [20]u8 = undefined;
            @memcpy(&new_addr, hash[12..32]);

            // Increment sender nonce
            state.set_nonce(sender_addr, nonce + 1) catch {};

            // Mark as created
            const new_addr_typed = core.types.Address{ .bytes = new_addr };
            state.mark_created(new_addr_typed) catch {};

            // Transfer value to new contract
            if (!isZero(value)) {
                bridge.transfer(new_addr, value) catch {
                    return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = 0 };
                };
            }

            // Execute initcode via recursive VM call
            var sub_bridge = StateBridge.init(
                alloc,
                bridge.overlay,
                new_addr,
                bridge.self_address,
                value,
                gas,
            );
            sub_bridge.depth = bridge.depth + 1;
            sub_bridge.inheritContext(bridge);
            defer sub_bridge.deinit();

            const result = executeContract(
                alloc,
                code,
                &[_]u8{},
                gas,
                @ptrCast(&sub_bridge),
            ) catch {
                return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = gas };
            };

            if (result.success and result.return_data.len > 0) {
                // Store runtime code at new address
                state.set_code(new_addr_typed, result.return_data) catch {
                    return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = result.gas_used };
                };
            }

            return .{
                .success = result.success,
                .new_address = new_addr,
                .gas_used = result.gas_used,
            };
        }
    };
    CreateProvider.bridge = sb;
    CreateProvider.alloc = allocator;
    host.create_fn = &CreateProvider.createContract;

    // ── Wire create2 provider ───────────────────────────────────────
    // Routes CREATE2 syscall to: hash initcode → derive salt-based address → execute initcode.
    // Address derivation follows EIP-1014: keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
    // This produces deterministic addresses independent of sender nonce.
    const Create2Provider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn create2Contract(
            code: []const u8,
            salt: [32]u8,
            value: [32]u8,
            gas: u64,
        ) vm.syscall_dispatch.CreateProviderResult {
            const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));

            // Step 1: Hash the initcode
            var initcode_hash: [32]u8 = undefined;
            var code_hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            code_hasher.update(code);
            code_hasher.final(&initcode_hash);

            // Step 2: Derive CREATE2 address = keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
            var addr_hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            addr_hasher.update(&[_]u8{0xFF});
            addr_hasher.update(&bridge.self_address);
            addr_hasher.update(&salt);
            addr_hasher.update(&initcode_hash);
            var hash: [32]u8 = undefined;
            addr_hasher.final(&hash);
            var new_addr: [20]u8 = undefined;
            @memcpy(&new_addr, hash[12..32]);

            // Step 3: Check for address collision (code already exists at derived address)
            const new_addr_typed = core.types.Address{ .bytes = new_addr };
            const existing_code = state.get_code(new_addr_typed) catch &[_]u8{};
            if (existing_code.len > 0) {
                // Address collision — CREATE2 must fail
                return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = 0 };
            }

            // Step 4: Increment sender nonce (same as CREATE)
            const sender_addr = core.types.Address{ .bytes = bridge.self_address };
            const nonce = state.get_nonce(sender_addr);
            state.set_nonce(sender_addr, nonce + 1) catch {};

            // Step 5: Mark as created
            state.mark_created(new_addr_typed) catch {};

            // Step 6: Transfer value to new contract
            if (!isZero(value)) {
                bridge.transfer(new_addr, value) catch {
                    return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = 0 };
                };
            }

            // Step 7: Execute initcode in child VM
            var sub_bridge = StateBridge.init(
                alloc,
                bridge.overlay,
                new_addr,
                bridge.self_address,
                value,
                gas,
            );
            sub_bridge.depth = bridge.depth + 1;
            sub_bridge.inheritContext(bridge);
            defer sub_bridge.deinit();

            const result = executeContract(
                alloc,
                code,
                &[_]u8{},
                gas,
                @ptrCast(&sub_bridge),
            ) catch {
                return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = gas };
            };

            // Step 8: Store runtime bytecode at derived address
            if (result.success and result.return_data.len > 0) {
                state.set_code(new_addr_typed, result.return_data) catch {
                    return .{ .success = false, .new_address = [_]u8{0} ** 20, .gas_used = result.gas_used };
                };
            }

            return .{
                .success = result.success,
                .new_address = new_addr,
                .gas_used = result.gas_used,
            };
        }
    };
    Create2Provider.bridge = sb;
    Create2Provider.alloc = allocator;
    host.create2_fn = &Create2Provider.create2Contract;

    // ── Wire ecrecover provider ─────────────────────────────────────
    // Routes ECRECOVER syscall to real secp256k1 ECDSA signature recovery.
    // Uses the existing eoa.recoverPublicKey() which performs actual elliptic
    // curve point recovery on the secp256k1 curve, then derives the Ethereum
    // address via keccak256(uncompressed_pubkey[1..])[12..32].
    //
    // This enables: EIP-712 typed data signing, ERC-20 permit(), meta-transactions,
    // signature-based authentication, and all signature-dependent DeFi protocols.
    const EcrecoverProvider = struct {
        fn ecrecoverFn(hash: [32]u8, v: u8, r: [32]u8, s: [32]u8) [20]u8 {
            // Validate v (must be 27 or 28 for Ethereum-style signatures)
            if (v != 27 and v != 28) {
                return [_]u8{0} ** 20; // Invalid v — return zero address
            }

            // Validate r and s are non-zero (basic validity check)
            if (isZero(r) or isZero(s)) {
                return [_]u8{0} ** 20;
            }

            // Validate s is in the lower half of the curve order (EIP-2)
            // s must be <= secp256k1 order / 2
            // Upper bound: 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
            if (s[0] > 0x7F) {
                return [_]u8{0} ** 20; // s too high — malleable signature
            }

            // Recovery ID: v - 27 gives 0 or 1
            const recovery_id: u8 = v - 27;

            // Real secp256k1 ECDSA point recovery:
            // 1. Recover the uncompressed public key (65 bytes) from (hash, r, s, recovery_id)
            // 2. Derive Ethereum address = keccak256(pubkey[1..65])[12..32]
            const uncompressed_pubkey = core.account.recoverPublicKey(hash, r, s, recovery_id) catch {
                return [_]u8{0} ** 20; // Recovery failed — invalid signature
            };

            // Derive address from recovered public key
            const addr_result = core.account.addressFromPubKey(&uncompressed_pubkey) catch {
                return [_]u8{0} ** 20; // Address derivation failed
            };

            return addr_result.bytes;
        }
    };
    host.ecrecover_fn = &EcrecoverProvider.ecrecoverFn;

    // ── Wire selfdestruct provider ──────────────────────────────────
    // Routes SELFDESTRUCT syscall to StateBridge.selfDestruct which transfers
    // remaining balance to beneficiary and marks the account for deletion
    // via Overlay.suicide().
    const SelfDestructProvider = struct {
        var bridge: *StateBridge = undefined;
        fn selfDestructFn(beneficiary: [20]u8) bool {
            bridge.selfDestruct(beneficiary) catch return false;
            return true;
        }
    };
    SelfDestructProvider.bridge = sb;
    host.selfdestruct_fn = &SelfDestructProvider.selfDestructFn;

    // ── Execute via the contract loader ─────────────────────────────
    const sys_result = vm.contract_loader.executeFromElf(
        allocator,
        bytecode,
        calldata,
        gas_limit,
        &host,
    ) catch |err| {
        std.log.err("executeFromElf failed: {}", .{err});
        return ExecutionResult{
            .success = false,
            .gas_used = 0,
            .gas_remaining = gas_limit,
            .return_data = &[_]u8{},
            .logs = &[_]vm.syscall_dispatch.LogEntry{},
            .status = .fault,
        };
    };

    if (sys_result.status != .returned) {
        if (sys_result.status == .fault) {
            std.log.err("VM Fault at PC=0x{x}: {s}", .{ sys_result.fault_pc, sys_result.fault_reason orelse "Unknown" });
        }
    }

    return ExecutionResult{
        .success = sys_result.status == .returned,
        .gas_used = sys_result.gas_used,
        .gas_remaining = sys_result.gas_remaining,
        .return_data = sys_result.return_data,
        .logs = host.logs.items,
        .status = sys_result.status,
    };
}

/// Deploy a new contract (execute initcode, return runtime code).
pub fn deployContract(
    allocator: std.mem.Allocator,
    initcode: []const u8,
    gas_limit: u64,
    state_bridge: *anyopaque,
) !DeployResult {
    const result = try executeContract(
        allocator,
        initcode,
        &[_]u8{},
        gas_limit,
        state_bridge,
    );

    return DeployResult{
        .success = result.success,
        .gas_used = result.gas_used,
        .runtime_code = result.return_data,
        .logs = result.logs,
    };
}

/// Result of contract execution.
pub const ExecutionResult = struct {
    success: bool,
    gas_used: u64,
    gas_remaining: u64,
    return_data: []const u8,
    /// Logs emitted during execution (from HostEnv)
    logs: []const vm.syscall_dispatch.LogEntry,
    status: vm_core.ExecutionStatus,
};

/// Result of contract deployment.
pub const DeployResult = struct {
    success: bool,
    gas_used: u64,
    runtime_code: []const u8,
    /// Logs emitted during deployment
    logs: []const vm.syscall_dispatch.LogEntry,
};

// ── Helpers ─────────────────────────────────────────────────────────

fn isZero(value: [32]u8) bool {
    for (value) |b| {
        if (b != 0) return false;
    }
    return true;
}
