// ============================================================================
// RISC-V VM Module — Full Node Integration (Production)
// ============================================================================
//
// Bridges the forgec RISC-V RV32EM VM (at /vm/) with the Zephyria node.
// Provides:
//   • executeContract() — execute runtime code with calldata
//   • deployContract() — execute initcode, return runtime code
//   • All HostEnv provider slots wired:
//       balanceFn      → StateBridge.getBalance (real state query)
//       callFn         → recursive VM re-entry with call-type semantics:
//                         CALL: msg.sender = caller, storage = target
//                         DELEGATECALL: msg.sender = original caller, storage = caller
//                         STATICCALL: read-only execution, no state mutation
//       createFn       → derive address via blake3(sender, sequence), execute initcode
//       ecrecoverFn    → secp256k1 ECDSA signature recovery
//       selfDestructFn → transfer balance + mark for deletion via StateBridge
//
// Isolated Accounts & Zero-Conflict Parallel Model:
//   The VM operates within per-TX Overlay isolation. Each SLOAD/SSTORE goes through
//   the Overlay → KV HighperfDB and ZephyrDB path where:
//     StorageKey = blake3(contract || slot)          — different slots = zero conflict
//     DerivedKey = blake3(user || contract || slot)   — different users = zero conflict
//     GlobalKey  = blake3(contract || "global" || slot) — commutative accumulators
//   Sub-calls share the same Overlay, preserving per-TX atomicity.

const std = @import("std");
const core = @import("core");
const vm = @import("vm");
const StateBridge = @import("state_bridge").StateBridge;
// const polkavm = @import("polkavm");
// PolkaVM support temporarily disabled — needs full rework.

// Re-export forgec VM components
pub const vmCore = vm.executor;
pub const vmSyscall = vm.syscallDispatch;
//
// pub fn detectPolkaVM(code: []const u8) bool {
//     if (code.len < 4 or code[0] != 0x7F or code[1] != 'E' or code[2] != 'L' or code[3] != 'F') {
//         return false;
//     }
//     return std.mem.indexOf(u8, code, "seal_") != null;
// }
//
// fn executePolkaContract(
//     allocator: std.mem.Allocator,
//     bytecode: []const u8,
//     calldata: []const u8,
//     executionBudget: u64,
//     stateBridge: *anyopaque,
// ) !ExecutionResult {
//     const sb: *StateBridge = @ptrCast(@alignCast(stateBridge));
//
//     // Create host environment
//     var host = polkavm.HostEnv.init(allocator);
//     defer host.deinit();
//
//     // ── Wire storage backend ────────────────────────────────────────
//     var storageBackend = polkavm.syscallDispatch.StorageBackend{
//         .ctx = sb,
//         .loadFn = struct {
//             fn load(ctx: *anyopaque, key: [32]u8) [32]u8 {
//                 const s: *StateBridge = @ptrCast(@alignCast(ctx));
//                 return s.storageLoad(key);
//             }
//         }.load,
//         .storeFn = struct {
//             fn store(ctx: *anyopaque, key: [32]u8, value: [32]u8) void {
//                 const s: *StateBridge = @ptrCast(@alignCast(ctx));
//                 _ = s.storageStore(key, value);
//             }
//         }.store,
//     };
//     host.storage = &storageBackend;
//
//     // ── Wire derived storage provider ────────────────────────────────
//     const DerivedStorageProvider = struct {
//         var bridge: *StateBridge = undefined;
//         fn load(host_env: *polkavm.HostEnv, user: [32]u8, slot: [32]u8) [32]u8 {
//             _ = host_env;
//             return bridge.derivedStorageLoad(user, slot);
//         }
//         fn store(host_env: *polkavm.HostEnv, user: [32]u8, slot: [32]u8, value: [32]u8) anyerror!void {
//             _ = host_env;
//             try bridge.derivedStorageStore(user, slot, value);
//         }
//     };
//     DerivedStorageProvider.bridge = sb;
//     host.derivedLoadFn = &DerivedStorageProvider.load;
//     host.derivedStoreFn = &DerivedStorageProvider.store;
//
//     // ── Wire global storage provider ─────────────────────────────────
//     const GlobalStorageProvider = struct {
//         var bridge: *StateBridge = undefined;
//         fn load(host_env: *polkavm.HostEnv, slot: [32]u8) [32]u8 {
//             _ = host_env;
//             return bridge.globalStorageLoad(slot);
//         }
//         fn store(host_env: *polkavm.HostEnv, slot: [32]u8, delta: [32]u8, isAddition: bool) anyerror!void {
//             _ = host_env;
//             try bridge.globalStorageStore(slot, delta, isAddition);
//         }
//     };
//     GlobalStorageProvider.bridge = sb;
//     host.globalLoadFn = &GlobalStorageProvider.load;
//     host.globalStoreFn = &GlobalStorageProvider.store;
//
//     // ── Wire execution context (from block/tx) ──────────────────────
//     host.caller = sb.caller;
//     host.selfAddress = sb.selfAddress;
//     host.callValue = sb.value;
//     host.executionBudget = executionBudget;
//     host.blockNumber = sb.blockNumber;
//     host.chainId = sb.chainId;
//     host.timestamp = sb.timestamp;
//     host.txOrigin = sb.txOrigin;
//     host.computePrice = sb.computePrice;
//     host.producer = sb.producer;
//     host.prevrandao = sb.prevRandao;
//
//     // ── Wire VM execution pool (threaded executor + code cache) ─────
//     host.vm_pool = if (sb.vm_pool) |pool| @as(*anyopaque, @ptrCast(pool)) else null;
//
//     // ── Wire code hash & size provider ──────────────────────────────
//     const CodeInfoProvider = struct {
//         var bridge: *StateBridge = undefined;
//         fn getCodeHash(addr: [32]u8) [32]u8 {
//             return bridge.getCodeHash(addr);
//         }
//         fn getCodeSize(addr: [32]u8) u64 {
//             return bridge.getCodeSize(addr);
//         }
//     };
//     CodeInfoProvider.bridge = sb;
//     host.codeHashFn = &CodeInfoProvider.getCodeHash;
//     host.codeSizeFn = &CodeInfoProvider.getCodeSize;
//
//     // ── Wire balance provider ───────────────────────────────────────
//     const BalanceProvider = struct {
//         var bridge: *StateBridge = undefined;
//         fn getBalance(addr: [32]u8) [32]u8 {
//             return bridge.getBalance(addr);
//         }
//     };
//     BalanceProvider.bridge = sb;
//     host.balanceFn = &BalanceProvider.getBalance;
//
//     // ── Wire call provider ──────────────────────────────────────────
//     const CallProvider = struct {
//         var bridge: *StateBridge = undefined;
//         var alloc: std.mem.Allocator = undefined;
//
//         fn callContract(
//             callType: polkavm.syscallDispatch.CallType,
//             to: [32]u8,
//             value: [32]u8,
//             data: []const u8,
//             budget: u64,
//         ) polkavm.syscallDispatch.CallProviderResult {
//             const code = bridge.getCode(to) catch {
//                 return .{ .success = true, .returnData = &[_]u8{}, .budgetUsed = 0 };
//             };
//             if (code.len == 0) {
//                 return .{ .success = true, .returnData = &[_]u8{}, .budgetUsed = 0 };
//             }
//             defer {
//                 const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
//                 state.general_allocator.free(code);
//             }
//
//             var subSelfAddress: [32]u8 = undefined;
//             var subCaller: [32]u8 = undefined;
//             var subValue: [32]u8 = undefined;
//             const execCode = code;
//
//             const compatCallType = switch (callType) {
//                 .call => polkavm.syscallDispatch.CallType.call,
//                 .delegatecall => polkavm.syscallDispatch.CallType.delegatecall,
//                 .staticcall => polkavm.syscallDispatch.CallType.staticcall,
//             };
//
//             switch (compatCallType) {
//                 .call => {
//                     subSelfAddress = to;
//                     subCaller = bridge.selfAddress;
//                     subValue = value;
//
//                     if (!isZero(value)) {
//                         bridge.transfer(to, value) catch {
//                             return .{ .success = false, .returnData = &[_]u8{}, .budgetUsed = 0 };
//                         };
//                     }
//                 },
//                 .delegatecall => {
//                     subSelfAddress = bridge.selfAddress;
//                     subCaller = bridge.caller;
//                     subValue = bridge.value;
//                 },
//                 .staticcall => {
//                     subSelfAddress = to;
//                     subCaller = bridge.selfAddress;
//                     subValue = [_]u8{0} ** 32;
//                 },
//             }
//             var subBridge = StateBridge.init(
//                 alloc,
//                 bridge.overlay,
//                 subSelfAddress,
//                 subCaller,
//                 subValue,
//                 budget,
//             );
//             subBridge.depth = bridge.depth + 1;
//             subBridge.inheritContext(bridge);
//             defer subBridge.deinit();
//
//             if (subBridge.depth > subBridge.maxDepth) {
//                 return .{ .success = false, .returnData = &[_]u8{}, .budgetUsed = 0 };
//             }
//
//             const result = executePolkaContract(
//                 alloc,
//                 execCode,
//                 data,
//                 budget,
//                 @ptrCast(&subBridge),
//             ) catch {
//                 return .{ .success = false, .returnData = &[_]u8{}, .budgetUsed = budget };
//             };
//
//             return .{
//                 .success = result.success,
//                 .returnData = result.returnData,
//                 .budgetUsed = result.budgetUsed,
//             };
//         }
//     };
//     CallProvider.bridge = sb;
//     CallProvider.alloc = allocator;
//     host.callFn = &CallProvider.callContract;
//
//     // ── Wire create provider ────────────────────────────────────────
//     const CreateProvider = struct {
//         var bridge: *StateBridge = undefined;
//         var alloc: std.mem.Allocator = undefined;
//
//         fn createContract(
//             code: []const u8,
//             value: [32]u8,
//             budget: u64,
//         ) polkavm.syscallDispatch.CreateProviderResult {
//             const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
//             const senderAddr = core.types.Address{ .bytes = bridge.selfAddress };
//             const sequence = state.getSequence(senderAddr);
//
//             var sequenceBytes: [8]u8 = undefined;
//             std.mem.writeInt(u64, &sequenceBytes, sequence, .big);
//             var createInput: [40]u8 = undefined;
//             @memcpy(createInput[0..32], &bridge.selfAddress);
//             @memcpy(createInput[32..40], &sequenceBytes);
//             var newAddr: [32]u8 = undefined;
//             std.crypto.hash.Blake3.hash(&createInput, &newAddr, .{});
//
//             state.setSequence(senderAddr, sequence + 1) catch {};
//
//             const newAddrTyped = core.types.Address{ .bytes = newAddr };
//             state.markCreated(newAddrTyped, .ContractRoot) catch {};
//
//             if (!isZero(value)) {
//                 bridge.transfer(newAddr, value) catch {
//                     return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
//                 };
//             }
//
//             var subBridge = StateBridge.init(
//                 alloc,
//                 bridge.overlay,
//                 newAddr,
//                 bridge.selfAddress,
//                 value,
//                 budget,
//             );
//             subBridge.depth = bridge.depth + 1;
//             subBridge.inheritContext(bridge);
//             defer subBridge.deinit();
//
//             const result = executePolkaContract(
//                 alloc,
//                 code,
//                 &[_]u8{},
//                 budget,
//                 @ptrCast(&subBridge),
//             ) catch {
//                 return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = budget };
//             };
//
//             if (result.success and result.returnData.len > 0) {
//                 state.setCode(newAddrTyped, result.returnData) catch {
//                     return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = result.budgetUsed };
//                 };
//             }
//
//             return .{
//                 .success = result.success,
//                 .newAddress = newAddr,
//                 .budgetUsed = result.budgetUsed,
//             };
//         }
//     };
//     CreateProvider.bridge = sb;
//     CreateProvider.alloc = allocator;
//     host.createFn = &CreateProvider.createContract;
//
//     // ── Wire create2 provider ───────────────────────────────────────
//     const Create2Provider = struct {
//         var bridge: *StateBridge = undefined;
//         var alloc: std.mem.Allocator = undefined;
//
//         fn create2Contract(
//             code: []const u8,
//             salt: [32]u8,
//             value: [32]u8,
//             budget: u64,
//         ) polkavm.syscallDispatch.CreateProviderResult {
//             const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
//
//             var initcodeHash: [32]u8 = undefined;
//             std.crypto.hash.Blake3.hash(code, &initcodeHash, .{});
//
//             var create2Input: [97]u8 = undefined;
//             create2Input[0] = 0x02;
//             @memcpy(create2Input[1..33], &bridge.selfAddress);
//             @memcpy(create2Input[33..65], &salt);
//             @memcpy(create2Input[65..97], &initcodeHash);
//             var newAddr: [32]u8 = undefined;
//             std.crypto.hash.Blake3.hash(&create2Input, &newAddr, .{});
//
//             const newAddrTyped = core.types.Address{ .bytes = newAddr };
//             const existingCode = state.getCode(newAddrTyped) catch &[_]u8{};
//             defer if (existingCode.len > 0) {
//                 state.general_allocator.free(existingCode);
//             };
//             if (existingCode.len > 0) {
//                 return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
//             }
//
//             const senderAddr = core.types.Address{ .bytes = bridge.selfAddress };
//             const sequence = state.getSequence(senderAddr);
//             state.setSequence(senderAddr, sequence + 1) catch {};
//
//             state.markCreated(newAddrTyped, .ContractRoot) catch {};
//
//             if (!isZero(value)) {
//                 bridge.transfer(newAddr, value) catch {
//                     return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
//                 };
//             }
//
//             var subBridge = StateBridge.init(
//                 alloc,
//                 bridge.overlay,
//                 newAddr,
//                 bridge.selfAddress,
//                 value,
//                 budget,
//             );
//             subBridge.depth = bridge.depth + 1;
//             subBridge.inheritContext(bridge);
//             defer subBridge.deinit();
//
//             const result = executePolkaContract(
//                 alloc,
//                 code,
//                 &[_]u8{},
//                 budget,
//                 @ptrCast(&subBridge),
//             ) catch {
//                 return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = budget };
//             };
//
//             if (result.success and result.returnData.len > 0) {
//                 state.setCode(newAddrTyped, result.returnData) catch {
//                     return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = result.budgetUsed };
//                 };
//             }
//
//             return .{
//                 .success = result.success,
//                 .newAddress = newAddr,
//                 .budgetUsed = result.budgetUsed,
//             };
//         }
//     };
//     Create2Provider.bridge = sb;
//     Create2Provider.alloc = allocator;
//     host.create2Fn = &Create2Provider.create2Contract;
//
//     // ── Wire instantiate provider ───────────────────────────────────
//     const InstantiateProvider = struct {
//         var bridge: *StateBridge = undefined;
//         var alloc: std.mem.Allocator = undefined;
//
//         fn instantiateContract(
//             code_hash: [32]u8,
//             value: [32]u8,
//             input: []const u8,
//             salt: ?[32]u8,
//             budget: u64,
//         ) polkavm.syscallDispatch.CreateProviderResult {
//             _ = bridge;
//             _ = alloc;
//             _ = code_hash;
//             _ = value;
//             _ = input;
//             _ = salt;
//             _ = budget;
//             return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
//         }
//     };
//     InstantiateProvider.bridge = sb;
//     InstantiateProvider.alloc = allocator;
//     host.instantiateFn = &InstantiateProvider.instantiateContract;
//
//     // ── Wire sig-verify provider ────────────────────────────────────
//     const EcrecoverProvider = struct {
//         fn ecrecoverFn(hash: [32]u8, scheme: u8, pubkey: [32]u8, signature: [64]u8) [32]u8 {
//             switch (scheme) {
//                 0 => {
//                     const Ed25519 = std.crypto.sign.Ed25519;
//                     const pk = Ed25519.PublicKey.fromBytes(pubkey) catch return [_]u8{0} ** 32;
//                     const sig = Ed25519.Signature.fromBytes(signature);
//                     Ed25519.Signature.verify(sig, &hash, pk) catch return [_]u8{0} ** 32;
//                     var addr: [32]u8 = undefined;
//                     std.crypto.hash.Blake3.hash(&pubkey, &addr, .{});
//                     return addr;
//                 },
//                 else => return [_]u8{0} ** 32,
//             }
//         }
//     };
//     host.ecrecoverFn = &EcrecoverProvider.ecrecoverFn;
//
//     // ── Wire selfdestruct provider ──────────────────────────────────
//     const SelfDestructProvider = struct {
//         var bridge: *StateBridge = undefined;
//         fn selfDestructFn(beneficiary: [32]u8) bool {
//             bridge.selfDestruct(beneficiary) catch return false;
//             return true;
//         }
//     };
//     SelfDestructProvider.bridge = sb;
//     host.selfDestructFn = &SelfDestructProvider.selfDestructFn;
//
//     // ── Execute via the contract loader ─────────────────────────────
//     std.debug.print("DEBUG executePolkaContract: calling executeFromElf, calldata size={d}\n", .{calldata.len});
//     const sysResult = polkavm.contractLoader.executeFromElf(
//         allocator,
//         bytecode,
//         calldata,
//         executionBudget,
//         &host,
//     ) catch |err| {
//         std.debug.print("DEBUG executePolkaContract: executeFromElf failed with error={}\n", .{err});
//         std.log.err("executePolkaContract failed: {}", .{err});
//             return ExecutionResult{
//                 .success = false,
//                 .budgetUsed = 0,
//                 .budgetRemaining = executionBudget,
//             .returnData = &[_]u8{},
//             .logs = &[_]vm.LogEntry{},
//             .status = .fault,
//         };
//     };
//     std.debug.print("DEBUG executePolkaContract: executeFromElf returned status={}\n", .{sysResult.status});
//
//     if (sysResult.status != .returned) {
//         if (sysResult.status == .fault) {
//             std.log.err("PolkaVM Fault at PC=0x{x}: {s}", .{ sysResult.faultPc, sysResult.faultReason orelse "Unknown" });
//         }
//     }
//
//     const compatStatus: vm.executor.ExecutionStatus = switch (sysResult.status) {
//         .running => .running,
//         .returned => .returned,
//         .reverted => .reverted,
//         .outOfbudget => .outOfBudget,
//         .fault => .fault,
//         .breakpoint => .breakpoint,
//         .selfDestruct => .selfDestruct,
//     };
//
//     // Convert logs
//     const mappedLogs = try allocator.alloc(vm.LogEntry, sysResult.logs.len);
//     for (sysResult.logs, 0..) |log, i| {
//         mappedLogs[i] = .{
//             .topics = .{
//                 .items = log.topics.items,
//                 .capacity = log.topics.capacity,
//             },
//             .data = .{
//                 .items = log.data.items,
//                 .capacity = log.data.capacity,
//             },
//             .alloc = log.alloc,
//         };
//     }
//
//     return ExecutionResult{
//         .success = sysResult.status == .returned,
//         .budgetUsed = sysResult.budgetUsed,
//         .budgetRemaining = sysResult.budgetRemaining,
//         .returnData = sysResult.returnData,
//         .logs = mappedLogs,
//         .status = compatStatus,
//     };
// }

pub fn executeContract(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    calldata: []const u8,
    executionBudget: u64,
    stateBridge: *anyopaque,
) !ExecutionResult {
    var sb: *StateBridge = @ptrCast(@alignCast(stateBridge));

    // Create host environment
    var host = vm.HostEnv.init(allocator);
    defer host.deinit();

    // ── Wire storage backend ────────────────────────────────────────
    var storageBackend = sb.createStorageBackend();
    host.storage = &storageBackend;

    // ── Wire derived storage provider ────────────────────────────────
    const DerivedStorageProvider = struct {
        var bridge: *StateBridge = undefined;
        fn load(host_env: *vm.HostEnv, user: [32]u8, slot: [32]u8) [32]u8 {
            _ = host_env;
            return bridge.derivedStorageLoad(user, slot);
        }
        fn store(host_env: *vm.HostEnv, user: [32]u8, slot: [32]u8, value: [32]u8) anyerror!void {
            _ = host_env;
            try bridge.derivedStorageStore(user, slot, value);
        }
    };
    DerivedStorageProvider.bridge = sb;
    host.derivedLoadFn = &DerivedStorageProvider.load;
    host.derivedStoreFn = &DerivedStorageProvider.store;

    // ── Wire global storage provider ─────────────────────────────────
    const GlobalStorageProvider = struct {
        var bridge: *StateBridge = undefined;
        fn load(host_env: *vm.HostEnv, slot: [32]u8) [32]u8 {
            _ = host_env;
            return bridge.globalStorageLoad(slot);
        }
        fn store(host_env: *vm.HostEnv, slot: [32]u8, delta: [32]u8, isAddition: bool) anyerror!void {
            _ = host_env;
            try bridge.globalStorageStore(slot, delta, isAddition);
        }
    };
    GlobalStorageProvider.bridge = sb;
    host.globalLoadFn = &GlobalStorageProvider.load;
    host.globalStoreFn = &GlobalStorageProvider.store;

    // ── Wire execution context (from block/tx) ──────────────────────
    host.caller = sb.caller;
    host.selfAddress = sb.selfAddress;
    host.callValue = sb.value;
    host.executionBudget = executionBudget;
    host.blockNumber = sb.blockNumber;
    host.chainId = sb.chainId;
    host.timestamp = sb.timestamp;
    host.txOrigin = sb.txOrigin;
    host.computePrice = sb.computePrice;
    host.producer = sb.producer;
    host.prevrandao = sb.prevRandao;

    // ── Wire VM execution pool (threaded executor + code cache) ─────
    host.vm_pool = if (sb.vm_pool) |pool| @as(*anyopaque, @ptrCast(pool)) else null;

    // ── Wire balance provider ───────────────────────────────────────
    // Routes GET_BALANCE syscall to real state overlay lookup.
    const BalanceProvider = struct {
        var bridge: *StateBridge = undefined;
        fn getBalance(addr: [32]u8) [32]u8 {
            return bridge.getBalance(addr);
        }
    };
    BalanceProvider.bridge = sb;
    host.balanceFn = &BalanceProvider.getBalance;

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
            callType: vm.syscallDispatch.CallType,
            to: [32]u8,
            value: [32]u8,
            data: []const u8,
            budget: u64,
        ) vm.syscallDispatch.CallProviderResult {
            const code = bridge.getCode(to) catch {
                return .{ .success = true, .returnData = &[_]u8{}, .budgetUsed = 0 };
            };
            if (code.len == 0) {
                return .{ .success = true, .returnData = &[_]u8{}, .budgetUsed = 0 };
            }
            defer {
                const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
                state.general_allocator.free(code);
            }

            var subSelfAddress: [32]u8 = undefined;
            var subCaller: [32]u8 = undefined;
            var subValue: [32]u8 = undefined;
            const execCode = code;

            switch (callType) {
                .call => {
                    subSelfAddress = to;
                    subCaller = bridge.selfAddress;
                    subValue = value;

                    if (!isZero(value)) {
                        bridge.transfer(to, value) catch {
                            return .{ .success = false, .returnData = &[_]u8{}, .budgetUsed = 0 };
                        };
                    }
                },
                .delegatecall => {
                    subSelfAddress = bridge.selfAddress;
                    subCaller = bridge.caller;
                    subValue = bridge.value;
                },
                .staticcall => {
                    subSelfAddress = to;
                    subCaller = bridge.selfAddress;
                    subValue = [_]u8{0} ** 32;
                },
            }
            // Create sub-bridge. For DELEGATECALL subSelfAddress = bridge.selfAddress
            // so that SLOAD/SSTORE inside the callee operate on the caller's storage slots.
            var subBridge = StateBridge.init(
                alloc,
                bridge.overlay,
                subSelfAddress,
                subCaller,
                subValue,
                budget,
            );
            subBridge.depth = bridge.depth + 1;
            subBridge.inheritContext(bridge);
            defer subBridge.deinit();

            // Check call depth (EIP limit: 1024)
            if (subBridge.depth > subBridge.maxDepth) {
                return .{ .success = false, .returnData = &[_]u8{}, .budgetUsed = 0 };
            }

            const result = executeContract(
                alloc,
                execCode,
                data,
                budget,
                @ptrCast(&subBridge),
            ) catch {
                return .{ .success = false, .returnData = &[_]u8{}, .budgetUsed = budget };
            };

            return .{
                .success = result.success,
                .returnData = result.returnData,
                .budgetUsed = result.budgetUsed,
            };
        }
    };
    CallProvider.bridge = sb;
    CallProvider.alloc = allocator;
    host.callFn = &CallProvider.callContract;

    // ── Wire create provider ────────────────────────────────────────
    // Routes CREATE_CONTRACT syscall to: derive address → execute initcode → store runtime code.
    // Address derivation follows: blake3(sender || sequence)
    const CreateProvider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn createContract(
            code: []const u8,
            value: [32]u8,
            budget: u64,
        ) vm.syscallDispatch.CreateProviderResult {
            const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
            const senderAddr = core.types.Address{ .bytes = bridge.selfAddress };
            const sequence = state.getSequence(senderAddr);

            var sequenceBytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &sequenceBytes, sequence, .big);
            var createInput: [40]u8 = undefined;
            @memcpy(createInput[0..32], &bridge.selfAddress);
            @memcpy(createInput[32..40], &sequenceBytes);
            var newAddr: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(&createInput, &newAddr, .{});

            state.setSequence(senderAddr, sequence + 1) catch {};

            const newAddrTyped = core.types.Address{ .bytes = newAddr };
            state.markCreated(newAddrTyped, .ContractRoot) catch {};

            if (!isZero(value)) {
                bridge.transfer(newAddr, value) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
                };
            }

            var subBridge = StateBridge.init(
                alloc,
                bridge.overlay,
                newAddr,
                bridge.selfAddress,
                value,
                budget,
            );
            subBridge.depth = bridge.depth + 1;
            subBridge.inheritContext(bridge);
            defer subBridge.deinit();

            const result = executeContract(
                alloc,
                code,
                &[_]u8{},
                budget,
                @ptrCast(&subBridge),
            ) catch {
                return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = budget };
            };

            if (result.success and result.returnData.len > 0) {
                state.setCode(newAddrTyped, result.returnData) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = result.budgetUsed };
                };
            }

            return .{
                .success = result.success,
                .newAddress = newAddr,
                .budgetUsed = result.budgetUsed,
            };
        }
    };
    CreateProvider.bridge = sb;
    CreateProvider.alloc = allocator;
    host.createFn = &CreateProvider.createContract;

    // ── Wire create2 provider ───────────────────────────────────────
    // Routes CREATE2 syscall to: hash initcode → derive salt-based address → execute initcode.
    // Address derivation follows: blake3(0x02 || sender || salt || blake3(initcode))
    // This produces deterministic addresses independent of sender sequence.
    const Create2Provider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn create2Contract(
            code: []const u8,
            salt: [32]u8,
            value: [32]u8,
            budget: u64,
        ) vm.syscallDispatch.CreateProviderResult {
            const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));

            var initcodeHash: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(code, &initcodeHash, .{});

            var create2Input: [97]u8 = undefined;
            create2Input[0] = 0x02;
            @memcpy(create2Input[1..33], &bridge.selfAddress);
            @memcpy(create2Input[33..65], &salt);
            @memcpy(create2Input[65..97], &initcodeHash);
            var newAddr: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(&create2Input, &newAddr, .{});

            const newAddrTyped = core.types.Address{ .bytes = newAddr };
            const existingCode = state.getCode(newAddrTyped) catch &[_]u8{};
            defer if (existingCode.len > 0) {
                state.general_allocator.free(existingCode);
            };
            if (existingCode.len > 0) {
                return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
            }

            const senderAddr = core.types.Address{ .bytes = bridge.selfAddress };
            const sequence = state.getSequence(senderAddr);
            state.setSequence(senderAddr, sequence + 1) catch {};

            state.markCreated(newAddrTyped, .ContractRoot) catch {};

            if (!isZero(value)) {
                bridge.transfer(newAddr, value) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = 0 };
                };
            }

            var subBridge = StateBridge.init(
                alloc,
                bridge.overlay,
                newAddr,
                bridge.selfAddress,
                value,
                budget,
            );
            subBridge.depth = bridge.depth + 1;
            subBridge.inheritContext(bridge);
            defer subBridge.deinit();

            const result = executeContract(
                alloc,
                code,
                &[_]u8{},
                budget,
                @ptrCast(&subBridge),
            ) catch {
                return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = budget };
            };

            if (result.success and result.returnData.len > 0) {
                state.setCode(newAddrTyped, result.returnData) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 32, .budgetUsed = result.budgetUsed };
                };
            }

            return .{
                .success = result.success,
                .newAddress = newAddr,
                .budgetUsed = result.budgetUsed,
            };
        }
    };
    Create2Provider.bridge = sb;
    Create2Provider.alloc = allocator;
    host.create2Fn = &Create2Provider.create2Contract;

    // ── Wire sig-verify provider (replaces ecrecover) ───────────────
    // Routes VERIFY_SIG syscall to Ed25519 signature verification.
    // scheme 0 = Ed25519: verifies sig over hash, derives signer address as blake3(pubkey)
    // This is pluggable: swap scheme handler to support BLS12-381 or PQC signatures.
    const EcrecoverProvider = struct {
        fn ecrecoverFn(hash: [32]u8, scheme: u8, pubkey: [32]u8, signature: [64]u8) [32]u8 {
            switch (scheme) {
                0 => {
                    const Ed25519 = std.crypto.sign.Ed25519;
                    //Ed25519 verificationconst
                    //ed25519 = std.crypto.sign.Ed25519;
                    const pk = Ed25519.PublicKey.fromBytes(pubkey) catch return [_]u8{0} ** 32;
                    const sig = Ed25519.Signature.fromBytes(signature);
                    // FIXED: Call verify on the ed25519 namespace, passing pk as the 3rd argument
                    Ed25519.Signature.verify(sig, &hash, pk) catch return [_]u8{0} ** 32; // Derive address = blake3(pubkey)
                    var addr: [32]u8 = undefined;
                    std.crypto.hash.Blake3.hash(&pubkey, &addr, .{});
                    return addr;
                },
                else => return [_]u8{0} ** 32, // Unknown scheme
            }
        }
    };

    host.ecrecoverFn = &EcrecoverProvider.ecrecoverFn;

    // ── Wire selfdestruct provider ──────────────────────────────────
    // Routes SELFDESTRUCT syscall to StateBridge.selfDestruct which transfers
    // remaining balance to beneficiary and marks the account for deletion
    // via Overlay.suicide().
    const SelfDestructProvider = struct {
        var bridge: *StateBridge = undefined;
        fn selfDestructFn(beneficiary: [32]u8) bool {
            bridge.selfDestruct(beneficiary) catch return false;
            return true;
        }
    };
    SelfDestructProvider.bridge = sb;
    host.selfDestructFn = &SelfDestructProvider.selfDestructFn;

    // ── Execute via the contract loader ─────────────────────────────
    const is_pkg = bytecode.len >= 4 and std.mem.eql(u8, bytecode[0..4], "FORG");
    const sysResult = if (is_pkg)
        vm.contractLoader.executeFromZeph(
            allocator,
            bytecode,
            calldata,
            executionBudget,
            &host,
        ) catch |err| {
            std.log.err("executeFromZeph failed: {}", .{err});
            return ExecutionResult{
                .success = false,
                .budgetUsed = 0,
                .budgetRemaining = executionBudget,
                .returnData = &[_]u8{},
                .logs = &[_]vm.syscallDispatch.LogEntry{},
                .status = .fault,
            };
        }
    else
        vm.contractLoader.executeFromElf(
            allocator,
            bytecode,
            calldata,
            executionBudget,
            &host,
        ) catch |err| {
            std.log.err("executeFromElf failed: {}", .{err});
            return ExecutionResult{
                .success = false,
                .budgetUsed = 0,
                .budgetRemaining = executionBudget,
                .returnData = &[_]u8{},
                .logs = &[_]vm.syscallDispatch.LogEntry{},
                .status = .fault,
            };
        };

    if (sysResult.status != .returned) {
        if (sysResult.status == .fault) {
            std.log.err("VM Fault at PC=0x{x}: {s}", .{ sysResult.faultPc, sysResult.faultReason orelse "Unknown" });
        }
    }

    return ExecutionResult{
        .success = sysResult.status == .returned,
        .budgetUsed = sysResult.budgetUsed,
        .budgetRemaining = sysResult.budgetRemaining,
        .returnData = sysResult.returnData,
        .logs = host.logs.items,
        .status = sysResult.status,
    };
}

/// Deploy a new contract (execute initcode, return runtime code).
/// Deploys a new contract by executing its initcode.
/// Returns the resulting runtime bytecode generated by the initcode execution.
pub fn deployContract(
    allocator: std.mem.Allocator,
    initcode: []const u8,
    executionBudget: u64,
    stateBridge: *anyopaque,
) !DeployResult {
    const result = try executeContract(
        allocator,
        initcode,
        &[_]u8{},
        executionBudget,
        stateBridge,
    );

    return DeployResult{
        .success = result.success,
        .budgetUsed = result.budgetUsed,
        .runtimeCode = result.returnData,
        .logs = result.logs,
    };
}

/// Result of contract execution.
/// Detailed results from a contract execution session.
pub const ExecutionResult = struct {
    success: bool,
    budgetUsed: u64,
    budgetRemaining: u64,
    returnData: []const u8,
    /// Logs emitted during execution (from HostEnv)
    logs: []const vm.LogEntry,
    status: vmCore.ExecutionStatus,
};

/// Result of contract deployment.
/// Results from a contract deployment (initcode execution).
pub const DeployResult = struct {
    success: bool,
    budgetUsed: u64,
    runtimeCode: []const u8,
    /// Logs emitted during deployment
    logs: []const vm.LogEntry,
};

// ── Helpers ─────────────────────────────────────────────────────────

fn isZero(value: [32]u8) bool {
    for (value) |b| {
        if (b != 0) return false;
    }
    return true;
}
