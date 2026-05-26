// File: vm/loader/contract_loader.zig
// Contract loader for ForgeVM.
// Orchestrates: .forge parse → ELF extract → validate → sandbox setup → execute.

const std = @import("std");
const forgeLoader = @import("forge_loader.zig");
const forgeFormat = @import("forge_format.zig");
const sandbox = @import("../memory/sandbox.zig");
const executor = @import("../core/executor.zig");
const threaded_executor = @import("../core/threaded_executor.zig");
const basic_block = @import("../core/basic_block.zig");
const syscallDispatch = @import("../syscall/dispatch.zig");
const zephbinLoader = @import("zephbin_loader.zig");
const gasMeter = @import("../gas/meter.zig");
const aot = @import("../compiler/aot.zig");

pub const LoadError = error{
    // Format errors
    InvalidPackage,
    InvalidElf,
    CodeTooLarge,
    // Runtime errors
    OutOfMemory,
    ExecutionFailed,
};

/// Result of loading and executing a contract
pub const ContractResult = struct {
    status: executor.ExecutionStatus,
    gasUsed: u64,
    gasRemaining: u64,
    returnData: []const u8,
    logs: []const syscallDispatch.LogEntry,
    faultPc: u32,
    faultReason: ?[]const u8,
};

/// Load and execute a contract from raw bytecode (ELF binary).
/// This is the simpler path — no .forge packaging, just raw ELF.
pub fn executeFromElf(
    allocator: std.mem.Allocator,
    elfData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeWithMemory(allocator, &memory, elfData, calldata, gasLimit, env);
}

/// Load and execute a contract using a pre-allocated sandbox memory.
pub fn executeWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    elfData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    const isElf = elfData.len >= 4 and elfData[0] == 0x7F and elfData[1] == 'E' and elfData[2] == 'L' and elfData[3] == 'F';
    // No allocation here! We use the provided memory.
    memory.reset();

    var codeLen: usize = 0;
    var entryPoint: u32 = 0;

    if (isElf) {
        // 1. Parse ELF
        const elf = forgeLoader.parse(elfData) catch return LoadError.InvalidElf;

        // 2. Validate code size
        if (elf.code.len > sandbox.codeSize) return LoadError.CodeTooLarge;

        // Give the VM the full Code Sandbox area so that execution inside .rodata or multiple segments doesn't trip the bounds restriction.
        codeLen = sandbox.codeSize;
        entryPoint = elf.entryPoint -| elf.codeVaddr;

        // 4. Load segments directly into memory at their vaddr
        if (elf.segmentCount > 0) {
            var i: usize = 0;
            while (i < elf.segmentCount) : (i += 1) {
                const seg = elf.segments[i];
                if (seg.vaddr + seg.data.len > sandbox.memorySize) return LoadError.InvalidElf;
                if (seg.data.len > 0) {
                    @memcpy(memory.backing[seg.vaddr .. seg.vaddr + seg.data.len], seg.data);
                }
            }
        } else {
            // Fallback for flat binary
            memory.loadCode(elf.code) catch return LoadError.ExecutionFailed;
            if (elf.initData.len > 0) {
                const max_data = sandbox.heapEnd - sandbox.heapStart + 1;
                const data_len = @min(elf.initData.len, max_data);
                if (elf.dataVaddr > 0 and elf.dataVaddr + data_len <= sandbox.memorySize) {
                    @memcpy(memory.backing[elf.dataVaddr .. elf.dataVaddr + data_len], elf.initData[0..data_len]);
                } else {
                    @memcpy(memory.backing[sandbox.heapStart .. sandbox.heapStart + data_len], elf.initData[0..data_len]);
                }
            }
        }
    } else {
        // Raw RISC-V bytecode execution (EVM style)
        if (elfData.len > sandbox.codeSize) return LoadError.CodeTooLarge;
        memory.loadCode(elfData) catch return LoadError.ExecutionFailed;
        codeLen = elfData.len;
        entryPoint = 0;
    }

    // 6. Load calldata
    if (calldata.len > 0) {
        memory.loadCalldata(calldata) catch return LoadError.ExecutionFailed;
    }

    // 7. Create syscall handler
    const handler = syscallDispatch.createHandler(env);

    // 8. Initialize VM
    // 8. Initialize VM
    var vm = executor.ForgeVM.init(
        memory,
        @intCast(codeLen),
        gasLimit,
        handler,
    );

    // Wire hostCtx so the thread-safe syscall dispatcher can retrieve HostEnv
    // without going through a shared static pointer.
    vm.hostCtx = env;

    // 9. Set entry point
    vm.pc = entryPoint;

    // 9b. Set actual calldata length
    vm.calldataLen = @intCast(calldata.len);

    // 10. Execute
    const result = vm.execute();

    // 11. Extract return data
    var returnData: []const u8 = &[_]u8{};
    if (result.returnDataLen > 0) {
        const rawReturn = memory.getReturnData(
            result.returnDataOffset,
            result.returnDataLen,
        ) catch &[_]u8{};
        if (rawReturn.len > 0) {
            returnData = allocator.dupe(u8, rawReturn) catch &[_]u8{};
        }
    }

    return .{
        .status = result.status,
        .gasUsed = result.gasUsed,
        .gasRemaining = result.gasRemaining,
        .returnData = returnData,
        .logs = env.logs.items,
        .faultPc = result.faultPc,
        .faultReason = result.faultReason,
    };
}

/// Load and execute a contract from a .fozbin or .forge package.
///
/// Detection order:
///   1. ZephBin v1 (magic "FORG", version=1) — emitted by the Forge compiler (codegen.zig)
///   2. ForgeHeader v2 (magic "FORG", version=2) — VM internal format
///   3. Falls back to executeFromElf for bare ELF or raw bytecode
pub fn executeFromZeph(
    allocator: std.mem.Allocator,
    forgeData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    if (env.vm_pool) |pool_ptr| {
        const pool: *@import("../vm_pool.zig").VMPool = @ptrCast(@alignCast(pool_ptr));
        const mem = pool.acquire() orelse {
            var legacy_mem = try sandbox.SandboxMemory.init(allocator);
            defer legacy_mem.deinit();
            return executeFromZephWithMemory(allocator, &legacy_mem, forgeData, calldata, gasLimit, env);
        };
        defer pool.release(mem);
        return executeFromZephWithMemory(allocator, mem, forgeData, calldata, gasLimit, env);
    }
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeFromZephWithMemory(allocator, &memory, forgeData, calldata, gasLimit, env);
}

/// Load and execute a contract from a .fozbin package using pre-allocated memory.
pub fn executeFromZephWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    forgeData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    if (zephbinLoader.isZephBin(forgeData)) {
        return executeFromZephBinWithMemory(allocator, memory, forgeData, calldata, gasLimit, env);
    }

    const pkg = forgeFormat.parse(forgeData) catch return LoadError.InvalidPackage;

    var computedHash: [32]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(pkg.bytecode);
    hasher.final(&computedHash);
    if (!std.mem.eql(u8, &computedHash, &pkg.header.code_hash)) {
        return LoadError.InvalidPackage;
    }

    const isElf = pkg.bytecode.len >= 4 and pkg.bytecode[0] == 0x7F and pkg.bytecode[1] == 'E' and pkg.bytecode[2] == 'L' and pkg.bytecode[3] == 'F';
    if (!isElf) return LoadError.InvalidElf;

    return executeWithMemory(allocator, memory, pkg.bytecode, calldata, gasLimit, env);
}

/// Execute a contract from a ZephBin v1 package (compiler output).
/// Selects the first action by default (selector = 0 = constructor, else action[0]).
/// Pass `calldata[0..4]` as the 4-byte selector to dispatch a specific action.
pub fn executeFromZephBin(
    allocator: std.mem.Allocator,
    binData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeFromZephBinWithMemory(allocator, &memory, binData, calldata, gasLimit, env);
}

fn aotSyscallHandler(vm_opaque: ?*anyopaque, syscall_id: u32) callconv(.c) i32 {
    _ = syscall_id;
    const vm: *executor.ForgeVM = @ptrCast(@alignCast(vm_opaque orelse return 5));
    if (vm.syscallHandler) |handler| {
        handler(vm) catch |err| {
            return switch (err) {
                error.ReturnData => @as(i32, 1),
                error.Revert => @as(i32, 2),
                error.SelfDestruct => @as(i32, 3),
                error.OutOfGas => @as(i32, 4),
                else => @as(i32, 5),
            };
        };
        return 0; // success
    }
    return 5; // fault
}

const AotLibEntry = struct {
    hash: [32]u8,
    lib: std.DynLib,
};

const AotFuncEntry = struct {
    hash: [32]u8,
    selector: u32,
    func: *const fn (*const aot.AotContext) callconv(.c) void,
};

var aot_cache_rwlock: std.Thread.RwLock = .{};
var aot_cache_entries: std.ArrayListUnmanaged(AotLibEntry) = .empty;
var aot_func_entries: std.ArrayListUnmanaged(AotFuncEntry) = .empty;

var no_aot_cached: bool = false;
var no_aot_initialized: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn isNoAotEnabled(allocator: std.mem.Allocator) bool {
    if (no_aot_initialized.load(.acquire)) {
        return no_aot_cached;
    }
    
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();
    
    if (no_aot_initialized.load(.unordered)) {
        return no_aot_cached;
    }
    
    var is_no_aot = false;
    if (std.process.getEnvVarOwned(allocator, "FORGE_NO_AOT")) |env_val| {
        defer allocator.free(env_val);
        if (std.mem.eql(u8, env_val, "1")) {
            is_no_aot = true;
        }
    } else |_| {}
    no_aot_cached = is_no_aot;
    no_aot_initialized.store(true, .release);
    return is_no_aot;
}

fn getCachedLib(hash: [32]u8) ?std.DynLib {
    aot_cache_rwlock.lockShared();
    defer aot_cache_rwlock.unlockShared();

    for (aot_cache_entries.items) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) {
            return entry.lib;
        }
    }
    return null;
}

fn putCachedLib(allocator: std.mem.Allocator, hash: [32]u8, lib: std.DynLib) !void {
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();

    for (aot_cache_entries.items) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) {
            return;
        }
    }

    try aot_cache_entries.append(allocator, .{ .hash = hash, .lib = lib });
}

fn getCachedFunc(hash: [32]u8, selector: u32) ?*const fn (*const aot.AotContext) callconv(.c) void {
    aot_cache_rwlock.lockShared();
    defer aot_cache_rwlock.unlockShared();

    for (aot_func_entries.items) |entry| {
        if (entry.selector == selector and std.mem.eql(u8, &entry.hash, &hash)) {
            return entry.func;
        }
    }
    return null;
}


fn putCachedFunc(allocator: std.mem.Allocator, hash: [32]u8, selector: u32, func: *const fn (*const aot.AotContext) callconv(.c) void) !void {
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();

    for (aot_func_entries.items) |entry| {
        if (entry.selector == selector and std.mem.eql(u8, &entry.hash, &hash)) {
            return;
        }
    }

    try aot_func_entries.append(allocator, .{ .hash = hash, .selector = selector, .func = func });
}

pub fn deinitAotCache(allocator: std.mem.Allocator) void {
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();

    for (aot_cache_entries.items) |*entry| {
        entry.lib.close();
    }
    aot_cache_entries.deinit(allocator);
    aot_func_entries.deinit(allocator);

    if (last_parsed_pkg) |*old_pkg| {
        old_pkg.deinit();
        last_parsed_pkg = null;
    }
    last_parsed_bin_ptr = null;
    last_parsed_bin_len = 0;
}

pub fn preWarmAot(allocator: std.mem.Allocator, binData: []const u8) !void {
    if (!zephbinLoader.isZephBin(binData)) return;

    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(binData, &hash, .{});

    // 1. Check/load dynamic library
    var lib: std.DynLib = undefined;
    var cached = false;

    aot_cache_rwlock.lockShared();
    for (aot_cache_entries.items) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) {
            lib = entry.lib;
            cached = true;
            break;
        }
    }
    aot_cache_rwlock.unlockShared();

    if (!cached) {
        // Compile the entire package
        const lib_path = try aot.compileAot(allocator, binData);
        defer allocator.free(lib_path);

        const abs_lib_path = try std.fs.cwd().realpathAlloc(allocator, lib_path);
        defer allocator.free(abs_lib_path);

        lib = try std.DynLib.open(abs_lib_path);
        try putCachedLib(allocator, hash, lib);
    }

    // 2. Parse the package to get the list of actions/selectors
    const pkg = try zephbinLoader.parse(allocator, binData);
    defer {
        var mutable_pkg = pkg;
        mutable_pkg.deinit();
    }

    // 3. Lookup and cache all action functions
    for (pkg.actions) |action| {
        var is_func_cached = false;
        aot_cache_rwlock.lockShared();
        for (aot_func_entries.items) |entry| {
            if (entry.selector == action.selector and std.mem.eql(u8, &entry.hash, &hash)) {
                is_func_cached = true;
                break;
            }
        }
        aot_cache_rwlock.unlockShared();

        if (!is_func_cached) {
            var sym_name_buf: [64]u8 = undefined;
            const sym_name = try std.fmt.bufPrintZ(&sym_name_buf, "action_{x:0>8}", .{action.selector});
            const action_fn = lib.lookup(*const fn (*const aot.AotContext) callconv(.c) void, sym_name) orelse continue;
            try putCachedFunc(allocator, hash, action.selector, action_fn);
        }
    }
}


threadlocal var last_action_fn: ?*const fn (*const aot.AotContext) callconv(.c) void = null;
threadlocal var last_action_selector: u32 = 0;
threadlocal var last_action_bin_ptr: ?[*]const u8 = null;
threadlocal var last_action_bin_len: usize = 0;

threadlocal var last_parsed_bin_ptr: ?[*]const u8 = null;
threadlocal var last_parsed_bin_len: usize = 0;
threadlocal var last_parsed_pkg: ?zephbinLoader.ZephBinPackage = null;

fn compileAndRunAot(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    binData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
    pkg: *const zephbinLoader.ZephBinPackage,
    action: *const zephbinLoader.ZephAction,
) !ContractResult {
    var action_fn: *const fn (*const aot.AotContext) callconv(.c) void = undefined;
    if (last_action_bin_ptr == binData.ptr and last_action_bin_len == binData.len and last_action_selector == action.selector and last_action_fn != null) {
        action_fn = last_action_fn.?;
    } else {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(binData, &hash, .{});

        if (getCachedFunc(hash, action.selector)) |f| {
            action_fn = f;
        } else {
            std.debug.print("[AOT Cache Miss] hash[0]={d}, selector={x}\n", .{ hash[0], action.selector });
            var lib: std.DynLib = undefined;
            if (getCachedLib(hash)) |cached_lib| {
                std.debug.print("[AOT Cache Lib Hit]\n", .{});
                lib = cached_lib;
            } else {
                std.debug.print("[AOT Cache Lib Miss] Compiling...\n", .{});
                const lib_path = try aot.compileAot(allocator, binData);
                defer allocator.free(lib_path);

                const abs_lib_path = try std.fs.cwd().realpathAlloc(allocator, lib_path);
                defer allocator.free(abs_lib_path);

                lib = try std.DynLib.open(abs_lib_path);
                try putCachedLib(allocator, hash, lib);
            }

            var sym_name_buf: [64]u8 = undefined;
            const sym_name = try std.fmt.bufPrintZ(&sym_name_buf, "action_{x:0>8}", .{action.selector});
            action_fn = lib.lookup(*const fn (*const aot.AotContext) callconv(.c) void, sym_name) orelse return error.SymbolNotFound;
            try putCachedFunc(allocator, hash, action.selector, action_fn);
        }

        // Cache the lookup results thread-locally
        last_action_bin_ptr = binData.ptr;
        last_action_bin_len = binData.len;
        last_action_selector = action.selector;
        last_action_fn = action_fn;
    }


    // Load data section (string literals etc.) into heap at HEAP_START
    if (pkg.dataSection.len > 0) {
        const max_ds = sandbox.heapEnd - sandbox.heapStart + 1;
        const ds_len = @min(pkg.dataSection.len, max_ds);
        @memcpy(memory.backing[sandbox.heapStart .. sandbox.heapStart + ds_len], pkg.dataSection[0..ds_len]);
    }

    // Load calldata (skip the 4-byte selector if present)
    const actualCalldata = if (calldata.len >= 4) calldata[4..] else calldata;
    if (actualCalldata.len > 0) {
        try memory.loadCalldata(actualCalldata);
    }

    const handler = syscallDispatch.createHandler(env);

    const stubOffset: u32 = @intCast(action.code.len);
    const stubEnd = stubOffset + 8;
    if (stubEnd > sandbox.codeSize) return LoadError.CodeTooLarge;

    // Load the action bytecode into the code region so that code-relative data
    // references (e.g. error message bytes at small offsets) are readable.
    memory.loadCode(action.code) catch return LoadError.CodeTooLarge;

    // Write exit stub after the action code
    const addiReturn: u32 = 0x05000513;
    const ecall: u32 = 0x00000073;
    std.mem.writeInt(u32, memory.backing[stubOffset..][0..4], addiReturn, .little);
    std.mem.writeInt(u32, memory.backing[stubOffset + 4 ..][0..4], ecall, .little);

    var vm = executor.ForgeVM.init(
        memory,
        stubEnd,
        gasLimit,
        handler,
    );
    vm.hostCtx = env;
    vm.calldataLen = @intCast(actualCalldata.len);
    vm.regs[3] = sandbox.heapStart; // GP
    vm.regs[1] = stubOffset;        // RA

    var pc: u32 = 0;
    var status_val: u32 = 0;

    const ctx = aot.AotContext{
        .regs = &vm.regs,
        .pc = &pc,
        .memory_backing = memory.backing.ptr,
        .memory_size = @intCast(memory.backing.len),
        .gas_limit = &vm.gas.limit,
        .gas_used = &vm.gas.used,
        .status = &status_val,
        .syscall_handler = aotSyscallHandler,
        .vm_ctx = &vm,
        .dirty_tracker = &memory.dirty_tracker,
    };

    // Execute the action natively
    action_fn(&ctx);

    // Sync PC and status back to VM structure (gas.used is already synced via pointer)
    vm.pc = pc;
    vm.status = std.meta.intToEnum(executor.ExecutionStatus, status_val) catch .fault;

    // Extract return data — include both returned and reverted (matches interpreter behavior)
    var returnData: []const u8 = &[_]u8{};
    if (vm.returnDataLen > 0) {
        const raw = memory.getReturnData(
            vm.returnDataOffset,
            vm.returnDataLen,
        ) catch &[_]u8{};
        if (raw.len > 0) {
            returnData = try allocator.dupe(u8, raw);
        }
    }

    return ContractResult{
        .status = vm.status,
        .gasUsed = vm.gas.used,
        .gasRemaining = vm.gas.remaining(),
        .returnData = returnData,
        .logs = env.logs.items,
        .faultPc = vm.pc,
        .faultReason = vm.faultReason,
    };
}

/// Execute a contract from a ZephBin v1 package using pre-allocated memory.
pub fn executeFromZephBinWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    binData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    // No allocation here!
    memory.reset();

    // 1. Parse ZephBin (with thread-local caching to eliminate heap contention)
    var pkg: zephbinLoader.ZephBinPackage = undefined;
    if (last_parsed_bin_ptr == binData.ptr and last_parsed_bin_len == binData.len and last_parsed_pkg != null) {
        pkg = last_parsed_pkg.?;
    } else {
        pkg = try zephbinLoader.parse(allocator, binData);
        if (last_parsed_pkg) |*old_pkg| {
            old_pkg.deinit();
        }
        last_parsed_bin_ptr = binData.ptr;
        last_parsed_bin_len = binData.len;
        last_parsed_pkg = pkg;
    }

    // 2. Pick action: use first 4 bytes of calldata as selector if present
    const selector: u32 = if (calldata.len >= 4)
        std.mem.readInt(u32, calldata[0..4], .little)
    else
        0;
    const action = pkg.pickAction(selector) orelse return LoadError.CodeTooLarge;
    if (action.code.len == 0) return LoadError.CodeTooLarge;

    const use_aot = !isNoAotEnabled(allocator);

    if (use_aot) {
        if (compileAndRunAot(allocator, memory, binData, calldata, gasLimit, env, &pkg, action)) |aot_res| {
            return aot_res;
        } else |err| {
            std.debug.print("AOT compilation/execution failed: {}, falling back to interpreter\n", .{err});
        }
    }

    // Load action bytecode into code region
    memory.loadCode(action.code) catch return LoadError.CodeTooLarge;

    // ── Exit stub ─────────────────────────────────────────────────────────
    // The Forge compiler epilogue ends with JALR zero, ra, 0  (return through ra).
    // The VM initialises ra (x1) = 0, so without a stub the function returns to
    // PC=0 and loops forever until gas is exhausted.
    //
    // Fix: write two instructions immediately after the action code and set ra
    // to that address before execution.  When the epilogue returns, it hits:
    //   ADDI a0, zero, 0x50   ; a0 = RETURN_DATA syscall ID
    //   ECALL                 ; triggers clean halt with status=returned
    //
    // The stub is 8 bytes; verify it fits in the code region.
    const actionCodeLen = action.code.len;
    const stubOffset: u32 = @intCast(actionCodeLen);
    const stubEnd: u32 = stubOffset + 8;
    if (stubEnd > sandbox.codeSize) return LoadError.CodeTooLarge;

    // ADDI a0, zero, 0x50  (opcode=0x13, rd=10, funct3=0, rs1=0, imm=0x50)
    const addiReturn: u32 = 0x05000513;
    // ECALL
    const ecall: u32 = 0x00000073;

    std.mem.writeInt(u32, memory.backing[stubOffset..][0..4], addiReturn, .little);
    std.mem.writeInt(u32, memory.backing[stubOffset + 4 ..][0..4], ecall, .little);

    // Load data section (string literals etc.) into heap at HEAP_START
    if (pkg.dataSection.len > 0) {
        const max_ds = sandbox.heapEnd - sandbox.heapStart + 1;
        const ds_len = @min(pkg.dataSection.len, max_ds);
        @memcpy(memory.backing[sandbox.heapStart .. sandbox.heapStart + ds_len], pkg.dataSection[0..ds_len]);
    }

    // Load calldata (skip the 4-byte selector if present)
    const actualCalldata = if (calldata.len >= 4) calldata[4..] else calldata;
    if (actualCalldata.len > 0) {
        memory.loadCalldata(actualCalldata) catch return LoadError.ExecutionFailed;
    }

    // 4. Set up host env
    const handler = syscallDispatch.createHandler(env);

    var vm = executor.ForgeVM.init(
        memory,
        stubEnd, // codeLen includes the exit stub
        gasLimit,
        handler,
    );
    vm.hostCtx = env;
    vm.calldataLen = @intCast(actualCalldata.len);

    // Set GP (x3) = HEAP_START so gp-relative string loads work correctly.
    // The Forge compiler emits: dest = gp + string_offset
    vm.regs[3] = sandbox.heapStart;

    // Set RA (x1) = stubOffset so the compiler epilogue's JALR zero, ra, 0
    // lands on the exit stub instead of looping back to PC=0.
    vm.regs[1] = stubOffset;

    // 5. Execute (threaded if VMPool is available)
    const result = if (env.vm_pool) |pool_ptr| blk: {
        const pool: *@import("../vm_pool.zig").VMPool = @ptrCast(@alignCast(pool_ptr));
        const code_slice = memory.backing[0..stubEnd];
        var code_hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(code_slice, &code_hash, .{});

        if (pool.getDecodedCode(code_hash)) |cached| {
            break :blk threaded_executor.executeThreaded(&vm, cached.decoded_insns, null);
        }

        const decoded = try threaded_executor.preDecodeProgram(allocator, code_slice, stubEnd);
        const insn_count: u32 = @intCast(decoded.len);

        var analysis = try basic_block.analyze(allocator, code_slice, stubEnd);
        defer analysis.deinit();
        basic_block.resolveBranchTargets(&analysis, code_slice);

        pool.cacheDecodedCode(code_hash, decoded, insn_count, stubEnd);
        break :blk threaded_executor.executeThreaded(&vm, decoded, &analysis);
    } else vm.execute();

    // 6. Extract return data
    var returnData: []const u8 = &[_]u8{};
    if (result.returnDataLen > 0) {
        const raw = memory.getReturnData(
            result.returnDataOffset,
            result.returnDataLen,
        ) catch &[_]u8{};
        if (raw.len > 0) {
            returnData = allocator.dupe(u8, raw) catch &[_]u8{};
        }
    }

    return ContractResult{
        .status = result.status,
        .gasUsed = result.gasUsed,
        .gasRemaining = result.gasRemaining,
        .returnData = returnData,
        .logs = env.logs.items,
        .faultPc = result.faultPc,
        .faultReason = result.faultReason,
    };
}

/// Validate a bytecode blob (ELF) without executing it.
/// Returns true if the bytecode passes all validation checks.
pub fn validate(elfData: []const u8) bool {
    const isElf = elfData.len >= 4 and elfData[0] == 0x7F and elfData[1] == 'E' and elfData[2] == 'L' and elfData[3] == 'F';

    var codeToScan: []const u8 = undefined;

    if (isElf) {
        // 1. Must be a valid ELF
        const elf = forgeLoader.parse(elfData) catch return false;

        // 2. Code must fit in sandbox
        if (elf.code.len > sandbox.codeSize) return false;
        codeToScan = elf.code;
    } else {
        // Raw bytecode
        if (elfData.len > sandbox.codeSize) return false;
        codeToScan = elfData;
    }

    if (codeToScan.len == 0) return false;
    // Max deployed code size = CODE_SIZE (128 KB) for FORGE contracts.
    // (EVM's 24 576 B EIP-170 limit does NOT apply to the FORGE VM.)
    if (codeToScan.len > sandbox.codeSize) return false;

    // 3. Code must be 4-byte aligned (RISC-V instructions are 32-bit)
    if (codeToScan.len & 3 != 0) return false;

    // 4. Scan for basic instruction validity
    var i: usize = 0;
    while (i < codeToScan.len) : (i += 4) {
        const word = std.mem.readInt(u32, codeToScan[i..][0..4], .little);
        const opcode: u7 = @truncate(word & 0x7F);

        // Check opcode is a known RV64IM opcode (includes 64-bit word ops)
        const decoder = @import("../core/decoder.zig");
        switch (opcode) {
            decoder.Opcode.OP, // R-type 64-bit (ADD, SUB, MUL…)
            decoder.Opcode.OP_32, // R-type 32-bit word ops (ADDW, SUBW, MULW…)
            decoder.Opcode.OP_IMM, // I-type imm 64-bit (ADDI, SLTI…)
            decoder.Opcode.OP_IMM_32, // I-type imm 32-bit word ops (ADDIW, SLLIW…)
            decoder.Opcode.LOAD,
            decoder.Opcode.STORE,
            decoder.Opcode.BRANCH,
            decoder.Opcode.JAL,
            decoder.Opcode.JALR,
            decoder.Opcode.LUI,
            decoder.Opcode.AUIPC,
            decoder.Opcode.SYSTEM,
            // Forge compiler ZEPH custom instructions
            decoder.Opcode.CUSTOM_0,
            decoder.Opcode.CUSTOM_1,
            decoder.Opcode.CUSTOM_2,
            decoder.Opcode.CUSTOM_3,
            => {},
            else => return false, // Unknown opcode
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "validate rejects empty bytecode" {
    try testing.expect(!validate(&[_]u8{}));
}

test "validate rejects misaligned code" {
    // 3 bytes — not 4-byte aligned
    const badElf = [_]u8{ 0x13, 0x00, 0x00 };
    try testing.expect(!validate(&badElf));
}

test "executeFromZeph with built package" {
    // Build a minimal .forge package containing a simple EBREAK (halt) instruction
    // First, create a minimal ELF-like structure with just an EBREAK
    // For now we test the .forge parsing path
    const ebreak: u32 = 0x00100073;
    const raw_code = std.mem.asBytes(&ebreak);

    // Build .forge package
    const pkg = try forgeFormat.build(testing.allocator, raw_code, .{});
    defer testing.allocator.free(pkg);

    // This will fail at ELF parse (raw_code isn't a valid ELF) but tests the flow
    var env = syscallDispatch.HostEnv.init(testing.allocator);
    defer env.deinit();

    const result = executeFromZeph(testing.allocator, pkg, &[_]u8{}, 100_000, &env);
    // Expect InvalidElf since raw code bytes aren't a valid ELF binary
    try testing.expectError(LoadError.InvalidElf, result);
}
