// File: vm/loader/contract_loader.zig
// Contract loader for ForgeVM.
// Orchestrates: .forge parse → ELF extract → validate → sandbox setup → execute.

const std = @import("std");
const forgeLoader = @import("forge_loader.zig");
const forgeFormat = @import("forge_format.zig");
const sandbox = @import("../memory/sandbox.zig");
const executor = @import("../core/executor.zig");
const syscallDispatch = @import("../syscall/dispatch.zig");
const zephbinLoader = @import("zephbin_loader.zig");
const gasMeter = @import("../gas/meter.zig");

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
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(pkg.bytecode);
    hasher.final(&computedHash);
    if (!std.mem.eql(u8, &computedHash, &pkg.header.code_hash)) {
        return LoadError.InvalidPackage;
    }
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

    // 1. Parse ZephBin
    var pkg = try zephbinLoader.parse(allocator, binData);
    defer pkg.deinit();

    // 2. Pick action: use first 4 bytes of calldata as selector if present
    const selector: u32 = if (calldata.len >= 4)
        std.mem.readInt(u32, calldata[0..4], .little)
    else
        0;

    const action = pkg.pickAction(selector) orelse return LoadError.CodeTooLarge; // no actions

    if (action.code.len == 0) return LoadError.CodeTooLarge;

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

    // 5. Execute
    const result = vm.execute();

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
