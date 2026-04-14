// File: vm/loader/contract_loader.zig
// Contract loader for ForgeVM.
// Orchestrates: .forge parse → ELF extract → validate → sandbox setup → execute.

const std = @import("std");
const forge_loader = @import("forge_loader.zig");
const forge_format = @import("forge_format.zig");
const sandbox = @import("../memory/sandbox.zig");
const executor = @import("../core/executor.zig");
const syscall_dispatch = @import("../syscall/dispatch.zig");
const zephbin_loader = @import("zephbin_loader.zig");
const gas_meter = @import("../gas/meter.zig");

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
    gas_used: u64,
    gas_remaining: u64,
    return_data: []const u8,
    logs: []const syscall_dispatch.LogEntry,
    fault_pc: u32,
    fault_reason: ?[]const u8,
};

/// Load and execute a contract from raw bytecode (ELF binary).
/// This is the simpler path — no .forge packaging, just raw ELF.
pub fn executeFromElf(
    allocator: std.mem.Allocator,
    elf_data: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    env: *syscall_dispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeWithMemory(allocator, &memory, elf_data, calldata, gas_limit, env);
}

/// Load and execute a contract using a pre-allocated sandbox memory.
pub fn executeWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    elf_data: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    env: *syscall_dispatch.HostEnv,
) !ContractResult {
    const is_elf = elf_data.len >= 4 and elf_data[0] == 0x7F and elf_data[1] == 'E' and elf_data[2] == 'L' and elf_data[3] == 'F';
    // No allocation here! We use the provided memory.
    memory.reset();

    var code_len: usize = 0;
    var entry_point: u32 = 0;

    if (is_elf) {
        // 1. Parse ELF
        const elf = forge_loader.parse(elf_data) catch return LoadError.InvalidElf;

        // 2. Validate code size
        if (elf.code.len > sandbox.CODE_SIZE) return LoadError.CodeTooLarge;

        // Give the VM the full Code Sandbox area so that execution inside .rodata or multiple segments doesn't trip the bounds restriction.
        code_len = sandbox.CODE_SIZE;
        entry_point = elf.entry_point -| elf.code_vaddr;

        // 4. Load segments directly into memory at their vaddr
        if (elf.segment_count > 0) {
            var i: usize = 0;
            while (i < elf.segment_count) : (i += 1) {
                const seg = elf.segments[i];
                if (seg.vaddr + seg.data.len > sandbox.MEMORY_SIZE) return LoadError.InvalidElf;
                if (seg.data.len > 0) {
                    @memcpy(memory.backing[seg.vaddr .. seg.vaddr + seg.data.len], seg.data);
                }
            }
        } else {
            // Fallback for flat binary
            memory.loadCode(elf.code) catch return LoadError.ExecutionFailed;
            if (elf.init_data.len > 0) {
                const max_data = sandbox.HEAP_END - sandbox.HEAP_START + 1;
                const data_len = @min(elf.init_data.len, max_data);
                if (elf.data_vaddr > 0 and elf.data_vaddr + data_len <= sandbox.MEMORY_SIZE) {
                    @memcpy(memory.backing[elf.data_vaddr .. elf.data_vaddr + data_len], elf.init_data[0..data_len]);
                } else {
                    @memcpy(memory.backing[sandbox.HEAP_START .. sandbox.HEAP_START + data_len], elf.init_data[0..data_len]);
                }
            }
        }
    } else {
        // Raw RISC-V bytecode execution (EVM style)
        if (elf_data.len > sandbox.CODE_SIZE) return LoadError.CodeTooLarge;
        memory.loadCode(elf_data) catch return LoadError.ExecutionFailed;
        code_len = elf_data.len;
        entry_point = 0;
    }

    // 6. Load calldata
    if (calldata.len > 0) {
        memory.loadCalldata(calldata) catch return LoadError.ExecutionFailed;
    }

    // 7. Create syscall handler
    const handler = syscall_dispatch.createHandler(env);

    // 8. Initialize VM
    // 8. Initialize VM
    var vm = executor.ForgeVM.init(
        memory,
        @intCast(code_len),
        gas_limit,
        handler,
    );

    // Wire host_ctx so the thread-safe syscall dispatcher can retrieve HostEnv
    // without going through a shared static pointer.
    vm.host_ctx = env;

    // 9. Set entry point
    vm.pc = entry_point;

    // 9b. Set actual calldata length
    vm.calldata_len = @intCast(calldata.len);

    // 10. Execute
    const result = vm.execute();

    // 11. Extract return data
    var return_data: []const u8 = &[_]u8{};
    if (result.return_data_len > 0) {
        const raw_return = memory.getReturnData(
            result.return_data_offset,
            result.return_data_len,
        ) catch &[_]u8{};
        if (raw_return.len > 0) {
            return_data = allocator.dupe(u8, raw_return) catch &[_]u8{};
        }
    }

    return .{
        .status = result.status,
        .gas_used = result.gas_used,
        .gas_remaining = result.gas_remaining,
        .return_data = return_data,
        .logs = env.logs.items,
        .fault_pc = result.fault_pc,
        .fault_reason = result.fault_reason,
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
    forge_data: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    env: *syscall_dispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeFromZephWithMemory(allocator, &memory, forge_data, calldata, gas_limit, env);
}

/// Load and execute a contract from a .fozbin package using pre-allocated memory.
pub fn executeFromZephWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    forge_data: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    env: *syscall_dispatch.HostEnv,
) !ContractResult {
    if (zephbin_loader.isZephBin(forge_data)) {
        return executeFromZephBinWithMemory(allocator, memory, forge_data, calldata, gas_limit, env);
    }

    const pkg = forge_format.parse(forge_data) catch return LoadError.InvalidPackage;

    var computed_hash: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(pkg.bytecode);
    hasher.final(&computed_hash);
    if (!std.mem.eql(u8, &computed_hash, &pkg.header.code_hash)) {
        return LoadError.InvalidPackage;
    }
    return executeWithMemory(allocator, memory, pkg.bytecode, calldata, gas_limit, env);
}

/// Execute a contract from a ZephBin v1 package (compiler output).
/// Selects the first action by default (selector = 0 = constructor, else action[0]).
/// Pass `calldata[0..4]` as the 4-byte selector to dispatch a specific action.
pub fn executeFromZephBin(
    allocator: std.mem.Allocator,
    bin_data: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    env: *syscall_dispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeFromZephBinWithMemory(allocator, &memory, bin_data, calldata, gas_limit, env);
}

/// Execute a contract from a ZephBin v1 package using pre-allocated memory.
pub fn executeFromZephBinWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    bin_data: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    env: *syscall_dispatch.HostEnv,
) !ContractResult {
    // No allocation here!
    memory.reset();

    // 1. Parse ZephBin
    var pkg = try zephbin_loader.parse(allocator, bin_data);
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
    const action_code_len = action.code.len;
    const stub_offset: u32 = @intCast(action_code_len);
    const stub_end:    u32 = stub_offset + 8;
    if (stub_end > sandbox.CODE_SIZE) return LoadError.CodeTooLarge;

    // ADDI a0, zero, 0x50  (opcode=0x13, rd=10, funct3=0, rs1=0, imm=0x50)
    const addi_return: u32 = 0x05000513;
    // ECALL
    const ecall: u32 = 0x00000073;

    std.mem.writeInt(u32, memory.backing[stub_offset..][0..4], addi_return, .little);
    std.mem.writeInt(u32, memory.backing[stub_offset + 4..][0..4], ecall, .little);

    // Load data section (string literals etc.) into heap at HEAP_START
    if (pkg.data_section.len > 0) {
        const max_ds = sandbox.HEAP_END - sandbox.HEAP_START + 1;
        const ds_len = @min(pkg.data_section.len, max_ds);
        @memcpy(memory.backing[sandbox.HEAP_START .. sandbox.HEAP_START + ds_len],
                pkg.data_section[0..ds_len]);
    }

    // Load calldata (skip the 4-byte selector if present)
    const actual_calldata = if (calldata.len >= 4) calldata[4..] else calldata;
    if (actual_calldata.len > 0) {
        memory.loadCalldata(actual_calldata) catch return LoadError.ExecutionFailed;
    }

    // 4. Set up host env
    const handler = syscall_dispatch.createHandler(env);

    var vm = executor.ForgeVM.init(
        memory,
        stub_end,          // code_len includes the exit stub
        gas_limit,
        handler,
    );
    vm.host_ctx = env;
    vm.calldata_len = @intCast(actual_calldata.len);

    // Set GP (x3) = HEAP_START so gp-relative string loads work correctly.
    // The Forge compiler emits: dest = gp + string_offset
    vm.regs[3] = sandbox.HEAP_START;

    // Set RA (x1) = stub_offset so the compiler epilogue's JALR zero, ra, 0
    // lands on the exit stub instead of looping back to PC=0.
    vm.regs[1] = stub_offset;

    // 5. Execute
    const result = vm.execute();

    // 6. Extract return data
    var return_data: []const u8 = &[_]u8{};
    if (result.return_data_len > 0) {
        const raw = memory.getReturnData(
            result.return_data_offset, result.return_data_len,
        ) catch &[_]u8{};
        if (raw.len > 0) {
            return_data = allocator.dupe(u8, raw) catch &[_]u8{};
        }
    }

    return ContractResult{
        .status        = result.status,
        .gas_used      = result.gas_used,
        .gas_remaining = result.gas_remaining,
        .return_data   = return_data,
        .logs          = env.logs.items,
        .fault_pc      = result.fault_pc,
        .fault_reason  = result.fault_reason,
    };
}

/// Validate a bytecode blob (ELF) without executing it.
/// Returns true if the bytecode passes all validation checks.
pub fn validate(elf_data: []const u8) bool {
    const is_elf = elf_data.len >= 4 and elf_data[0] == 0x7F and elf_data[1] == 'E' and elf_data[2] == 'L' and elf_data[3] == 'F';

    var code_to_scan: []const u8 = undefined;

    if (is_elf) {
        // 1. Must be a valid ELF
        const elf = forge_loader.parse(elf_data) catch return false;

        // 2. Code must fit in sandbox
        if (elf.code.len > sandbox.CODE_SIZE) return false;
        code_to_scan = elf.code;
    } else {
        // Raw bytecode
        if (elf_data.len > sandbox.CODE_SIZE) return false;
        code_to_scan = elf_data;
    }

    if (code_to_scan.len == 0) return false;
    // Max deployed code size = CODE_SIZE (128 KB) for FORGE contracts.
    // (EVM's 24 576 B EIP-170 limit does NOT apply to the FORGE VM.)
    if (code_to_scan.len > sandbox.CODE_SIZE) return false;

    // 3. Code must be 4-byte aligned (RISC-V instructions are 32-bit)
    if (code_to_scan.len & 3 != 0) return false;

    // 4. Scan for basic instruction validity
    var i: usize = 0;
    while (i < code_to_scan.len) : (i += 4) {
        const word = std.mem.readInt(u32, code_to_scan[i..][0..4], .little);
        const opcode: u7 = @truncate(word & 0x7F);

        // Check opcode is a known RV64IM opcode (includes 64-bit word ops)
        const decoder = @import("../core/decoder.zig");
        switch (opcode) {
            decoder.Opcode.OP,         // R-type 64-bit (ADD, SUB, MUL…)
            decoder.Opcode.OP_32,      // R-type 32-bit word ops (ADDW, SUBW, MULW…)
            decoder.Opcode.OP_IMM,     // I-type imm 64-bit (ADDI, SLTI…)
            decoder.Opcode.OP_IMM_32,  // I-type imm 32-bit word ops (ADDIW, SLLIW…)
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
    const bad_elf = [_]u8{ 0x13, 0x00, 0x00 };
    try testing.expect(!validate(&bad_elf));
}

test "executeFromZeph with built package" {
    // Build a minimal .forge package containing a simple EBREAK (halt) instruction
    // First, create a minimal ELF-like structure with just an EBREAK
    // For now we test the .forge parsing path
    const ebreak: u32 = 0x00100073;
    const raw_code = std.mem.asBytes(&ebreak);

    // Build .forge package
    const pkg = try forge_format.build(testing.allocator, raw_code, .{});
    defer testing.allocator.free(pkg);

    // This will fail at ELF parse (raw_code isn't a valid ELF) but tests the flow
    var env = syscall_dispatch.HostEnv.init(testing.allocator);
    defer env.deinit();

    const result = executeFromZeph(testing.allocator, pkg, &[_]u8{}, 100_000, &env);
    // Expect InvalidElf since raw code bytes aren't a valid ELF binary
    try testing.expectError(LoadError.InvalidElf, result);
}
