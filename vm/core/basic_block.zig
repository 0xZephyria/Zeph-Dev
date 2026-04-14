// File: vm/core/basic_block.zig
// Basic Block Analysis for ForgeVM.
//
// Analyzes RISC-V bytecode at load time to identify basic blocks — maximal
// sequences of instructions between control flow points (branches, jumps, ecalls).
//
// This enables two critical optimizations:
//   1. Gas pre-computation: pre-compute total gas cost per basic block, reducing
//      gas checks from per-instruction to per-block (~5-10 instructions amortized).
//   2. Super-instruction identification: detect common instruction patterns within
//      blocks for pattern collapsing (e.g., LUI+ADDI → load immediate).
//
// Design:
//   - O(n) single-pass analysis over bytecode
//   - Stores results in a compact array indexed by basic block ID
//   - Maximum 16384 basic blocks per contract (64KB code / 4 bytes per insn)

const std = @import("std");
const decoder = @import("decoder.zig");
const gas_table = @import("../gas/table.zig");

/// A basic block is a maximal sequence of instructions with:
///   - One entry point (the first instruction, or a branch target)
///   - One exit point (the last instruction, which is a branch/jump/ecall/end)
pub const BasicBlock = struct {
    /// PC of the first instruction in this block
    start_pc: u32,
    /// PC of the last instruction in this block (inclusive)
    end_pc: u32,
    /// Number of instructions in this block
    insn_count: u16,
    /// Pre-computed total gas cost for all instructions in this block
    total_gas: u64,
    /// Index of the fallthrough block (next sequential block), or null
    fallthrough: ?u16,
    /// Index of the branch target block, or null
    branch_target: ?u16,
    /// Whether this block ends with a syscall (ECALL)
    ends_with_ecall: bool,
    /// Whether this block ends with a branch (B-type)
    ends_with_branch: bool,
    /// Whether this block ends with a jump (JAL/JALR)
    ends_with_jump: bool,
};

/// Result of basic block analysis on a program.
pub const ProgramAnalysis = struct {
    /// Array of basic blocks in program order
    blocks: []BasicBlock,
    /// Map from PC → basic block index (for branch target resolution)
    /// Indexed by PC/4 (instruction index)
    pc_to_block: []u16,
    /// Total number of basic blocks
    block_count: u16,
    /// Allocator used for allocations
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ProgramAnalysis) void {
        self.allocator.free(self.blocks);
        self.allocator.free(self.pc_to_block);
    }

    /// Look up which basic block contains a given PC.
    pub fn getBlockForPC(self: *const ProgramAnalysis, pc: u32) ?u16 {
        const idx = pc / 4;
        if (idx >= self.pc_to_block.len) return null;
        return self.pc_to_block[idx];
    }
};

/// Maximum number of basic blocks we support per contract.
/// 64KB code / 4 bytes per insn = 16384 instructions max.
/// In practice, basic blocks average ~6 instructions, so ~2700 blocks typical.
const MAX_BLOCKS: u16 = 16384;

/// Sentinel value for "no block mapped"
const NO_BLOCK: u16 = 0xFFFF;

/// Analyze a RISC-V program and identify basic blocks.
/// Returns a ProgramAnalysis with pre-computed gas costs.
///
/// The analysis works in two passes:
///   Pass 1: Identify block boundaries (branch targets + instructions after branches)
///   Pass 2: Build basic blocks with gas costs
pub fn analyze(allocator: std.mem.Allocator, code: []const u8, code_len: u32) !ProgramAnalysis {
    const insn_count = code_len / 4;
    if (insn_count == 0) {
        return ProgramAnalysis{
            .blocks = try allocator.alloc(BasicBlock, 0),
            .pc_to_block = try allocator.alloc(u16, 0),
            .block_count = 0,
            .allocator = allocator,
        };
    }

    // ---- Pass 1: Mark block leaders ----
    // A block leader is:
    //   - The first instruction (PC=0)
    //   - Any branch/jump target
    //   - Any instruction immediately after a branch/jump/ecall
    var is_leader = try allocator.alloc(bool, insn_count);
    defer allocator.free(is_leader);
    @memset(is_leader, false);
    is_leader[0] = true; // First instruction is always a leader

    var i: u32 = 0;
    while (i < insn_count) : (i += 1) {
        const pc = i * 4;
        const word = std.mem.readInt(u32, code[pc..][0..4], .little);
        const opcode: u7 = @truncate(word & 0x7F);

        switch (opcode) {
            decoder.Opcode.BRANCH => {
                // B-type: mark branch target and fallthrough as leaders
                const insn = decoder.decode(word) catch continue;
                if (insn == .b_type) {
                    const target_pc = pc +% @as(u32, @bitCast(insn.b_type.imm));
                    const target_idx = target_pc / 4;
                    if (target_idx < insn_count) is_leader[target_idx] = true;
                }
                // Instruction after branch is a new leader
                if (i + 1 < insn_count) is_leader[i + 1] = true;
            },
            decoder.Opcode.JAL => {
                // J-type: mark jump target and fallthrough as leaders
                const insn = decoder.decode(word) catch continue;
                if (insn == .j_type) {
                    const target_pc = pc +% @as(u32, @bitCast(insn.j_type.imm));
                    const target_idx = target_pc / 4;
                    if (target_idx < insn_count) is_leader[target_idx] = true;
                }
                if (i + 1 < insn_count) is_leader[i + 1] = true;
            },
            decoder.Opcode.JALR => {
                // JALR: indirect jump — next instruction is new leader
                if (i + 1 < insn_count) is_leader[i + 1] = true;
            },
            decoder.Opcode.SYSTEM => {
                // ECALL/EBREAK — next instruction is new leader
                if (i + 1 < insn_count) is_leader[i + 1] = true;
            },
            else => {},
        }
    }

    // ---- Count leaders to determine number of blocks ----
    var block_count: u16 = 0;
    for (is_leader) |leader| {
        if (leader) block_count += 1;
    }

    // ---- Pass 2: Build basic blocks ----
    var blocks = try allocator.alloc(BasicBlock, block_count);
    var pc_to_block = try allocator.alloc(u16, insn_count);
    @memset(pc_to_block, NO_BLOCK);

    var current_block: u16 = 0;
    var block_start: u32 = 0;
    var block_gas: u64 = 0;
    var block_insn_count: u16 = 0;

    i = 0;
    while (i < insn_count) : (i += 1) {
        const pc = i * 4;

        // Start new block if this is a leader (and not the first instruction in the current block)
        if (is_leader[i] and block_insn_count > 0) {
            // Finalize previous block
            blocks[current_block] = buildBlock(
                block_start,
                (i - 1) * 4,
                block_insn_count,
                block_gas,
                code,
                insn_count,
                current_block,
                block_count,
            );
            current_block += 1;
            block_start = pc;
            block_gas = 0;
            block_insn_count = 0;
        }

        // Map this PC to the current block
        pc_to_block[i] = current_block;

        // Accumulate gas for this instruction
        const word = std.mem.readInt(u32, code[pc..][0..4], .little);
        const opcode: u7 = @truncate(word & 0x7F);
        block_gas += gas_table.OPCODE_GAS_TABLE[opcode];

        // For M-extension instructions, add extra gas
        if (opcode == decoder.Opcode.OP) {
            const insn = decoder.decode(word) catch {
                block_insn_count += 1;
                continue;
            };
            if (insn == .r_type and insn.r_type.funct7 == decoder.Funct7.MULDIV) {
                const extra = gas_table.instructionCost(insn) -| gas_table.InstructionGas.ALU;
                block_gas += extra;
            }
        }

        block_insn_count += 1;
    }

    // Finalize last block
    if (block_insn_count > 0 and current_block < block_count) {
        blocks[current_block] = buildBlock(
            block_start,
            (insn_count - 1) * 4,
            block_insn_count,
            block_gas,
            code,
            insn_count,
            current_block,
            block_count,
        );
    }

    return ProgramAnalysis{
        .blocks = blocks,
        .pc_to_block = pc_to_block,
        .block_count = block_count,
        .allocator = allocator,
    };
}

/// Build a BasicBlock struct from accumulated data.
fn buildBlock(
    start_pc: u32,
    end_pc: u32,
    insn_count: u16,
    total_gas: u64,
    code: []const u8,
    total_insn_count: u32,
    block_idx: u16,
    total_blocks: u16,
) BasicBlock {
    // Examine the last instruction to determine block terminator type
    const last_word = std.mem.readInt(u32, code[end_pc..][0..4], .little);
    const last_opcode: u7 = @truncate(last_word & 0x7F);

    const ends_with_branch = last_opcode == decoder.Opcode.BRANCH;
    const ends_with_jump = last_opcode == decoder.Opcode.JAL or last_opcode == decoder.Opcode.JALR;
    const ends_with_ecall = last_opcode == decoder.Opcode.SYSTEM;

    // Determine fallthrough block
    const next_insn_idx = (end_pc / 4) + 1;
    const has_fallthrough = next_insn_idx < total_insn_count and !ends_with_jump;
    const fallthrough: ?u16 = if (has_fallthrough and block_idx + 1 < total_blocks)
        block_idx + 1
    else
        null;

    // Determine branch target block
    var branch_target: ?u16 = null;
    if (ends_with_branch) {
        const insn = decoder.decode(last_word) catch null;
        if (insn) |decoded| {
            if (decoded == .b_type) {
                const target_pc = end_pc +% @as(u32, @bitCast(decoded.b_type.imm));
                const target_idx = target_pc / 4;
                if (target_idx < total_insn_count) {
                    // We'd need the pc_to_block map here, but we handle this in a fixup pass
                    branch_target = null; // Will be resolved after building all blocks
                }
            }
        }
    }

    return BasicBlock{
        .start_pc = start_pc,
        .end_pc = end_pc,
        .insn_count = insn_count,
        .total_gas = total_gas,
        .fallthrough = fallthrough,
        .branch_target = branch_target,
        .ends_with_ecall = ends_with_ecall,
        .ends_with_branch = ends_with_branch,
        .ends_with_jump = ends_with_jump,
    };
}

/// Resolve branch targets in the basic blocks using the pc_to_block map.
/// Must be called after analyze() to fixup branch_target fields.
pub fn resolveBranchTargets(analysis: *ProgramAnalysis, code: []const u8) void {
    for (analysis.blocks[0..analysis.block_count]) |*block| {
        if (!block.ends_with_branch) continue;

        const last_word = std.mem.readInt(u32, code[block.end_pc..][0..4], .little);
        const insn = decoder.decode(last_word) catch continue;
        if (insn == .b_type) {
            const target_pc = block.end_pc +% @as(u32, @bitCast(insn.b_type.imm));
            const target_idx = target_pc / 4;
            if (target_idx < analysis.pc_to_block.len) {
                block.branch_target = analysis.pc_to_block[target_idx];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Super-instruction pattern detection
// ---------------------------------------------------------------------------

/// Detected super-instruction patterns within a basic block.
pub const SuperPattern = enum {
    /// LUI rd, imm20 + ADDI rd, rd, imm12 → load full 32-bit immediate
    lui_addi,
    /// LW rd, offset(rs1) + LW rd2, offset2(rs1) → double load from same base
    double_load,
    /// ADDI rd, rs1, imm + SW rd, offset(rs2) → add-and-store
    addi_store,
    /// No pattern detected
    none,
};

/// Detect if two consecutive instructions form a super-instruction pattern.
pub fn detectSuperPattern(word1: u32, word2: u32) SuperPattern {
    const op1: u7 = @truncate(word1 & 0x7F);
    const op2: u7 = @truncate(word2 & 0x7F);

    // LUI + ADDI → load 32-bit immediate
    if (op1 == decoder.Opcode.LUI and op2 == decoder.Opcode.OP_IMM) {
        const insn1 = decoder.decode(word1) catch return .none;
        const insn2 = decoder.decode(word2) catch return .none;
        if (insn1 == .u_type and insn2 == .i_type) {
            // Check if ADDI's rs1 == LUI's rd (same register)
            if (insn2.i_type.rs1 == insn1.u_type.rd and insn2.i_type.rd == insn1.u_type.rd) {
                if (insn2.i_type.funct3 == decoder.Funct3.ADD_SUB) {
                    return .lui_addi;
                }
            }
        }
    }

    // LW + LW → double load from same base
    if (op1 == decoder.Opcode.LOAD and op2 == decoder.Opcode.LOAD) {
        const insn1 = decoder.decode(word1) catch return .none;
        const insn2 = decoder.decode(word2) catch return .none;
        if (insn1 == .i_type and insn2 == .i_type) {
            if (insn1.i_type.funct3 == decoder.Funct3.LW and insn2.i_type.funct3 == decoder.Funct3.LW) {
                // Same base register
                if (insn1.i_type.rs1 == insn2.i_type.rs1) {
                    return .double_load;
                }
            }
        }
    }

    // ADDI + SW → add-and-store
    if (op1 == decoder.Opcode.OP_IMM and op2 == decoder.Opcode.STORE) {
        const insn1 = decoder.decode(word1) catch return .none;
        const insn2 = decoder.decode(word2) catch return .none;
        if (insn1 == .i_type and insn2 == .s_type) {
            if (insn1.i_type.funct3 == decoder.Funct3.ADD_SUB and insn2.s_type.funct3 == decoder.Funct3.SW) {
                // The ADDI result register is the source register for the store
                if (insn1.i_type.rd == insn2.s_type.rs2) {
                    return .addi_store;
                }
            }
        }
    }

    return .none;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "analyze: empty program" {
    var analysis = try analyze(testing.allocator, &[_]u8{}, 0);
    defer analysis.deinit();
    try testing.expectEqual(@as(u16, 0), analysis.block_count);
}

test "analyze: single instruction = one block" {
    // ADDI x1, x0, 42
    const code = [_]u8{ 0x93, 0x00, 0xA0, 0x02 }; // 0x02A00093
    var analysis = try analyze(testing.allocator, &code, 4);
    defer analysis.deinit();
    try testing.expectEqual(@as(u16, 1), analysis.block_count);
    try testing.expectEqual(@as(u32, 0), analysis.blocks[0].start_pc);
    try testing.expectEqual(@as(u32, 0), analysis.blocks[0].end_pc);
    try testing.expectEqual(@as(u16, 1), analysis.blocks[0].insn_count);
}

test "analyze: straight-line code = one block" {
    // 3 ADDI instructions
    const code = [_]u8{
        0x93, 0x00, 0x10, 0x00, // ADDI x1, x0, 1
        0x93, 0x80, 0x10, 0x00, // ADDI x1, x1, 1
        0x93, 0x80, 0x10, 0x00, // ADDI x1, x1, 1
    };
    var analysis = try analyze(testing.allocator, &code, 12);
    defer analysis.deinit();
    try testing.expectEqual(@as(u16, 1), analysis.block_count);
    try testing.expectEqual(@as(u16, 3), analysis.blocks[0].insn_count);
    try testing.expect(analysis.blocks[0].total_gas > 0);
}

test "analyze: ECALL splits blocks" {
    // ADDI + ECALL + ADDI → 3 blocks
    const code = [_]u8{
        0x93, 0x00, 0x10, 0x00, // ADDI x1, x0, 1
        0x73, 0x00, 0x00, 0x00, // ECALL
        0x93, 0x00, 0x10, 0x00, // ADDI x1, x0, 1
    };
    var analysis = try analyze(testing.allocator, &code, 12);
    defer analysis.deinit();
    try testing.expectEqual(@as(u16, 3), analysis.block_count);
    try testing.expect(analysis.blocks[1].ends_with_ecall);
}

test "analyze: pc_to_block mapping" {
    // 2 ADDIs + ECALL + 1 ADDI → blocks mapped correctly
    const code = [_]u8{
        0x93, 0x00, 0x10, 0x00, // ADDI x1, x0, 1
        0x93, 0x80, 0x10, 0x00, // ADDI x1, x1, 1
        0x73, 0x00, 0x00, 0x00, // ECALL
        0x93, 0x00, 0x10, 0x00, // ADDI x1, x0, 1
    };
    var analysis = try analyze(testing.allocator, &code, 16);
    defer analysis.deinit();
    // First two ADDIs are in block 0
    try testing.expectEqual(@as(u16, 0), analysis.pc_to_block[0]);
    try testing.expectEqual(@as(u16, 0), analysis.pc_to_block[1]);
    // ECALL is in block 1
    try testing.expectEqual(@as(u16, 1), analysis.pc_to_block[2]);
    // Last ADDI is in block 2
    try testing.expectEqual(@as(u16, 2), analysis.pc_to_block[3]);
}

test "analyze: gas pre-computation correct" {
    // 3 ADDI instructions (1 gas each) → block total = 3
    const code = [_]u8{
        0x93, 0x00, 0x10, 0x00, // ADDI x1, x0, 1
        0x93, 0x80, 0x10, 0x00, // ADDI x1, x1, 1
        0x93, 0x80, 0x10, 0x00, // ADDI x1, x1, 1
    };
    var analysis = try analyze(testing.allocator, &code, 12);
    defer analysis.deinit();
    // OP_IMM costs 1 gas each → total should be 3
    try testing.expectEqual(@as(u64, 3), analysis.blocks[0].total_gas);
}

test "super-instruction: LUI + ADDI detected" {
    // LUI x1, 0x12345
    const lui_word: u32 = 0x12345_0B7; // LUI x1 (rd=1)
    // ADDI x1, x1, 0x678
    const addi_word: u32 = 0x678_08_093; // ADDI x1, x1 (rd=1, rs1=1, imm=0x678)
    const lui_bytes = std.mem.asBytes(&lui_word);
    const addi_bytes = std.mem.asBytes(&addi_word);

    const pattern = detectSuperPattern(
        std.mem.readInt(u32, lui_bytes, .little),
        std.mem.readInt(u32, addi_bytes, .little),
    );
    try testing.expectEqual(SuperPattern.lui_addi, pattern);
}

test "super-instruction: non-matching pair returns none" {
    // Two unrelated ADDIs
    const word1: u32 = 0x00100093; // ADDI x1, x0, 1
    const word2: u32 = 0x00200113; // ADDI x2, x0, 2
    const pattern = detectSuperPattern(word1, word2);
    try testing.expectEqual(SuperPattern.none, pattern);
}
