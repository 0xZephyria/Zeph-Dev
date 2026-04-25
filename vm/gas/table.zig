// File: vm/gas/table.zig
// Gas cost table for RV64IM instructions and syscalls.
// Costs are calibrated to approximate real CPU cycle costs.

const decoder = @import("../core/decoder.zig");

/// Gas costs for base RV64IM instructions (indexed by opcode)
pub const InstructionGas = struct {
    pub const ALU: u64 = 1; // unchanged
    pub const ALU_IMM: u64 = 1; // unchanged
    pub const MUL: u64 = 2; // unchanged (RV64 MULH still multi-cycle)
    pub const MULW: u64 = 2; // new: 32-bit word multiply
    pub const DIV: u64 = 5; // increased: 64-bit division is slower
    pub const DIVW: u64 = 3; // new: 32-bit word division
    pub const LOAD_WORD: u64 = 2; // reduced from 3: LW/LD in hot cache
    pub const LOAD_BYTE: u64 = 3; // LB/LH (byte lane split costs more)
    pub const STORE: u64 = 2; // reduced from 3
    pub const BRANCH: u64 = 1; // reduced: branch predictor hits >90%
    pub const JAL: u64 = 2; // unchanged
    pub const JALR: u64 = 2; // unchanged
    pub const LUI: u64 = 1; // unchanged
    pub const AUIPC: u64 = 1; // unchanged
    pub const ECALL_BASE: u64 = 3; // reduced from 5
    pub const EBREAK: u64 = 1; // unchanged
};

/// Gas costs for syscalls (on top of ECALL_BASE)
/// Aligned with EIP-2929 (warm/cold access) and EVM Shanghai costs.
pub const SyscallGas = struct {
    // ── Storage (FORGE flat model, no warm/cold distinction) ──
    pub const STORAGE_LOAD: u64 = 200;
    pub const STORAGE_STORE: u64 = 500;
    pub const STORAGE_STORE_SET: u64 = 5_000; // 0 → non-zero
    pub const STORAGE_CLEAR_REFUND: u64 = 2_000; // non-zero → 0

    // ── Asset operations (FORGE-native, no EVM equivalent) ──
    pub const ASSET_TRANSFER: u64 = 300;
    pub const ASSET_CREATE: u64 = 20_000;
    pub const ASSET_BURN: u64 = 500;
    pub const ASSET_QUERY_BALANCE: u64 = 100;
    pub const ASSET_QUERY_METADATA: u64 = 150;

    // ── Authority / Role system ──
    pub const AUTHORITY_CHECK: u64 = 50;
    pub const AUTHORITY_GRANT: u64 = 1_000;
    pub const AUTHORITY_REVOKE: u64 = 1_000;

    // ── Cross-contract calls ──
    pub const CALL_CONTRACT: u64 = 200;
    pub const DELEGATECALL: u64 = 200;
    pub const STATICCALL: u64 = 200;
    pub const CREATE_CONTRACT: u64 = 32000;

    // ── Events ──
    pub const EMIT_EVENT_BASE: u64 = 100;
    pub const EMIT_EVENT_PER_TOPIC: u64 = 50;
    pub const EMIT_EVENT_PER_BYTE: u64 = 4;

    // ── Environment queries ──
    pub const GET_CALLER: u64 = 2;
    pub const GET_CALLVALUE: u64 = 2;
    pub const GET_CALLDATA: u64 = 2;
    pub const GET_BLOCK_NUMBER: u64 = 2;
    pub const GET_TIMESTAMP: u64 = 2;
    pub const GET_CHAIN_ID: u64 = 2;
    pub const RETURN_DATA: u64 = 0;
    pub const REVERT: u64 = 0;

    // ── Cryptography ──
    pub const HASH_BLAKE3_BASE: u64 = 20; // replaces KECCAK256
    pub const HASH_BLAKE3_PER_WORD: u64 = 4;
    pub const HASH_SHA256_BASE: u64 = 30;
    pub const HASH_SHA256_PER_WORD: u64 = 6;
    pub const ECRECOVER: u64 = 3_000;
    pub const BLS_VERIFY: u64 = 45_000; // BLS12-381 pairing

    // ── Parallel execution hints (gas rebate for conflict-free ops) ──
    pub const PARALLEL_HINT: u64 = 0; // free — just metadata
    pub const RESOURCE_LOCK: u64 = 100;
    pub const RESOURCE_UNLOCK: u64 = 50;

    // ── Debug (stripped in production build) ──
    pub const DEBUG_LOG: u64 = 0;
};

/// Get gas cost for a decoded instruction.
pub fn instructionCost(insn: decoder.Instruction) u64 {
    return switch (insn) {
        .rType => |r| rTypeCost(r),
        .iType => InstructionGas.ALU_IMM, // covers ADDI, SLTI, loads, JALR
        .sType => InstructionGas.STORE,
        .bType => InstructionGas.BRANCH,
        .uType => InstructionGas.LUI, // LUI and AUIPC same cost
        .jType => InstructionGas.JAL,
        .system => InstructionGas.ECALL_BASE,
        // ZEPH custom instructions cost the same as an ECALL (base syscall cost)
        .custom => InstructionGas.ECALL_BASE,
    };
}

/// Get gas cost for an R-type instruction based on funct7 (M extension vs normal).
fn rTypeCost(r: decoder.RType) u64 {
    if (r.funct7 == decoder.Funct7.MULDIV) {
        // M extension: MUL vs DIV
        return switch (r.funct3) {
            decoder.Funct3.MUL, decoder.Funct3.MULH, decoder.Funct3.MULHSU, decoder.Funct3.MULHU => InstructionGas.MUL,
            decoder.Funct3.DIV, decoder.Funct3.DIVU, decoder.Funct3.REM, decoder.Funct3.REMU => InstructionGas.DIV,
        };
    }
    return InstructionGas.ALU;
}

/// Opcode-indexed lookup table for fast gas costing from raw instruction words.
/// Index = opcode[6:0] (7 bits → 128 entries).
pub const OPCODE_GAS_TABLE: [128]u64 = blk: {
    var table = [_]u64{0} ** 128;
    table[decoder.Opcode.OP] = InstructionGas.ALU; // R-type (approximate, M-ext checked separately)
    table[decoder.Opcode.OP_32] = InstructionGas.ALU;
    table[decoder.Opcode.OP_IMM] = InstructionGas.ALU_IMM;
    table[decoder.Opcode.OP_IMM_32] = InstructionGas.ALU_IMM;
    table[decoder.Opcode.LOAD] = InstructionGas.LOAD_WORD;
    table[decoder.Opcode.STORE] = InstructionGas.STORE;
    table[decoder.Opcode.BRANCH] = InstructionGas.BRANCH;
    table[decoder.Opcode.JAL] = InstructionGas.JAL;
    table[decoder.Opcode.JALR] = InstructionGas.JALR;
    table[decoder.Opcode.LUI] = InstructionGas.LUI;
    table[decoder.Opcode.AUIPC] = InstructionGas.AUIPC;
    table[decoder.Opcode.SYSTEM] = InstructionGas.ECALL_BASE;
    break :blk table;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = @import("std").testing;

test "ALU instruction costs 1 gas" {
    try testing.expectEqual(@as(u64, 1), OPCODE_GAS_TABLE[decoder.Opcode.OP]);
}

test "LOAD instruction costs 2 gas" {
    try testing.expectEqual(@as(u64, 2), OPCODE_GAS_TABLE[decoder.Opcode.LOAD]);
}

test "STORE instruction costs 2 gas" {
    try testing.expectEqual(@as(u64, 2), OPCODE_GAS_TABLE[decoder.Opcode.STORE]);
}

test "BRANCH instruction costs 1 gas" {
    try testing.expectEqual(@as(u64, 1), OPCODE_GAS_TABLE[decoder.Opcode.BRANCH]);
}

test "ECALL costs 3 gas base" {
    try testing.expectEqual(@as(u64, 3), OPCODE_GAS_TABLE[decoder.Opcode.SYSTEM]);
}

test "MUL R-type costs 2 gas" {
    const r = decoder.RType{ .rd = 1, .rs1 = 2, .rs2 = 3, .funct3 = decoder.Funct3.MUL, .funct7 = decoder.Funct7.MULDIV, .wordOp = false };
    try testing.expectEqual(@as(u64, 2), rTypeCost(r));
}

test "DIV R-type costs 5 gas" {
    const r = decoder.RType{ .rd = 1, .rs1 = 2, .rs2 = 3, .funct3 = decoder.Funct3.DIV, .funct7 = decoder.Funct7.MULDIV, .wordOp = false };
    try testing.expectEqual(@as(u64, 5), rTypeCost(r));
}
