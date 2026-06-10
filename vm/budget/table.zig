const decoder = @import("../core/decoder.zig");

pub const InstructionBudget = struct {
    pub const ALU: u64 = 1;
    pub const ALU_IMM: u64 = 1;
    pub const MUL: u64 = 2;
    pub const MULW: u64 = 2;
    pub const DIV: u64 = 5;
    pub const DIVW: u64 = 3;
    pub const LOAD_WORD: u64 = 2;
    pub const LOAD_BYTE: u64 = 3;
    pub const STORE: u64 = 2;
    pub const BRANCH: u64 = 1;
    pub const JAL: u64 = 2;
    pub const JALR: u64 = 2;
    pub const LUI: u64 = 1;
    pub const AUIPC: u64 = 1;
    pub const ECALL_BASE: u64 = 3;
    pub const EBREAK: u64 = 1;
};

pub const SyscallBudget = struct {
    pub const STORAGE_LOAD: u64 = 30;
    pub const STORAGE_STORE: u64 = 80;
    pub const STORAGE_STORE_SET: u64 = 500;
    pub const STORAGE_CLEAR_REFUND: u64 = 300;

    pub const ASSET_TRANSFER: u64 = 50;
    pub const ASSET_CREATE: u64 = 1000;
    pub const ASSET_BURN: u64 = 100;
    pub const ASSET_QUERY_BALANCE: u64 = 30;
    pub const ASSET_QUERY_METADATA: u64 = 50;

    pub const AUTHORITY_CHECK: u64 = 20;
    pub const AUTHORITY_GRANT: u64 = 200;
    pub const AUTHORITY_REVOKE: u64 = 200;

    pub const CALL_CONTRACT: u64 = 100;
    pub const DELEGATECALL: u64 = 100;
    pub const STATICCALL: u64 = 100;
    pub const CREATE_CONTRACT: u64 = 2000;
    pub const CREATE2_PER_WORD: u64 = 3;

    pub const EMIT_EVENT_BASE: u64 = 50;
    pub const EMIT_EVENT_PER_TOPIC: u64 = 20;
    pub const EMIT_EVENT_PER_BYTE: u64 = 2;

    pub const GET_CALLER: u64 = 1;
    pub const GET_CALLVALUE: u64 = 1;
    pub const GET_CALLDATA: u64 = 1;
    pub const GET_BLOCK_NUMBER: u64 = 1;
    pub const GET_TIMESTAMP: u64 = 1;
    pub const GET_CHAIN_ID: u64 = 1;
    pub const RETURN_DATA: u64 = 0;
    pub const REVERT: u64 = 0;

    pub const HASH_BLAKE3_BASE: u64 = 10;
    pub const HASH_BLAKE3_PER_WORD: u64 = 2;
    pub const HASH_SHA256_BASE: u64 = 20;
    pub const HASH_SHA256_PER_WORD: u64 = 4;
    pub const BLS_VERIFY: u64 = 10_000;

    pub const PARALLEL_HINT: u64 = 0;
    pub const RESOURCE_LOCK: u64 = 30;
    pub const RESOURCE_UNLOCK: u64 = 15;

    pub const DEBUG_LOG: u64 = 0;
};

pub fn instructionCost(insn: decoder.Instruction) u64 {
    return switch (insn) {
        .rType => |r| rTypeCost(r),
        .iType => InstructionBudget.ALU_IMM,
        .sType => InstructionBudget.STORE,
        .bType => InstructionBudget.BRANCH,
        .uType => InstructionBudget.LUI,
        .jType => InstructionBudget.JAL,
        .system => InstructionBudget.ECALL_BASE,
        .custom => InstructionBudget.ECALL_BASE,
    };
}

fn rTypeCost(r: decoder.RType) u64 {
    if (r.funct7 == decoder.Funct7.MULDIV) {
        return switch (r.funct3) {
            decoder.Funct3.MUL, decoder.Funct3.MULH, decoder.Funct3.MULHSU, decoder.Funct3.MULHU => InstructionBudget.MUL,
            decoder.Funct3.DIV, decoder.Funct3.DIVU, decoder.Funct3.REM, decoder.Funct3.REMU => InstructionBudget.DIV,
        };
    }
    return InstructionBudget.ALU;
}

pub const OPCODE_budget_TABLE: [128]u64 = blk: {
    var table = [_]u64{0} ** 128;
    table[decoder.Opcode.OP] = InstructionBudget.ALU;
    table[decoder.Opcode.OP_32] = InstructionBudget.ALU;
    table[decoder.Opcode.OP_IMM] = InstructionBudget.ALU_IMM;
    table[decoder.Opcode.OP_IMM_32] = InstructionBudget.ALU_IMM;
    table[decoder.Opcode.LOAD] = InstructionBudget.LOAD_WORD;
    table[decoder.Opcode.STORE] = InstructionBudget.STORE;
    table[decoder.Opcode.BRANCH] = InstructionBudget.BRANCH;
    table[decoder.Opcode.JAL] = InstructionBudget.JAL;
    table[decoder.Opcode.JALR] = InstructionBudget.JALR;
    table[decoder.Opcode.LUI] = InstructionBudget.LUI;
    table[decoder.Opcode.AUIPC] = InstructionBudget.AUIPC;
    table[decoder.Opcode.SYSTEM] = InstructionBudget.ECALL_BASE;
    break :blk table;
};

const testing = @import("std").testing;

test "ALU instruction costs 1" {
    try testing.expectEqual(@as(u64, 1), OPCODE_budget_TABLE[decoder.Opcode.OP]);
}

test "LOAD instruction costs 2" {
    try testing.expectEqual(@as(u64, 2), OPCODE_budget_TABLE[decoder.Opcode.LOAD]);
}

test "STORE instruction costs 2" {
    try testing.expectEqual(@as(u64, 2), OPCODE_budget_TABLE[decoder.Opcode.STORE]);
}

test "BRANCH instruction costs 1" {
    try testing.expectEqual(@as(u64, 1), OPCODE_budget_TABLE[decoder.Opcode.BRANCH]);
}

test "ECALL costs 3 base" {
    try testing.expectEqual(@as(u64, 3), OPCODE_budget_TABLE[decoder.Opcode.SYSTEM]);
}

test "MUL R-type costs 2" {
    const r = decoder.RType{ .rd = 1, .rs1 = 2, .rs2 = 3, .funct3 = decoder.Funct3.MUL, .funct7 = decoder.Funct7.MULDIV, .wordOp = false };
    try testing.expectEqual(@as(u64, 2), rTypeCost(r));
}

test "DIV R-type costs 5" {
    const r = decoder.RType{ .rd = 1, .rs1 = 2, .rs2 = 3, .funct3 = decoder.Funct3.DIV, .funct7 = decoder.Funct7.MULDIV, .wordOp = false };
    try testing.expectEqual(@as(u64, 5), rTypeCost(r));
}

test "SyscallBudget storage costs are RISC-V-native" {
    try testing.expectEqual(@as(u64, 30), SyscallBudget.STORAGE_LOAD);
    try testing.expectEqual(@as(u64, 80), SyscallBudget.STORAGE_STORE);
    try testing.expectEqual(@as(u64, 500), SyscallBudget.STORAGE_STORE_SET);
}
