// File: vm/core/decoder.zig
// RISC-V RV64IM Instruction Decoder
// Decodes raw 32-bit instruction words into structured Instruction union.
// RV64IM uses 6 instruction formats: R, I, S, B, U, J + System.
// Includes RV64 word-operation opcodes: OP_32 (ADDW/SUBW/MULW…) and OP_IMM_32 (ADDIW…).
// Full 32-register file (x0–x31); x0 is hardwired to zero by the executor.

/// Decoded instruction — one of 7 format variants.
pub const Instruction = union(Tag) {
    rType: RType,
    iType: IType,
    sType: SType,
    bType: BType,
    uType: UType,
    jType: JType,
    system: SystemOp,
    /// Forge ZEPH custom instruction (CUSTOM_0..3 opcode space)
    custom: CustomType,

    pub const Tag = enum {
        rType,
        iType,
        sType,
        bType,
        uType,
        jType,
        system,
        custom,
    };
};

// ---------------------------------------------------------------------------
// Instruction format structs
// ---------------------------------------------------------------------------

/// R-type: register-register operations (ADD, SUB, MUL, AND, OR, XOR, SLL, SRL, SRA, SLT, SLTU)
pub const RType = struct {
    rd: u5,
    rs1: u5,
    rs2: u5,
    funct3: u3,
    funct7: u7,
    wordOp: bool,
};

/// I-type: immediate operations (ADDI, SLTI, ANDI, loads, JALR, shifts)
pub const IType = struct {
    rd: u5,
    rs1: u5,
    funct3: u3,
    imm: i64, // sign-extended 12-bit immediate
    wordOp: bool,
};

/// S-type: stores (SB, SH, SW)
pub const SType = struct {
    rs1: u5,
    rs2: u5,
    funct3: u3,
    imm: i64,
};

/// B-type: conditional branches (BEQ, BNE, BLT, BGE, BLTU, BGEU)
pub const BType = struct {
    rs1: u5,
    rs2: u5,
    funct3: u3,
    imm: i64,
};

/// U-type: upper immediate (LUI, AUIPC)
pub const UType = struct {
    rd: u5,
    imm: i64,
};

/// J-type: jump (JAL)
pub const JType = struct {
    rd: u5,
    imm: i64,
};

/// Custom-type: Forge ZEPH instruction decoded from custom-0..3 opcode space.
/// The operation is encoded in the instruction word (not in a register):
///   funct3 = op_val >> 4
///   imm[3:0] = op_val & 0x0F
///   op_val = @intFromEnum(ZephCustomOp) from compiler riscv.zig
pub const CustomType = struct {
    /// The full ZephCustomOp value (0x00-0x37), as emitted by the compiler.
    opVal: u8,
    // Arguments come from registers a0-a5 (x10-x15) per ZEPH ABI.
    // The instruction itself does not carry rs1/rs2 that the executor uses.
};

/// System operations
pub const SystemOp = enum {
    ecall,
    ebreak,
};

// ---------------------------------------------------------------------------
// Opcodes (7-bit, bits [6:0] of the instruction word)
// ---------------------------------------------------------------------------

pub const Opcode = struct {
    pub const OP: u7 = 0b0110011; // R-type: ADD, SUB, MUL, etc.
    pub const OP_IMM: u7 = 0b0010011; // I-type: ADDI, SLTI, etc.
    pub const LOAD: u7 = 0b0000011; // I-type: LB, LH, LW, LBU, LHU
    pub const STORE: u7 = 0b0100011; // S-type: SB, SH, SW
    pub const BRANCH: u7 = 0b1100011; // B-type: BEQ, BNE, BLT, etc.
    pub const JAL: u7 = 0b1101111; // J-type: JAL
    pub const JALR: u7 = 0b1100111; // I-type: JALR
    pub const LUI: u7 = 0b0110111; // U-type: LUI
    pub const AUIPC: u7 = 0b0010111; // U-type: AUIPC
    pub const SYSTEM: u7 = 0b1110011; // System: ECALL, EBREAK
    pub const OP_32: u7 = 0b0111011; // RV64 word ops: ADDW, SUBW, etc.
    pub const OP_IMM_32: u7 = 0b0011011; // RV64 word imm ops: ADDIW, etc.
    pub const LOAD_FP: u7 = 0b0000111; // Reserved — emit fault
    pub const STORE_FP: u7 = 0b0100111; // Reserved — emit fault
    // RISC-V custom opcode space — used by Forge compiler for ZEPH instructions
    pub const CUSTOM_0: u7 = 0b0001011; // 0x0B — state operations
    pub const CUSTOM_1: u7 = 0b0101011; // 0x2B — authority & access
    pub const CUSTOM_2: u7 = 0b1011011; // 0x5B — asset & payment
    pub const CUSTOM_3: u7 = 0b1111011; // 0x7B — vm-level operations
};

// ---------------------------------------------------------------------------
// funct3 values
// ---------------------------------------------------------------------------

pub const Funct3 = struct {
    // OP / OP_IMM arithmetic
    pub const ADD_SUB: u3 = 0b000; // ADD (funct7=0), SUB (funct7=0x20)
    pub const SLL: u3 = 0b001;
    pub const SLT: u3 = 0b010;
    pub const SLTU: u3 = 0b011;
    pub const XOR: u3 = 0b100;
    pub const SRL_SRA: u3 = 0b101; // SRL (funct7=0), SRA (funct7=0x20)
    pub const OR: u3 = 0b110;
    pub const AND: u3 = 0b111;

    // M extension (funct7=0x01)
    pub const MUL: u3 = 0b000;
    pub const MULH: u3 = 0b001;
    pub const MULHSU: u3 = 0b010;
    pub const MULHU: u3 = 0b011;
    pub const DIV: u3 = 0b100;
    pub const DIVU: u3 = 0b101;
    pub const REM: u3 = 0b110;
    pub const REMU: u3 = 0b111;

    // Branch
    pub const BEQ: u3 = 0b000;
    pub const BNE: u3 = 0b001;
    pub const BLT: u3 = 0b100;
    pub const BGE: u3 = 0b101;
    pub const BLTU: u3 = 0b110;
    pub const BGEU: u3 = 0b111;

    // Load
    pub const LB: u3 = 0b000;
    pub const LH: u3 = 0b001;
    pub const LW: u3 = 0b010;
    pub const LBU: u3 = 0b100;
    pub const LHU: u3 = 0b101;
    pub const LWU: u3 = 0b110;
    pub const LD: u3 = 0b011;

    // Store
    pub const SB: u3 = 0b000;
    pub const SH: u3 = 0b001;
    pub const SW: u3 = 0b010;
    pub const SD: u3 = 0b011;
};

pub const Funct7 = struct {
    pub const NORMAL: u7 = 0b0000000;
    pub const SUB_SRA: u7 = 0b0100000; // SUB (with ADD funct3), SRA (with SRL funct3)
    pub const MULDIV: u7 = 0b0000001; // M extension
};

// ---------------------------------------------------------------------------
// Decode error
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    IllegalInstruction, // Unrecognised opcode
    // Note: InvalidRegister was removed — RV64IM uses all 32 registers (x0–x31),
    // so every 5-bit register field is valid. x0 hardwiring is the executor's job.
};

// ---------------------------------------------------------------------------
// Main decode function
// ---------------------------------------------------------------------------

/// Decode a raw 32-bit RISC-V instruction word into a structured Instruction.
/// Returns DecodeError.IllegalInstruction for unrecognized opcodes.
pub fn decode(word: u32) DecodeError!Instruction {
    const opcode: u7 = @truncate(word & 0x7F);

    return switch (opcode) {
        Opcode.OP, Opcode.OP_32 => decodeR(word),
        Opcode.OP_IMM, Opcode.OP_IMM_32 => decodeI(word, @truncate(word & 0x7F)),
        Opcode.LOAD => decodeI(word, Opcode.LOAD),
        Opcode.JALR => decodeI(word, Opcode.JALR),
        Opcode.STORE => decodeS(word),
        Opcode.BRANCH => decodeB(word),
        Opcode.LUI => decodeU(word),
        Opcode.AUIPC => decodeU(word),
        Opcode.JAL => decodeJ(word),
        Opcode.SYSTEM => decodeSystem(word),
        Opcode.CUSTOM_0, Opcode.CUSTOM_1, Opcode.CUSTOM_2, Opcode.CUSTOM_3 => decodeCustom(word),
        else => DecodeError.IllegalInstruction,
    };
}
pub fn decompress(inst: u16) ?u32 {
    const op = inst & 3;
    switch (op) {
        0 => { // Quadrant 0
            const funct3: u3 = @truncate(inst >> 13);
            switch (funct3) {
                0 => { // c.addi4spn -> addi rd', sp, imm
                    const rd = 8 + ((inst >> 2) & 7);
                    const imm = (((inst >> 7) & 15) << 6) | (((inst >> 11) & 3) << 4) | (((inst >> 5) & 1) << 3) | (((inst >> 6) & 1) << 2);
                    if (imm == 0) return null; // Illegal
                    return (@as(u32, imm) << 20) | (@as(u32, 2) << 15) | (0 << 12) | (@as(u32, rd) << 7) | 0x13;
                },
                2 => { // c.lw -> lw rd', offset(rs1')
                    const rd = 8 + ((inst >> 2) & 7);
                    const rs1 = 8 + ((inst >> 7) & 7);
                    const imm = (((inst >> 5) & 1) << 6) | (((inst >> 10) & 7) << 3) | (((inst >> 6) & 1) << 2);
                    return (@as(u32, imm) << 20) | (@as(u32, rs1) << 15) | (2 << 12) | (@as(u32, rd) << 7) | 0x03;
                },
                3 => { // c.ld -> ld rd', offset(rs1')
                    const rd = 8 + ((inst >> 2) & 7);
                    const rs1 = 8 + ((inst >> 7) & 7);
                    const imm = (((inst >> 5) & 3) << 6) | (((inst >> 10) & 7) << 3);
                    return (@as(u32, imm) << 20) | (@as(u32, rs1) << 15) | (3 << 12) | (@as(u32, rd) << 7) | 0x03;
                },
                6 => { // c.sw -> sw rs2', offset(rs1')
                    const rs2 = 8 + ((inst >> 2) & 7);
                    const rs1 = 8 + ((inst >> 7) & 7);
                    const imm = (((inst >> 5) & 1) << 6) | (((inst >> 10) & 7) << 3) | (((inst >> 6) & 1) << 2);
                    const imm_lo = imm & 0x1F;
                    const imm_hi = (imm >> 5) & 0x7F;
                    return (@as(u32, imm_hi) << 25) | (@as(u32, rs2) << 20) | (@as(u32, rs1) << 15) | (2 << 12) | (@as(u32, imm_lo) << 7) | 0x23;
                },
                7 => { // c.sd -> sd rs2', offset(rs1')
                    const rs2 = 8 + ((inst >> 2) & 7);
                    const rs1 = 8 + ((inst >> 7) & 7);
                    const imm = (((inst >> 5) & 3) << 6) | (((inst >> 10) & 7) << 3);
                    const imm_lo = imm & 0x1F;
                    const imm_hi = (imm >> 5) & 0x7F;
                    return (@as(u32, imm_hi) << 25) | (@as(u32, rs2) << 20) | (@as(u32, rs1) << 15) | (3 << 12) | (@as(u32, imm_lo) << 7) | 0x23;
                },
                else => return null,
            }
        },
        1 => { // Quadrant 1
            const funct3: u3 = @truncate(inst >> 13);
            const rd = (inst >> 7) & 0x1F;
            const imm_6_raw = (((inst >> 12) & 1) << 5) | ((inst >> 2) & 0x1F);
            const imm_6 = @as(u32, @truncate(@as(u64, @bitCast(signExtend(imm_6_raw, 6)))));

            switch (funct3) {
                0 => { // c.addi -> addi rd, rd, imm
                    const imm_u = imm_6 & 0xFFF;
                    return (@as(u32, imm_u) << 20) | (@as(u32, rd) << 15) | (0 << 12) | (@as(u32, rd) << 7) | 0x13;
                },
                1 => { // c.addiw -> addiw rd, rd, imm
                    if (rd == 0) return null;
                    const imm_u = imm_6 & 0xFFF;
                    return (@as(u32, imm_u) << 20) | (@as(u32, rd) << 15) | (0 << 12) | (@as(u32, rd) << 7) | 0x1B;
                },
                2 => { // c.li -> addi rd, zero, imm
                    const imm_u = imm_6 & 0xFFF;
                    return (@as(u32, imm_u) << 20) | (0 << 15) | (0 << 12) | (@as(u32, rd) << 7) | 0x13;
                },
                3 => {
                    if (rd == 2) { // c.addi16sp -> addi sp, sp, imm
                        const imm_raw = (((inst >> 12) & 1) << 9) | (((inst >> 3) & 3) << 7) | (((inst >> 5) & 1) << 6) | (((inst >> 2) & 1) << 5) | (((inst >> 6) & 1) << 4);
                        if (imm_raw == 0) return null;
                        const imm_s = @as(u32, @truncate(@as(u64, @bitCast(signExtend(imm_raw, 10)))));
                        const imm_u = imm_s & 0xFFF;
                        return (@as(u32, imm_u) << 20) | (@as(u32, 2) << 15) | (0 << 12) | (2 << 7) | 0x13;
                    } else if (rd != 0) { // c.lui -> lui rd, imm
                        const imm_u = imm_6 & 0xFFFFF;
                        return (@as(u32, imm_u) << 12) | (@as(u32, rd) << 7) | 0x37;
                    } else {
                        return null;
                    }
                },
                4 => { // Sub-opcodes
                    const subop = (inst >> 10) & 3;
                    const rd_p = 8 + ((inst >> 7) & 7);
                    const shamt = (((inst >> 12) & 1) << 5) | ((inst >> 2) & 0x1F);
                    switch (subop) {
                        0 => { // c.srli -> srli rd', rd', shamt
                            return (@as(u32, shamt) << 20) | (@as(u32, rd_p) << 15) | (5 << 12) | (@as(u32, rd_p) << 7) | 0x13;
                        },
                        1 => { // c.srai -> srai rd', rd', shamt
                            return (@as(u32, 0x20 | shamt) << 20) | (@as(u32, rd_p) << 15) | (5 << 12) | (@as(u32, rd_p) << 7) | 0x13;
                        },
                        2 => { // c.andi -> andi rd', rd', imm
                            const imm_u = imm_6 & 0xFFF;
                            return (@as(u32, imm_u) << 20) | (@as(u32, rd_p) << 15) | (7 << 12) | (@as(u32, rd_p) << 7) | 0x13;
                        },
                        3 => {
                            const rs2_p = 8 + ((inst >> 2) & 7);
                            const bit12 = (inst >> 12) & 1;
                            const funct2 = (inst >> 5) & 3;
                            if (bit12 == 0) {
                                return switch (funct2) {
                                    0 => (@as(u32, 0x20) << 25) | (@as(u32, rs2_p) << 20) | (@as(u32, rd_p) << 15) | (0 << 12) | (@as(u32, rd_p) << 7) | 0x33, // c.sub
                                    1 => (@as(u32, rs2_p) << 20) | (@as(u32, rd_p) << 15) | (4 << 12) | (@as(u32, rd_p) << 7) | 0x33, // c.xor
                                    2 => (@as(u32, rs2_p) << 20) | (@as(u32, rd_p) << 15) | (6 << 12) | (@as(u32, rd_p) << 7) | 0x33, // c.or
                                    3 => (@as(u32, rs2_p) << 20) | (@as(u32, rd_p) << 15) | (7 << 12) | (@as(u32, rd_p) << 7) | 0x33, // c.and
                                    else => unreachable,
                                };
                            } else {
                                return switch (funct2) {
                                    0 => (@as(u32, 0x20) << 25) | (@as(u32, rs2_p) << 20) | (@as(u32, rd_p) << 15) | (0 << 12) | (@as(u32, rd_p) << 7) | 0x3B, // c.subw
                                    1 => (@as(u32, rs2_p) << 20) | (@as(u32, rd_p) << 15) | (0 << 12) | (@as(u32, rd_p) << 7) | 0x3B, // c.addw
                                    else => null,
                                };
                            }
                        },
                        else => unreachable,
                    }
                },
                5 => { // c.j -> jal zero, offset
                    const bit11 = (inst >> 12) & 1;
                    const bit10 = (inst >> 8) & 1;
                    const bit9_8 = (inst >> 9) & 3;
                    const bit7 = (inst >> 6) & 1;
                    const bit6 = (inst >> 7) & 1;
                    const bit5 = (inst >> 2) & 1;
                    const bit4 = (inst >> 11) & 1;
                    const bit3_1 = (inst >> 3) & 7;
                    const offset_val = (bit11 << 11) | (bit10 << 10) | (bit9_8 << 8) | (bit7 << 7) | (bit6 << 6) | (bit5 << 5) | (bit4 << 4) | (bit3_1 << 1);
                    const imm_s = @as(u32, @truncate(@as(u64, @bitCast(signExtend(offset_val, 12)))));
                    const j_imm = ((imm_s >> 20) & 1) << 31 | ((imm_s >> 1) & 0x3FF) << 21 | ((imm_s >> 11) & 1) << 20 | ((imm_s >> 12) & 0xFF) << 12;
                    return j_imm | (0 << 7) | 0x6F;
                },
                6 => { // c.beqz -> beq rs1', zero, offset
                    const rs1 = 8 + ((inst >> 7) & 7);
                    const bit8 = (inst >> 12) & 1;
                    const bit7_6 = (inst >> 5) & 3;
                    const bit5 = (inst >> 2) & 1;
                    const bit4_3 = (inst >> 10) & 3;
                    const bit2_1 = (inst >> 3) & 3;
                    const offset_val = (bit8 << 8) | (bit7_6 << 6) | (bit5 << 5) | (bit4_3 << 3) | (bit2_1 << 1);
                    const imm_s = @as(u32, @truncate(@as(u64, @bitCast(signExtend(offset_val, 9)))));
                    const b_imm = ((imm_s >> 12) & 1) << 31 | ((imm_s >> 5) & 0x3F) << 25 | ((imm_s >> 1) & 0xF) << 8 | ((imm_s >> 11) & 1) << 7;
                    return b_imm | (@as(u32, rs1) << 15) | 0x63;
                },
                7 => { // c.bnez -> bne rs1', zero, offset
                    const rs1 = 8 + ((inst >> 7) & 7);
                    const bit8 = (inst >> 12) & 1;
                    const bit7_6 = (inst >> 5) & 3;
                    const bit5 = (inst >> 2) & 1;
                    const bit4_3 = (inst >> 10) & 3;
                    const bit2_1 = (inst >> 3) & 3;
                    const offset_val = (bit8 << 8) | (bit7_6 << 6) | (bit5 << 5) | (bit4_3 << 3) | (bit2_1 << 1);
                    const imm_s = @as(u32, @truncate(@as(u64, @bitCast(signExtend(offset_val, 9)))));
                    const b_imm = ((imm_s >> 12) & 1) << 31 | ((imm_s >> 5) & 0x3F) << 25 | ((imm_s >> 1) & 0xF) << 8 | ((imm_s >> 11) & 1) << 7;
                    return b_imm | (@as(u32, rs1) << 15) | (1 << 12) | 0x63;
                },
            }
        },
        2 => { // Quadrant 2
            const funct3: u3 = @truncate(inst >> 13);
            const rd = (inst >> 7) & 0x1F;
            const rs2 = (inst >> 2) & 0x1F;

            switch (funct3) {
                0 => { // c.slli -> slli rd, rd, shamt
                    const shamt = (((inst >> 12) & 1) << 5) | rs2;
                    return (@as(u32, shamt) << 20) | (@as(u32, rd) << 15) | (1 << 12) | (@as(u32, rd) << 7) | 0x13;
                },
                2 => { // c.lwsp -> lw rd, offset(sp)
                    if (rd == 0) return null;
                    const imm = (((inst >> 12) & 1) << 5) | (((inst >> 2) & 3) << 6) | (((inst >> 4) & 7) << 2);
                    return (@as(u32, imm) << 20) | (@as(u32, 2) << 15) | (2 << 12) | (@as(u32, rd) << 7) | 0x03;
                },
                3 => { // c.ldsp -> ld rd, offset(sp)
                    if (rd == 0) return null;
                    const imm = (((inst >> 12) & 1) << 5) | (((inst >> 5) & 3) << 3) | (((inst >> 2) & 7) << 6);
                    return (@as(u32, imm) << 20) | (@as(u32, 2) << 15) | (3 << 12) | (@as(u32, rd) << 7) | 0x03;
                },
                4 => {
                    const bit12 = (inst >> 12) & 1;
                    if (bit12 == 0) {
                        if (rs2 == 0) { // c.jr -> jalr zero, rs1, 0
                            return (@as(u32, rd) << 15) | 0x67;
                        } else { // c.mv -> add rd, zero, rs2
                            return (@as(u32, rs2) << 20) | (@as(u32, rd) << 7) | 0x33;
                        }
                    } else {
                        if (rs2 == 0) {
                            if (rd == 0) { // c.ebreak -> ebreak
                                return (@as(u32, 1) << 20) | 0x73;
                            } else { // c.jalr -> jalr ra, rs1, 0
                                return (@as(u32, rd) << 15) | (1 << 7) | 0x67;
                            }
                        } else { // c.add -> add rd, rd, rs2
                            return (@as(u32, rs2) << 20) | (@as(u32, rd) << 15) | (@as(u32, rd) << 7) | 0x33;
                        }
                    }
                },
                6 => { // c.swsp -> sw rs2, offset(sp)
                    const imm = (((inst >> 9) & 15) << 2) | (((inst >> 7) & 3) << 6);
                    const imm_lo = imm & 0x1F;
                    const imm_hi = (imm >> 5) & 0x7F;
                    return (@as(u32, imm_hi) << 25) | (@as(u32, rs2) << 20) | (2 << 15) | (2 << 12) | (@as(u32, imm_lo) << 7) | 0x23;
                },
                7 => { // c.sdsp -> sd rs2, offset(sp)
                    const imm = (((inst >> 10) & 7) << 3) | (((inst >> 7) & 7) << 6);
                    const imm_lo = imm & 0x1F;
                    const imm_hi = (imm >> 5) & 0x7F;
                    return (@as(u32, imm_hi) << 25) | (@as(u32, rs2) << 20) | (2 << 15) | (3 << 12) | (@as(u32, imm_lo) << 7) | 0x23;
                },
                else => return null,
            }
        },
        else => return null,
    }
}


// ---------------------------------------------------------------------------
// Format-specific decoders
// ---------------------------------------------------------------------------

fn decodeR(word: u32) DecodeError!Instruction {
    const rd = extractReg(word, 7).?; // RV64IM: all 32 regs valid
    const rs1 = extractReg(word, 15).?; // RV64IM: all 32 regs valid
    const rs2 = extractReg(word, 20).?; // RV64IM: all 32 regs valid
    const funct3: u3 = @truncate((word >> 12) & 0x7);
    const funct7: u7 = @truncate((word >> 25) & 0x7F);
    const opcode: u7 = @truncate(word & 0x7F);
    const wordOp = (opcode == Opcode.OP_32);

    return .{ .rType = .{
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .funct3 = funct3,
        .funct7 = funct7,
        .wordOp = wordOp,
    } };
}

fn decodeI(word: u32, opcode: u7) DecodeError!Instruction {
    const rd = extractReg(word, 7).?; // RV64IM: all 32 regs valid
    const rs1 = extractReg(word, 15).?; // RV64IM: all 32 regs valid
    const funct3: u3 = @truncate((word >> 12) & 0x7);
    const immRaw: u32 = word >> 20; // bits [31:20]
    const imm = signExtend(immRaw, 12);
    const wordOp = (opcode == Opcode.OP_IMM_32);

    return .{ .iType = .{
        .rd = rd,
        .rs1 = rs1,
        .funct3 = funct3,
        .imm = imm,
        .wordOp = wordOp,
    } };
}

fn decodeS(word: u32) DecodeError!Instruction {
    const rs1 = extractReg(word, 15).?; // RV64IM: all 32 regs valid
    const rs2 = extractReg(word, 20).?; // RV64IM: all 32 regs valid
    const funct3: u3 = @truncate((word >> 12) & 0x7);
    const immLo: u32 = (word >> 7) & 0x1F; // bits [11:7] → imm[4:0]
    const immHi: u32 = (word >> 25) & 0x7F; // bits [31:25] → imm[11:5]
    const immRaw = (immHi << 5) | immLo;
    const imm = signExtend(immRaw, 12);

    return .{ .sType = .{
        .rs1 = rs1,
        .rs2 = rs2,
        .funct3 = funct3,
        .imm = imm,
    } };
}

fn decodeB(word: u32) DecodeError!Instruction {
    const rs1 = extractReg(word, 15).?; // RV64IM: all 32 regs valid
    const rs2 = extractReg(word, 20).?; // RV64IM: all 32 regs valid
    const funct3: u3 = @truncate((word >> 12) & 0x7);

    // B-type immediate encoding (13-bit, bit 0 is always 0):
    // imm[12|10:5|4:1|11]
    const bit11: u32 = (word >> 7) & 0x1; // bit 7 → imm[11]
    const bit41: u32 = (word >> 8) & 0xF; // bits [11:8] → imm[4:1]
    const bit105: u32 = (word >> 25) & 0x3F; // bits [30:25] → imm[10:5]
    const bit12: u32 = (word >> 31) & 0x1; // bit 31 → imm[12] (sign)

    const immRaw = (bit12 << 12) | (bit11 << 11) | (bit105 << 5) | (bit41 << 1);
    const imm = signExtend(immRaw, 13);

    return .{ .bType = .{
        .rs1 = rs1,
        .rs2 = rs2,
        .funct3 = funct3,
        .imm = imm,
    } };
}

fn decodeU(word: u32) DecodeError!Instruction {
    const rd = extractReg(word, 7).?; // RV64IM: all 32 regs valid
    // U-type: imm[31:12] already in upper 20 bits, we keep it shifted
    const imm: i64 = @as(i64, @as(i32, @bitCast(word & 0xFFFFF000)));

    return .{ .uType = .{
        .rd = rd,
        .imm = imm,
    } };
}

fn decodeJ(word: u32) DecodeError!Instruction {
    const rd = extractReg(word, 7).?; // RV64IM: all 32 regs valid

    // J-type immediate encoding (21-bit, bit 0 is always 0):
    // imm[20|10:1|11|19:12]
    const bit1912: u32 = (word >> 12) & 0xFF; // bits [19:12] → imm[19:12]
    const bit11: u32 = (word >> 20) & 0x1; // bit 20 → imm[11]
    const bit101: u32 = (word >> 21) & 0x3FF; // bits [30:21] → imm[10:1]
    const bit20: u32 = (word >> 31) & 0x1; // bit 31 → imm[20] (sign)

    const immRaw = (bit20 << 20) | (bit1912 << 12) | (bit11 << 11) | (bit101 << 1);
    const imm = signExtend(immRaw, 21);

    return .{ .jType = .{
        .rd = rd,
        .imm = imm,
    } };
}

fn decodeSystem(word: u32) DecodeError!Instruction {
    const immRaw: u32 = (word >> 20) & 0xFFF;
    return switch (immRaw) {
        0x000 => .{ .system = .ecall },
        0x001 => .{ .system = .ebreak },
        else => DecodeError.IllegalInstruction,
    };
}

// ---------------------------------------------------------------------------
// Custom (ZEPH) instruction decoder
// ---------------------------------------------------------------------------

/// Decode a ZEPH custom instruction from the custom-0..3 opcode space.
/// The op_val is reconstructed from funct3 (upper nibble) and imm[3:0] (lower nibble).
fn decodeCustom(word: u32) DecodeError!Instruction {
    const funct3: u8 = @truncate((word >> 12) & 0x7);
    const immLo: u8 = @truncate((word >> 20) & 0xF); // lower 4 bits of imm12
    const opVal: u8 = (funct3 << 4) | immLo;
    return .{ .custom = .{ .opVal = opVal } };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a 5-bit register index from the instruction word at the given bit position.
/// RV64IM uses a full 32-register file (x0–x31); all 5-bit values are valid.
/// x0 is hardwired to zero and enforced by the executor after every instruction.
fn extractReg(word: u32, shift: u5) ?u5 {
    const raw: u5 = @truncate((word >> shift) & 0x1F);
    return raw; // Always valid: all 32 registers are legal in RV64IM
}

/// Sign-extend a `bits`-wide unsigned value to i64.
fn signExtend(value: u64, comptime bits: u6) i64 {
    const ShiftType = u6;
    const shift: ShiftType = @intCast(64 - @as(u7, bits));
    const signed: i64 = @bitCast(value << shift);
    return signed >> shift;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = @import("std").testing;

test "decode ADD x1, x2, x3" {
    // ADD x1, x2, x3:  funct7=0000000 rs2=00011 rs1=00010 funct3=000 rd=00001 opcode=0110011
    const word: u32 = 0b0000000_00011_00010_000_00001_0110011;
    const insn = try decode(word);
    try testing.expect(insn == .rType);
    const r = insn.rType;
    try testing.expectEqual(@as(u5, 1), r.rd);
    try testing.expectEqual(@as(u5, 2), r.rs1);
    try testing.expectEqual(@as(u5, 3), r.rs2);
    try testing.expectEqual(@as(u3, 0), r.funct3);
    try testing.expectEqual(@as(u7, 0), r.funct7);
}

test "decode SUB x5, x6, x7" {
    // SUB x5, x6, x7: funct7=0100000 rs2=00111 rs1=00110 funct3=000 rd=00101 opcode=0110011
    const word: u32 = 0b0100000_00111_00110_000_00101_0110011;
    const insn = try decode(word);
    try testing.expect(insn == .rType);
    const r = insn.rType;
    try testing.expectEqual(@as(u5, 5), r.rd);
    try testing.expectEqual(@as(u5, 6), r.rs1);
    try testing.expectEqual(@as(u5, 7), r.rs2);
    try testing.expectEqual(@as(u7, 0b0100000), r.funct7);
}

test "decode ADDI x1, x2, -1" {
    // ADDI x1, x2, -1: imm=111111111111 rs1=00010 funct3=000 rd=00001 opcode=0010011
    const word: u32 = 0b111111111111_00010_000_00001_0010011;
    const insn = try decode(word);
    try testing.expect(insn == .iType);
    const i = insn.iType;
    try testing.expectEqual(@as(u5, 1), i.rd);
    try testing.expectEqual(@as(u5, 2), i.rs1);
    try testing.expectEqual(@as(i64, -1), i.imm);
}

test "decode LW x10, 8(x2)" {
    // LW x10, 8(x2): imm=000000001000 rs1=00010 funct3=010 rd=01010 opcode=0000011
    const word: u32 = 0b000000001000_00010_010_01010_0000011;
    const insn = try decode(word);
    try testing.expect(insn == .iType);
    const i = insn.iType;
    try testing.expectEqual(@as(u5, 10), i.rd);
    try testing.expectEqual(@as(u5, 2), i.rs1);
    try testing.expectEqual(@as(u3, Funct3.LW), i.funct3);
    try testing.expectEqual(@as(i64, 8), i.imm);
}

test "decode SW x5, 12(x2)" {
    // SW x5, 12(x2): imm[11:5]=0000000 rs2=00101 rs1=00010 funct3=010 imm[4:0]=01100 opcode=0100011
    const word: u32 = 0b0000000_00101_00010_010_01100_0100011;
    const insn = try decode(word);
    try testing.expect(insn == .sType);
    const s = insn.sType;
    try testing.expectEqual(@as(u5, 2), s.rs1);
    try testing.expectEqual(@as(u5, 5), s.rs2);
    try testing.expectEqual(@as(i64, 12), s.imm);
}

test "decode BEQ x1, x2, +8" {
    // BEQ x1, x2, 8: B-type with offset = 8
    // imm[12|10:5] = 0_000000, rs2=00010, rs1=00001, funct3=000, imm[4:1|11] = 0100_0, opcode=1100011
    const word: u32 = 0b0_000000_00010_00001_000_0100_0_1100011;
    const insn = try decode(word);
    try testing.expect(insn == .bType);
    const b = insn.bType;
    try testing.expectEqual(@as(u5, 1), b.rs1);
    try testing.expectEqual(@as(u5, 2), b.rs2);
    try testing.expectEqual(@as(i64, 8), b.imm);
}

test "decode LUI x1, 0x12345" {
    // LUI x1, 0x12345: imm=0001_0010_0011_0100_0101 rd=00001 opcode=0110111
    const word: u32 = 0x12345_0B7; // 0x12345000 | (1 << 7) | 0x37
    const immExpected: i64 = 0x12345 << 12;
    const insn = try decode(word);
    try testing.expect(insn == .uType);
    try testing.expectEqual(immExpected, insn.uType.imm);
}

test "decode ECALL" {
    // ECALL: 000000000000 00000 000 00000 1110011
    const word: u32 = 0b000000000000_00000_000_00000_1110011;
    const insn = try decode(word);
    try testing.expect(insn == .system);
    try testing.expectEqual(SystemOp.ecall, insn.system);
}

test "decode EBREAK" {
    // EBREAK: 000000000001 00000 000 00000 1110011
    const word: u32 = 0b000000000001_00000_000_00000_1110011;
    const insn = try decode(word);
    try testing.expect(insn == .system);
    try testing.expectEqual(SystemOp.ebreak, insn.system);
}

test "invalid opcode returns IllegalInstruction" {
    const word: u32 = 0x0000007F; // opcode = 0x7F, not a valid RV32 opcode
    const result = decode(word);
    try testing.expectError(DecodeError.IllegalInstruction, result);
}

test "sign extension works correctly" {
    // Positive 12-bit value: 0x7FF = 2047
    try testing.expectEqual(@as(i64, 2047), signExtend(0x7FF, 12));
    // Negative 12-bit value: 0x800 = -2048
    try testing.expectEqual(@as(i64, -2048), signExtend(0x800, 12));
    // Full negative: 0xFFF = -1
    try testing.expectEqual(@as(i64, -1), signExtend(0xFFF, 12));
}
