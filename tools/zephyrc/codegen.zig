// File: tools/zephyrc/codegen.zig
// ZephyrLang Code Generator — Produces RISC-V machine code from ZephyrLang AST.
// Generates instructions for function dispatch, storage ops, arithmetic,
// control flow, events, and external calls via ZephVM syscalls.

const std = @import("std");
const ast = @import("ast.zig");

// ============================================================================
// RISC-V Registers (RV32I/RV64I)
// ============================================================================
pub const Reg = enum(u5) {
    zero = 0,
    ra = 1,
    sp = 2,
    gp = 3,
    tp = 4,
    t0 = 5,
    t1 = 6,
    t2 = 7,
    s0 = 8,
    s1 = 9,
    a0 = 10,
    a1 = 11,
    a2 = 12,
    a3 = 13,
    a4 = 14,
    a5 = 15,
    a6 = 16,
    a7 = 17,
    s2 = 18,
    s3 = 19,
    s4 = 20,
    s5 = 21,
    s6 = 22,
    s7 = 23,
    s8 = 24,
    s9 = 25,
    s10 = 26,
    s11 = 27,
    t3 = 28,
    t4 = 29,
    t5 = 30,
    t6 = 31,
};

// ============================================================================
// ZephVM Syscall IDs (must match vm/syscall/dispatch.zig)
// ============================================================================
pub const Syscall = enum(u32) {
    STORAGE_LOAD = 0x01,
    STORAGE_STORE = 0x02,
    GET_CALLER = 0x03,
    GET_CALLVALUE = 0x04,
    GET_CALLDATA_SIZE = 0x05,
    COPY_CALLDATA = 0x06,
    SET_RETURN_DATA = 0x07,
    REVERT = 0x08,
    KECCAK256 = 0x09,
    LOG_EVENT = 0x0A,
    CALL_CONTRACT = 0x0B,
    DELEGATE_CALL = 0x0C,
    STATIC_CALL = 0x0D,
    CREATE_CONTRACT = 0x0E,
    GET_BALANCE = 0x0F,
    GET_TX_ORIGIN = 0x10,
    GET_BLOCK_NUMBER = 0x11,
    GET_BLOCK_TIMESTAMP = 0x12,
    GET_GAS_REMAINING = 0x13,
    SELF_DESTRUCT = 0x14,
    GET_CODE_SIZE = 0x15,
    GET_EXTERNAL_CODE_SIZE = 0x16,
    COPY_CODE = 0x17,
    GET_RETURN_DATA_SIZE = 0x18,
    COPY_RETURN_DATA = 0x19,
    GET_BLOCK_HASH = 0x1A,
    GET_COINBASE = 0x1B,
    GET_GAS_PRICE = 0x1C,
    GET_DIFFICULTY = 0x1D,
    GET_GAS_LIMIT = 0x1E,
    GET_CHAIN_ID = 0x1F,
    SELF_BALANCE = 0x20,
    CREATE2 = 0x21,
    TLOAD = 0x22,
    TSTORE = 0x23,
    ECRECOVER = 0x24,
    GET_ADDRESS = 0x25,
    // ZephyrLang extensions
    ROLE_CHECK = 0x26,
    ROLE_GRANT = 0x27,
    ROLE_REVOKE = 0x28,
    DEBUG_LOG = 0x30,
};

// ============================================================================
// Instruction Encoding
// ============================================================================
pub const Instruction = struct {
    bytes: [4]u8,

    pub fn encode(self: Instruction) u32 {
        return std.mem.readInt(u32, &self.bytes, .little);
    }
};

/// R-type: funct7[31:25] rs2[24:20] rs1[19:15] funct3[14:12] rd[11:7] opcode[6:0]
pub fn encodeR(opcode: u7, rd: Reg, funct3: u3, rs1: Reg, rs2: Reg, funct7: u7) Instruction {
    const val: u32 = @as(u32, opcode) |
        (@as(u32, @intFromEnum(rd)) << 7) |
        (@as(u32, funct3) << 12) |
        (@as(u32, @intFromEnum(rs1)) << 15) |
        (@as(u32, @intFromEnum(rs2)) << 20) |
        (@as(u32, funct7) << 25);
    return .{ .bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, val)) };
}

/// I-type: imm[31:20] rs1[19:15] funct3[14:12] rd[11:7] opcode[6:0]
pub fn encodeI(opcode: u7, rd: Reg, funct3: u3, rs1: Reg, imm: i12) Instruction {
    const uimm: u32 = @bitCast(@as(i32, imm));
    const val: u32 = @as(u32, opcode) |
        (@as(u32, @intFromEnum(rd)) << 7) |
        (@as(u32, funct3) << 12) |
        (@as(u32, @intFromEnum(rs1)) << 15) |
        ((uimm & 0xFFF) << 20);
    return .{ .bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, val)) };
}

/// S-type: imm[11:5] rs2 rs1 funct3 imm[4:0] opcode
pub fn encodeS(opcode: u7, funct3: u3, rs1: Reg, rs2: Reg, imm: i12) Instruction {
    const uimm: u32 = @bitCast(@as(i32, imm));
    const val: u32 = @as(u32, opcode) |
        ((uimm & 0x1F) << 7) |
        (@as(u32, funct3) << 12) |
        (@as(u32, @intFromEnum(rs1)) << 15) |
        (@as(u32, @intFromEnum(rs2)) << 20) |
        (((uimm >> 5) & 0x7F) << 25);
    return .{ .bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, val)) };
}

/// B-type: imm[12|10:5] rs2 rs1 funct3 imm[4:1|11] opcode
pub fn encodeB(opcode: u7, funct3: u3, rs1: Reg, rs2: Reg, imm: i13) Instruction {
    const uimm: u32 = @bitCast(@as(i32, imm));
    const val: u32 = @as(u32, opcode) |
        (((uimm >> 11) & 1) << 7) |
        (((uimm >> 1) & 0xF) << 8) |
        (@as(u32, funct3) << 12) |
        (@as(u32, @intFromEnum(rs1)) << 15) |
        (@as(u32, @intFromEnum(rs2)) << 20) |
        (((uimm >> 5) & 0x3F) << 25) |
        (((uimm >> 12) & 1) << 31);
    return .{ .bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, val)) };
}

/// U-type: imm[31:12] rd opcode
pub fn encodeU(opcode: u7, rd: Reg, imm: u20) Instruction {
    const val: u32 = @as(u32, opcode) |
        (@as(u32, @intFromEnum(rd)) << 7) |
        (@as(u32, imm) << 12);
    return .{ .bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, val)) };
}

/// J-type: imm[20|10:1|11|19:12] rd opcode
pub fn encodeJ(opcode: u7, rd: Reg, imm: i21) Instruction {
    const uimm: u32 = @bitCast(@as(i32, imm));
    const val: u32 = @as(u32, opcode) |
        (@as(u32, @intFromEnum(rd)) << 7) |
        (((uimm >> 12) & 0xFF) << 12) |
        (((uimm >> 11) & 1) << 20) |
        (((uimm >> 1) & 0x3FF) << 21) |
        (((uimm >> 20) & 1) << 31);
    return .{ .bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, val)) };
}

// ============================================================================
// Instruction Helpers (RV32I subset used by ZephyrLang)
// ============================================================================

// Arithmetic
pub fn add(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 0, rs1, rs2, 0);
}
pub fn sub(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 0, rs1, rs2, 0x20);
}
pub fn addi(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x13, rd, 0, rs1, imm);
}
pub fn lui(rd: Reg, imm: u20) Instruction {
    return encodeU(0x37, rd, imm);
}
pub fn auipc(rd: Reg, imm: u20) Instruction {
    return encodeU(0x17, rd, imm);
}

// Logical
pub fn and_inst(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 7, rs1, rs2, 0);
}
pub fn or_inst(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 6, rs1, rs2, 0);
}
pub fn xor_inst(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 4, rs1, rs2, 0);
}
pub fn andi(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x13, rd, 7, rs1, imm);
}
pub fn ori(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x13, rd, 6, rs1, imm);
}

// Shifts
pub fn sll(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 1, rs1, rs2, 0);
}
pub fn srl(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 5, rs1, rs2, 0);
}
pub fn sra(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 5, rs1, rs2, 0x20);
}

// Comparison
pub fn slt(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 2, rs1, rs2, 0);
}
pub fn sltu(rd: Reg, rs1: Reg, rs2: Reg) Instruction {
    return encodeR(0x33, rd, 3, rs1, rs2, 0);
}
pub fn slti(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x13, rd, 2, rs1, imm);
}

// Memory
pub fn lw(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x03, rd, 2, rs1, imm);
}
pub fn sw(rs1: Reg, rs2: Reg, imm: i12) Instruction {
    return encodeS(0x23, 2, rs1, rs2, imm);
}
pub fn lb(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x03, rd, 0, rs1, imm);
}
pub fn sb(rs1: Reg, rs2: Reg, imm: i12) Instruction {
    return encodeS(0x23, 0, rs1, rs2, imm);
}

// Branches
pub fn beq(rs1: Reg, rs2: Reg, imm: i13) Instruction {
    return encodeB(0x63, 0, rs1, rs2, imm);
}
pub fn bne(rs1: Reg, rs2: Reg, imm: i13) Instruction {
    return encodeB(0x63, 1, rs1, rs2, imm);
}
pub fn blt(rs1: Reg, rs2: Reg, imm: i13) Instruction {
    return encodeB(0x63, 4, rs1, rs2, imm);
}
pub fn bge(rs1: Reg, rs2: Reg, imm: i13) Instruction {
    return encodeB(0x63, 5, rs1, rs2, imm);
}
pub fn bltu(rs1: Reg, rs2: Reg, imm: i13) Instruction {
    return encodeB(0x63, 6, rs1, rs2, imm);
}

// Jump
pub fn jal(rd: Reg, imm: i21) Instruction {
    return encodeJ(0x6F, rd, imm);
}
pub fn jalr(rd: Reg, rs1: Reg, imm: i12) Instruction {
    return encodeI(0x67, rd, 0, rs1, imm);
}

// System — ECALL triggers syscall dispatch in ZephVM
pub fn ecall() Instruction {
    return encodeI(0x73, .zero, 0, .zero, 0);
}
pub fn ebreak() Instruction {
    return encodeI(0x73, .zero, 0, .zero, 1);
}

// Pseudo-instructions
pub fn nop() Instruction {
    return addi(.zero, .zero, 0);
}
pub fn mv(rd: Reg, rs: Reg) Instruction {
    return addi(rd, rs, 0);
}
pub fn li(rd: Reg, imm: i12) Instruction {
    return addi(rd, .zero, imm);
}
pub fn ret() Instruction {
    return jalr(.zero, .ra, 0);
}
pub fn call_fn(offset: i21) Instruction {
    return jal(.ra, offset);
}

// ============================================================================
// Code Emitter — Buffer of instructions
// ============================================================================
pub const Emitter = struct {
    code: std.ArrayList(u8),
    alloc: std.mem.Allocator,
    labels: std.StringHashMap(u32),
    fixups: std.ArrayList(Fixup),

    const Fixup = struct { offset: u32, label: []const u8, kind: FixupKind };
    const FixupKind = enum { branch, jump, call_rel };

    pub fn init(alloc: std.mem.Allocator) Emitter {
        return .{
            .code = .{},
            .alloc = alloc,
            .labels = std.StringHashMap(u32).init(alloc),
            .fixups = .{},
        };
    }

    pub fn deinit(self: *Emitter) void {
        self.code.deinit(self.alloc);
        self.labels.deinit();
        self.fixups.deinit(self.alloc);
    }

    pub fn emit(self: *Emitter, inst: Instruction) !void {
        try self.code.appendSlice(self.alloc, &inst.bytes);
    }

    pub fn currentOffset(self: *const Emitter) u32 {
        return @intCast(self.code.items.len);
    }

    pub fn defineLabel(self: *Emitter, name: []const u8) !void {
        try self.labels.put(name, self.currentOffset());
    }

    pub fn emitFixup(self: *Emitter, label: []const u8, kind: FixupKind) !void {
        const offset = self.currentOffset();
        try self.fixups.append(self.alloc, .{ .offset = offset, .label = label, .kind = kind });
        try self.emit(nop()); // placeholder
    }

    /// Emit a syscall: set a7 = syscall_id, then ecall
    pub fn emitSyscall(self: *Emitter, id: Syscall) !void {
        try self.emit(li(.a7, @intCast(@intFromEnum(id))));
        try self.emit(ecall());
    }

    /// Resolve all label fixups after code generation is complete.
    pub fn resolveFixups(self: *Emitter) !void {
        for (self.fixups.items) |fixup| {
            const target = self.labels.get(fixup.label) orelse continue;
            const offset: i32 = @intCast(@as(i64, target) - @as(i64, fixup.offset));
            const inst = switch (fixup.kind) {
                .branch => encodeB(0x63, 0, .zero, .zero, @intCast(offset)),
                .jump => encodeJ(0x6F, .ra, @intCast(offset)),
                .call_rel => encodeJ(0x6F, .ra, @intCast(offset)),
            };
            @memcpy(self.code.items[fixup.offset..][0..4], &inst.bytes);
        }
    }

    pub fn getCode(self: *const Emitter) []const u8 {
        return self.code.items;
    }
};

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;

test "codegen: ADD instruction encoding" {
    const inst = add(.t0, .a0, .a1);
    const val = inst.encode();
    // ADD t0, a0, a1: funct7=0 rs2=a1(11) rs1=a0(10) funct3=0 rd=t0(5) opcode=0x33
    try testing.expectEqual(@as(u7, 0x33), @as(u7, @truncate(val)));
    try testing.expectEqual(@as(u5, 5), @as(u5, @truncate(val >> 7))); // rd=t0
}

test "codegen: ADDI instruction" {
    const inst = addi(.a0, .zero, 42);
    const val = inst.encode();
    try testing.expectEqual(@as(u7, 0x13), @as(u7, @truncate(val))); // opcode
    try testing.expectEqual(@as(u5, 10), @as(u5, @truncate(val >> 7))); // rd=a0
}

test "codegen: ECALL" {
    const inst = ecall();
    try testing.expectEqual(@as(u32, 0x00000073), inst.encode());
}

test "codegen: emitter basic" {
    var em = Emitter.init(testing.allocator);
    defer em.deinit();
    try em.emit(addi(.a0, .zero, 1));
    try em.emit(ret());
    try testing.expectEqual(@as(usize, 8), em.getCode().len);
}

test "codegen: syscall emit" {
    var em = Emitter.init(testing.allocator);
    defer em.deinit();
    try em.emitSyscall(.STORAGE_LOAD);
    try testing.expectEqual(@as(usize, 8), em.getCode().len); // li + ecall
}
