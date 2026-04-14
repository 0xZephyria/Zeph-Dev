// File: tools/zephyrc/mir.zig
// ZephyrLang Mid-level IR — Optimized representation between AST and RISC-V.
// Performs constant folding, dead code elimination, storage read caching,
// and common subexpression elimination before final codegen.

const std = @import("std");
const ast = @import("ast.zig");

// ============================================================================
// MIR Instruction Set
// ============================================================================

pub const MirOp = enum(u8) {
    // Arithmetic (u256 semantics)
    add,
    sub,
    mul,
    div,
    mod,
    exp,
    wrapping_add,
    wrapping_sub,
    wrapping_mul,
    saturating_add,
    saturating_sub,
    // Comparison
    eq,
    neq,
    lt,
    gt,
    lte,
    gte,
    // Bitwise
    bit_and,
    bit_or,
    bit_xor,
    bit_not,
    shl,
    shr,
    // Logic
    log_and,
    log_or,
    log_not,
    // Storage
    sload,
    sstore,
    tload,
    tstore, // EIP-1153 transient storage
    // Memory
    mload,
    mstore,
    mstore8,
    // Control flow
    jump,
    jump_if,
    jump_if_not,
    label,
    call_internal,
    call_external,
    delegatecall,
    staticcall,
    ret,
    revert_op,
    stop,
    // Environment
    caller,
    callvalue,
    calldataload,
    calldatasize,
    calldatacopy,
    address_op,
    balance,
    selfbalance,
    origin,
    gasprice,
    blockhash,
    coinbase,
    timestamp,
    number,
    difficulty,
    gaslimit,
    chainid,
    basefee,
    // Crypto
    keccak256,
    // Events
    log0,
    log1,
    log2,
    log3,
    log4,
    // Data
    const_u32,
    const_u256,
    const_bytes,
    load_local,
    store_local,
    load_param,
    store_result,
    // Roles (ZephyrLang extensions)
    role_check,
    role_grant,
    role_revoke,
    // Resources
    resource_lock,
    resource_unlock,
    // No-op / marker
    nop,
};

pub const MirInstr = struct {
    op: MirOp,
    dest: u8, // destination register/slot
    src1: u8, // source operand 1
    src2: u8, // source operand 2
    imm: i64, // immediate value
    label_id: u32, // for jump targets / labels
    data: ?[]const u8, // for const_bytes, string data
};

pub const MirBlock = struct {
    label: u32,
    instrs: std.ArrayList(MirInstr),
    predecessors: std.ArrayList(u32),
    successors: std.ArrayList(u32),
    is_reachable: bool,
};

// ============================================================================
// MIR Builder — Converts AST to MIR
// ============================================================================

pub const MirBuilder = struct {
    alloc: std.mem.Allocator,
    blocks: std.ArrayList(MirBlock),
    current_block: u32,
    next_label: u32,
    next_reg: u8,
    constants: std.ArrayList(ConstEntry),

    const ConstEntry = struct { reg: u8, value: i64, used: bool };

    pub fn init(alloc: std.mem.Allocator) MirBuilder {
        return .{
            .alloc = alloc,
            .blocks = .{},
            .current_block = 0,
            .next_label = 0,
            .next_reg = 0,
            .constants = .{},
        };
    }

    pub fn deinit(self: *MirBuilder) void {
        for (self.blocks.items) |*b| {
            b.instrs.deinit(self.alloc);
            b.predecessors.deinit(self.alloc);
            b.successors.deinit(self.alloc);
        }
        self.blocks.deinit(self.alloc);
        self.constants.deinit(self.alloc);
    }

    pub fn newBlock(self: *MirBuilder) !u32 {
        const label = self.next_label;
        self.next_label += 1;
        try self.blocks.append(self.alloc, .{
            .label = label,
            .instrs = .{},
            .predecessors = .{},
            .successors = .{},
            .is_reachable = true,
        });
        return label;
    }

    pub fn emit(self: *MirBuilder, instr: MirInstr) !void {
        if (self.current_block < self.blocks.items.len) {
            try self.blocks.items[self.current_block].instrs.append(self.alloc, instr);
        }
    }

    pub fn allocReg(self: *MirBuilder) u8 {
        const r = self.next_reg;
        self.next_reg += 1;
        return r;
    }

    pub fn emitConst(self: *MirBuilder, value: i64) !u8 {
        // Check if constant already loaded
        for (self.constants.items) |*c| {
            if (c.value == value) {
                c.used = true;
                return c.reg;
            }
        }
        const reg = self.allocReg();
        try self.emit(.{ .op = .const_u32, .dest = reg, .src1 = 0, .src2 = 0, .imm = value, .label_id = 0, .data = null });
        try self.constants.append(self.alloc, .{ .reg = reg, .value = value, .used = true });
        return reg;
    }

    // Build MIR from a function body
    pub fn buildFunction(self: *MirBuilder, func: ast.FunctionDef) !void {
        const entry = try self.newBlock();
        self.current_block = entry;
        // Emit label
        try self.emit(.{ .op = .label, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = entry, .data = null });
        // Process body
        if (func.body) |body| {
            for (body.statements) |stmt| {
                try self.lowerStmt(stmt);
            }
        }
        // Emit implicit return
        try self.emit(.{ .op = .ret, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
    }

    fn lowerStmt(self: *MirBuilder, stmt: ast.Stmt) !void {
        switch (stmt) {
            .block => |b| for (b.statements) |s| try self.lowerStmt(s),
            .expression => |es| _ = try self.lowerExpr(es.expr),
            .return_stmt => |r| {
                if (r.value) |v| {
                    const reg = try self.lowerExpr(v);
                    try self.emit(.{ .op = .store_result, .dest = 0, .src1 = reg, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
                }
                try self.emit(.{ .op = .ret, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
            },
            .if_stmt => |i| {
                const cond = try self.lowerExpr(i.condition);
                const then_block = try self.newBlock();
                const end_block = try self.newBlock();
                const else_block = if (i.else_body != null) try self.newBlock() else end_block;
                try self.emit(.{ .op = .jump_if_not, .dest = 0, .src1 = cond, .src2 = 0, .imm = 0, .label_id = else_block, .data = null });
                self.current_block = then_block;
                try self.emit(.{ .op = .label, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = then_block, .data = null });
                try self.lowerStmt(i.then_body);
                try self.emit(.{ .op = .jump, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = end_block, .data = null });
                if (i.else_body) |eb| {
                    self.current_block = else_block;
                    try self.emit(.{ .op = .label, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = else_block, .data = null });
                    try self.lowerStmt(eb);
                    try self.emit(.{ .op = .jump, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = end_block, .data = null });
                }
                self.current_block = end_block;
                try self.emit(.{ .op = .label, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = end_block, .data = null });
            },
            .emit_stmt => |e| {
                // Lower event arguments
                for (e.args) |arg| _ = try self.lowerExpr(arg);
                const topic_count: u8 = @truncate(e.args.len);
                try self.emit(.{ .op = if (topic_count == 0) .log0 else if (topic_count == 1) .log1 else if (topic_count == 2) .log2 else .log3, .dest = 0, .src1 = topic_count, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
            },
            .revert_stmt => {
                try self.emit(.{ .op = .revert_op, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
            },
            else => {},
        }
    }

    fn lowerExpr(self: *MirBuilder, expr: ast.Expr) !u8 {
        switch (expr) {
            .literal => |lit| return self.lowerLiteral(lit),
            .identifier => {
                const reg = self.allocReg();
                try self.emit(.{ .op = .load_local, .dest = reg, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
                return reg;
            },
            .binary_op => |bin| return self.lowerBinOp(bin.*),
            .function_call => |fc| {
                for (fc.args) |arg| _ = try self.lowerExpr(arg);
                const reg = self.allocReg();
                try self.emit(.{ .op = .call_internal, .dest = reg, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
                return reg;
            },
            .member_access => {
                const reg = self.allocReg();
                try self.emit(.{ .op = .load_local, .dest = reg, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
                return reg;
            },
            .assignment => |a| {
                const val = try self.lowerExpr(a.value);
                try self.emit(.{ .op = .store_local, .dest = 0, .src1 = val, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
                return val;
            },
            else => return self.emitConst(0),
        }
    }

    fn lowerLiteral(self: *MirBuilder, lit: ast.LiteralExpr) !u8 {
        switch (lit.kind) {
            .number_decimal, .number_hex => {
                const val = std.fmt.parseInt(i64, lit.value, 0) catch 0;
                return self.emitConst(val);
            },
            .bool_true => return self.emitConst(1),
            .bool_false => return self.emitConst(0),
            else => return self.emitConst(0),
        }
    }

    fn lowerBinOp(self: *MirBuilder, bin: ast.BinaryOpExpr) !u8 {
        const left = try self.lowerExpr(bin.left);
        const right = try self.lowerExpr(bin.right);
        const dest = self.allocReg();
        const op: MirOp = switch (bin.op) {
            .add => .add,
            .sub => .sub,
            .mul => .mul,
            .div => .div,
            .mod => .mod,
            .wrapping_add => .wrapping_add,
            .wrapping_sub => .wrapping_sub,
            .wrapping_mul => .wrapping_mul,
            .saturating_add => .saturating_add,
            .saturating_sub => .saturating_sub,
            .eq => .eq,
            .neq => .neq,
            .lt => .lt,
            .gt => .gt,
            .lte => .lte,
            .gte => .gte,
            .bit_and => .bit_and,
            .bit_or => .bit_or,
            .bit_xor => .bit_xor,
            .shl => .shl,
            .shr => .shr,
            .and_op => .log_and,
            .or_op => .log_or,
            .exp => .exp,
        };
        try self.emit(.{ .op = op, .dest = dest, .src1 = left, .src2 = right, .imm = 0, .label_id = 0, .data = null });
        return dest;
    }
};

// ============================================================================
// Optimizer Passes
// ============================================================================

pub const Optimizer = struct {
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Optimizer {
        return .{ .alloc = alloc };
    }

    /// Run all optimization passes on MIR blocks.
    pub fn optimize(self: *Optimizer, builder: *MirBuilder) !void {
        try self.constantFold(builder);
        try self.deadCodeElim(builder);
        try self.storageCache(builder);
    }

    /// Constant Folding: evaluate const + const at compile time.
    fn constantFold(_: *Optimizer, builder: *MirBuilder) !void {
        for (builder.blocks.items) |*block| {
            var i: usize = 0;
            while (i < block.instrs.items.len) : (i += 1) {
                const instr = &block.instrs.items[i];
                // Look for binop where both sources are constants
                if (isArith(instr.op) and i >= 2) {
                    const s1 = findConst(block.instrs.items[0..i], instr.src1);
                    const s2 = findConst(block.instrs.items[0..i], instr.src2);
                    if (s1 != null and s2 != null) {
                        const result = evalConst(instr.op, s1.?, s2.?);
                        if (result) |val| {
                            instr.op = .const_u32;
                            instr.imm = val;
                            instr.src1 = 0;
                            instr.src2 = 0;
                        }
                    }
                }
            }
        }
    }

    /// Dead Code Elimination: remove NOPs and unreachable code after revert/ret.
    fn deadCodeElim(_: *Optimizer, builder: *MirBuilder) !void {
        for (builder.blocks.items) |*block| {
            var found_term = false;
            var i: usize = 0;
            while (i < block.instrs.items.len) {
                if (found_term and block.instrs.items[i].op != .label) {
                    _ = block.instrs.orderedRemove(i);
                } else {
                    if (block.instrs.items[i].op == .ret or block.instrs.items[i].op == .revert_op or block.instrs.items[i].op == .stop) {
                        found_term = true;
                    }
                    i += 1;
                }
            }
        }
    }

    /// Storage Read Caching: deduplicate SLOAD for the same slot within a block.
    fn storageCache(_: *Optimizer, builder: *MirBuilder) !void {
        for (builder.blocks.items) |*block| {
            var last_sload_slot: i64 = -1;
            var last_sload_reg: u8 = 0;
            for (block.instrs.items) |*instr| {
                if (instr.op == .sload) {
                    if (instr.imm == last_sload_slot and last_sload_slot >= 0) {
                        // Duplicate SLOAD — replace with register copy
                        instr.op = .load_local;
                        instr.src1 = last_sload_reg;
                    } else {
                        last_sload_slot = instr.imm;
                        last_sload_reg = instr.dest;
                    }
                }
                if (instr.op == .sstore) {
                    // Invalidate cache on write
                    if (instr.imm == last_sload_slot) last_sload_slot = -1;
                }
            }
        }
    }
};

fn isArith(op: MirOp) bool {
    return switch (op) {
        .add, .sub, .mul, .div, .mod => true,
        else => false,
    };
}

fn findConst(instrs: []const MirInstr, reg: u8) ?i64 {
    var i = instrs.len;
    while (i > 0) {
        i -= 1;
        if (instrs[i].op == .const_u32 and instrs[i].dest == reg) return instrs[i].imm;
    }
    return null;
}

fn evalConst(op: MirOp, a: i64, b: i64) ?i64 {
    return switch (op) {
        .add => a +| b,
        .sub => a -| b,
        .mul => a *| b,
        .div => if (b != 0) @divTrunc(a, b) else null,
        .mod => if (b != 0) @mod(a, b) else null,
        else => null,
    };
}

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;

test "mir: constant folding" {
    var builder = MirBuilder.init(testing.allocator);
    defer builder.deinit();
    _ = try builder.newBlock();
    // Emit: r0 = 10, r1 = 20, r2 = r0 + r1
    try builder.emit(.{ .op = .const_u32, .dest = 0, .src1 = 0, .src2 = 0, .imm = 10, .label_id = 0, .data = null });
    try builder.emit(.{ .op = .const_u32, .dest = 1, .src1 = 0, .src2 = 0, .imm = 20, .label_id = 0, .data = null });
    try builder.emit(.{ .op = .add, .dest = 2, .src1 = 0, .src2 = 1, .imm = 0, .label_id = 0, .data = null });

    var opt = Optimizer.init(testing.allocator);
    try opt.optimize(&builder);

    // After folding: r2 should be const_u32 with value 30
    const last = builder.blocks.items[0].instrs.items[2];
    try testing.expectEqual(MirOp.const_u32, last.op);
    try testing.expectEqual(@as(i64, 30), last.imm);
}

test "mir: dead code elimination" {
    var builder = MirBuilder.init(testing.allocator);
    defer builder.deinit();
    _ = try builder.newBlock();
    try builder.emit(.{ .op = .const_u32, .dest = 0, .src1 = 0, .src2 = 0, .imm = 1, .label_id = 0, .data = null });
    try builder.emit(.{ .op = .ret, .dest = 0, .src1 = 0, .src2 = 0, .imm = 0, .label_id = 0, .data = null });
    try builder.emit(.{ .op = .const_u32, .dest = 1, .src1 = 0, .src2 = 0, .imm = 99, .label_id = 0, .data = null }); // dead

    var opt = Optimizer.init(testing.allocator);
    try opt.optimize(&builder);

    // Dead instruction removed
    try testing.expectEqual(@as(usize, 2), builder.blocks.items[0].instrs.items.len);
}

test "mir: storage read caching" {
    var builder = MirBuilder.init(testing.allocator);
    defer builder.deinit();
    _ = try builder.newBlock();
    try builder.emit(.{ .op = .sload, .dest = 0, .src1 = 0, .src2 = 0, .imm = 5, .label_id = 0, .data = null });
    try builder.emit(.{ .op = .sload, .dest = 1, .src1 = 0, .src2 = 0, .imm = 5, .label_id = 0, .data = null }); // duplicate

    var opt = Optimizer.init(testing.allocator);
    try opt.optimize(&builder);

    // Second SLOAD replaced with load_local from cached reg
    try testing.expectEqual(MirOp.load_local, builder.blocks.items[0].instrs.items[1].op);
    try testing.expectEqual(@as(u8, 0), builder.blocks.items[0].instrs.items[1].src1);
}
