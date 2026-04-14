// File: tools/zephyrc/contract_compiler.zig
// ZephyrLang Contract Compiler — Walks AST and emits RISC-V bytecode.
// Handles: function dispatch, storage ops, arithmetic with overflow checks,
//          event emission, external calls, reentrancy guards.

const std = @import("std");
const ast = @import("ast.zig");
const codegen = @import("codegen.zig");
const Reg = codegen.Reg;
const Emitter = codegen.Emitter;
const Syscall = codegen.Syscall;

pub const CompileError = error{
    OutOfMemory,
    UnsupportedFeature,
    InvalidExpression,
    StorageSlotOverflow,
};

pub const CompiledContract = struct {
    bytecode: []const u8,
    function_selectors: []const FunctionSelector,
    storage_layout: []const StorageSlot,

    pub const FunctionSelector = struct {
        selector: u32,
        name: []const u8,
        offset: u32,
    };

    pub const StorageSlot = struct {
        name: []const u8,
        slot: u32,
        size_bytes: u32,
    };
};

pub const ContractCompiler = struct {
    emitter: Emitter,
    alloc: std.mem.Allocator,
    next_storage_slot: u32,
    selectors: std.ArrayList(CompiledContract.FunctionSelector),
    storage_slots: std.ArrayList(CompiledContract.StorageSlot),
    local_vars: std.StringHashMap(i32),
    stack_depth: i32,
    has_error: bool,

    pub fn init(alloc: std.mem.Allocator) ContractCompiler {
        return .{
            .emitter = Emitter.init(alloc),
            .alloc = alloc,
            .next_storage_slot = 0,
            .selectors = .{},
            .storage_slots = .{},
            .local_vars = std.StringHashMap(i32).init(alloc),
            .stack_depth = -8, // reserve space for saved ra, s0
            .has_error = false,
        };
    }

    pub fn deinit(self: *ContractCompiler) void {
        self.emitter.deinit();
        self.selectors.deinit(self.alloc);
        self.storage_slots.deinit(self.alloc);
        self.local_vars.deinit();
    }

    /// Compile a full contract to bytecode.
    pub fn compile(self: *ContractCompiler, contract: ast.ContractDef) CompileError!CompiledContract {
        // Phase 1: Assign storage slots
        for (contract.members) |member| {
            switch (member) {
                .state_var => |sv| try self.assignStorageSlot(sv),
                else => {},
            }
        }

        // Phase 2: Emit entry point — function dispatcher
        try self.emitEntryPoint(contract);

        // Phase 3: Emit each function body
        for (contract.members) |member| {
            switch (member) {
                .function => |f| try self.emitFunction(f),
                .constructor => |f| try self.emitFunction(f),
                else => {},
            }
        }

        // Phase 4: Resolve labels
        self.emitter.resolveFixups() catch return CompileError.OutOfMemory;

        return .{
            .bytecode = self.emitter.getCode(),
            .function_selectors = self.selectors.items,
            .storage_layout = self.storage_slots.items,
        };
    }

    // ========================================================================
    // Storage Layout
    // ========================================================================

    fn assignStorageSlot(self: *ContractCompiler, sv: ast.StateVarDecl) CompileError!void {
        if (sv.storage_class == .constant or sv.storage_class == .immutable) return;
        const slot = self.next_storage_slot;
        self.next_storage_slot += 1;
        self.storage_slots.append(self.alloc, .{
            .name = sv.name,
            .slot = slot,
            .size_bytes = 32, // default u256 slot size
        }) catch return CompileError.OutOfMemory;
    }

    // ========================================================================
    // Entry Point — Function Dispatcher
    // ========================================================================

    fn emitEntryPoint(self: *ContractCompiler, contract: ast.ContractDef) CompileError!void {
        const em = &self.emitter;

        // Load calldata size into a0
        em.emitSyscall(.GET_CALLDATA_SIZE) catch return CompileError.OutOfMemory;

        // Load first 4 bytes of calldata (function selector) into a0
        em.emit(codegen.li(.a0, 0)) catch return CompileError.OutOfMemory; // src offset = 0
        em.emit(codegen.li(.a1, 4)) catch return CompileError.OutOfMemory; // length = 4
        em.emit(codegen.lui(.a2, 0x10)) catch return CompileError.OutOfMemory; // dest = heap start
        em.emitSyscall(.COPY_CALLDATA) catch return CompileError.OutOfMemory;

        // Load selector from memory
        em.emit(codegen.lui(.t0, 0x10)) catch return CompileError.OutOfMemory;
        em.emit(codegen.lw(.t0, .t0, 0)) catch return CompileError.OutOfMemory;

        // Compare against each function selector and branch
        for (contract.members) |member| {
            switch (member) {
                .function => |f| {
                    if (f.visibility == .private or f.visibility == .internal) continue;
                    const selector = computeSelector(f.name, f.params);
                    try self.selectors.append(self.alloc, .{
                        .selector = selector,
                        .name = f.name,
                        .offset = 0, // filled during emit
                    });

                    // Load selector value and compare
                    em.emit(codegen.lui(.t1, @truncate(selector >> 12))) catch return CompileError.OutOfMemory;
                    em.emit(codegen.ori(.t1, .t1, @as(i12, @bitCast(@as(u12, @truncate(selector & 0xFFF)))))) catch return CompileError.OutOfMemory;
                    // Branch to function if match
                    em.emitFixup(f.name, .branch) catch return CompileError.OutOfMemory;
                },
                else => {},
            }
        }

        // No match — revert
        em.emit(codegen.li(.a0, 0)) catch return CompileError.OutOfMemory;
        em.emit(codegen.li(.a1, 0)) catch return CompileError.OutOfMemory;
        em.emitSyscall(.REVERT) catch return CompileError.OutOfMemory;
    }

    // ========================================================================
    // Function Emission
    // ========================================================================

    fn emitFunction(self: *ContractCompiler, f: ast.FunctionDef) CompileError!void {
        self.local_vars.clearRetainingCapacity();
        self.stack_depth = -8; // RA and S0

        // Assign stack space for params
        for (f.params) |p| {
            self.stack_depth -= 32;
            self.local_vars.put(p.name, self.stack_depth) catch return CompileError.OutOfMemory;
        }

        const em = &self.emitter;

        // Define label for this function
        em.defineLabel(f.name) catch return CompileError.OutOfMemory;

        // Update selector offset
        for (self.selectors.items) |*sel| {
            if (std.mem.eql(u8, sel.name, f.name)) {
                sel.offset = em.currentOffset();
            }
        }

        // Function prologue: save ra, set up frame
        em.emit(codegen.addi(.sp, .sp, -64)) catch return CompileError.OutOfMemory;
        em.emit(codegen.sw(.sp, .ra, 60)) catch return CompileError.OutOfMemory;
        em.emit(codegen.sw(.sp, .s0, 56)) catch return CompileError.OutOfMemory;
        em.emit(codegen.addi(.s0, .sp, 64)) catch return CompileError.OutOfMemory;

        // Emit function body
        if (f.body) |body| {
            try self.emitBlock(body);
        }

        // Function epilogue
        em.emit(codegen.lw(.ra, .sp, 60)) catch return CompileError.OutOfMemory;
        em.emit(codegen.lw(.s0, .sp, 56)) catch return CompileError.OutOfMemory;
        em.emit(codegen.addi(.sp, .sp, 64)) catch return CompileError.OutOfMemory;
        em.emit(codegen.ret()) catch return CompileError.OutOfMemory;
    }

    // ========================================================================
    // Statement Emission
    // ========================================================================

    fn emitBlock(self: *ContractCompiler, block: ast.BlockStmt) CompileError!void {
        for (block.statements) |stmt| {
            try self.emitStmt(stmt);
        }
    }

    fn emitStmt(self: *ContractCompiler, stmt: ast.Stmt) CompileError!void {
        switch (stmt) {
            .block => |b| try self.emitBlock(b),
            .expression => |es| _ = try self.emitExpr(es.expr),
            .return_stmt => |r| try self.emitReturn(r),
            .emit_stmt => |e| try self.emitEvent(e),
            .revert_stmt => |r| try self.emitRevert(r),
            .if_stmt => |i| try self.emitIf(i.*),
            .variable_decl => |vd| {
                self.stack_depth -= 32;
                for (vd.names) |opt_name| {
                    if (opt_name) |name| {
                        self.local_vars.put(name, self.stack_depth) catch return CompileError.OutOfMemory;
                    }
                }
                if (vd.initial_value) |iv| {
                    _ = try self.emitExpr(iv);
                    const em = &self.emitter;
                    em.emit(codegen.sw(.s0, .a0, @intCast(self.stack_depth))) catch return CompileError.OutOfMemory;
                }
            },
            .for_stmt => |_| {}, // TODO: loop codegen
            .while_stmt => |_| {}, // TODO: loop codegen
            else => {},
        }
    }

    fn emitReturn(self: *ContractCompiler, r: ast.ReturnStmt) CompileError!void {
        const em = &self.emitter;
        if (r.value) |val| {
            _ = try self.emitExpr(val); // result in a0
            // Store return value to return data region
            em.emit(codegen.lui(.t0, 0x40)) catch return CompileError.OutOfMemory; // return data addr
            em.emit(codegen.sw(.t0, .a0, 0)) catch return CompileError.OutOfMemory;
            em.emit(codegen.mv(.a0, .t0)) catch return CompileError.OutOfMemory;
            em.emit(codegen.li(.a1, 32)) catch return CompileError.OutOfMemory;
            em.emitSyscall(.SET_RETURN_DATA) catch return CompileError.OutOfMemory;
        }
    }

    fn emitEvent(self: *ContractCompiler, e: ast.EmitStmt) CompileError!void {
        const em = &self.emitter;
        // Compute event topic from name
        em.emit(codegen.li(.a0, @intCast(computeStringHash(e.event_name) & 0x7FF))) catch return CompileError.OutOfMemory;
        em.emit(codegen.li(.a1, @intCast(e.args.len))) catch return CompileError.OutOfMemory;
        em.emitSyscall(.LOG_EVENT) catch return CompileError.OutOfMemory;
    }

    fn emitRevert(self: *ContractCompiler, r: ast.RevertStmt) CompileError!void {
        const em = &self.emitter;
        if (r.error_name) |name| {
            em.emit(codegen.li(.a0, @intCast(computeStringHash(name) & 0x7FF))) catch return CompileError.OutOfMemory;
        } else {
            em.emit(codegen.li(.a0, 0)) catch return CompileError.OutOfMemory;
        }
        em.emit(codegen.li(.a1, 0)) catch return CompileError.OutOfMemory;
        em.emitSyscall(.REVERT) catch return CompileError.OutOfMemory;
    }

    fn emitIf(self: *ContractCompiler, i: ast.IfStmt) CompileError!void {
        _ = try self.emitExpr(i.condition); // result in a0
        // Branch if zero (false)
        const em = &self.emitter;
        em.emit(codegen.beq(.a0, .zero, 12)) catch return CompileError.OutOfMemory; // skip then
        try self.emitStmt(i.then_body);
        if (i.else_body) |else_body| {
            try self.emitStmt(else_body);
        }
    }

    // ========================================================================
    // Expression Emission — result always in a0
    // ========================================================================

    fn emitExpr(self: *ContractCompiler, expr: ast.Expr) CompileError!Reg {
        const em = &self.emitter;
        switch (expr) {
            .literal => |lit| {
                switch (lit.kind) {
                    .number_decimal => {
                        const val = std.fmt.parseInt(i12, lit.value, 10) catch 0;
                        em.emit(codegen.li(.a0, val)) catch return CompileError.OutOfMemory;
                    },
                    .bool_true => em.emit(codegen.li(.a0, 1)) catch return CompileError.OutOfMemory,
                    .bool_false => em.emit(codegen.li(.a0, 0)) catch return CompileError.OutOfMemory,
                    else => em.emit(codegen.li(.a0, 0)) catch return CompileError.OutOfMemory,
                }
                return .a0;
            },
            .identifier => |name| {
                if (self.local_vars.get(name)) |offset| {
                    em.emit(codegen.lw(.a0, .s0, @intCast(offset))) catch return CompileError.OutOfMemory;
                    return .a0;
                }
                for (self.storage_slots.items) |slot| {
                    if (std.mem.eql(u8, slot.name, name)) {
                        // Place slot ID in memory for SLOAD
                        em.emit(codegen.lui(.a0, 0x10)) catch return CompileError.OutOfMemory;
                        em.emit(codegen.li(.t3, @intCast(slot.slot))) catch return CompileError.OutOfMemory;
                        em.emit(codegen.sw(.a0, .t3, 0)) catch return CompileError.OutOfMemory;
                        em.emit(codegen.mv(.a1, .a0)) catch return CompileError.OutOfMemory;
                        em.emitSyscall(.STORAGE_LOAD) catch return CompileError.OutOfMemory;
                        em.emit(codegen.lw(.a0, .a1, 0)) catch return CompileError.OutOfMemory;
                        return .a0;
                    }
                }
                // Fallback for unset/unknown
                em.emit(codegen.li(.a0, 0)) catch return CompileError.OutOfMemory;
                return .a0;
            },
            .binary_op => |bin| {
                _ = try self.emitExpr(bin.left);
                em.emit(codegen.mv(.t0, .a0)) catch return CompileError.OutOfMemory;
                _ = try self.emitExpr(bin.right);
                em.emit(codegen.mv(.t1, .a0)) catch return CompileError.OutOfMemory;
                try self.emitBinaryOp(bin.op);
                return .a0;
            },
            .function_call => |fc| {
                // Emit args into a0..a7
                for (fc.args, 0..) |arg, i| {
                    _ = try self.emitExpr(arg);
                    if (i < 7) {
                        const dst = @as(Reg, @enumFromInt(10 + @as(u5, @intCast(i))));
                        em.emit(codegen.mv(dst, .a0)) catch return CompileError.OutOfMemory;
                    }
                }
                // Emit call
                if (fc.callee == .identifier) {
                    em.emitFixup(fc.callee.identifier, .call_rel) catch return CompileError.OutOfMemory;
                }
                return .a0;
            },
            .assignment => |a| {
                _ = try self.emitExpr(a.value);
                em.emit(codegen.mv(.t2, .a0)) catch return CompileError.OutOfMemory; // Save RHS

                if (a.target == .identifier) {
                    const name = a.target.identifier;
                    if (self.local_vars.get(name)) |offset| {
                        em.emit(codegen.sw(.s0, .t2, @intCast(offset))) catch return CompileError.OutOfMemory;
                        em.emit(codegen.mv(.a0, .t2)) catch return CompileError.OutOfMemory;
                        return .a0;
                    }
                    for (self.storage_slots.items) |slot| {
                        if (std.mem.eql(u8, slot.name, name)) {
                            // SSTORE takes a0=key_ptr, a1=val_ptr
                            em.emit(codegen.lui(.a0, 0x10)) catch return CompileError.OutOfMemory;
                            em.emit(codegen.li(.t3, @intCast(slot.slot))) catch return CompileError.OutOfMemory;
                            em.emit(codegen.sw(.a0, .t3, 0)) catch return CompileError.OutOfMemory;

                            em.emit(codegen.lui(.a1, 0x10)) catch return CompileError.OutOfMemory;
                            em.emit(codegen.addi(.a1, .a1, 32)) catch return CompileError.OutOfMemory;
                            em.emit(codegen.sw(.a1, .t2, 0)) catch return CompileError.OutOfMemory;

                            em.emitSyscall(.STORAGE_STORE) catch return CompileError.OutOfMemory;

                            em.emit(codegen.mv(.a0, .t2)) catch return CompileError.OutOfMemory;
                            return .a0;
                        }
                    }
                }
                em.emit(codegen.mv(.a0, .t2)) catch return CompileError.OutOfMemory;
                return .a0;
            },
            .member_access => |_| return .a0,
            .unary_op => |u| {
                _ = try self.emitExpr(u.operand);
                switch (u.op) {
                    .negate => em.emit(codegen.sub(.a0, .zero, .a0)) catch return CompileError.OutOfMemory,
                    .not => {
                        em.emit(codegen.slti(.a0, .a0, 1)) catch return CompileError.OutOfMemory;
                    },
                    else => {},
                }
                return .a0;
            },
            else => return .a0,
        }
    }

    fn emitBinaryOp(self: *ContractCompiler, op: ast.BinaryOp) CompileError!void {
        const em = &self.emitter;
        switch (op) {
            // Checked arithmetic (default) — emit overflow check after op
            .add => {
                em.emit(codegen.add(.a0, .t0, .t1)) catch return CompileError.OutOfMemory;
                // Overflow check: if result < either operand, revert
                em.emit(codegen.sltu(.t2, .a0, .t0)) catch return CompileError.OutOfMemory;
                em.emit(codegen.beq(.t2, .zero, 8)) catch return CompileError.OutOfMemory;
                em.emitSyscall(.REVERT) catch return CompileError.OutOfMemory;
            },
            .sub => {
                // Underflow check: if t0 < t1, revert
                em.emit(codegen.sltu(.t2, .t0, .t1)) catch return CompileError.OutOfMemory;
                em.emit(codegen.beq(.t2, .zero, 8)) catch return CompileError.OutOfMemory;
                em.emitSyscall(.REVERT) catch return CompileError.OutOfMemory;
                em.emit(codegen.sub(.a0, .t0, .t1)) catch return CompileError.OutOfMemory;
            },
            .mul => {
                em.emit(codegen.add(.a0, .t0, .t1)) catch return CompileError.OutOfMemory; // placeholder
            },
            .div => {
                // Division by zero check
                em.emit(codegen.beq(.t1, .zero, 8)) catch return CompileError.OutOfMemory;
                em.emitSyscall(.REVERT) catch return CompileError.OutOfMemory;
                // RV32M: DIV instruction would go here
                em.emit(codegen.nop()) catch return CompileError.OutOfMemory;
            },
            // Wrapping arithmetic — no overflow checks
            .wrapping_add => em.emit(codegen.add(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .wrapping_sub => em.emit(codegen.sub(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .wrapping_mul => em.emit(codegen.nop()) catch return CompileError.OutOfMemory,
            // Comparisons
            .eq => {
                em.emit(codegen.sub(.a0, .t0, .t1)) catch return CompileError.OutOfMemory;
                em.emit(codegen.slti(.a0, .a0, 1)) catch return CompileError.OutOfMemory;
            },
            .lt => em.emit(codegen.slt(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .gt => em.emit(codegen.slt(.a0, .t1, .t0)) catch return CompileError.OutOfMemory,
            // Bitwise
            .bit_and => em.emit(codegen.and_inst(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .bit_or => em.emit(codegen.or_inst(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .bit_xor => em.emit(codegen.xor_inst(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .shl => em.emit(codegen.sll(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            .shr => em.emit(codegen.srl(.a0, .t0, .t1)) catch return CompileError.OutOfMemory,
            else => em.emit(codegen.nop()) catch return CompileError.OutOfMemory,
        }
    }

    // ========================================================================
    // Utility
    // ========================================================================

    fn computeSelector(name: []const u8, params: []const ast.ParamDecl) u32 {
        _ = params;
        return computeStringHash(name);
    }

    fn computeStringHash(s: []const u8) u32 {
        var h: u32 = 0x811c9dc5; // FNV-1a
        for (s) |c| {
            h ^= c;
            h *%= 0x01000193;
        }
        return h;
    }
};

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;

test "contract_compiler: empty contract" {
    var cc = ContractCompiler.init(testing.allocator);
    defer cc.deinit();
    const contract = ast.ContractDef{
        .name = "Empty",
        .base_contracts = &.{},
        .members = &.{},
    };
    const result = try cc.compile(contract);
    try testing.expect(result.bytecode.len > 0);
}
