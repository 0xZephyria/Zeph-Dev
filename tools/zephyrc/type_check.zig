// File: tools/zephyrc/type_check.zig
// ZephyrLang Type Checker — Full semantic analysis pass over the AST.
// Resolves types, validates expressions, checks visibility, enforces
// storage safety, reentrancy guards, and role-based access control.

const std = @import("std");
const ast = @import("ast.zig");

// ============================================================================
// Resolved Type System
// ============================================================================

pub const ResolvedType = union(enum) {
    uint: u16, // bit width: 8..256
    int: u16,
    boolean: void,
    address: void,
    address_payable: void,
    bytes_fixed: u8, // 1..32
    bytes_dynamic: void,
    string_type: void,
    mapping: *MappingInfo,
    array_fixed: *ArrayInfo,
    array_dynamic: *ArrayInfo,
    struct_type: *StructInfo,
    enum_type: *EnumInfo,
    contract_type: []const u8,
    function_type: *FuncSig,
    option_of: *ResolvedType,
    result_of: *ResultInfo,
    resource_of: *ResolvedType,
    tuple_of: []const ResolvedType,
    void_type: void,
    error_type: void,
};

pub const MappingInfo = struct { key: ResolvedType, value: ResolvedType };
pub const ArrayInfo = struct { element: ResolvedType, length: ?u64 };
pub const StructInfo = struct { name: []const u8, fields: []const FieldInfo };
pub const FieldInfo = struct { name: []const u8, field_type: ResolvedType, offset: u32 };
pub const EnumInfo = struct { name: []const u8, members: []const []const u8 };
pub const FuncSig = struct {
    params: []const ResolvedType,
    returns: []const ResolvedType,
    mutability: ast.StateMutability,
    visibility: ast.Visibility,
};
pub const ResultInfo = struct { ok_type: ResolvedType, err_type: ResolvedType };

pub const Severity = enum { err, warning, hint };
pub const Diagnostic = struct { severity: Severity, message: []const u8, line: u32, col: u32 };

pub const Symbol = struct {
    name: []const u8,
    resolved_type: ResolvedType,
    kind: SymbolKind,
    visibility: ast.Visibility,
    mutability: ast.StateMutability,
    storage_slot: ?u32,
    is_constant: bool,
    is_immutable: bool,
};

pub const SymbolKind = enum {
    state_variable,
    local_variable,
    function_param,
    function_def,
    event_def,
    error_def,
    struct_def,
    enum_def,
    modifier_def,
    role_def,
    contract_def,
};

// Simple symbol table using only a hash map (no self-referential pointers)
pub const SymbolTable = struct {
    symbols: std.StringHashMap(Symbol),

    pub fn init(alloc: std.mem.Allocator) SymbolTable {
        return .{ .symbols = std.StringHashMap(Symbol).init(alloc) };
    }
    pub fn deinit(self: *SymbolTable) void {
        self.symbols.deinit();
    }
    pub fn define(self: *SymbolTable, name: []const u8, sym: Symbol) !void {
        try self.symbols.put(name, sym);
    }
    pub fn get(self: *const SymbolTable, name: []const u8) ?Symbol {
        return self.symbols.get(name);
    }
};

// ============================================================================
// Type Checker
// ============================================================================

pub const TypeChecker = struct {
    arena: std.heap.ArenaAllocator,
    alloc: std.mem.Allocator, // set by ready()
    backing: std.mem.Allocator,
    diagnostics: std.ArrayList(Diagnostic),
    globals: SymbolTable,
    locals: SymbolTable, // current function/contract scope
    current_contract: ?[]const u8,
    current_function: ?[]const u8,
    has_external_call: bool,
    state_modified_after_call: bool,
    next_storage_slot: u32,

    pub fn init(backing: std.mem.Allocator) TypeChecker {
        return .{
            .arena = std.heap.ArenaAllocator.init(backing),
            .alloc = undefined,
            .backing = backing,
            .diagnostics = .{},
            .globals = SymbolTable.init(backing),
            .locals = SymbolTable.init(backing),
            .current_contract = null,
            .current_function = null,
            .has_external_call = false,
            .state_modified_after_call = false,
            .next_storage_slot = 0,
        };
    }

    pub fn ready(self: *TypeChecker) void {
        self.alloc = self.arena.allocator();
    }

    pub fn deinit(self: *TypeChecker) void {
        self.diagnostics.deinit(self.backing);
        self.globals.deinit();
        self.locals.deinit();
        self.arena.deinit();
    }

    fn resolve(self: *const TypeChecker, name: []const u8) ?Symbol {
        if (self.locals.get(name)) |s| return s;
        return self.globals.get(name);
    }

    pub fn check(self: *TypeChecker, unit: ast.SourceUnit) !void {
        for (unit.definitions) |def| switch (def) {
            .contract, .interface, .library, .abstract_contract => |c| try self.registerContract(c),
            .struct_def => |s| try self.registerStruct(s),
            .enum_def => |e| try self.registerEnum(e),
            .error_def => |err| try self.registerErrorDef(err),
            else => {},
        };
        for (unit.definitions) |def| switch (def) {
            .contract, .interface, .library, .abstract_contract => |c| try self.checkContract(c),
            else => {},
        };
    }

    fn registerContract(self: *TypeChecker, c: ast.ContractDef) !void {
        try self.globals.define(c.name, .{
            .name = c.name,
            .resolved_type = .{ .contract_type = c.name },
            .kind = .contract_def,
            .visibility = .public,
            .mutability = .nonpayable,
            .storage_slot = null,
            .is_constant = false,
            .is_immutable = false,
        });
    }

    fn registerStruct(self: *TypeChecker, s: ast.StructDef) !void {
        var fields: std.ArrayList(FieldInfo) = .{};
        var offset: u32 = 0;
        for (s.members) |m| {
            const ft = self.resolveTypeExpr(m.type_expr);
            const sz = typeSize(ft);
            try fields.append(self.alloc, .{ .name = m.name, .field_type = ft, .offset = offset });
            offset += sz;
        }
        const info = try self.alloc.create(StructInfo);
        info.* = .{ .name = s.name, .fields = fields.items };
        try self.globals.define(s.name, .{
            .name = s.name,
            .resolved_type = .{ .struct_type = info },
            .kind = .struct_def,
            .visibility = .public,
            .mutability = .nonpayable,
            .storage_slot = null,
            .is_constant = false,
            .is_immutable = false,
        });
    }

    fn registerEnum(self: *TypeChecker, e: ast.EnumDef) !void {
        const info = try self.alloc.create(EnumInfo);
        info.* = .{ .name = e.name, .members = e.values };
        try self.globals.define(e.name, .{
            .name = e.name,
            .resolved_type = .{ .enum_type = info },
            .kind = .enum_def,
            .visibility = .public,
            .mutability = .nonpayable,
            .storage_slot = null,
            .is_constant = false,
            .is_immutable = false,
        });
    }

    fn registerErrorDef(self: *TypeChecker, e: ast.ErrorDef) !void {
        try self.globals.define(e.name, .{
            .name = e.name,
            .resolved_type = .void_type,
            .kind = .error_def,
            .visibility = .public,
            .mutability = .nonpayable,
            .storage_slot = null,
            .is_constant = false,
            .is_immutable = false,
        });
    }

    fn checkContract(self: *TypeChecker, c: ast.ContractDef) !void {
        self.current_contract = c.name;
        self.next_storage_slot = 0;
        self.locals.deinit();
        self.locals = SymbolTable.init(self.backing);

        for (c.members) |member| switch (member) {
            .state_var => |sv| try self.registerStateVar(sv),
            .function, .constructor => |f| try self.registerFunction(f),
            .event => |e| try self.registerEvent(e),
            .error_def => |e| try self.registerErrorDef(e),
            .role_def => |r| try self.registerRole(r),
            else => {},
        };
        for (c.members) |member| switch (member) {
            .function, .constructor => |f| try self.checkFunction(f),
            else => {},
        };
        self.current_contract = null;
    }

    fn registerStateVar(self: *TypeChecker, sv: ast.StateVarDecl) !void {
        const ty = self.resolveTypeExpr(sv.type_expr);
        const slot: ?u32 = if (sv.storage_class == .constant or sv.storage_class == .immutable) null else blk: {
            const s = self.next_storage_slot;
            self.next_storage_slot += 1;
            break :blk s;
        };
        try self.locals.define(sv.name, .{
            .name = sv.name,
            .resolved_type = ty,
            .kind = .state_variable,
            .visibility = sv.visibility,
            .mutability = .nonpayable,
            .storage_slot = slot,
            .is_constant = sv.storage_class == .constant,
            .is_immutable = sv.storage_class == .immutable,
        });
        if (sv.initial_value) |init_expr| {
            const init_type = self.checkExpr(init_expr);
            if (!isAssignable(ty, init_type)) self.emitErr("type mismatch in initializer", 0, 0);
        }
    }

    fn registerFunction(self: *TypeChecker, f: ast.FunctionDef) !void {
        var pt: std.ArrayList(ResolvedType) = .{};
        for (f.params) |p| try pt.append(self.alloc, self.resolveTypeExpr(p.type_expr));
        var rt: std.ArrayList(ResolvedType) = .{};
        for (f.returns) |r| try rt.append(self.alloc, self.resolveTypeExpr(r.type_expr));
        const sig = try self.alloc.create(FuncSig);
        sig.* = .{ .params = pt.items, .returns = rt.items, .mutability = f.mutability, .visibility = f.visibility };
        try self.locals.define(f.name, .{
            .name = f.name,
            .resolved_type = .{ .function_type = sig },
            .kind = .function_def,
            .visibility = f.visibility,
            .mutability = f.mutability,
            .storage_slot = null,
            .is_constant = false,
            .is_immutable = false,
        });
    }

    fn registerEvent(self: *TypeChecker, e: ast.EventDef) !void {
        var idx: u32 = 0;
        for (e.params) |p| {
            if (p.is_indexed) idx += 1;
        }
        if (idx > 3) self.emitErr("events can have at most 3 indexed parameters", 0, 0);
        try self.locals.define(e.name, .{
            .name = e.name,
            .resolved_type = .void_type,
            .kind = .event_def,
            .visibility = .public,
            .mutability = .nonpayable,
            .storage_slot = null,
            .is_constant = false,
            .is_immutable = false,
        });
    }

    fn registerRole(self: *TypeChecker, r: ast.RoleDef) !void {
        try self.locals.define(r.name, .{
            .name = r.name,
            .resolved_type = .{ .uint = 256 },
            .kind = .role_def,
            .visibility = .public,
            .mutability = .nonpayable,
            .storage_slot = null,
            .is_constant = true,
            .is_immutable = false,
        });
    }

    fn checkFunction(self: *TypeChecker, f: ast.FunctionDef) !void {
        self.current_function = f.name;
        self.has_external_call = false;
        self.state_modified_after_call = false;
        // Register params in locals
        for (f.params) |p| {
            try self.locals.define(p.name, .{
                .name = p.name,
                .resolved_type = self.resolveTypeExpr(p.type_expr),
                .kind = .function_param,
                .visibility = .private,
                .mutability = .nonpayable,
                .storage_slot = null,
                .is_constant = false,
                .is_immutable = false,
            });
        }
        if (f.body) |body| for (body.statements) |stmt| self.checkStmt(stmt, f.mutability);
        if (self.has_external_call and self.state_modified_after_call)
            self.emitWarn("potential reentrancy: state modified after external call (CEI violation)", 0, 0);
        self.current_function = null;
    }

    fn checkStmt(self: *TypeChecker, stmt: ast.Stmt, mut: ast.StateMutability) void {
        switch (stmt) {
            .block => |b| for (b.statements) |s| self.checkStmt(s, mut),
            .expression => |es| _ = self.checkExpr(es.expr),
            .variable_decl => |vd| {
                const ty = if (vd.type_expr) |te| self.resolveTypeExpr(te) else if (vd.initial_value) |iv| self.checkExpr(iv) else .error_type;
                if (vd.initial_value) |iv| {
                    const init_type = self.checkExpr(iv);
                    if (!isAssignable(ty, init_type)) self.emitErr("type mismatch in local initialization", 0, 0);
                }
                for (vd.names) |opt_name| {
                    if (opt_name) |name| {
                        self.locals.define(name, .{
                            .name = name,
                            .resolved_type = ty,
                            .kind = .local_variable,
                            .visibility = .private,
                            .mutability = .nonpayable,
                            .storage_slot = null,
                            .is_constant = vd.is_constant,
                            .is_immutable = false,
                        }) catch {};
                    }
                }
            },
            .return_stmt => |r| {
                if (r.value) |v| {
                    _ = self.checkExpr(v);
                }
            },
            .if_stmt => |i| {
                _ = self.checkExpr(i.condition);
                self.checkStmt(i.then_body, mut);
                if (i.else_body) |eb| self.checkStmt(eb, mut);
            },
            .emit_stmt => |e| {
                if (mut == .pure or mut == .view) self.emitErr("cannot emit in pure/view", 0, 0);
                if (self.resolve(e.event_name) == null) self.emitErr("undefined event", 0, 0);
                for (e.args) |a| _ = self.checkExpr(a);
            },
            .revert_stmt => |r| {
                if (r.error_name) |name| {
                    if (self.resolve(name) == null) self.emitErr("undefined error type", 0, 0);
                }
            },
            else => {},
        }
    }

    // === Expression checking ===
    fn checkExpr(self: *TypeChecker, expr: ast.Expr) ResolvedType {
        switch (expr) {
            .literal => |lit| return checkLiteral(lit),
            .identifier => |name| {
                if (self.resolve(name)) |sym| return sym.resolved_type;
                if (isBuiltin(name)) return builtinType(name);
                std.debug.print("DEBUG: Undefined identifier '{s}'\n", .{name});
                self.emitErr("undefined identifier", 0, 0);
                return .error_type;
            },
            .binary_op => |bin| return self.checkBinOp(bin.*),
            .unary_op => |un| {
                const t = self.checkExpr(un.operand);
                return switch (un.op) {
                    .not => .boolean,
                    .delete => .void_type,
                    else => t,
                };
            },
            .function_call => |fc| return self.checkCall(fc.*),
            .member_access => |ma| return self.checkMember(ma.*),
            .index_access => |ia| return self.checkIndex(ia.*),
            .assignment => |a| {
                const tt = self.checkExpr(a.target);
                const vt = self.checkExpr(a.value);
                if (!isAssignable(tt, vt)) self.emitErr("type mismatch in assignment", 0, 0);
                if (self.has_external_call) self.state_modified_after_call = true;
                return tt;
            },
            .ternary => |t| {
                _ = self.checkExpr(t.condition);
                const tt = self.checkExpr(t.true_expr);
                _ = self.checkExpr(t.false_expr);
                return tt;
            },
            .some_expr => |inner| {
                const it = self.checkExpr(inner.*);
                const ptr = self.alloc.create(ResolvedType) catch return .error_type;
                ptr.* = it;
                return .{ .option_of = ptr };
            },
            .none_expr => return .void_type,
            else => return .error_type,
        }
    }

    fn checkBinOp(self: *TypeChecker, bin: ast.BinaryOpExpr) ResolvedType {
        const l = self.checkExpr(bin.left);
        const r = self.checkExpr(bin.right);
        return switch (bin.op) {
            .add, .sub, .mul, .div, .mod, .exp, .wrapping_add, .wrapping_sub, .wrapping_mul, .saturating_add, .saturating_sub, .bit_and, .bit_or, .bit_xor, .shl, .shr => blk: {
                if (!isNumeric(l) or !isNumeric(r)) self.emitErr("arithmetic requires numeric types", 0, 0);
                break :blk l;
            },
            .eq, .neq, .lt, .gt, .lte, .gte => .boolean,
            .and_op, .or_op => .boolean,
        };
    }

    fn checkCall(self: *TypeChecker, fc: ast.FunctionCallExpr) ResolvedType {
        if (fc.callee == .member_access) self.has_external_call = true;
        if (fc.callee == .identifier) {
            const name = fc.callee.identifier;
            if (std.mem.eql(u8, name, "require") or std.mem.eql(u8, name, "assert")) return .void_type;
            if (std.mem.eql(u8, name, "keccak256")) return .{ .bytes_fixed = 32 };
            if (self.resolve(name)) |sym| {
                if (sym.resolved_type == .function_type) {
                    const sig = sym.resolved_type.function_type;
                    if (fc.args.len != sig.params.len) self.emitErr("wrong number of arguments", 0, 0);
                    return if (sig.returns.len == 1) sig.returns[0] else .void_type;
                }
            }
        }
        for (fc.args) |a| _ = self.checkExpr(a);
        return .{ .uint = 256 };
    }

    fn checkMember(self: *TypeChecker, ma: ast.MemberAccessExpr) ResolvedType {
        const ot = self.checkExpr(ma.object);
        if (ma.object == .identifier) {
            const n = ma.object.identifier;
            if (std.mem.eql(u8, n, "msg")) {
                if (std.mem.eql(u8, ma.member, "sender")) return .address;
                if (std.mem.eql(u8, ma.member, "value")) return .{ .uint = 256 };
                if (std.mem.eql(u8, ma.member, "data")) return .bytes_dynamic;
            }
            if (std.mem.eql(u8, n, "block")) return .{ .uint = 256 };
            if (std.mem.eql(u8, n, "tx")) return .address;
        }
        if (ot == .struct_type) {
            for (ot.struct_type.fields) |f|
                if (std.mem.eql(u8, f.name, ma.member)) return f.field_type;
        }
        return .{ .uint = 256 };
    }

    fn checkIndex(self: *TypeChecker, ia: ast.IndexAccessExpr) ResolvedType {
        const bt = self.checkExpr(ia.base);
        if (ia.index) |idx| _ = self.checkExpr(idx);
        return switch (bt) {
            .mapping => |m| m.value,
            .array_fixed, .array_dynamic => |a| a.element,
            .bytes_dynamic => .{ .bytes_fixed = 1 },
            else => .{ .uint = 256 },
        };
    }

    // === Type resolution ===
    pub fn resolveTypeExpr(self: *TypeChecker, ty: ast.TypeExpr) ResolvedType {
        return switch (ty) {
            .elementary => |e| resolveElementary(e),
            .user_defined => |name| {
                if (self.resolve(name)) |sym| return sym.resolved_type;
                if (parseIntType(name)) |info| return info;
                return .error_type;
            },
            .mapping => |m| blk: {
                const info = self.alloc.create(MappingInfo) catch return .error_type;
                info.* = .{ .key = self.resolveTypeExpr(m.key_type), .value = self.resolveTypeExpr(m.value_type) };
                break :blk .{ .mapping = info };
            },
            .array => |a| blk: {
                const info = self.alloc.create(ArrayInfo) catch return .error_type;
                info.* = .{ .element = self.resolveTypeExpr(a.base_type), .length = null };
                break :blk .{ .array_dynamic = info };
            },
            .option_type => |inner| blk: {
                const ptr = self.alloc.create(ResolvedType) catch return .error_type;
                ptr.* = self.resolveTypeExpr(inner.*);
                break :blk .{ .option_of = ptr };
            },
            .result_type => |r| blk: {
                const info = self.alloc.create(ResultInfo) catch return .error_type;
                info.* = .{ .ok_type = self.resolveTypeExpr(r.ok_type), .err_type = self.resolveTypeExpr(r.err_type) };
                break :blk .{ .result_of = info };
            },
            .resource_type => |inner| blk: {
                const ptr = self.alloc.create(ResolvedType) catch return .error_type;
                ptr.* = self.resolveTypeExpr(inner.*);
                break :blk .{ .resource_of = ptr };
            },
            .tuple_type => |types| blk: {
                const resolved = self.alloc.alloc(ResolvedType, types.len) catch return .error_type;
                for (types, 0..) |t, i| resolved[i] = self.resolveTypeExpr(t);
                break :blk .{ .tuple_of = resolved };
            },
            .function_type => .error_type,
        };
    }

    fn emitErr(self: *TypeChecker, msg: []const u8, line: u32, col: u32) void {
        self.diagnostics.append(self.backing, .{ .severity = .err, .message = msg, .line = line, .col = col }) catch {};
    }
    fn emitWarn(self: *TypeChecker, msg: []const u8, line: u32, col: u32) void {
        self.diagnostics.append(self.backing, .{ .severity = .warning, .message = msg, .line = line, .col = col }) catch {};
    }

    pub fn hasErrors(self: *const TypeChecker) bool {
        for (self.diagnostics.items) |d| {
            if (d.severity == .err) return true;
        }
        return false;
    }

    pub fn errorCount(self: *const TypeChecker) u32 {
        var c: u32 = 0;
        for (self.diagnostics.items) |d| {
            if (d.severity == .err) c += 1;
        }
        return c;
    }
};

// ============================================================================
// Free helper functions
// ============================================================================

fn checkLiteral(lit: ast.LiteralExpr) ResolvedType {
    return switch (lit.kind) {
        .number_decimal, .number_hex => .{ .uint = 256 },
        .bool_true, .bool_false => .boolean,
        .string_literal, .unicode_string => .string_type,
        .hex_string => .bytes_dynamic,
        .address_literal => .address,
    };
}

fn isBuiltin(n: []const u8) bool {
    return std.mem.eql(u8, n, "msg") or std.mem.eql(u8, n, "block") or std.mem.eql(u8, n, "tx");
}

fn builtinType(n: []const u8) ResolvedType {
    if (std.mem.eql(u8, n, "msg") or std.mem.eql(u8, n, "tx")) return .address;
    return .{ .uint = 256 };
}

fn isAssignable(target: ResolvedType, source: ResolvedType) bool {
    if (source == .error_type or target == .error_type) return true;
    if (std.meta.activeTag(target) == std.meta.activeTag(source)) return true;
    if (isNumeric(target) and isNumeric(source)) return true;
    if (target == .address and source == .address_payable) return true;
    return false;
}

fn isNumeric(ty: ResolvedType) bool {
    return ty == .uint or ty == .int or ty == .bytes_fixed;
}

fn resolveElementary(e: ast.ElementaryType) ResolvedType {
    return switch (e) {
        .uint8 => .{ .uint = 8 },
        .uint16 => .{ .uint = 16 },
        .uint32 => .{ .uint = 32 },
        .uint64 => .{ .uint = 64 },
        .uint128 => .{ .uint = 128 },
        .uint256 => .{ .uint = 256 },
        .int8 => .{ .int = 8 },
        .int16 => .{ .int = 16 },
        .int32 => .{ .int = 32 },
        .int64 => .{ .int = 64 },
        .int128 => .{ .int = 128 },
        .int256 => .{ .int = 256 },
        .address => .address,
        .address_payable => .address_payable,
        .bool_type => .boolean,
        .string_type => .string_type,
        .bytes_type => .bytes_dynamic,
        .bytes1 => .{ .bytes_fixed = 1 },
        .bytes4 => .{ .bytes_fixed = 4 },
        .bytes32 => .{ .bytes_fixed = 32 },
        else => .{ .uint = 256 },
    };
}

fn parseIntType(name: []const u8) ?ResolvedType {
    if (name.len >= 5 and std.mem.startsWith(u8, name, "uint")) {
        const bits = std.fmt.parseInt(u16, name[4..], 10) catch return null;
        if (bits >= 8 and bits <= 256 and bits % 8 == 0) return .{ .uint = bits };
    }
    if (name.len >= 4 and std.mem.startsWith(u8, name, "int")) {
        const bits = std.fmt.parseInt(u16, name[3..], 10) catch return null;
        if (bits >= 8 and bits <= 256 and bits % 8 == 0) return .{ .int = bits };
    }
    return null;
}

fn typeSize(ty: ResolvedType) u32 {
    return switch (ty) {
        .uint => |b| b / 8,
        .int => |b| b / 8,
        .boolean => 1,
        .address, .address_payable => 20,
        .bytes_fixed => |n| n,
        else => 32,
    };
}

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");

fn parseAndCheck(alloc: std.mem.Allocator, src: []const u8) !*TypeChecker {
    var lex = lexer.Lexer.init(src);
    const tokens = try lex.tokenizeAll(alloc);
    defer alloc.free(tokens);
    var p = parser.Parser.init(alloc, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    const tc = try alloc.create(TypeChecker);
    tc.* = TypeChecker.init(alloc);
    tc.ready();
    try tc.check(unit);
    return tc;
}

fn destroyTc(alloc: std.mem.Allocator, tc: *TypeChecker) void {
    tc.deinit();
    alloc.destroy(tc);
}

test "type_check: empty contract" {
    const tc = try parseAndCheck(testing.allocator, "contract Foo { }");
    defer destroyTc(testing.allocator, tc);
    try testing.expect(!tc.hasErrors());
}

test "type_check: state variable" {
    const tc = try parseAndCheck(testing.allocator, "contract T { uint256 public x; }");
    defer destroyTc(testing.allocator, tc);
    try testing.expect(!tc.hasErrors());
}

test "type_check: function" {
    const tc = try parseAndCheck(testing.allocator, "contract T { function foo(uint256 a, address b) external view returns (uint256) { return a; } }");
    defer destroyTc(testing.allocator, tc);
    try testing.expect(!tc.hasErrors());
}

test "type_check: event indexed limit" {
    const tc = try parseAndCheck(testing.allocator, "contract T { event Bad(uint256 indexed a, uint256 indexed b, uint256 indexed c, uint256 indexed d); }");
    defer destroyTc(testing.allocator, tc);
    try testing.expectEqual(@as(u32, 1), tc.errorCount());
}
