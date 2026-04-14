// File: tools/sol2zig/ast.zig
// Expression and Statement AST node types for the Solidity-to-Zig transpiler
// These types represent the structured parse tree for function bodies,
// enabling proper code generation instead of raw text passthrough.

const std = @import("std");

// ============================================================================
// Expression AST Nodes
// ============================================================================

pub const Expression = union(enum) {
    literal: LiteralExpr,
    identifier: IdentifierExpr,
    binary_op: *BinaryOpExpr,
    unary_op: *UnaryOpExpr,
    member_access: *MemberAccessExpr,
    function_call: *FunctionCallExpr,
    index_access: *IndexAccessExpr,
    conditional: *ConditionalExpr,
    assignment: *AssignmentExpr,
    type_cast: *TypeCastExpr,
    new_expression: *NewExpr,
    tuple: *TupleExpr,
    elementary_type: ElementaryTypeExpr,
    array_literal: *ArrayLiteralExpr,
    state_var_ref: StateVarRefExpr,
    delete_expr: *DeleteExpr,
    // Special Solidity expressions
    emit_expr: *EmitExpr,
    abi_call: *AbiCallExpr,
    type_info: *TypeInfoExpr,

    pub fn format(self: Expression, comptime _: []const u8, _: std.fmt.FormatOptions, _: anytype) !void {
        _ = self;
    }
};

pub const LiteralExpr = struct {
    value: []const u8,
    kind: LiteralKind,
};

pub const LiteralKind = enum {
    number_decimal,
    number_hex,
    string_literal,
    bool_true,
    bool_false,
    hex_string,
    unicode_string,
};

pub const IdentifierExpr = struct {
    name: []const u8,
};

pub const BinaryOpExpr = struct {
    left: Expression,
    op: BinaryOp,
    right: Expression,
};

pub const BinaryOp = enum {
    // Arithmetic
    add, // +
    sub, // -
    mul, // *
    div, // /
    mod, // %
    exp, // **
    // Comparison
    eq, // ==
    neq, // !=
    lt, // <
    gt, // >
    lte, // <=
    gte, // >=
    // Logical
    and_, // &&
    or_, // ||
    // Bitwise
    bit_and, // &
    bit_or, // |
    bit_xor, // ^
    shl, // <<
    shr, // >>

    pub fn toString(self: BinaryOp) []const u8 {
        return switch (self) {
            .add => "+",
            .sub => "-",
            .mul => "*",
            .div => "/",
            .mod => "%",
            .exp => "**",
            .eq => "==",
            .neq => "!=",
            .lt => "<",
            .gt => ">",
            .lte => "<=",
            .gte => ">=",
            .and_ => "&&",
            .or_ => "||",
            .bit_and => "&",
            .bit_or => "|",
            .bit_xor => "^",
            .shl => "<<",
            .shr => ">>",
        };
    }
};

pub const UnaryOpExpr = struct {
    op: UnaryOp,
    operand: Expression,
    is_prefix: bool, // true for prefix (++x, --x, !x), false for postfix (x++, x--)
};

pub const UnaryOp = enum {
    negate, // -x
    not, // !x
    bit_not, // ~x
    increment, // ++x or x++
    decrement, // --x or x--
    delete, // delete x

    pub fn toString(self: UnaryOp) []const u8 {
        return switch (self) {
            .negate => "-",
            .not => "!",
            .bit_not => "~",
            .increment => "++",
            .decrement => "--",
            .delete => "delete",
        };
    }
};

pub const MemberAccessExpr = struct {
    object: Expression,
    member: []const u8,
};

pub const FunctionCallExpr = struct {
    callee: Expression,
    args: []const Expression,
    /// For named arguments: foo({a: 1, b: 2})
    named_args: ?[]const NamedArg,
    /// For call options: addr.call{value: 1 ether}("")
    call_options: ?[]const NamedArg,
};

pub const NamedArg = struct {
    name: []const u8,
    value: Expression,
};

pub const IndexAccessExpr = struct {
    object: Expression,
    index: Expression,
};

pub const ConditionalExpr = struct {
    condition: Expression,
    true_expr: Expression,
    false_expr: Expression,
};

pub const AssignmentExpr = struct {
    target: Expression,
    op: AssignmentOp,
    value: Expression,
};

pub const AssignmentOp = enum {
    assign, // =
    add_assign, // +=
    sub_assign, // -=
    mul_assign, // *=
    div_assign, // /=
    mod_assign, // %=
    or_assign, // |=
    and_assign, // &=
    xor_assign, // ^=
    shl_assign, // <<=
    shr_assign, // >>=

    pub fn toString(self: AssignmentOp) []const u8 {
        return switch (self) {
            .assign => "=",
            .add_assign => "+=",
            .sub_assign => "-=",
            .mul_assign => "*=",
            .div_assign => "/=",
            .mod_assign => "%=",
            .or_assign => "|=",
            .and_assign => "&=",
            .xor_assign => "^=",
            .shl_assign => "<<=",
            .shr_assign => ">>=",
        };
    }

    pub fn toBinaryOp(self: AssignmentOp) ?BinaryOp {
        return switch (self) {
            .assign => null,
            .add_assign => .add,
            .sub_assign => .sub,
            .mul_assign => .mul,
            .div_assign => .div,
            .mod_assign => .mod,
            .or_assign => .bit_or,
            .and_assign => .bit_and,
            .xor_assign => .bit_xor,
            .shl_assign => .shl,
            .shr_assign => .shr,
        };
    }
};

pub const TypeCastExpr = struct {
    target_type: []const u8,
    operand: Expression,
};

pub const NewExpr = struct {
    type_name: []const u8,
    args: []const Expression,
};

pub const TupleExpr = struct {
    elements: []const ?Expression, // nullable for gaps: (a, , b)
};

pub const ElementaryTypeExpr = struct {
    type_name: []const u8,
};

pub const ArrayLiteralExpr = struct {
    elements: []const Expression,
};

pub const StateVarRefExpr = struct {
    name: []const u8,
};

pub const DeleteExpr = struct {
    operand: Expression,
};

pub const EmitExpr = struct {
    event_name: []const u8,
    args: []const Expression,
};

pub const AbiCallExpr = struct {
    function: []const u8, // "encode", "decode", "encodePacked", etc.
    args: []const Expression,
};

pub const TypeInfoExpr = struct {
    target_type: []const u8,
    member: []const u8, // "min", "max", "interfaceId", "name", "creationCode", "runtimeCode"
};

// ============================================================================
// Statement AST Nodes
// ============================================================================

pub const Statement = union(enum) {
    variable_decl: *VarDeclStmt,
    expression_stmt: *ExprStmt,
    if_stmt: *IfStmt,
    for_stmt: *ForStmt,
    while_stmt: *WhileStmt,
    do_while_stmt: *DoWhileStmt,
    return_stmt: *ReturnStmt,
    emit_stmt: *EmitStmt,
    revert_stmt: *RevertStmt,
    block: *BlockStmt,
    unchecked_block: *UncheckedStmt,
    try_catch: *TryCatchStmt,
    assembly_block: *AssemblyStmt,
    break_stmt: void,
    continue_stmt: void,
    placeholder_stmt: void, // _; in modifiers
    raw_statement: RawStmt, // Fallback for unparseable statements
};

pub const VarDeclStmt = struct {
    type_name: ?[]const u8, // null for `var` declarations
    var_names: []const []const u8, // single or multiple for tuple destructuring
    var_types: ?[]const ?[]const u8, // per-variable types for tuple: (uint a, , uint b)
    is_constant: bool,
    initial_value: ?Expression,
    storage_location: ?[]const u8, // memory, storage, calldata
};

pub const ExprStmt = struct {
    expr: Expression,
};

pub const IfStmt = struct {
    condition: Expression,
    then_body: []const Statement,
    else_body: ?[]const Statement, // null if no else, or another if_stmt for else-if
};

pub const ForStmt = struct {
    init: ?Statement, // Initialization (variable_decl or expression_stmt)
    condition: ?Expression,
    post: ?Expression, // Post-iteration expression (i++)
    body: []const Statement,
};

pub const WhileStmt = struct {
    condition: Expression,
    body: []const Statement,
};

pub const DoWhileStmt = struct {
    body: []const Statement,
    condition: Expression,
};

pub const ReturnStmt = struct {
    value: ?Expression,
};

pub const EmitStmt = struct {
    event_name: []const u8,
    args: []const Expression,
};

pub const RevertStmt = struct {
    error_name: ?[]const u8, // null for revert("message")
    args: []const Expression,
};

pub const BlockStmt = struct {
    statements: []const Statement,
};

pub const UncheckedStmt = struct {
    body: []const Statement,
};

pub const TryCatchStmt = struct {
    call_expr: Expression,
    returns: ?[]const TryCatchReturn,
    success_body: []const Statement,
    catch_clauses: []const CatchClause,
};

pub const TryCatchReturn = struct {
    type_name: []const u8,
    name: []const u8,
};

pub const CatchClause = struct {
    error_name: ?[]const u8, // "Error", "Panic", or null for catch (bytes memory)
    params: ?[]const TryCatchReturn,
    body: []const Statement,
};

pub const AssemblyStmt = struct {
    raw_code: []const u8, // Raw assembly code passed through
    dialect: ?[]const u8, // "evmasm" or null
};

pub const RawStmt = struct {
    text: []const u8,
};
