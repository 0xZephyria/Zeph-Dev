// File: tools/zephyrc/ast.zig
// ZephyrLang AST — Complete Abstract Syntax Tree Node Definitions
// Represents the full parse tree for ZephyrLang source files.
// Supports: contracts, interfaces, libraries, functions, modifiers, events,
//           errors, structs, enums, roles, storage, transient, immutable,
//           option/result types, resource types, pattern matching.

const std = @import("std");

// ============================================================================
// Top-Level Nodes
// ============================================================================

pub const SourceUnit = struct {
    pragmas: []const Pragma,
    imports: []const Import,
    definitions: []const Definition,
};

pub const Pragma = struct {
    name: []const u8,
    value: []const u8,
};

pub const Import = struct {
    path: []const u8,
    symbols: ?[]const ImportSymbol,
    alias: ?[]const u8,
};

pub const ImportSymbol = struct {
    name: []const u8,
    alias: ?[]const u8,
};

pub const Definition = union(enum) {
    contract: ContractDef,
    interface: ContractDef,
    library: ContractDef,
    abstract_contract: ContractDef,
    free_function: FunctionDef,
    constant: StateVarDecl,
    struct_def: StructDef,
    enum_def: EnumDef,
    error_def: ErrorDef,
    type_alias: TypeAlias,
};

// ============================================================================
// Contract Definition
// ============================================================================

pub const ContractDef = struct {
    name: []const u8,
    base_contracts: []const InheritanceSpec,
    members: []const ContractMember,
};

pub const InheritanceSpec = struct {
    name: []const u8,
    args: []const Expr,
};

pub const ContractMember = union(enum) {
    state_var: StateVarDecl,
    function: FunctionDef,
    constructor: FunctionDef,
    fallback: FunctionDef,
    receive: FunctionDef,
    modifier: ModifierDef,
    event: EventDef,
    error_def: ErrorDef,
    struct_def: StructDef,
    enum_def: EnumDef,
    role_def: RoleDef,
    using_directive: UsingDirective,
};

// ============================================================================
// State Variables
// ============================================================================

pub const StorageClass = enum {
    regular,
    transient,
    immutable,
    constant,
};

pub const StateVarDecl = struct {
    name: []const u8,
    type_expr: TypeExpr,
    visibility: Visibility,
    storage_class: StorageClass,
    is_override: bool,
    initial_value: ?Expr,
};

// ============================================================================
// Functions
// ============================================================================

pub const FunctionDef = struct {
    name: []const u8,
    params: []const ParamDecl,
    returns: []const ParamDecl,
    visibility: Visibility,
    mutability: StateMutability,
    modifiers: []const ModifierInvocation,
    is_virtual: bool,
    is_override: bool,
    override_specifiers: []const []const u8,
    body: ?BlockStmt,
};

pub const ParamDecl = struct {
    name: []const u8,
    type_expr: TypeExpr,
    data_location: ?DataLocation,
};

pub const DataLocation = enum {
    storage,
    memory,
    calldata,
};

pub const Visibility = enum {
    public,
    private,
    internal,
    external,
    default,
};

pub const StateMutability = enum {
    nonpayable,
    view,
    pure,
    payable,
};

pub const ModifierInvocation = struct {
    name: []const u8,
    args: []const Expr,
};

// ============================================================================
// Modifiers
// ============================================================================

pub const ModifierDef = struct {
    name: []const u8,
    params: []const ParamDecl,
    is_virtual: bool,
    is_override: bool,
    body: ?BlockStmt,
};

// ============================================================================
// Events, Errors, Roles
// ============================================================================

pub const EventDef = struct {
    name: []const u8,
    params: []const EventParam,
    is_anonymous: bool,
};

pub const EventParam = struct {
    name: []const u8,
    type_expr: TypeExpr,
    is_indexed: bool,
    default_expr: ?Expr,
};

pub const ErrorDef = struct {
    name: []const u8,
    params: []const ParamDecl,
};

pub const RoleDef = struct {
    name: []const u8,
    inherits: ?[]const u8,
};

// ============================================================================
// Structs, Enums, Type Aliases
// ============================================================================

pub const StructDef = struct {
    name: []const u8,
    members: []const StructMember,
};

pub const StructMember = struct {
    name: []const u8,
    type_expr: TypeExpr,
};

pub const EnumDef = struct {
    name: []const u8,
    values: []const []const u8,
};

pub const TypeAlias = struct {
    name: []const u8,
    type_expr: TypeExpr,
};

pub const UsingDirective = struct {
    library: []const u8,
    target_type: ?TypeExpr,
    is_global: bool,
};

// ============================================================================
// Type Expressions
// ============================================================================

pub const TypeExpr = union(enum) {
    elementary: ElementaryType,
    mapping: *MappingType,
    array: *ArrayType,
    function_type: *FunctionType,
    user_defined: []const u8,
    option_type: *TypeExpr,
    result_type: *ResultType,
    tuple_type: []const TypeExpr,
    resource_type: *TypeExpr,
};

pub const ElementaryType = enum {
    // Unsigned integers
    uint8,
    uint16,
    uint24,
    uint32,
    uint40,
    uint48,
    uint56,
    uint64,
    uint72,
    uint80,
    uint88,
    uint96,
    uint104,
    uint112,
    uint120,
    uint128,
    uint136,
    uint144,
    uint152,
    uint160,
    uint168,
    uint176,
    uint184,
    uint192,
    uint200,
    uint208,
    uint216,
    uint224,
    uint232,
    uint240,
    uint248,
    uint256,
    // Signed integers
    int8,
    int16,
    int24,
    int32,
    int40,
    int48,
    int56,
    int64,
    int72,
    int80,
    int88,
    int96,
    int104,
    int112,
    int120,
    int128,
    int136,
    int144,
    int152,
    int160,
    int168,
    int176,
    int184,
    int192,
    int200,
    int208,
    int216,
    int224,
    int232,
    int240,
    int248,
    int256,
    // Fixed-size bytes
    bytes1,
    bytes2,
    bytes3,
    bytes4,
    bytes5,
    bytes6,
    bytes7,
    bytes8,
    bytes9,
    bytes10,
    bytes11,
    bytes12,
    bytes13,
    bytes14,
    bytes15,
    bytes16,
    bytes17,
    bytes18,
    bytes19,
    bytes20,
    bytes21,
    bytes22,
    bytes23,
    bytes24,
    bytes25,
    bytes26,
    bytes27,
    bytes28,
    bytes29,
    bytes30,
    bytes31,
    bytes32,
    // Other primitives
    address,
    address_payable,
    bool_type,
    string_type,
    bytes_type,

    pub fn sizeInBytes(self: ElementaryType) ?u32 {
        return switch (self) {
            .uint8, .int8, .bytes1 => 1,
            .uint16, .int16, .bytes2 => 2,
            .uint24, .int24, .bytes3 => 3,
            .uint32, .int32, .bytes4 => 4,
            .uint64, .int64, .bytes8 => 8,
            .uint128, .int128, .bytes16 => 16,
            .uint160, .int160, .bytes20 => 20,
            .uint256, .int256, .bytes32 => 32,
            .address, .address_payable => 20,
            .bool_type => 1,
            .string_type, .bytes_type => null, // dynamic
            else => null,
        };
    }
};

pub const MappingType = struct {
    key_type: TypeExpr,
    value_type: TypeExpr,
};

pub const ArrayType = struct {
    base_type: TypeExpr,
    length: ?Expr,
};

pub const FunctionType = struct {
    param_types: []const TypeExpr,
    return_types: []const TypeExpr,
    visibility: Visibility,
    mutability: StateMutability,
};

pub const ResultType = struct {
    ok_type: TypeExpr,
    err_type: TypeExpr,
};

// ============================================================================
// Statements
// ============================================================================

pub const Stmt = union(enum) {
    block: BlockStmt,
    variable_decl: VarDeclStmt,
    expression: ExprStmt,
    if_stmt: *IfStmt,
    for_stmt: *ForStmt,
    while_stmt: *WhileStmt,
    do_while: *DoWhileStmt,
    return_stmt: ReturnStmt,
    emit_stmt: EmitStmt,
    revert_stmt: RevertStmt,
    break_stmt: void,
    continue_stmt: void,
    placeholder: void,
    unchecked_block: BlockStmt,
    try_catch: *TryCatchStmt,
    match_stmt: *MatchStmt,
    assembly: AssemblyStmt,
};

pub const BlockStmt = struct {
    statements: []const Stmt,
};

pub const VarDeclStmt = struct {
    names: []const ?[]const u8,
    type_expr: ?TypeExpr,
    data_location: ?DataLocation,
    initial_value: ?Expr,
    is_constant: bool,
};

pub const ExprStmt = struct {
    expr: Expr,
};

pub const IfStmt = struct {
    condition: Expr,
    then_body: Stmt,
    else_body: ?Stmt,
};

pub const ForStmt = struct {
    init: ?*Stmt,
    condition: ?Expr,
    update: ?Expr,
    body: Stmt,
};

pub const WhileStmt = struct {
    condition: Expr,
    body: Stmt,
};

pub const DoWhileStmt = struct {
    body: Stmt,
    condition: Expr,
};

pub const ReturnStmt = struct {
    value: ?Expr,
};

pub const EmitStmt = struct {
    event_name: []const u8,
    args: []const Expr,
};

pub const RevertStmt = struct {
    error_name: ?[]const u8,
    args: []const Expr,
};

pub const TryCatchStmt = struct {
    call_expr: Expr,
    return_params: ?[]const ParamDecl,
    success_body: BlockStmt,
    catch_clauses: []const CatchClause,
};

pub const CatchClause = struct {
    error_name: ?[]const u8,
    param: ?ParamDecl,
    body: BlockStmt,
};

pub const MatchStmt = struct {
    subject: Expr,
    arms: []const MatchArm,
};

pub const MatchArm = struct {
    pattern: MatchPattern,
    body: Stmt,
};

pub const MatchPattern = union(enum) {
    some_pattern: []const u8,
    none_pattern: void,
    ok_pattern: []const u8,
    err_pattern: []const u8,
    literal: Expr,
    wildcard: void,
};

pub const AssemblyStmt = struct {
    dialect: ?[]const u8,
    raw_code: []const u8,
};

// ============================================================================
// Expressions
// ============================================================================

pub const Expr = union(enum) {
    literal: LiteralExpr,
    identifier: []const u8,
    binary_op: *BinaryOpExpr,
    unary_op: *UnaryOpExpr,
    ternary: *TernaryExpr,
    assignment: *AssignmentExpr,
    function_call: *FunctionCallExpr,
    member_access: *MemberAccessExpr,
    index_access: *IndexAccessExpr,
    type_cast: *TypeCastExpr,
    new_expr: *NewExpr,
    tuple: []const ?Expr,
    some_expr: *Expr,
    none_expr: void,
    type_expr: TypeExpr,
    payable_conversion: *Expr,
    elementary_call: *ElementaryCallExpr,
    delete_expr: *Expr,
};

pub const LiteralExpr = struct {
    value: []const u8,
    kind: LiteralKind,
    sub_denomination: ?SubDenomination,
};

pub const LiteralKind = enum {
    number_decimal,
    number_hex,
    string_literal,
    hex_string,
    unicode_string,
    bool_true,
    bool_false,
    address_literal,
};

pub const SubDenomination = enum {
    wei,
    gwei,
    ether,
    seconds,
    minutes,
    hours,
    days,
    weeks,
};

pub const BinaryOpExpr = struct {
    left: Expr,
    op: BinaryOp,
    right: Expr,
};

pub const BinaryOp = enum {
    add, // +
    sub, // -
    mul, // *
    div, // /
    mod, // %
    exp, // **
    eq, // ==
    neq, // !=
    lt, // <
    gt, // >
    lte, // <=
    gte, // >=
    and_op, // &&
    or_op, // ||
    bit_and, // &
    bit_or, // |
    bit_xor, // ^
    shl, // <<
    shr, // >>
    wrapping_add, // +%  (NEW)
    wrapping_sub, // -%  (NEW)
    wrapping_mul, // *%  (NEW)
    saturating_add, // +| (NEW)
    saturating_sub, // -| (NEW)

    pub fn symbol(self: BinaryOp) []const u8 {
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
            .and_op => "&&",
            .or_op => "||",
            .bit_and => "&",
            .bit_or => "|",
            .bit_xor => "^",
            .shl => "<<",
            .shr => ">>",
            .wrapping_add => "+%",
            .wrapping_sub => "-%",
            .wrapping_mul => "*%",
            .saturating_add => "+|",
            .saturating_sub => "-|",
        };
    }
};

pub const UnaryOpExpr = struct {
    op: UnaryOp,
    operand: Expr,
    is_prefix: bool,
};

pub const UnaryOp = enum {
    negate, // -x
    not, // !x
    bit_not, // ~x
    increment, // ++x or x++
    decrement, // --x or x--
    delete, // delete x
};

pub const TernaryExpr = struct {
    condition: Expr,
    true_expr: Expr,
    false_expr: Expr,
};

pub const AssignmentExpr = struct {
    target: Expr,
    op: AssignmentOp,
    value: Expr,
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
};

pub const FunctionCallExpr = struct {
    callee: Expr,
    args: []const Expr,
    named_args: []const NamedArg,
    call_options: []const CallOption,
};

pub const NamedArg = struct {
    name: []const u8,
    value: Expr,
};

pub const CallOption = struct {
    name: []const u8,
    value: Expr,
};

pub const MemberAccessExpr = struct {
    object: Expr,
    member: []const u8,
};

pub const IndexAccessExpr = struct {
    base: Expr,
    index: ?Expr,
    end_index: ?Expr,
};

pub const TypeCastExpr = struct {
    target_type: TypeExpr,
    operand: Expr,
};

pub const NewExpr = struct {
    type_name: TypeExpr,
    args: []const Expr,
};

pub const ElementaryCallExpr = struct {
    type_name: ElementaryType,
    args: []const Expr,
};
