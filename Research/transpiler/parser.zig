// File: tools/sol2zig/parser.zig
// Solidity Source Parser — produces structured AST from Solidity source code
// Supports: contracts, interfaces, libraries, state variables, functions,
// events, modifiers, structs, enums, custom errors, using directives

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// AST Type Definitions
// ============================================================================

pub const SolidityAST = struct {
    backing_allocator: Allocator,
    arena: *std.heap.ArenaAllocator,
    allocator: Allocator,
    contracts: std.ArrayListUnmanaged(ContractDef),
    imports: std.ArrayListUnmanaged(ImportDef),
    pragmas: std.ArrayListUnmanaged(PragmaDef),

    pub fn deinit(self: *SolidityAST) void {
        // Arena owns ALL memory allocated during parsing
        const arena_ptr = self.arena;
        const backing = self.backing_allocator;
        arena_ptr.deinit();
        backing.destroy(arena_ptr);
    }
};

pub const PragmaDef = struct {
    name: []const u8,
    value: []const u8,
};

pub const ImportDef = struct {
    path: []const u8,
    symbols: ?[]const u8,
};

pub const ContractDef = struct {
    name: []const u8,
    kind: ContractKind,
    base_contracts: std.ArrayListUnmanaged([]const u8),
    state_variables: std.ArrayListUnmanaged(StateVarDef),
    functions: std.ArrayListUnmanaged(FunctionDef),
    events: std.ArrayListUnmanaged(EventDef),
    modifiers: std.ArrayListUnmanaged(ModifierDef),
    structs: std.ArrayListUnmanaged(StructDef),
    enums: std.ArrayListUnmanaged(EnumDef),
    errors_list: std.ArrayListUnmanaged(ErrorDef),
    using_directives: std.ArrayListUnmanaged(UsingDef),
};

pub const ContractKind = enum {
    contract,
    interface,
    library,
    abstract_contract,
};

pub const StateVarDef = struct {
    name: []const u8,
    type_name: []const u8,
    visibility: Visibility,
    mutability: VarMutability,
    initial_value: ?[]const u8,
};

pub const Visibility = enum {
    public,
    private,
    internal,
    external,
};

pub const VarMutability = enum {
    mutable,
    constant,
    immutable,
};

pub const FunctionDef = struct {
    name: []const u8,
    kind: FunctionKind,
    visibility: Visibility,
    state_mutability: StateMutability,
    is_virtual: bool,
    is_override: bool,
    params: std.ArrayListUnmanaged(ParamDef),
    returns: std.ArrayListUnmanaged(ParamDef),
    body: ?[]const u8,
    body_start: usize,
    body_end: usize,
    modifiers_applied: std.ArrayListUnmanaged(ModifierCall),
};

pub const FunctionKind = enum {
    function,
    constructor,
    receive,
    fallback,
};

pub const StateMutability = enum {
    nonpayable,
    view,
    pure,
    payable,
};

pub const ParamDef = struct {
    name: []const u8,
    type_name: []const u8,
    storage_location: ?[]const u8,
};

pub const ModifierCall = struct {
    name: []const u8,
    args: std.ArrayListUnmanaged([]const u8),
};

pub const EventDef = struct {
    name: []const u8,
    params: std.ArrayListUnmanaged(EventParam),
    is_anonymous: bool,
};

pub const EventParam = struct {
    name: []const u8,
    type_name: []const u8,
    is_indexed: bool,
};

pub const ModifierDef = struct {
    name: []const u8,
    params: std.ArrayListUnmanaged(ParamDef),
    body: ?[]const u8,
};

pub const StructDef = struct {
    name: []const u8,
    fields: std.ArrayListUnmanaged(StructField),
};

pub const StructField = struct {
    name: []const u8,
    type_name: []const u8,
};

pub const EnumDef = struct {
    name: []const u8,
    members: std.ArrayListUnmanaged([]const u8),
};

pub const ErrorDef = struct {
    name: []const u8,
    params: std.ArrayListUnmanaged(ParamDef),
};

pub const UsingDef = struct {
    library_name: []const u8,
    target_type: ?[]const u8,
};

// ============================================================================
// Parser
// ============================================================================

pub const Parser = struct {
    allocator: Allocator,
    source: []const u8,
    pos: usize,
    line: usize,

    pub fn init(allocator: Allocator, source: []const u8) Parser {
        return .{
            .allocator = allocator,
            .source = source,
            .pos = 0,
            .line = 1,
        };
    }

    pub fn parseSource(self: *Parser) !SolidityAST {
        // Heap-allocate the arena to prevent move invalidation when returning SolidityAST by value
        const arena_ptr = try self.allocator.create(std.heap.ArenaAllocator);
        arena_ptr.* = std.heap.ArenaAllocator.init(self.allocator);
        const arena_alloc = arena_ptr.allocator();
        // Switch parser's allocator to use the arena for all sub-allocations
        self.allocator = arena_alloc;
        var ast = SolidityAST{
            .backing_allocator = arena_ptr.child_allocator,
            .arena = arena_ptr,
            .allocator = arena_alloc,
            .contracts = .{},
            .imports = .{},
            .pragmas = .{},
        };

        while (self.pos < self.source.len) {
            self.skipWhitespaceAndComments();
            if (self.pos >= self.source.len) break;

            if (self.startsWith("pragma ")) {
                const pragma = self.parsePragma();
                try ast.pragmas.append(self.allocator, pragma);
            } else if (self.startsWith("import ")) {
                const import_def = self.parseImport();
                try ast.imports.append(self.allocator, import_def);
            } else if (self.startsWith("contract ") or
                self.startsWith("interface ") or
                self.startsWith("library ") or
                self.startsWith("abstract contract "))
            {
                const contract = try self.parseContract();
                try ast.contracts.append(self.allocator, contract);
            } else {
                // Skip unknown top-level tokens
                self.pos += 1;
            }
        }

        return ast;
    }

    /// Parse source and merge contracts/imports/pragmas into an existing AST.
    /// Uses the target AST's own allocator for all sub-allocations,
    /// ensuring all data lives in the same arena. Skips duplicate contracts.
    pub fn parseSourceInto(self: *Parser, target_ast: *SolidityAST) !void {
        // Use the target AST's allocator so all parsed data lives in its arena
        self.allocator = target_ast.allocator;

        while (self.pos < self.source.len) {
            self.skipWhitespaceAndComments();
            if (self.pos >= self.source.len) break;

            if (self.startsWith("pragma ")) {
                _ = self.parsePragma(); // skip, already have pragmas
            } else if (self.startsWith("import ")) {
                _ = self.parseImport(); // skip, already resolving imports
            } else if (self.startsWith("contract ") or
                self.startsWith("interface ") or
                self.startsWith("library ") or
                self.startsWith("abstract contract "))
            {
                const contract = try self.parseContract();
                // Skip duplicates
                var exists = false;
                for (target_ast.contracts.items) |existing| {
                    if (std.mem.eql(u8, existing.name, contract.name)) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    try target_ast.contracts.append(target_ast.allocator, contract);
                }
            } else {
                self.pos += 1;
            }
        }
    }

    fn parsePragma(self: *Parser) PragmaDef {
        self.pos += 7; // skip "pragma "
        const name_start = self.pos;
        while (self.pos < self.source.len and self.source[self.pos] != ' ' and self.source[self.pos] != ';') {
            self.pos += 1;
        }
        const name = self.source[name_start..self.pos];

        self.skipWhitespaceAndComments();
        const val_start = self.pos;
        while (self.pos < self.source.len and self.source[self.pos] != ';') {
            self.pos += 1;
        }
        const value = self.source[val_start..self.pos];
        if (self.pos < self.source.len) self.pos += 1; // skip ';'

        return .{ .name = name, .value = value };
    }

    fn parseImport(self: *Parser) ImportDef {
        self.pos += 7; // skip "import "
        self.skipWhitespaceAndComments();

        // Handle: import {X} from "path"; or import "path";
        var symbols: ?[]const u8 = null;
        if (self.pos < self.source.len and self.source[self.pos] == '{') {
            const sym_start = self.pos;
            while (self.pos < self.source.len and self.source[self.pos] != '}') self.pos += 1;
            if (self.pos < self.source.len) self.pos += 1;
            symbols = self.source[sym_start..self.pos];
            // skip "from"
            self.skipWhitespaceAndComments();
            if (self.startsWith("from")) self.pos += 4;
            self.skipWhitespaceAndComments();
        }

        // Parse path string
        var path: []const u8 = "";
        if (self.pos < self.source.len and (self.source[self.pos] == '"' or self.source[self.pos] == '\'')) {
            const quote = self.source[self.pos];
            self.pos += 1;
            const path_start = self.pos;
            while (self.pos < self.source.len and self.source[self.pos] != quote) self.pos += 1;
            path = self.source[path_start..self.pos];
            if (self.pos < self.source.len) self.pos += 1;
        }

        // Skip to semicolon
        while (self.pos < self.source.len and self.source[self.pos] != ';') self.pos += 1;
        if (self.pos < self.source.len) self.pos += 1;

        return .{ .path = path, .symbols = symbols };
    }

    fn parseContract(self: *Parser) !ContractDef {
        // Determine kind
        var kind: ContractKind = .contract;
        if (self.startsWith("abstract contract ")) {
            kind = .abstract_contract;
            self.pos += 18;
        } else if (self.startsWith("interface ")) {
            kind = .interface;
            self.pos += 10;
        } else if (self.startsWith("library ")) {
            kind = .library;
            self.pos += 8;
        } else {
            self.pos += 9; // "contract "
        }

        self.skipWhitespaceAndComments();

        // Parse name
        const name = self.parseIdentifier();

        self.skipWhitespaceAndComments();

        // Parse base contracts (is X, Y)
        var base_contracts = std.ArrayListUnmanaged([]const u8){};
        if (self.startsWith("is ")) {
            self.pos += 3;
            while (self.pos < self.source.len and self.source[self.pos] != '{') {
                self.skipWhitespaceAndComments();
                const base = self.parseIdentifier();
                if (base.len > 0) {
                    try base_contracts.append(self.allocator, base);
                }
                self.skipWhitespaceAndComments();
                // Skip constructor args like Ownable(msg.sender)
                if (self.pos < self.source.len and self.source[self.pos] == '(') {
                    self.skipBalanced('(', ')');
                }
                if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
            }
        }

        // Skip opening brace
        self.skipWhitespaceAndComments();
        if (self.pos < self.source.len and self.source[self.pos] == '{') self.pos += 1;

        var contract = ContractDef{
            .name = name,
            .kind = kind,
            .base_contracts = base_contracts,
            .state_variables = .{},
            .functions = .{},
            .events = .{},
            .modifiers = .{},
            .structs = .{},
            .enums = .{},
            .errors_list = .{},
            .using_directives = .{},
        };

        // Parse contract body
        var brace_depth: usize = 1;
        while (self.pos < self.source.len and brace_depth > 0) {
            self.skipWhitespaceAndComments();
            if (self.pos >= self.source.len) break;

            if (self.source[self.pos] == '}') {
                brace_depth -= 1;
                self.pos += 1;
                continue;
            }

            if (self.startsWith("function ") or self.startsWith("constructor(") or
                self.startsWith("constructor ") or self.startsWith("receive(") or
                self.startsWith("receive ") or self.startsWith("fallback(") or
                self.startsWith("fallback "))
            {
                const func = try self.parseFunction();
                try contract.functions.append(self.allocator, func);
            } else if (self.startsWith("event ")) {
                const event = try self.parseEvent();
                try contract.events.append(self.allocator, event);
            } else if (self.startsWith("modifier ")) {
                const modifier = try self.parseModifier();
                try contract.modifiers.append(self.allocator, modifier);
            } else if (self.startsWith("struct ")) {
                const struct_def = try self.parseStruct();
                try contract.structs.append(self.allocator, struct_def);
            } else if (self.startsWith("enum ")) {
                const enum_def = try self.parseEnum();
                try contract.enums.append(self.allocator, enum_def);
            } else if (self.startsWith("error ")) {
                const error_def = try self.parseError();
                try contract.errors_list.append(self.allocator, error_def);
            } else if (self.startsWith("using ")) {
                const using = self.parseUsing();
                try contract.using_directives.append(self.allocator, using);
            } else if (self.startsWith("mapping(") or self.startsWithType()) {
                const state_var = self.parseStateVariable();
                try contract.state_variables.append(self.allocator, state_var);
            } else {
                self.pos += 1;
            }
        }

        return contract;
    }

    fn parseFunction(self: *Parser) !FunctionDef {
        var kind: FunctionKind = .function;
        var name: []const u8 = "";

        if (self.startsWith("constructor")) {
            kind = .constructor;
            name = "constructor";
            self.pos += 11;
        } else if (self.startsWith("receive")) {
            kind = .receive;
            name = "receive";
            self.pos += 7;
        } else if (self.startsWith("fallback")) {
            kind = .fallback;
            name = "fallback";
            self.pos += 8;
        } else {
            self.pos += 9; // "function "
            self.skipWhitespaceAndComments();
            name = self.parseIdentifier();
        }

        self.skipWhitespaceAndComments();

        // Parse params
        var params = std.ArrayListUnmanaged(ParamDef){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') {
            params = try self.parseParams();
        }

        self.skipWhitespaceAndComments();

        // Parse modifiers: visibility, state mutability, virtual, override, custom modifiers
        var visibility: Visibility = if (kind == .constructor) .internal else .public;
        var state_mutability: StateMutability = .nonpayable;
        var is_virtual = false;
        var is_override = false;
        var modifiers_applied = std.ArrayListUnmanaged(ModifierCall){};

        while (self.pos < self.source.len and self.source[self.pos] != '{' and self.source[self.pos] != ';' and !self.startsWith("returns")) {
            self.skipWhitespaceAndComments();
            if (self.pos >= self.source.len) break;

            if (self.startsWith("public")) {
                visibility = .public;
                self.pos += 6;
            } else if (self.startsWith("private")) {
                visibility = .private;
                self.pos += 7;
            } else if (self.startsWith("internal")) {
                visibility = .internal;
                self.pos += 8;
            } else if (self.startsWith("external")) {
                visibility = .external;
                self.pos += 8;
            } else if (self.startsWith("view")) {
                state_mutability = .view;
                self.pos += 4;
            } else if (self.startsWith("pure")) {
                state_mutability = .pure;
                self.pos += 4;
            } else if (self.startsWith("payable")) {
                state_mutability = .payable;
                self.pos += 7;
            } else if (self.startsWith("virtual")) {
                is_virtual = true;
                self.pos += 7;
            } else if (self.startsWith("override")) {
                is_override = true;
                self.pos += 8;
                if (self.pos < self.source.len and self.source[self.pos] == '(') {
                    self.skipBalanced('(', ')');
                }
            } else if (self.startsWith("returns")) {
                break;
            } else if (self.source[self.pos] == '{' or self.source[self.pos] == ';') {
                break;
            } else {
                // Custom modifier
                const mod_name = self.parseIdentifier();
                if (mod_name.len > 0) {
                    var mod_args = std.ArrayListUnmanaged([]const u8){};
                    if (self.pos < self.source.len and self.source[self.pos] == '(') {
                        mod_args = try self.parseModifierArgs();
                    }
                    try modifiers_applied.append(self.allocator, .{
                        .name = mod_name,
                        .args = mod_args,
                    });
                } else {
                    self.pos += 1;
                }
            }
        }

        // Parse returns
        var returns = std.ArrayListUnmanaged(ParamDef){};
        self.skipWhitespaceAndComments();
        if (self.startsWith("returns")) {
            self.pos += 7;
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == '(') {
                returns = try self.parseParams();
            }
        }

        // Parse body
        self.skipWhitespaceAndComments();
        var body: ?[]const u8 = null;
        var body_start: usize = 0;
        var body_end: usize = 0;

        if (self.pos < self.source.len and self.source[self.pos] == '{') {
            body_start = self.pos;
            self.skipBalanced('{', '}');
            body_end = self.pos;
            body = self.source[body_start..body_end];
        } else if (self.pos < self.source.len and self.source[self.pos] == ';') {
            self.pos += 1;
        }

        return .{
            .name = name,
            .kind = kind,
            .visibility = visibility,
            .state_mutability = state_mutability,
            .is_virtual = is_virtual,
            .is_override = is_override,
            .params = params,
            .returns = returns,
            .body = body,
            .body_start = body_start,
            .body_end = body_end,
            .modifiers_applied = modifiers_applied,
        };
    }

    fn parseEvent(self: *Parser) !EventDef {
        self.pos += 6; // "event "
        self.skipWhitespaceAndComments();
        const name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var params = std.ArrayListUnmanaged(EventParam){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') {
            self.pos += 1;
            while (self.pos < self.source.len and self.source[self.pos] != ')') {
                self.skipWhitespaceAndComments();
                if (self.source[self.pos] == ')') break;

                const type_name = self.parseTypeName();
                self.skipWhitespaceAndComments();

                var is_indexed = false;
                if (self.startsWith("indexed")) {
                    is_indexed = true;
                    self.pos += 7;
                    self.skipWhitespaceAndComments();
                }

                const param_name = self.parseIdentifier();
                try params.append(self.allocator, .{
                    .name = param_name,
                    .type_name = type_name,
                    .is_indexed = is_indexed,
                });

                self.skipWhitespaceAndComments();
                if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
            }
            if (self.pos < self.source.len) self.pos += 1; // skip ')'
        }

        var is_anonymous = false;
        self.skipWhitespaceAndComments();
        if (self.startsWith("anonymous")) {
            is_anonymous = true;
            self.pos += 9;
        }

        // Skip semicolon
        while (self.pos < self.source.len and self.source[self.pos] != ';') self.pos += 1;
        if (self.pos < self.source.len) self.pos += 1;

        return .{ .name = name, .params = params, .is_anonymous = is_anonymous };
    }

    fn parseModifier(self: *Parser) !ModifierDef {
        self.pos += 9; // "modifier "
        self.skipWhitespaceAndComments();
        const name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var params = std.ArrayListUnmanaged(ParamDef){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') {
            params = try self.parseParams();
        }

        self.skipWhitespaceAndComments();
        // skip virtual/override
        while (self.startsWith("virtual") or self.startsWith("override")) {
            if (self.startsWith("virtual")) self.pos += 7;
            if (self.startsWith("override")) {
                self.pos += 8;
                if (self.pos < self.source.len and self.source[self.pos] == '(') self.skipBalanced('(', ')');
            }
            self.skipWhitespaceAndComments();
        }

        var body: ?[]const u8 = null;
        if (self.pos < self.source.len and self.source[self.pos] == '{') {
            const start = self.pos;
            self.skipBalanced('{', '}');
            body = self.source[start..self.pos];
        }

        return .{ .name = name, .params = params, .body = body };
    }

    fn parseStruct(self: *Parser) !StructDef {
        self.pos += 7; // "struct "
        self.skipWhitespaceAndComments();
        const name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var fields = std.ArrayListUnmanaged(StructField){};
        if (self.pos < self.source.len and self.source[self.pos] == '{') {
            self.pos += 1;
            while (self.pos < self.source.len and self.source[self.pos] != '}') {
                self.skipWhitespaceAndComments();
                if (self.pos < self.source.len and self.source[self.pos] == '}') break;

                const type_name = self.parseTypeName();
                self.skipWhitespaceAndComments();
                const field_name = self.parseIdentifier();

                try fields.append(self.allocator, .{ .name = field_name, .type_name = type_name });

                // Skip semicolon
                while (self.pos < self.source.len and self.source[self.pos] != ';' and self.source[self.pos] != '}') self.pos += 1;
                if (self.pos < self.source.len and self.source[self.pos] == ';') self.pos += 1;
            }
            if (self.pos < self.source.len) self.pos += 1; // skip '}'
        }

        return .{ .name = name, .fields = fields };
    }

    fn parseEnum(self: *Parser) !EnumDef {
        self.pos += 5; // "enum "
        self.skipWhitespaceAndComments();
        const name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var members = std.ArrayListUnmanaged([]const u8){};
        if (self.pos < self.source.len and self.source[self.pos] == '{') {
            self.pos += 1;
            while (self.pos < self.source.len and self.source[self.pos] != '}') {
                self.skipWhitespaceAndComments();
                if (self.pos < self.source.len and self.source[self.pos] == '}') break;

                const member = self.parseIdentifier();
                if (member.len > 0) {
                    try members.append(self.allocator, member);
                }

                self.skipWhitespaceAndComments();
                if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
            }
            if (self.pos < self.source.len) self.pos += 1; // skip '}'
        }

        return .{ .name = name, .members = members };
    }

    fn parseError(self: *Parser) !ErrorDef {
        self.pos += 6; // "error "
        self.skipWhitespaceAndComments();
        const name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var params = std.ArrayListUnmanaged(ParamDef){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') {
            params = try self.parseParams();
        }

        // Skip semicolon
        while (self.pos < self.source.len and self.source[self.pos] != ';') self.pos += 1;
        if (self.pos < self.source.len) self.pos += 1;

        return .{ .name = name, .params = params };
    }

    fn parseUsing(self: *Parser) UsingDef {
        self.pos += 6; // "using "
        self.skipWhitespaceAndComments();
        const library_name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var target_type: ?[]const u8 = null;
        if (self.startsWith("for ")) {
            self.pos += 4;
            self.skipWhitespaceAndComments();
            if (self.source[self.pos] == '*') {
                target_type = "*";
                self.pos += 1;
            } else {
                target_type = self.parseTypeName();
            }
        }

        // Skip to semicolon
        while (self.pos < self.source.len and self.source[self.pos] != ';') self.pos += 1;
        if (self.pos < self.source.len) self.pos += 1;

        return .{ .library_name = library_name, .target_type = target_type };
    }

    fn parseStateVariable(self: *Parser) StateVarDef {
        const type_name = self.parseTypeName();
        self.skipWhitespaceAndComments();

        var visibility: Visibility = .internal;
        var mutability: VarMutability = .mutable;

        // Parse optional visibility/mutability before name
        while (true) {
            if (self.startsWith("public")) {
                visibility = .public;
                self.pos += 6;
                self.skipWhitespaceAndComments();
            } else if (self.startsWith("private")) {
                visibility = .private;
                self.pos += 7;
                self.skipWhitespaceAndComments();
            } else if (self.startsWith("internal")) {
                visibility = .internal;
                self.pos += 8;
                self.skipWhitespaceAndComments();
            } else if (self.startsWith("constant")) {
                mutability = .constant;
                self.pos += 8;
                self.skipWhitespaceAndComments();
            } else if (self.startsWith("immutable")) {
                mutability = .immutable;
                self.pos += 9;
                self.skipWhitespaceAndComments();
            } else {
                break;
            }
        }

        const name = self.parseIdentifier();
        self.skipWhitespaceAndComments();

        var initial_value: ?[]const u8 = null;
        if (self.pos < self.source.len and self.source[self.pos] == '=') {
            self.pos += 1;
            self.skipWhitespaceAndComments();
            const val_start = self.pos;
            while (self.pos < self.source.len and self.source[self.pos] != ';') self.pos += 1;
            initial_value = self.source[val_start..self.pos];
        }

        // Skip semicolon
        while (self.pos < self.source.len and self.source[self.pos] != ';') self.pos += 1;
        if (self.pos < self.source.len) self.pos += 1;

        return .{
            .name = name,
            .type_name = type_name,
            .visibility = visibility,
            .mutability = mutability,
            .initial_value = initial_value,
        };
    }

    fn parseParams(self: *Parser) !std.ArrayListUnmanaged(ParamDef) {
        var params = std.ArrayListUnmanaged(ParamDef){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') self.pos += 1;

        while (self.pos < self.source.len and self.source[self.pos] != ')') {
            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == ')') break;

            const type_name = self.parseTypeName();
            self.skipWhitespaceAndComments();

            var storage_location: ?[]const u8 = null;
            if (self.startsWith("memory")) {
                storage_location = "memory";
                self.pos += 6;
                self.skipWhitespaceAndComments();
            } else if (self.startsWith("storage")) {
                storage_location = "storage";
                self.pos += 7;
                self.skipWhitespaceAndComments();
            } else if (self.startsWith("calldata")) {
                storage_location = "calldata";
                self.pos += 8;
                self.skipWhitespaceAndComments();
            }

            var param_name: []const u8 = "";
            if (self.pos < self.source.len and self.source[self.pos] != ',' and self.source[self.pos] != ')') {
                param_name = self.parseIdentifier();
            }

            try params.append(self.allocator, .{
                .name = param_name,
                .type_name = type_name,
                .storage_location = storage_location,
            });

            self.skipWhitespaceAndComments();
            if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
        }

        if (self.pos < self.source.len) self.pos += 1; // skip ')'
        return params;
    }

    fn parseModifierArgs(self: *Parser) !std.ArrayListUnmanaged([]const u8) {
        var args = std.ArrayListUnmanaged([]const u8){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') self.pos += 1;

        while (self.pos < self.source.len and self.source[self.pos] != ')') {
            self.skipWhitespaceAndComments();
            if (self.source[self.pos] == ')') break;

            const arg_start = self.pos;
            var depth: usize = 0;
            while (self.pos < self.source.len) {
                if (self.source[self.pos] == '(') depth += 1;
                if (self.source[self.pos] == ')' and depth == 0) break;
                if (self.source[self.pos] == ')') depth -= 1;
                if (self.source[self.pos] == ',' and depth == 0) break;
                self.pos += 1;
            }
            const arg = std.mem.trim(u8, self.source[arg_start..self.pos], " \t\n\r");
            if (arg.len > 0) try args.append(self.allocator, arg);

            if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
        }

        if (self.pos < self.source.len) self.pos += 1; // skip ')'
        return args;
    }

    // ========================================================================
    // Helper functions
    // ========================================================================

    fn parseIdentifier(self: *Parser) []const u8 {
        const start = self.pos;
        while (self.pos < self.source.len and (std.ascii.isAlphanumeric(self.source[self.pos]) or self.source[self.pos] == '_' or self.source[self.pos] == '$')) {
            self.pos += 1;
        }
        return self.source[start..self.pos];
    }

    fn parseTypeName(self: *Parser) []const u8 {
        self.skipWhitespaceAndComments();
        const start = self.pos;

        // Handle mapping(K => V) types — use balanced paren skipping
        if (self.startsWith("mapping(") or self.startsWith("mapping ")) {
            // Advance past "mapping" identifier
            self.pos += 7; // "mapping"
            self.skipWhitespaceAndComments();
            // Now pos should be at '(' — use skipBalanced to correctly handle nesting
            if (self.pos < self.source.len and self.source[self.pos] == '(') {
                self.skipBalanced('(', ')');
            }
            return self.source[start..self.pos];
        }

        // Regular type: identifier possibly followed by [] or [N]
        _ = self.parseIdentifier();
        while (self.pos < self.source.len and self.source[self.pos] == '[') {
            while (self.pos < self.source.len and self.source[self.pos] != ']') self.pos += 1;
            if (self.pos < self.source.len) self.pos += 1;
        }

        return self.source[start..self.pos];
    }

    fn startsWithType(self: *Parser) bool {
        const type_prefixes = [_][]const u8{
            "uint",   "int",    "address",  "bool",
            "bytes",  "string", "mapping(", "fixed",
            "ufixed",
        };
        for (type_prefixes) |prefix| {
            if (self.startsWith(prefix)) return true;
        }
        return false;
    }

    fn startsWith(self: *Parser, prefix: []const u8) bool {
        if (self.pos + prefix.len > self.source.len) return false;
        return std.mem.eql(u8, self.source[self.pos .. self.pos + prefix.len], prefix);
    }

    fn skipWhitespaceAndComments(self: *Parser) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == ' ' or c == '\t' or c == '\r') {
                self.pos += 1;
            } else if (c == '\n') {
                self.pos += 1;
                self.line += 1;
            } else if (self.pos + 1 < self.source.len and c == '/' and self.source[self.pos + 1] == '/') {
                // Line comment
                while (self.pos < self.source.len and self.source[self.pos] != '\n') self.pos += 1;
            } else if (self.pos + 1 < self.source.len and c == '/' and self.source[self.pos + 1] == '*') {
                // Block comment
                self.pos += 2;
                while (self.pos + 1 < self.source.len) {
                    if (self.source[self.pos] == '\n') self.line += 1;
                    if (self.source[self.pos] == '*' and self.source[self.pos + 1] == '/') {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn skipBalanced(self: *Parser, open: u8, close: u8) void {
        if (self.pos < self.source.len and self.source[self.pos] == open) {
            var depth: usize = 1;
            self.pos += 1;
            while (self.pos < self.source.len and depth > 0) {
                if (self.source[self.pos] == '\n') self.line += 1;
                // Skip string literals
                if (self.source[self.pos] == '"' or self.source[self.pos] == '\'') {
                    const quote = self.source[self.pos];
                    self.pos += 1;
                    while (self.pos < self.source.len and self.source[self.pos] != quote) {
                        if (self.source[self.pos] == '\\') self.pos += 1;
                        self.pos += 1;
                    }
                    if (self.pos < self.source.len) self.pos += 1;
                    continue;
                }
                if (self.source[self.pos] == open) depth += 1;
                if (self.source[self.pos] == close) depth -= 1;
                if (depth > 0) self.pos += 1;
            }
            if (self.pos < self.source.len) self.pos += 1; // skip final close
        }
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn parse(allocator: Allocator, source: []const u8) !SolidityAST {
    var p = Parser.init(allocator, source);
    return p.parseSource();
}

/// Get the arena allocator from an existing AST (for expr_parser usage)
pub fn arenaAllocator(ast: *SolidityAST) Allocator {
    return ast.arena.allocator();
}
