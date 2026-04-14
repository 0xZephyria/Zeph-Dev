// File: tools/zephyrc/parser.zig
// ZephyrLang Parser — Recursive descent parser producing AST from token stream.
const std = @import("std");
const lexer = @import("lexer.zig");
const ast = @import("ast.zig");
const Token = lexer.Token;
const TK = lexer.TokenKind;

pub const ParseError = error{
    UnexpectedToken,
    UnexpectedEof,
    InvalidType,
    OutOfMemory,
};

pub const Parser = struct {
    tokens: []const Token,
    pos: u32,
    source: []const u8,
    arena: std.heap.ArenaAllocator,
    alloc: std.mem.Allocator,
    backing: std.mem.Allocator,
    errors: std.ArrayList(Diagnostic),

    pub const Diagnostic = struct {
        message: []const u8,
        line: u32,
        col: u32,
    };

    pub fn init(backing: std.mem.Allocator, tokens: []const Token, source: []const u8) Parser {
        return .{
            .tokens = tokens,
            .pos = 0,
            .source = source,
            .arena = std.heap.ArenaAllocator.init(backing),
            .alloc = undefined, // set after init
            .backing = backing,
            .errors = .{},
        };
    }

    /// Must be called after init before parsing to fix the arena allocator pointer.
    pub fn ready(self: *Parser) void {
        self.alloc = self.arena.allocator();
    }

    pub fn deinit(self: *Parser) void {
        for (self.errors.items) |diag| self.backing.free(diag.message);
        self.errors.deinit(self.backing);
        self.arena.deinit();
    }

    pub fn err(self: *Parser, comptime format: []const u8, args: anytype) !void {
        const msg = try std.fmt.allocPrint(self.backing, format, args);
        try self.errors.append(self.backing, .{
            .message = msg,
            .line = self.peek().line,
            .col = self.peek().col,
        });
    }

    // === Token access ===
    fn peek(self: *const Parser) Token {
        if (self.pos >= self.tokens.len) return .{ .kind = .eof, .start = 0, .end = 0, .line = 0, .col = 0 };
        return self.tokens[self.pos];
    }

    fn advance(self: *Parser) Token {
        const tok = self.peek();
        if (self.pos < self.tokens.len) self.pos += 1;
        return tok;
    }

    fn expect(self: *Parser, kind: TK) ParseError!Token {
        const tok = self.peek();
        if (tok.kind != kind) {
            self.err("Expected symbol/token '{s}', found '{s}' at line {d}", .{ @tagName(kind), self.text(tok), tok.line }) catch {};
            return ParseError.UnexpectedToken;
        }
        return self.advance();
    }

    fn check(self: *const Parser, kind: TK) bool {
        return self.peek().kind == kind;
    }

    fn match(self: *Parser, kind: TK) bool {
        if (self.check(kind)) {
            _ = self.advance();
            return true;
        }
        return false;
    }

    fn text(self: *const Parser, tok: Token) []const u8 {
        return tok.text(self.source);
    }

    // === Top-level parsing ===
    pub fn parseSourceUnit(self: *Parser) ParseError!ast.SourceUnit {
        var pragmas = std.ArrayList(ast.Pragma){};
        var imports = std.ArrayList(ast.Import){};
        var defs = std.ArrayList(ast.Definition){};

        while (self.peek().kind != .eof) {
            switch (self.peek().kind) {
                .kw_pragma => pragmas.append(self.alloc, self.parsePragma()) catch return ParseError.OutOfMemory,
                .kw_import => imports.append(self.alloc, try self.parseImport()) catch return ParseError.OutOfMemory,
                .kw_contract => defs.append(self.alloc, .{ .contract = try self.parseContract(.contract) }) catch return ParseError.OutOfMemory,
                .kw_interface => defs.append(self.alloc, .{ .interface = try self.parseContract(.interface) }) catch return ParseError.OutOfMemory,
                .kw_library => defs.append(self.alloc, .{ .library = try self.parseContract(.library) }) catch return ParseError.OutOfMemory,
                .kw_abstract => defs.append(self.alloc, .{ .abstract_contract = try self.parseAbstract() }) catch return ParseError.OutOfMemory,
                .kw_struct => defs.append(self.alloc, .{ .struct_def = try self.parseStruct() }) catch return ParseError.OutOfMemory,
                .kw_enum => defs.append(self.alloc, .{ .enum_def = try self.parseEnum() }) catch return ParseError.OutOfMemory,
                .kw_error => defs.append(self.alloc, .{ .error_def = try self.parseErrorDef() }) catch return ParseError.OutOfMemory,
                else => _ = self.advance(),
            }
        }
        return .{
            .pragmas = pragmas.items,
            .imports = imports.items,
            .definitions = defs.items,
        };
    }

    fn parsePragma(self: *Parser) ast.Pragma {
        _ = self.advance(); // pragma
        const name_tok = self.advance();
        const name = self.text(name_tok);
        const value_start = self.pos;
        while (self.peek().kind != .semicolon and self.peek().kind != .eof) _ = self.advance();
        const value = if (self.pos > value_start) self.source[self.tokens[value_start].start..self.tokens[self.pos - 1].end] else "";
        _ = self.match(.semicolon);
        return .{ .name = name, .value = value };
    }

    fn parseImport(self: *Parser) ParseError!ast.Import {
        _ = self.advance(); // import
        var path: []const u8 = "";
        var symbols: ?[]const ast.ImportSymbol = null;
        var alias: ?[]const u8 = null;

        if (self.check(.lbrace)) {
            _ = self.advance();
            var syms = std.ArrayList(ast.ImportSymbol){};
            while (!self.check(.rbrace) and !self.check(.eof)) {
                const sym_name = self.text(self.advance());
                var sym_alias: ?[]const u8 = null;
                if (self.check(.identifier) and std.mem.eql(u8, self.text(self.peek()), "as")) {
                    _ = self.advance();
                    sym_alias = self.text(self.advance());
                }
                syms.append(self.alloc, .{ .name = sym_name, .alias = sym_alias }) catch return ParseError.OutOfMemory;
                _ = self.match(.comma);
            }
            _ = self.match(.rbrace);
            symbols = syms.items;
            // expect "from"
            if (self.check(.identifier) and std.mem.eql(u8, self.text(self.peek()), "from")) _ = self.advance();
        }
        if (self.check(.string_literal)) {
            const raw = self.text(self.advance());
            path = if (raw.len >= 2) raw[1 .. raw.len - 1] else raw;
        }
        if (self.check(.identifier) and std.mem.eql(u8, self.text(self.peek()), "as")) {
            _ = self.advance();
            alias = self.text(self.advance());
        }
        _ = self.match(.semicolon);
        return .{ .path = path, .symbols = symbols, .alias = alias };
    }

    const ContractKindTag = enum { contract, interface, library, abstract_contract };

    fn parseAbstract(self: *Parser) ParseError!ast.ContractDef {
        _ = self.advance(); // abstract
        return self.parseContract(.abstract_contract);
    }

    fn parseContract(self: *Parser, _: ContractKindTag) ParseError!ast.ContractDef {
        _ = self.advance(); // contract/interface/library
        const name = self.text(try self.expect(.identifier));
        var bases = std.ArrayList(ast.InheritanceSpec){};
        if (self.match(.kw_is)) {
            while (!self.check(.lbrace) and !self.check(.eof)) {
                const base_name = self.text(self.advance());
                var args = std.ArrayList(ast.Expr){};
                if (self.match(.lparen)) {
                    while (!self.check(.rparen) and !self.check(.eof)) {
                        args.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
                        _ = self.match(.comma);
                    }
                    _ = self.match(.rparen);
                }
                bases.append(self.alloc, .{ .name = base_name, .args = args.items }) catch return ParseError.OutOfMemory;
                _ = self.match(.comma);
            }
        }
        _ = try self.expect(.lbrace);
        var members = std.ArrayList(ast.ContractMember){};
        while (!self.check(.rbrace) and !self.check(.eof)) {
            if (try self.parseContractMember()) |m|
                members.append(self.alloc, m) catch return ParseError.OutOfMemory
            else
                _ = self.advance();
        }
        _ = self.match(.rbrace);
        return .{ .name = name, .base_contracts = bases.items, .members = members.items };
    }

    fn parseContractMember(self: *Parser) ParseError!?ast.ContractMember {
        return switch (self.peek().kind) {
            .kw_function => .{ .function = try self.parseFunction() },
            .kw_constructor => .{ .constructor = try self.parseFunction() },
            .kw_fallback => .{ .fallback = try self.parseFunction() },
            .kw_receive => .{ .receive = try self.parseFunction() },
            .kw_modifier => .{ .modifier = try self.parseModifier() },
            .kw_event => .{ .event = try self.parseEvent() },
            .kw_error => .{ .error_def = try self.parseErrorDef() },
            .kw_struct => .{ .struct_def = try self.parseStruct() },
            .kw_enum => .{ .enum_def = try self.parseEnum() },
            .kw_role => .{ .role_def = try self.parseRole() },
            .kw_using => .{ .using_directive = try self.parseUsing() },
            .kw_mapping,
            .kw_address,
            .kw_bool,
            .kw_string,
            .kw_bytes,
            .identifier,
            .kw_transient,
            .kw_immutable,
            .kw_constant,
            .kw_public,
            .kw_private,
            .kw_internal,
            => .{ .state_var = try self.parseStateVar() },
            else => null,
        };
    }

    // === Function parsing ===
    fn parseFunction(self: *Parser) ParseError!ast.FunctionDef {
        const kind_tok = self.advance(); // function/constructor/fallback/receive
        var name: []const u8 = self.text(kind_tok);
        if (kind_tok.kind == .kw_function and self.check(.identifier)) name = self.text(self.advance());
        _ = try self.expect(.lparen);
        const params = try self.parseParamList();
        _ = try self.expect(.rparen);

        var vis: ast.Visibility = .default;
        var mut: ast.StateMutability = .nonpayable;
        var is_virtual = false;
        var is_override = false;
        var mods = std.ArrayList(ast.ModifierInvocation){};
        var override_specs = std.ArrayList([]const u8){};

        while (true) {
            switch (self.peek().kind) {
                .kw_public => {
                    vis = .public;
                    _ = self.advance();
                },
                .kw_private => {
                    vis = .private;
                    _ = self.advance();
                },
                .kw_internal => {
                    vis = .internal;
                    _ = self.advance();
                },
                .kw_external => {
                    vis = .external;
                    _ = self.advance();
                },
                .kw_view => {
                    mut = .view;
                    _ = self.advance();
                },
                .kw_pure => {
                    mut = .pure;
                    _ = self.advance();
                },
                .kw_payable => {
                    mut = .payable;
                    _ = self.advance();
                },
                .kw_virtual => {
                    is_virtual = true;
                    _ = self.advance();
                },
                .kw_override => {
                    is_override = true;
                    _ = self.advance();
                    if (self.match(.lparen)) {
                        while (!self.check(.rparen) and !self.check(.eof)) {
                            override_specs.append(self.alloc, self.text(self.advance())) catch return ParseError.OutOfMemory;
                            _ = self.match(.comma);
                        }
                        _ = self.match(.rparen);
                    }
                },
                .identifier => {
                    const mod_name = self.text(self.advance());
                    var args = std.ArrayList(ast.Expr){};
                    if (self.match(.lparen)) {
                        while (!self.check(.rparen) and !self.check(.eof)) {
                            args.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
                            _ = self.match(.comma);
                        }
                        _ = self.match(.rparen);
                    }
                    mods.append(self.alloc, .{ .name = mod_name, .args = args.items }) catch return ParseError.OutOfMemory;
                },
                .kw_only => {
                    _ = self.advance();
                    _ = self.match(.lparen);
                    const role_name = self.text(self.advance());
                    _ = self.match(.rparen);
                    mods.append(self.alloc, .{ .name = role_name, .args = &.{} }) catch return ParseError.OutOfMemory;
                },
                else => break,
            }
        }

        var returns: []const ast.ParamDecl = &.{};
        if (self.match(.kw_returns)) {
            _ = try self.expect(.lparen);
            returns = try self.parseParamList();
            _ = try self.expect(.rparen);
        }

        var body: ?ast.BlockStmt = null;
        if (self.check(.lbrace)) {
            body = try self.parseBlock();
        } else {
            _ = self.match(.semicolon);
        }

        return .{
            .name = name,
            .params = params,
            .returns = returns,
            .visibility = vis,
            .mutability = mut,
            .modifiers = mods.items,
            .is_virtual = is_virtual,
            .is_override = is_override,
            .override_specifiers = override_specs.items,
            .body = body,
        };
    }

    fn parseParamList(self: *Parser) ParseError![]const ast.ParamDecl {
        var params = std.ArrayList(ast.ParamDecl){};
        while (!self.check(.rparen) and !self.check(.eof)) {
            const ty = try self.parseTypeExpr();
            var loc: ?ast.DataLocation = null;
            if (self.check(.kw_memory)) {
                loc = .memory;
                _ = self.advance();
            } else if (self.check(.kw_storage)) {
                loc = .storage;
                _ = self.advance();
            } else if (self.check(.kw_calldata)) {
                loc = .calldata;
                _ = self.advance();
            }
            var name: []const u8 = "";
            if (self.check(.identifier)) name = self.text(self.advance());
            params.append(self.alloc, .{ .name = name, .type_expr = ty, .data_location = loc }) catch return ParseError.OutOfMemory;
            if (!self.match(.comma)) break;
        }
        return params.items;
    }

    // === State variable ===
    fn parseStateVar(self: *Parser) ParseError!ast.StateVarDecl {
        var sc: ast.StorageClass = .regular;
        if (self.match(.kw_transient)) sc = .transient else if (self.match(.kw_immutable)) sc = .immutable else if (self.match(.kw_constant)) sc = .constant;

        var vis: ast.Visibility = .default;
        if (self.check(.kw_public) or self.check(.kw_private) or self.check(.kw_internal)) {
            vis = switch (self.advance().kind) {
                .kw_public => .public,
                .kw_private => .private,
                .kw_internal => .internal,
                else => .default,
            };
        }

        const ty = try self.parseTypeExpr();
        // check visibility after type too
        if (vis == .default) {
            if (self.check(.kw_public)) {
                vis = .public;
                _ = self.advance();
            } else if (self.check(.kw_private)) {
                vis = .private;
                _ = self.advance();
            } else if (self.check(.kw_internal)) {
                vis = .internal;
                _ = self.advance();
            }
        }
        // check storage class after type
        if (sc == .regular) {
            if (self.check(.kw_constant)) {
                sc = .constant;
                _ = self.advance();
            } else if (self.check(.kw_immutable)) {
                sc = .immutable;
                _ = self.advance();
            }
        }
        const is_override = self.match(.kw_override);
        const name = self.text(try self.expect(.identifier));
        var init_val: ?ast.Expr = null;
        if (self.match(.eq)) init_val = try self.parseExpr();
        _ = self.match(.semicolon);
        return .{ .name = name, .type_expr = ty, .visibility = vis, .storage_class = sc, .is_override = is_override, .initial_value = init_val };
    }

    // === Events, Errors, Modifiers, Roles, Structs, Enums, Using ===
    fn parseEvent(self: *Parser) ParseError!ast.EventDef {
        _ = self.advance(); // event
        const name = self.text(try self.expect(.identifier));
        _ = try self.expect(.lparen);
        var params = std.ArrayList(ast.EventParam){};
        while (!self.check(.rparen) and !self.check(.eof)) {
            const ty = try self.parseTypeExpr();
            const indexed = self.match(.kw_indexed);
            var pname: []const u8 = "";
            if (self.check(.identifier)) pname = self.text(self.advance());
            params.append(self.alloc, .{ .name = pname, .type_expr = ty, .is_indexed = indexed, .default_expr = null }) catch return ParseError.OutOfMemory;
            if (!self.match(.comma)) break;
        }
        _ = try self.expect(.rparen);
        const anon = self.match(.kw_anonymous);
        _ = self.match(.semicolon);
        return .{ .name = name, .params = params.items, .is_anonymous = anon };
    }

    fn parseErrorDef(self: *Parser) ParseError!ast.ErrorDef {
        _ = self.advance(); // error
        const name = self.text(try self.expect(.identifier));
        _ = try self.expect(.lparen);
        const params = try self.parseParamList();
        _ = try self.expect(.rparen);
        _ = self.match(.semicolon);
        return .{ .name = name, .params = params };
    }

    fn parseModifier(self: *Parser) ParseError!ast.ModifierDef {
        _ = self.advance(); // modifier
        const name = self.text(try self.expect(.identifier));
        _ = try self.expect(.lparen);
        const params = try self.parseParamList();
        _ = try self.expect(.rparen);
        const is_virtual = self.match(.kw_virtual);
        const is_override = self.match(.kw_override);
        var body: ?ast.BlockStmt = null;
        if (self.check(.lbrace)) body = try self.parseBlock() else _ = self.match(.semicolon);
        return .{ .name = name, .params = params, .is_virtual = is_virtual, .is_override = is_override, .body = body };
    }

    fn parseRole(self: *Parser) ParseError!ast.RoleDef {
        _ = self.advance(); // role
        const name = self.text(try self.expect(.identifier));
        var inherits: ?[]const u8 = null;
        if (self.match(.kw_inherits)) inherits = self.text(try self.expect(.identifier));
        _ = self.match(.semicolon);
        return .{ .name = name, .inherits = inherits };
    }

    fn parseStruct(self: *Parser) ParseError!ast.StructDef {
        _ = self.advance(); // struct
        const name = self.text(try self.expect(.identifier));
        _ = try self.expect(.lbrace);
        var mems = std.ArrayList(ast.StructMember){};
        while (!self.check(.rbrace) and !self.check(.eof)) {
            const ty = try self.parseTypeExpr();
            const mname = self.text(try self.expect(.identifier));
            _ = self.match(.semicolon);
            mems.append(self.alloc, .{ .name = mname, .type_expr = ty }) catch return ParseError.OutOfMemory;
        }
        _ = self.match(.rbrace);
        return .{ .name = name, .members = mems.items };
    }

    fn parseEnum(self: *Parser) ParseError!ast.EnumDef {
        _ = self.advance(); // enum
        const name = self.text(try self.expect(.identifier));
        _ = try self.expect(.lbrace);
        var vals = std.ArrayList([]const u8){};
        while (!self.check(.rbrace) and !self.check(.eof)) {
            vals.append(self.alloc, self.text(self.advance())) catch return ParseError.OutOfMemory;
            _ = self.match(.comma);
        }
        _ = self.match(.rbrace);
        return .{ .name = name, .values = vals.items };
    }

    fn parseUsing(self: *Parser) ParseError!ast.UsingDirective {
        _ = self.advance(); // using
        const lib = self.text(self.advance());
        _ = self.match(.kw_for);
        var target: ?ast.TypeExpr = null;
        if (!self.check(.star) and !self.check(.semicolon)) target = try self.parseTypeExpr();
        if (self.check(.star)) _ = self.advance();
        const is_global = self.check(.identifier) and std.mem.eql(u8, self.text(self.peek()), "global");
        if (is_global) _ = self.advance();
        _ = self.match(.semicolon);
        return .{ .library = lib, .target_type = target, .is_global = is_global };
    }

    // === Type expressions ===
    fn parseTypeExpr(self: *Parser) ParseError!ast.TypeExpr {
        if (self.check(.kw_mapping)) return self.parseMappingType();
        if (self.check(.kw_option)) {
            _ = self.advance();
            _ = try self.expect(.lparen);
            const inner = try self.parseTypeExpr();
            _ = try self.expect(.rparen);
            const ptr = self.alloc.create(ast.TypeExpr) catch return ParseError.OutOfMemory;
            ptr.* = inner;
            return .{ .option_type = ptr };
        }
        if (self.check(.kw_result)) {
            _ = self.advance();
            _ = try self.expect(.lparen);
            const ok_ty = try self.parseTypeExpr();
            _ = try self.expect(.comma);
            const err_ty = try self.parseTypeExpr();
            _ = try self.expect(.rparen);
            const ptr = self.alloc.create(ast.ResultType) catch return ParseError.OutOfMemory;
            ptr.* = .{ .ok_type = ok_ty, .err_type = err_ty };
            return .{ .result_type = ptr };
        }
        if (self.check(.kw_resource)) {
            _ = self.advance();
            const inner = try self.parseTypeExpr();
            const ptr = self.alloc.create(ast.TypeExpr) catch return ParseError.OutOfMemory;
            ptr.* = inner;
            return .{ .resource_type = ptr };
        }

        var base: ast.TypeExpr = undefined;
        const tok = self.peek();
        switch (tok.kind) {
            .kw_address => {
                _ = self.advance();
                base = .{ .elementary = .address };
            },
            .kw_bool => {
                _ = self.advance();
                base = .{ .elementary = .bool_type };
            },
            .kw_string => {
                _ = self.advance();
                base = .{ .elementary = .string_type };
            },
            .kw_bytes => {
                _ = self.advance();
                base = .{ .elementary = .bytes_type };
            },
            .identifier => {
                base = .{ .user_defined = self.text(self.advance()) };
            },
            else => return ParseError.InvalidType,
        }
        // Array dimensions
        while (self.check(.lbracket)) {
            _ = self.advance();
            var length: ?ast.Expr = null;
            if (!self.check(.rbracket)) length = try self.parseExpr();
            _ = try self.expect(.rbracket);
            const ptr = self.alloc.create(ast.ArrayType) catch return ParseError.OutOfMemory;
            ptr.* = .{ .base_type = base, .length = length };
            base = .{ .array = ptr };
        }
        return base;
    }

    fn parseMappingType(self: *Parser) ParseError!ast.TypeExpr {
        _ = self.advance(); // mapping
        _ = try self.expect(.lparen);
        const key = try self.parseTypeExpr();
        _ = try self.expect(.arrow);
        const val = try self.parseTypeExpr();
        _ = try self.expect(.rparen);
        const ptr = self.alloc.create(ast.MappingType) catch return ParseError.OutOfMemory;
        ptr.* = .{ .key_type = key, .value_type = val };
        return .{ .mapping = ptr };
    }

    // === Block and Statements ===
    fn parseBlock(self: *Parser) ParseError!ast.BlockStmt {
        _ = try self.expect(.lbrace);
        var stmts = std.ArrayList(ast.Stmt){};
        while (!self.check(.rbrace) and !self.check(.eof)) {
            stmts.append(self.alloc, try self.parseStmt()) catch return ParseError.OutOfMemory;
        }
        _ = self.match(.rbrace);
        return .{ .statements = stmts.items };
    }

    fn parseStmt(self: *Parser) ParseError!ast.Stmt {
        switch (self.peek().kind) {
            .lbrace => return .{ .block = try self.parseBlock() },
            .kw_if => return .{ .if_stmt = try self.parseIf() },
            .kw_for => return .{ .for_stmt = try self.parseFor() },
            .kw_while => return .{ .while_stmt = try self.parseWhile() },
            .kw_return => return self.parseReturn(),
            .kw_emit => return self.parseEmit(),
            .kw_revert => return self.parseRevert(),
            .kw_require => return self.parseRequireStmt(),
            .kw_break => {
                _ = self.advance();
                _ = self.match(.semicolon);
                return .{ .break_stmt = {} };
            },
            .kw_continue => {
                _ = self.advance();
                _ = self.match(.semicolon);
                return .{ .continue_stmt = {} };
            },
            .kw_unchecked => {
                _ = self.advance();
                return .{ .unchecked_block = try self.parseBlock() };
            },
            .kw_match => return .{ .match_stmt = try self.parseMatch() },
            .kw_assembly => return self.parseAssembly(),
            else => {
                // Could be var decl or expression statement
                if (self.isVarDecl()) return .{ .variable_decl = try self.parseVarDecl() };
                const expr = try self.parseExpr();
                _ = self.match(.semicolon);
                return .{ .expression = .{ .expr = expr } };
            },
        }
    }

    fn isVarDecl(self: *Parser) bool {
        const saved = self.pos;
        defer self.pos = saved;
        // Try to parse type + identifier
        switch (self.peek().kind) {
            .kw_mapping, .kw_address, .kw_bool, .kw_string, .kw_bytes, .kw_option, .kw_result => return true,
            .identifier => {
                _ = self.advance();

                // skip array brackets to check what follows
                while (self.check(.lbracket)) {
                    _ = self.advance(); // consume [
                    var depth: usize = 1;
                    while (depth > 0 and self.peek().kind != .eof) {
                        const tk = self.advance().kind;
                        if (tk == .lbracket) depth += 1;
                        if (tk == .rbracket) depth -= 1;
                    }
                }

                return switch (self.peek().kind) {
                    .identifier, .kw_memory, .kw_storage, .kw_calldata => true,
                    else => false,
                };
            },
            else => return false,
        }
    }

    fn parseVarDecl(self: *Parser) ParseError!ast.VarDeclStmt {
        const ty = try self.parseTypeExpr();
        var loc: ?ast.DataLocation = null;
        if (self.check(.kw_memory)) {
            loc = .memory;
            _ = self.advance();
        } else if (self.check(.kw_storage)) {
            loc = .storage;
            _ = self.advance();
        } else if (self.check(.kw_calldata)) {
            loc = .calldata;
            _ = self.advance();
        }
        var names = std.ArrayList(?[]const u8){};
        names.append(self.alloc, self.text(try self.expect(.identifier))) catch return ParseError.OutOfMemory;
        var init_val: ?ast.Expr = null;
        if (self.match(.eq)) init_val = try self.parseExpr();
        _ = self.match(.semicolon);
        return .{ .names = names.items, .type_expr = ty, .data_location = loc, .initial_value = init_val, .is_constant = false };
    }

    fn parseIf(self: *Parser) ParseError!*ast.IfStmt {
        _ = self.advance(); // if
        _ = try self.expect(.lparen);
        const cond = try self.parseExpr();
        _ = try self.expect(.rparen);
        const then_body = try self.parseStmt();
        var else_body: ?ast.Stmt = null;
        if (self.match(.kw_else)) else_body = try self.parseStmt();
        const ptr = self.alloc.create(ast.IfStmt) catch return ParseError.OutOfMemory;
        ptr.* = .{ .condition = cond, .then_body = then_body, .else_body = else_body };
        return ptr;
    }

    fn parseFor(self: *Parser) ParseError!*ast.ForStmt {
        _ = self.advance(); // for
        _ = try self.expect(.lparen);
        var init_stmt: ?*ast.Stmt = null;
        if (!self.check(.semicolon)) {
            const s = self.alloc.create(ast.Stmt) catch return ParseError.OutOfMemory;
            s.* = try self.parseStmt();
            init_stmt = s;
        } else _ = self.advance();
        var cond: ?ast.Expr = null;
        if (!self.check(.semicolon)) cond = try self.parseExpr();
        _ = self.match(.semicolon);
        var update: ?ast.Expr = null;
        if (!self.check(.rparen)) update = try self.parseExpr();
        _ = try self.expect(.rparen);
        const body = try self.parseStmt();
        const ptr = self.alloc.create(ast.ForStmt) catch return ParseError.OutOfMemory;
        ptr.* = .{ .init = init_stmt, .condition = cond, .update = update, .body = body };
        return ptr;
    }

    fn parseWhile(self: *Parser) ParseError!*ast.WhileStmt {
        _ = self.advance();
        _ = try self.expect(.lparen);
        const cond = try self.parseExpr();
        _ = try self.expect(.rparen);
        const body = try self.parseStmt();
        const ptr = self.alloc.create(ast.WhileStmt) catch return ParseError.OutOfMemory;
        ptr.* = .{ .condition = cond, .body = body };
        return ptr;
    }

    fn parseReturn(self: *Parser) ParseError!ast.Stmt {
        _ = self.advance();
        var val: ?ast.Expr = null;
        if (!self.check(.semicolon)) val = try self.parseExpr();
        _ = self.match(.semicolon);
        return .{ .return_stmt = .{ .value = val } };
    }

    fn parseEmit(self: *Parser) ParseError!ast.Stmt {
        _ = self.advance();
        const name = self.text(try self.expect(.identifier));
        _ = try self.expect(.lparen);
        var args = std.ArrayList(ast.Expr){};
        while (!self.check(.rparen) and !self.check(.eof)) {
            args.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
            _ = self.match(.comma);
        }
        _ = try self.expect(.rparen);
        _ = self.match(.semicolon);
        return .{ .emit_stmt = .{ .event_name = name, .args = args.items } };
    }

    fn parseRevert(self: *Parser) ParseError!ast.Stmt {
        _ = self.advance();
        var name: ?[]const u8 = null;
        if (self.check(.identifier)) name = self.text(self.advance());
        _ = try self.expect(.lparen);
        var args = std.ArrayList(ast.Expr){};
        while (!self.check(.rparen) and !self.check(.eof)) {
            args.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
            _ = self.match(.comma);
        }
        _ = try self.expect(.rparen);
        _ = self.match(.semicolon);
        return .{ .revert_stmt = .{ .error_name = name, .args = args.items } };
    }

    fn parseRequireStmt(self: *Parser) ParseError!ast.Stmt {
        // Desugar require(cond, msg) into expression statement
        const expr = try self.parseExpr();
        _ = self.match(.semicolon);
        return .{ .expression = .{ .expr = expr } };
    }

    fn parseMatch(self: *Parser) ParseError!*ast.MatchStmt {
        _ = self.advance(); // match
        const subject = try self.parseExpr();
        _ = try self.expect(.lbrace);
        var arms = std.ArrayList(ast.MatchArm){};
        while (!self.check(.rbrace) and !self.check(.eof)) {
            const pattern = try self.parseMatchPattern();
            _ = try self.expect(.arrow);
            const body = try self.parseStmt();
            arms.append(self.alloc, .{ .pattern = pattern, .body = body }) catch return ParseError.OutOfMemory;
            _ = self.match(.comma);
        }
        _ = self.match(.rbrace);
        const ptr = self.alloc.create(ast.MatchStmt) catch return ParseError.OutOfMemory;
        ptr.* = .{ .subject = subject, .arms = arms.items };
        return ptr;
    }

    fn parseMatchPattern(self: *Parser) ParseError!ast.MatchPattern {
        if (self.match(.kw_some)) {
            _ = try self.expect(.lparen);
            const name = self.text(try self.expect(.identifier));
            _ = try self.expect(.rparen);
            return .{ .some_pattern = name };
        }
        if (self.match(.kw_none)) return .{ .none_pattern = {} };
        if (self.check(.identifier) and std.mem.eql(u8, self.text(self.peek()), "_")) {
            _ = self.advance();
            return .{ .wildcard = {} };
        }
        return .{ .literal = try self.parseExpr() };
    }

    fn parseAssembly(self: *Parser) ParseError!ast.Stmt {
        _ = self.advance(); // assembly
        var dialect: ?[]const u8 = null;
        if (self.check(.string_literal)) {
            const raw = self.text(self.advance());
            dialect = if (raw.len >= 2) raw[1 .. raw.len - 1] else raw;
        }
        _ = try self.expect(.lbrace);
        const start = self.pos;
        var depth: u32 = 1;
        while (depth > 0 and self.peek().kind != .eof) {
            if (self.peek().kind == .lbrace) depth += 1;
            if (self.peek().kind == .rbrace) depth -= 1;
            if (depth > 0) _ = self.advance();
        }
        const raw_code = if (self.pos > start) self.source[self.tokens[start].start..self.tokens[self.pos - 1].end] else "";
        _ = self.match(.rbrace);
        return .{ .assembly = .{ .dialect = dialect, .raw_code = raw_code } };
    }

    // === Expression parsing (Pratt-style precedence climbing) ===
    pub fn parseExpr(self: *Parser) ParseError!ast.Expr {
        return self.parseAssignment();
    }

    fn parseAssignment(self: *Parser) ParseError!ast.Expr {
        var left = try self.parseTernary();
        if (self.isAssignmentOp()) {
            const op = self.mapAssignOp(self.advance().kind);
            const right = try self.parseAssignment();
            const ptr = self.alloc.create(ast.AssignmentExpr) catch return ParseError.OutOfMemory;
            ptr.* = .{ .target = left, .op = op, .value = right };
            left = .{ .assignment = ptr };
        }
        return left;
    }

    fn isAssignmentOp(self: *const Parser) bool {
        return switch (self.peek().kind) {
            .eq, .plus_eq, .minus_eq, .star_eq, .slash_eq, .percent_eq, .amp_eq, .pipe_eq, .caret_eq, .lt_lt_eq, .gt_gt_eq => true,
            else => false,
        };
    }

    fn mapAssignOp(_: *const Parser, k: TK) ast.AssignmentOp {
        return switch (k) {
            .eq => .assign,
            .plus_eq => .add_assign,
            .minus_eq => .sub_assign,
            .star_eq => .mul_assign,
            .slash_eq => .div_assign,
            .percent_eq => .mod_assign,
            .amp_eq => .and_assign,
            .pipe_eq => .or_assign,
            .caret_eq => .xor_assign,
            .lt_lt_eq => .shl_assign,
            .gt_gt_eq => .shr_assign,
            else => .assign,
        };
    }

    fn parseTernary(self: *Parser) ParseError!ast.Expr {
        var expr = try self.parseOr();
        if (self.match(.question_mark)) {
            const true_e = try self.parseExpr();
            _ = try self.expect(.colon);
            const false_e = try self.parseExpr();
            const ptr = self.alloc.create(ast.TernaryExpr) catch return ParseError.OutOfMemory;
            ptr.* = .{ .condition = expr, .true_expr = true_e, .false_expr = false_e };
            expr = .{ .ternary = ptr };
        }
        return expr;
    }

    fn parseOr(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{.pipe_pipe}, parseBinOpEnum(.or_op), parseAnd);
    }
    fn parseAnd(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{.amp_amp}, parseBinOpEnum(.and_op), parseBitOr);
    }
    fn parseBitOr(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{.pipe}, parseBinOpEnum(.bit_or), parseBitXor);
    }
    fn parseBitXor(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{.caret}, parseBinOpEnum(.bit_xor), parseBitAnd);
    }
    fn parseBitAnd(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{.amp}, parseBinOpEnum(.bit_and), parseEquality);
    }

    fn parseEquality(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{ .eq_eq, .bang_eq }, eqMapper, parseComparison);
    }
    fn parseComparison(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{ .lt, .gt, .lt_eq, .gt_eq }, cmpMapper, parseShift);
    }
    fn parseShift(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{ .lt_lt, .gt_gt }, shiftMapper, parseAddSub);
    }
    fn parseAddSub(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{ .plus, .minus, .plus_percent, .minus_percent, .plus_pipe, .minus_pipe }, addMapper, parseMulDiv);
    }
    fn parseMulDiv(self: *Parser) ParseError!ast.Expr {
        return self.parseBinLeft(&[_]TK{ .star, .slash, .percent, .star_percent }, mulMapper, parseExp);
    }

    fn parseExp(self: *Parser) ParseError!ast.Expr {
        var base = try self.parseUnary();
        if (self.match(.star_star)) {
            const right = try self.parseExp(); // right-associative
            const ptr = self.alloc.create(ast.BinaryOpExpr) catch return ParseError.OutOfMemory;
            ptr.* = .{ .left = base, .op = .exp, .right = right };
            base = .{ .binary_op = ptr };
        }
        return base;
    }

    fn parseUnary(self: *Parser) ParseError!ast.Expr {
        switch (self.peek().kind) {
            .bang => {
                _ = self.advance();
                const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                ptr.* = .{ .op = .not, .operand = try self.parseUnary(), .is_prefix = true };
                return .{ .unary_op = ptr };
            },
            .minus => {
                _ = self.advance();
                const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                ptr.* = .{ .op = .negate, .operand = try self.parseUnary(), .is_prefix = true };
                return .{ .unary_op = ptr };
            },
            .tilde => {
                _ = self.advance();
                const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                ptr.* = .{ .op = .bit_not, .operand = try self.parseUnary(), .is_prefix = true };
                return .{ .unary_op = ptr };
            },
            .plus_plus => {
                _ = self.advance();
                const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                ptr.* = .{ .op = .increment, .operand = try self.parseUnary(), .is_prefix = true };
                return .{ .unary_op = ptr };
            },
            .minus_minus => {
                _ = self.advance();
                const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                ptr.* = .{ .op = .decrement, .operand = try self.parseUnary(), .is_prefix = true };
                return .{ .unary_op = ptr };
            },
            .kw_delete => {
                _ = self.advance();
                const ptr = self.alloc.create(ast.Expr) catch return ParseError.OutOfMemory;
                ptr.* = try self.parseUnary();
                return .{ .delete_expr = ptr };
            },
            else => return self.parsePostfix(),
        }
    }

    fn parsePostfix(self: *Parser) ParseError!ast.Expr {
        var expr = try self.parsePrimary();
        while (true) {
            switch (self.peek().kind) {
                .dot => {
                    _ = self.advance();
                    const member = self.text(self.advance());
                    const ptr = self.alloc.create(ast.MemberAccessExpr) catch return ParseError.OutOfMemory;
                    ptr.* = .{ .object = expr, .member = member };
                    expr = .{ .member_access = ptr };
                },
                .lbracket => {
                    _ = self.advance();
                    var idx: ?ast.Expr = null;
                    if (!self.check(.rbracket)) idx = try self.parseExpr();
                    _ = try self.expect(.rbracket);
                    const ptr = self.alloc.create(ast.IndexAccessExpr) catch return ParseError.OutOfMemory;
                    ptr.* = .{ .base = expr, .index = idx, .end_index = null };
                    expr = .{ .index_access = ptr };
                },
                .lparen => {
                    _ = self.advance();
                    var args = std.ArrayList(ast.Expr){};
                    while (!self.check(.rparen) and !self.check(.eof)) {
                        args.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
                        _ = self.match(.comma);
                    }
                    _ = self.match(.rparen);
                    // Parse call options {value: x, gas: y}
                    var opts = std.ArrayList(ast.CallOption){};
                    if (self.check(.lbrace)) {
                        _ = self.advance();
                        while (!self.check(.rbrace) and !self.check(.eof)) {
                            const oname = self.text(self.advance());
                            _ = try self.expect(.colon);
                            const oval = try self.parseExpr();
                            opts.append(self.alloc, .{ .name = oname, .value = oval }) catch return ParseError.OutOfMemory;
                            _ = self.match(.comma);
                        }
                        _ = self.match(.rbrace);
                    }
                    const ptr = self.alloc.create(ast.FunctionCallExpr) catch return ParseError.OutOfMemory;
                    ptr.* = .{ .callee = expr, .args = args.items, .named_args = &.{}, .call_options = opts.items };
                    expr = .{ .function_call = ptr };
                },
                .plus_plus => {
                    _ = self.advance();
                    const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                    ptr.* = .{ .op = .increment, .operand = expr, .is_prefix = false };
                    expr = .{ .unary_op = ptr };
                },
                .minus_minus => {
                    _ = self.advance();
                    const ptr = self.alloc.create(ast.UnaryOpExpr) catch return ParseError.OutOfMemory;
                    ptr.* = .{ .op = .decrement, .operand = expr, .is_prefix = false };
                    expr = .{ .unary_op = ptr };
                },
                else => break,
            }
        }
        return expr;
    }

    fn parsePrimary(self: *Parser) ParseError!ast.Expr {
        switch (self.peek().kind) {
            .number_literal => return .{ .literal = .{ .value = self.text(self.advance()), .kind = .number_decimal, .sub_denomination = null } },
            .string_literal => return .{ .literal = .{ .value = self.text(self.advance()), .kind = .string_literal, .sub_denomination = null } },
            .hex_string_literal => return .{ .literal = .{ .value = self.text(self.advance()), .kind = .hex_string, .sub_denomination = null } },
            .kw_true => {
                _ = self.advance();
                return .{ .literal = .{ .value = "true", .kind = .bool_true, .sub_denomination = null } };
            },
            .kw_false => {
                _ = self.advance();
                return .{ .literal = .{ .value = "false", .kind = .bool_false, .sub_denomination = null } };
            },
            .kw_some => {
                _ = self.advance();
                _ = try self.expect(.lparen);
                const inner = try self.parseExpr();
                _ = try self.expect(.rparen);
                const ptr = self.alloc.create(ast.Expr) catch return ParseError.OutOfMemory;
                ptr.* = inner;
                return .{ .some_expr = ptr };
            },
            .kw_none => {
                _ = self.advance();
                return .{ .none_expr = {} };
            },
            .kw_new => {
                _ = self.advance();
                const ty = try self.parseTypeExpr();
                _ = try self.expect(.lparen);
                var args = std.ArrayList(ast.Expr){};
                while (!self.check(.rparen) and !self.check(.eof)) {
                    args.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
                    _ = self.match(.comma);
                }
                _ = try self.expect(.rparen);
                const ptr = self.alloc.create(ast.NewExpr) catch return ParseError.OutOfMemory;
                ptr.* = .{ .type_name = ty, .args = args.items };
                return .{ .new_expr = ptr };
            },
            .lparen => {
                _ = self.advance();
                if (self.check(.rparen)) {
                    _ = self.advance();
                    return .{ .tuple = &.{} };
                }
                const first = try self.parseExpr();
                if (self.match(.comma)) {
                    var elems = std.ArrayList(?ast.Expr){};
                    elems.append(self.alloc, first) catch return ParseError.OutOfMemory;
                    while (!self.check(.rparen) and !self.check(.eof)) {
                        if (self.check(.comma)) {
                            elems.append(self.alloc, null) catch return ParseError.OutOfMemory;
                        } else {
                            elems.append(self.alloc, try self.parseExpr()) catch return ParseError.OutOfMemory;
                        }
                        _ = self.match(.comma);
                    }
                    _ = self.match(.rparen);
                    return .{ .tuple = elems.items };
                }
                _ = try self.expect(.rparen);
                return first;
            },
            .kw_require, .kw_assert, .identifier, .kw_address, .kw_payable => {
                return .{ .identifier = self.text(self.advance()) };
            },
            .kw_mapping => {
                const ty = try self.parseMappingType();
                return .{ .type_expr = ty };
            },
            else => {
                _ = self.advance();
                return .{ .identifier = "" };
            },
        }
    }

    // === Binary operator helpers ===
    fn parseBinLeft(self: *Parser, ops: []const TK, comptime mapper: anytype, comptime next: fn (*Parser) ParseError!ast.Expr) ParseError!ast.Expr {
        var left = try next(self);
        while (self.matchAny(ops)) |tok_kind| {
            const right = try next(self);
            const ptr = self.alloc.create(ast.BinaryOpExpr) catch return ParseError.OutOfMemory;
            ptr.* = .{ .left = left, .op = mapper(tok_kind), .right = right };
            left = .{ .binary_op = ptr };
        }
        return left;
    }

    fn matchAny(self: *Parser, kinds: []const TK) ?TK {
        const cur = self.peek().kind;
        for (kinds) |k| {
            if (cur == k) {
                _ = self.advance();
                return k;
            }
        }
        return null;
    }

    fn parseBinOpEnum(comptime op: ast.BinaryOp) fn (TK) ast.BinaryOp {
        return struct {
            fn f(_: TK) ast.BinaryOp {
                return op;
            }
        }.f;
    }
    fn eqMapper(k: TK) ast.BinaryOp {
        return if (k == .eq_eq) .eq else .neq;
    }
    fn cmpMapper(k: TK) ast.BinaryOp {
        return switch (k) {
            .lt => .lt,
            .gt => .gt,
            .lt_eq => .lte,
            .gt_eq => .gte,
            else => .lt,
        };
    }
    fn shiftMapper(k: TK) ast.BinaryOp {
        return if (k == .lt_lt) .shl else .shr;
    }
    fn addMapper(k: TK) ast.BinaryOp {
        return switch (k) {
            .plus => .add,
            .minus => .sub,
            .plus_percent => .wrapping_add,
            .minus_percent => .wrapping_sub,
            .plus_pipe => .saturating_add,
            .minus_pipe => .saturating_sub,
            else => .add,
        };
    }
    fn mulMapper(k: TK) ast.BinaryOp {
        return switch (k) {
            .star => .mul,
            .slash => .div,
            .percent => .mod,
            .star_percent => .wrapping_mul,
            else => .mul,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;

fn tokenize(alloc: std.mem.Allocator, src: []const u8) ![]Token {
    var lex = lexer.Lexer.init(src);
    return lex.tokenizeAll(alloc);
}

test "parser: empty contract" {
    const src = "contract Foo { }";
    const tokens = try tokenize(testing.allocator, src);
    defer testing.allocator.free(tokens);
    var p = Parser.init(testing.allocator, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    try testing.expectEqual(@as(usize, 1), unit.definitions.len);
    try testing.expectEqualStrings("Foo", unit.definitions[0].contract.name);
}

test "parser: state variable" {
    const src = "contract T { uint256 public x; }";
    const tokens = try tokenize(testing.allocator, src);
    defer testing.allocator.free(tokens);
    var p = Parser.init(testing.allocator, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    const c = unit.definitions[0].contract;
    try testing.expectEqual(@as(usize, 1), c.members.len);
    try testing.expectEqualStrings("x", c.members[0].state_var.name);
}

test "parser: function" {
    const src = "contract T { function foo(uint256 x) external view returns (uint256) { return x; } }";
    const tokens = try tokenize(testing.allocator, src);
    defer testing.allocator.free(tokens);
    var p = Parser.init(testing.allocator, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    const f = unit.definitions[0].contract.members[0].function;
    try testing.expectEqualStrings("foo", f.name);
    try testing.expectEqual(ast.Visibility.external, f.visibility);
    try testing.expectEqual(ast.StateMutability.view, f.mutability);
}

test "parser: event and role" {
    const src = "contract T { event Transfer(address indexed from, uint256 value); role ADMIN; }";
    const tokens = try tokenize(testing.allocator, src);
    defer testing.allocator.free(tokens);
    var p = Parser.init(testing.allocator, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    const c = unit.definitions[0].contract;
    try testing.expectEqual(@as(usize, 2), c.members.len);
    try testing.expectEqualStrings("Transfer", c.members[0].event.name);
    try testing.expectEqualStrings("ADMIN", c.members[1].role_def.name);
}

test "parser: mapping type" {
    const src = "contract T { mapping(address => uint256) public balances; }";
    const tokens = try tokenize(testing.allocator, src);
    defer testing.allocator.free(tokens);
    var p = Parser.init(testing.allocator, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    const sv = unit.definitions[0].contract.members[0].state_var;
    try testing.expectEqualStrings("balances", sv.name);
    try testing.expect(sv.type_expr == .mapping);
}

test "parser: pragma and import" {
    const src =
        \\pragma zephyr ^1.0;
        \\import "std.token.ERC20";
        \\contract T { }
    ;
    const tokens = try tokenize(testing.allocator, src);
    defer testing.allocator.free(tokens);
    var p = Parser.init(testing.allocator, tokens, src);
    p.ready();
    defer p.deinit();
    const unit = try p.parseSourceUnit();
    try testing.expectEqual(@as(usize, 1), unit.pragmas.len);
    try testing.expectEqual(@as(usize, 1), unit.imports.len);
    try testing.expectEqualStrings("std.token.ERC20", unit.imports[0].path);
}
