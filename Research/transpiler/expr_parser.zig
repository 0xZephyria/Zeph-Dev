// File: tools/sol2zig/expr_parser.zig
// Recursive-descent expression and statement parser for Solidity function bodies.
// Implements full Solidity operator precedence (13 levels).

const std = @import("std");
const ast = @import("ast.zig");

pub const ParseError = error{OutOfMemory};

pub const ExprParser = struct {
    allocator: std.mem.Allocator,
    source: []const u8,
    pos: usize,
    line: usize,
    in_unchecked: bool,

    pub fn init(allocator: std.mem.Allocator, source: []const u8) ExprParser {
        return .{
            .allocator = allocator,
            .source = source,
            .pos = 0,
            .line = 1,
            .in_unchecked = false,
        };
    }

    // ========================================================================
    // Statement Parsing
    // ========================================================================

    pub fn parseBlock(self: *ExprParser) ParseError![]const ast.Statement {
        var stmts = std.ArrayListUnmanaged(ast.Statement){};
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == '{') self.pos += 1;
        while (self.pos < self.source.len) {
            self.skipWS();
            if (self.pos >= self.source.len or self.source[self.pos] == '}') break;
            const stmt = try self.parseStatement();
            try stmts.append(self.allocator, stmt);
        }
        if (self.pos < self.source.len and self.source[self.pos] == '}') self.pos += 1;
        return try stmts.toOwnedSlice(self.allocator);
    }

    pub fn parseStatement(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        if (self.pos >= self.source.len) return ast.Statement{ .raw_statement = .{ .text = "" } };

        // Check statement-starting keywords
        if (self.matchKeyword("if")) return self.parseIfStmt();
        if (self.matchKeyword("for")) return self.parseForStmt();
        if (self.matchKeyword("while")) return self.parseWhileStmt();
        if (self.matchKeyword("do")) return self.parseDoWhileStmt();
        if (self.matchKeyword("return")) return self.parseReturnStmt();
        if (self.matchKeyword("emit")) return self.parseEmitStmt();
        if (self.matchKeyword("revert")) return self.parseRevertStmt();
        if (self.matchKeyword("unchecked")) return self.parseUncheckedStmt();
        if (self.matchKeyword("assembly")) return self.parseAssemblyStmt();
        if (self.matchKeyword("break")) {
            self.skipSemicolon();
            return ast.Statement{ .break_stmt = {} };
        }
        if (self.matchKeyword("continue")) {
            self.skipSemicolon();
            return ast.Statement{ .continue_stmt = {} };
        }
        if (self.source[self.pos] == '_' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == ';') {
            self.pos += 2;
            return ast.Statement{ .placeholder_stmt = {} };
        }
        if (self.source[self.pos] == '{') {
            const stmts = try self.parseBlock();
            const blk = try self.allocator.create(ast.BlockStmt);
            blk.* = .{ .statements = stmts };
            return ast.Statement{ .block = blk };
        }

        // Try variable declaration
        if (try self.tryParseVarDecl()) |decl| return decl;

        // Expression statement
        const expr = try self.parseExpression();
        self.skipSemicolon();
        const es = try self.allocator.create(ast.ExprStmt);
        es.* = .{ .expr = expr };
        return ast.Statement{ .expression_stmt = es };
    }

    fn parseIfStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == '(') self.pos += 1;
        const cond = try self.parseExpression();
        if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
        self.skipWS();
        const then_body = if (self.pos < self.source.len and self.source[self.pos] == '{')
            try self.parseBlock()
        else blk: {
            const s = try self.parseStatement();
            const sl = try self.allocator.alloc(ast.Statement, 1);
            sl[0] = s;
            break :blk sl;
        };
        self.skipWS();
        var else_body: ?[]const ast.Statement = null;
        if (self.matchKeyword("else")) {
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '{') {
                else_body = try self.parseBlock();
            } else {
                const s = try self.parseStatement();
                const sl = try self.allocator.alloc(ast.Statement, 1);
                sl[0] = s;
                else_body = sl;
            }
        }
        const node = try self.allocator.create(ast.IfStmt);
        node.* = .{ .condition = cond, .then_body = then_body, .else_body = else_body };
        return ast.Statement{ .if_stmt = node };
    }

    fn parseForStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == '(') self.pos += 1;
        self.skipWS();
        // Init
        var init_stmt: ?ast.Statement = null;
        if (self.pos < self.source.len and self.source[self.pos] != ';') {
            init_stmt = try self.parseStatement();
        } else {
            self.pos += 1; // skip ;
        }
        self.skipWS();
        // Condition
        var cond: ?ast.Expression = null;
        if (self.pos < self.source.len and self.source[self.pos] != ';') {
            cond = try self.parseExpression();
        }
        self.skipSemicolon();
        self.skipWS();
        // Post
        var post: ?ast.Expression = null;
        if (self.pos < self.source.len and self.source[self.pos] != ')') {
            post = try self.parseExpression();
        }
        if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
        self.skipWS();
        const body = if (self.pos < self.source.len and self.source[self.pos] == '{')
            try self.parseBlock()
        else blk: {
            const s = try self.parseStatement();
            const sl = try self.allocator.alloc(ast.Statement, 1);
            sl[0] = s;
            break :blk sl;
        };
        const node = try self.allocator.create(ast.ForStmt);
        node.* = .{ .init = init_stmt, .condition = cond, .post = post, .body = body };
        return ast.Statement{ .for_stmt = node };
    }

    fn parseWhileStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == '(') self.pos += 1;
        const cond = try self.parseExpression();
        if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
        self.skipWS();
        const body = if (self.pos < self.source.len and self.source[self.pos] == '{')
            try self.parseBlock()
        else blk: {
            const s = try self.parseStatement();
            const sl = try self.allocator.alloc(ast.Statement, 1);
            sl[0] = s;
            break :blk sl;
        };
        const node = try self.allocator.create(ast.WhileStmt);
        node.* = .{ .condition = cond, .body = body };
        return ast.Statement{ .while_stmt = node };
    }

    fn parseDoWhileStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        const body = try self.parseBlock();
        self.skipWS();
        _ = self.matchKeyword("while");
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == '(') self.pos += 1;
        const cond = try self.parseExpression();
        if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
        self.skipSemicolon();
        const node = try self.allocator.create(ast.DoWhileStmt);
        node.* = .{ .body = body, .condition = cond };
        return ast.Statement{ .do_while_stmt = node };
    }

    fn parseReturnStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        var value: ?ast.Expression = null;
        if (self.pos < self.source.len and self.source[self.pos] != ';') {
            value = try self.parseExpression();
        }
        self.skipSemicolon();
        const node = try self.allocator.create(ast.ReturnStmt);
        node.* = .{ .value = value };
        return ast.Statement{ .return_stmt = node };
    }

    fn parseEmitStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        const name = self.parseIdent();
        self.skipWS();
        var args = std.ArrayListUnmanaged(ast.Expression){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') {
            self.pos += 1;
            try self.parseArgList(&args);
        }
        self.skipSemicolon();
        const node = try self.allocator.create(ast.EmitStmt);
        node.* = .{ .event_name = name, .args = try args.toOwnedSlice(self.allocator) };
        return ast.Statement{ .emit_stmt = node };
    }

    fn parseRevertStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        var error_name: ?[]const u8 = null;
        var args = std.ArrayListUnmanaged(ast.Expression){};
        if (self.pos < self.source.len and self.source[self.pos] == '(') {
            // revert("message") form
            self.pos += 1;
            try self.parseArgList(&args);
        } else if (self.pos < self.source.len and std.ascii.isAlphabetic(self.source[self.pos])) {
            error_name = self.parseIdent();
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '(') {
                self.pos += 1;
                try self.parseArgList(&args);
            }
        }
        self.skipSemicolon();
        const node = try self.allocator.create(ast.RevertStmt);
        node.* = .{ .error_name = error_name, .args = try args.toOwnedSlice(self.allocator) };
        return ast.Statement{ .revert_stmt = node };
    }

    fn parseUncheckedStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        const prev = self.in_unchecked;
        self.in_unchecked = true;
        const body = try self.parseBlock();
        self.in_unchecked = prev;
        const node = try self.allocator.create(ast.UncheckedStmt);
        node.* = .{ .body = body };
        return ast.Statement{ .unchecked_block = node };
    }

    fn parseAssemblyStmt(self: *ExprParser) ParseError!ast.Statement {
        self.skipWS();
        var dialect: ?[]const u8 = null;
        if (self.pos < self.source.len and self.source[self.pos] == '"') {
            self.pos += 1;
            const start = self.pos;
            while (self.pos < self.source.len and self.source[self.pos] != '"') self.pos += 1;
            dialect = self.source[start..self.pos];
            if (self.pos < self.source.len) self.pos += 1;
            self.skipWS();
        }
        const start = self.pos;
        if (self.pos < self.source.len and self.source[self.pos] == '{') {
            var depth: usize = 1;
            self.pos += 1;
            while (self.pos < self.source.len and depth > 0) {
                if (self.source[self.pos] == '{') depth += 1;
                if (self.source[self.pos] == '}') depth -= 1;
                self.pos += 1;
            }
        }
        const node = try self.allocator.create(ast.AssemblyStmt);
        node.* = .{ .raw_code = self.source[start..self.pos], .dialect = dialect };
        return ast.Statement{ .assembly_block = node };
    }

    fn tryParseVarDecl(self: *ExprParser) ParseError!?ast.Statement {
        const save_pos = self.pos;
        self.skipWS();

        // Check for type keyword patterns: uint256, int128, address, bool, bytes32, string, mapping(...)
        const type_name = self.tryParseTypeName() orelse {
            self.pos = save_pos;
            return null;
        };
        self.skipWS();

        // Check storage location
        var storage_loc: ?[]const u8 = null;
        if (self.matchKeyword("memory")) {
            storage_loc = "memory";
        } else if (self.matchKeyword("storage")) {
            storage_loc = "storage";
        } else if (self.matchKeyword("calldata")) {
            storage_loc = "calldata";
        }
        self.skipWS();

        // Must be followed by an identifier (the variable name)
        if (self.pos >= self.source.len or (!std.ascii.isAlphabetic(self.source[self.pos]) and self.source[self.pos] != '_')) {
            self.pos = save_pos;
            return null;
        }
        const var_name = self.parseIdent();
        // Verify identifier is not a keyword that would indicate this wasn't a var decl
        if (isKeyword(var_name)) {
            self.pos = save_pos;
            return null;
        }
        self.skipWS();

        // Parse optional initializer
        var init_val: ?ast.Expression = null;
        if (self.pos < self.source.len and self.source[self.pos] == '=') {
            self.pos += 1;
            self.skipWS();
            init_val = try self.parseExpression();
        }
        self.skipSemicolon();

        const names = try self.allocator.alloc([]const u8, 1);
        names[0] = var_name;
        const node = try self.allocator.create(ast.VarDeclStmt);
        node.* = .{
            .type_name = type_name,
            .var_names = names,
            .var_types = null,
            .is_constant = false,
            .initial_value = init_val,
            .storage_location = storage_loc,
        };
        return ast.Statement{ .variable_decl = node };
    }

    // ========================================================================
    // Expression Parsing — Recursive Descent with Operator Precedence
    // ========================================================================

    pub fn parseExpression(self: *ExprParser) ParseError!ast.Expression {
        return self.parseAssignmentExpr();
    }

    fn parseAssignmentExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseConditionalExpr();
        self.skipWS();
        if (self.pos >= self.source.len) return left;
        const op = self.tryParseAssignOp() orelse return left;
        self.skipWS();
        const right = try self.parseAssignmentExpr(); // Right-associative
        const node = try self.allocator.create(ast.AssignmentExpr);
        node.* = .{ .target = left, .op = op, .value = right };
        left = ast.Expression{ .assignment = node };
        return left;
    }

    fn parseConditionalExpr(self: *ExprParser) ParseError!ast.Expression {
        var expr = try self.parseOrExpr();
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == '?') {
            self.pos += 1;
            self.skipWS();
            const true_e = try self.parseExpression();
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == ':') self.pos += 1;
            self.skipWS();
            const false_e = try self.parseConditionalExpr();
            const node = try self.allocator.create(ast.ConditionalExpr);
            node.* = .{ .condition = expr, .true_expr = true_e, .false_expr = false_e };
            expr = ast.Expression{ .conditional = node };
        }
        return expr;
    }

    fn parseOrExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseAndExpr();
        while (true) {
            self.skipWS();
            if (self.matchStr("||")) {
                self.skipWS();
                const right = try self.parseAndExpr();
                left = try self.makeBinary(left, .or_, right);
            } else break;
        }
        return left;
    }

    fn parseAndExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseBitOrExpr();
        while (true) {
            self.skipWS();
            if (self.matchStr("&&")) {
                self.skipWS();
                const right = try self.parseBitOrExpr();
                left = try self.makeBinary(left, .and_, right);
            } else break;
        }
        return left;
    }

    fn parseBitOrExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseBitXorExpr();
        while (true) {
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '|' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '|') and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '='))
            {
                self.pos += 1;
                self.skipWS();
                const right = try self.parseBitXorExpr();
                left = try self.makeBinary(left, .bit_or, right);
            } else break;
        }
        return left;
    }

    fn parseBitXorExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseBitAndExpr();
        while (true) {
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '^' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '='))
            {
                self.pos += 1;
                self.skipWS();
                const right = try self.parseBitAndExpr();
                left = try self.makeBinary(left, .bit_xor, right);
            } else break;
        }
        return left;
    }

    fn parseBitAndExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseEqualityExpr();
        while (true) {
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '&' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '&') and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '='))
            {
                self.pos += 1;
                self.skipWS();
                const right = try self.parseEqualityExpr();
                left = try self.makeBinary(left, .bit_and, right);
            } else break;
        }
        return left;
    }

    fn parseEqualityExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseComparisonExpr();
        while (true) {
            self.skipWS();
            if (self.matchStr("==")) {
                self.skipWS();
                const right = try self.parseComparisonExpr();
                left = try self.makeBinary(left, .eq, right);
            } else if (self.matchStr("!=")) {
                self.skipWS();
                const right = try self.parseComparisonExpr();
                left = try self.makeBinary(left, .neq, right);
            } else break;
        }
        return left;
    }

    fn parseComparisonExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseShiftExpr();
        while (true) {
            self.skipWS();
            if (self.matchStr("<=")) {
                self.skipWS();
                left = try self.makeBinary(left, .lte, try self.parseShiftExpr());
            } else if (self.matchStr(">=")) {
                self.skipWS();
                left = try self.makeBinary(left, .gte, try self.parseShiftExpr());
            } else if (self.pos < self.source.len and self.source[self.pos] == '<' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '<'))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .lt, try self.parseShiftExpr());
            } else if (self.pos < self.source.len and self.source[self.pos] == '>' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '>'))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .gt, try self.parseShiftExpr());
            } else break;
        }
        return left;
    }

    fn parseShiftExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseAddExpr();
        while (true) {
            self.skipWS();
            if (self.matchStr("<<")) {
                self.skipWS();
                left = try self.makeBinary(left, .shl, try self.parseAddExpr());
            } else if (self.matchStr(">>")) {
                self.skipWS();
                left = try self.makeBinary(left, .shr, try self.parseAddExpr());
            } else break;
        }
        return left;
    }

    fn parseAddExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseMulExpr();
        while (true) {
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '+' and
                (self.pos + 1 >= self.source.len or (self.source[self.pos + 1] != '+' and self.source[self.pos + 1] != '=')))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .add, try self.parseMulExpr());
            } else if (self.pos < self.source.len and self.source[self.pos] == '-' and
                (self.pos + 1 >= self.source.len or (self.source[self.pos + 1] != '-' and self.source[self.pos + 1] != '=')))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .sub, try self.parseMulExpr());
            } else break;
        }
        return left;
    }

    fn parseMulExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseExpExpr();
        while (true) {
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '*' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '*') and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '='))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .mul, try self.parseExpExpr());
            } else if (self.pos < self.source.len and self.source[self.pos] == '/' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '='))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .div, try self.parseExpExpr());
            } else if (self.pos < self.source.len and self.source[self.pos] == '%' and
                (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '='))
            {
                self.pos += 1;
                self.skipWS();
                left = try self.makeBinary(left, .mod, try self.parseExpExpr());
            } else break;
        }
        return left;
    }

    fn parseExpExpr(self: *ExprParser) ParseError!ast.Expression {
        var left = try self.parseUnaryExpr();
        self.skipWS();
        if (self.matchStr("**")) {
            self.skipWS();
            const right = try self.parseExpExpr(); // Right-associative
            left = try self.makeBinary(left, .exp, right);
        }
        return left;
    }

    fn parseUnaryExpr(self: *ExprParser) ParseError!ast.Expression {
        self.skipWS();
        if (self.pos >= self.source.len) return ast.Expression{ .literal = .{ .value = "", .kind = .number_decimal } };

        if (self.matchStr("++")) {
            self.skipWS();
            const operand = try self.parseUnaryExpr();
            return self.makeUnary(.increment, operand, true);
        }
        if (self.matchStr("--")) {
            self.skipWS();
            const operand = try self.parseUnaryExpr();
            return self.makeUnary(.decrement, operand, true);
        }
        if (self.source[self.pos] == '!' and (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '=')) {
            self.pos += 1;
            self.skipWS();
            const operand = try self.parseUnaryExpr();
            return self.makeUnary(.not, operand, true);
        }
        if (self.source[self.pos] == '~') {
            self.pos += 1;
            self.skipWS();
            const operand = try self.parseUnaryExpr();
            return self.makeUnary(.bit_not, operand, true);
        }
        if (self.source[self.pos] == '-' and (self.pos + 1 < self.source.len and self.source[self.pos + 1] != '-' and self.source[self.pos + 1] != '=')) {
            // Check if this is a negative literal or unary minus
            self.pos += 1;
            self.skipWS();
            const operand = try self.parseUnaryExpr();
            return self.makeUnary(.negate, operand, true);
        }
        if (self.matchKeyword("delete")) {
            self.skipWS();
            const operand = try self.parseUnaryExpr();
            return self.makeUnary(.delete, operand, true);
        }

        return self.parsePostfixExpr();
    }

    fn parsePostfixExpr(self: *ExprParser) ParseError!ast.Expression {
        var expr = try self.parsePrimaryExpr();
        while (true) {
            self.skipWS();
            if (self.pos >= self.source.len) break;

            if (self.source[self.pos] == '.') {
                self.pos += 1;
                self.skipWS();
                const member = self.parseIdent();
                const node = try self.allocator.create(ast.MemberAccessExpr);
                node.* = .{ .object = expr, .member = member };
                expr = ast.Expression{ .member_access = node };
            } else if (self.source[self.pos] == '[') {
                self.pos += 1;
                self.skipWS();
                const idx = try self.parseExpression();
                self.skipWS();
                if (self.pos < self.source.len and self.source[self.pos] == ']') self.pos += 1;
                const node = try self.allocator.create(ast.IndexAccessExpr);
                node.* = .{ .object = expr, .index = idx };
                expr = ast.Expression{ .index_access = node };
            } else if (self.source[self.pos] == '(') {
                self.pos += 1;
                var args = std.ArrayListUnmanaged(ast.Expression){};
                try self.parseArgList(&args);
                // Check for call options {value: ..., gas: ...}
                self.skipWS();
                const node = try self.allocator.create(ast.FunctionCallExpr);
                node.* = .{ .callee = expr, .args = try args.toOwnedSlice(self.allocator), .named_args = null, .call_options = null };
                expr = ast.Expression{ .function_call = node };
            } else if (self.matchStr("++")) {
                expr = try self.makeUnary(.increment, expr, false);
            } else if (self.matchStr("--")) {
                expr = try self.makeUnary(.decrement, expr, false);
            } else if (self.source[self.pos] == '{') {
                // Call options: addr.call{value: 1}("")
                const opts = try self.parseCallOptions();
                self.skipWS();
                if (self.pos < self.source.len and self.source[self.pos] == '(') {
                    self.pos += 1;
                    var args = std.ArrayListUnmanaged(ast.Expression){};
                    try self.parseArgList(&args);
                    const node = try self.allocator.create(ast.FunctionCallExpr);
                    node.* = .{ .callee = expr, .args = try args.toOwnedSlice(self.allocator), .named_args = null, .call_options = opts };
                    expr = ast.Expression{ .function_call = node };
                }
            } else break;
        }
        return expr;
    }

    fn parsePrimaryExpr(self: *ExprParser) ParseError!ast.Expression {
        self.skipWS();
        if (self.pos >= self.source.len) return ast.Expression{ .literal = .{ .value = "", .kind = .number_decimal } };

        const c = self.source[self.pos];

        // Parenthesized or tuple expression
        if (c == '(') {
            self.pos += 1;
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == ')') {
                self.pos += 1;
                const node = try self.allocator.create(ast.TupleExpr);
                node.* = .{ .elements = &.{} };
                return ast.Expression{ .tuple = node };
            }
            const first = try self.parseExpression();
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == ',') {
                // Tuple
                var elems = std.ArrayListUnmanaged(?ast.Expression){};
                try elems.append(self.allocator, first);
                while (self.pos < self.source.len and self.source[self.pos] == ',') {
                    self.pos += 1;
                    self.skipWS();
                    if (self.pos < self.source.len and (self.source[self.pos] == ',' or self.source[self.pos] == ')')) {
                        try elems.append(self.allocator, null); // gap
                    } else {
                        try elems.append(self.allocator, try self.parseExpression());
                    }
                    self.skipWS();
                }
                if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
                const node = try self.allocator.create(ast.TupleExpr);
                node.* = .{ .elements = try elems.toOwnedSlice(self.allocator) };
                return ast.Expression{ .tuple = node };
            }
            if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
            return first; // Just parenthesized
        }

        // String literal
        if (c == '"' or c == '\'') return self.parseStringLiteral();

        // Hex literal: hex"..."
        if (self.matchKeyword("hex")) {
            self.skipWS();
            if (self.pos < self.source.len and (self.source[self.pos] == '"' or self.source[self.pos] == '\'')) {
                const lit = self.parseStringLiteral();
                switch (lit) {
                    .literal => |l| return ast.Expression{ .literal = .{ .value = l.value, .kind = .hex_string } },
                    else => return lit,
                }
            }
        }

        // Number literal (decimal or hex)
        if (std.ascii.isDigit(c)) return self.parseNumberLiteral();
        if (c == '0' and self.pos + 1 < self.source.len and (self.source[self.pos + 1] == 'x' or self.source[self.pos + 1] == 'X')) {
            return self.parseNumberLiteral();
        }

        // Array literal [1, 2, 3]
        if (c == '[') {
            self.pos += 1;
            var elems = std.ArrayListUnmanaged(ast.Expression){};
            self.skipWS();
            while (self.pos < self.source.len and self.source[self.pos] != ']') {
                try elems.append(self.allocator, try self.parseExpression());
                self.skipWS();
                if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
                self.skipWS();
            }
            if (self.pos < self.source.len) self.pos += 1; // skip ]
            const node = try self.allocator.create(ast.ArrayLiteralExpr);
            node.* = .{ .elements = try elems.toOwnedSlice(self.allocator) };
            return ast.Expression{ .array_literal = node };
        }

        // Identifier or keyword
        if (std.ascii.isAlphabetic(c) or c == '_' or c == '$') {
            const ident = self.parseIdent();

            // Boolean literals
            if (std.mem.eql(u8, ident, "true")) return ast.Expression{ .literal = .{ .value = "true", .kind = .bool_true } };
            if (std.mem.eql(u8, ident, "false")) return ast.Expression{ .literal = .{ .value = "false", .kind = .bool_false } };

            // `new` expression
            if (std.mem.eql(u8, ident, "new")) {
                self.skipWS();
                const type_name = self.parseIdent();
                self.skipWS();
                var args = std.ArrayListUnmanaged(ast.Expression){};
                if (self.pos < self.source.len and self.source[self.pos] == '(') {
                    self.pos += 1;
                    try self.parseArgList(&args);
                }
                const node = try self.allocator.create(ast.NewExpr);
                node.* = .{ .type_name = type_name, .args = try args.toOwnedSlice(self.allocator) };
                return ast.Expression{ .new_expression = node };
            }

            // `type(X)` expression
            if (std.mem.eql(u8, ident, "type")) {
                self.skipWS();
                if (self.pos < self.source.len and self.source[self.pos] == '(') {
                    self.pos += 1;
                    self.skipWS();
                    const target = self.parseIdent();
                    self.skipWS();
                    if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
                    self.skipWS();
                    if (self.pos < self.source.len and self.source[self.pos] == '.') {
                        self.pos += 1;
                        const member = self.parseIdent();
                        const node = try self.allocator.create(ast.TypeInfoExpr);
                        node.* = .{ .target_type = target, .member = member };
                        return ast.Expression{ .type_info = node };
                    }
                }
            }

            // `abi.encode(...)` etc.
            if (std.mem.eql(u8, ident, "abi")) {
                self.skipWS();
                if (self.pos < self.source.len and self.source[self.pos] == '.') {
                    self.pos += 1;
                    const func = self.parseIdent();
                    self.skipWS();
                    var args = std.ArrayListUnmanaged(ast.Expression){};
                    if (self.pos < self.source.len and self.source[self.pos] == '(') {
                        self.pos += 1;
                        try self.parseArgList(&args);
                    }
                    const node = try self.allocator.create(ast.AbiCallExpr);
                    node.* = .{ .function = func, .args = try args.toOwnedSlice(self.allocator) };
                    return ast.Expression{ .abi_call = node };
                }
            }

            // Type cast: uint256(x), address(x), bytes32(x), payable(x)
            if (isSolidityType(ident)) {
                self.skipWS();
                if (self.pos < self.source.len and self.source[self.pos] == '(') {
                    self.pos += 1;
                    self.skipWS();
                    const operand = try self.parseExpression();
                    self.skipWS();
                    if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
                    const node = try self.allocator.create(ast.TypeCastExpr);
                    node.* = .{ .target_type = ident, .operand = operand };
                    return ast.Expression{ .type_cast = node };
                }
                return ast.Expression{ .elementary_type = .{ .type_name = ident } };
            }

            return ast.Expression{ .identifier = .{ .name = ident } };
        }

        // Unknown — consume one character to avoid infinite loop
        self.pos += 1;
        return ast.Expression{ .literal = .{ .value = "", .kind = .number_decimal } };
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn makeBinary(self: *ExprParser, left: ast.Expression, op: ast.BinaryOp, right: ast.Expression) ParseError!ast.Expression {
        const node = try self.allocator.create(ast.BinaryOpExpr);
        node.* = .{ .left = left, .op = op, .right = right };
        return ast.Expression{ .binary_op = node };
    }

    fn makeUnary(self: *ExprParser, op: ast.UnaryOp, operand: ast.Expression, is_prefix: bool) ParseError!ast.Expression {
        const node = try self.allocator.create(ast.UnaryOpExpr);
        node.* = .{ .op = op, .operand = operand, .is_prefix = is_prefix };
        return ast.Expression{ .unary_op = node };
    }

    fn parseArgList(self: *ExprParser, args: *std.ArrayListUnmanaged(ast.Expression)) ParseError!void {
        self.skipWS();
        while (self.pos < self.source.len and self.source[self.pos] != ')') {
            try args.append(self.allocator, try self.parseExpression());
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
            self.skipWS();
        }
        if (self.pos < self.source.len and self.source[self.pos] == ')') self.pos += 1;
    }

    fn parseCallOptions(self: *ExprParser) ParseError![]const ast.NamedArg {
        var opts = std.ArrayListUnmanaged(ast.NamedArg){};
        if (self.pos < self.source.len and self.source[self.pos] == '{') self.pos += 1;
        while (self.pos < self.source.len and self.source[self.pos] != '}') {
            self.skipWS();
            const name = self.parseIdent();
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == ':') self.pos += 1;
            self.skipWS();
            const value = try self.parseExpression();
            try opts.append(self.allocator, .{ .name = name, .value = value });
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == ',') self.pos += 1;
        }
        if (self.pos < self.source.len and self.source[self.pos] == '}') self.pos += 1;
        return try opts.toOwnedSlice(self.allocator);
    }

    fn parseStringLiteral(self: *ExprParser) ast.Expression {
        const quote = self.source[self.pos];
        self.pos += 1;
        const start = self.pos;
        while (self.pos < self.source.len and self.source[self.pos] != quote) {
            if (self.source[self.pos] == '\\') self.pos += 1; // skip escape
            self.pos += 1;
        }
        const value = self.source[start..self.pos];
        if (self.pos < self.source.len) self.pos += 1;
        return ast.Expression{ .literal = .{ .value = value, .kind = .string_literal } };
    }

    fn parseNumberLiteral(self: *ExprParser) ast.Expression {
        const start = self.pos;
        var kind: ast.LiteralKind = .number_decimal;
        if (self.pos + 1 < self.source.len and self.source[self.pos] == '0' and
            (self.source[self.pos + 1] == 'x' or self.source[self.pos + 1] == 'X'))
        {
            kind = .number_hex;
            self.pos += 2;
            while (self.pos < self.source.len and (std.ascii.isHex(self.source[self.pos]) or self.source[self.pos] == '_')) self.pos += 1;
        } else {
            while (self.pos < self.source.len and (std.ascii.isDigit(self.source[self.pos]) or self.source[self.pos] == '_' or self.source[self.pos] == '.' or self.source[self.pos] == 'e' or self.source[self.pos] == 'E')) self.pos += 1;
        }
        // Skip denomination: ether, wei, gwei, seconds, minutes, hours, days, weeks
        self.skipWS();
        const denoms = [_][]const u8{ "ether", "wei", "gwei", "finney", "szabo", "seconds", "minutes", "hours", "days", "weeks" };
        for (denoms) |d| {
            if (self.pos + d.len <= self.source.len and std.mem.eql(u8, self.source[self.pos .. self.pos + d.len], d)) {
                self.pos += d.len;
                break;
            }
        }
        return ast.Expression{ .literal = .{ .value = self.source[start..self.pos], .kind = kind } };
    }

    fn tryParseTypeName(self: *ExprParser) ?[]const u8 {
        const save = self.pos;
        self.skipWS();
        if (self.pos >= self.source.len) {
            self.pos = save;
            return null;
        }

        // mapping(...)
        if (self.pos + 7 <= self.source.len and std.mem.eql(u8, self.source[self.pos .. self.pos + 7], "mapping")) {
            const start = self.pos;
            self.pos += 7;
            self.skipWS();
            if (self.pos < self.source.len and self.source[self.pos] == '(') {
                var depth: usize = 1;
                self.pos += 1;
                while (self.pos < self.source.len and depth > 0) {
                    if (self.source[self.pos] == '(') depth += 1;
                    if (self.source[self.pos] == ')') depth -= 1;
                    self.pos += 1;
                }
                return self.source[start..self.pos];
            }
            self.pos = save;
            return null;
        }

        // Try known type identifiers
        const ident_start = self.pos;
        if (!std.ascii.isAlphabetic(self.source[self.pos]) and self.source[self.pos] != '_') {
            self.pos = save;
            return null;
        }
        while (self.pos < self.source.len and (std.ascii.isAlphanumeric(self.source[self.pos]) or self.source[self.pos] == '_')) self.pos += 1;
        const ident = self.source[ident_start..self.pos];

        if (!isSolidityType(ident) and !std.mem.eql(u8, ident, "var")) {
            // Could be a user-defined type — peek ahead for identifier (var name)
            const after_type = self.pos;
            self.skipWS();
            // Check for storage location or identifier
            if (self.pos < self.source.len) {
                const next_start = self.pos;
                if (std.ascii.isAlphabetic(self.source[self.pos]) or self.source[self.pos] == '_') {
                    while (self.pos < self.source.len and (std.ascii.isAlphanumeric(self.source[self.pos]) or self.source[self.pos] == '_')) self.pos += 1;
                    const next = self.source[next_start..self.pos];
                    self.pos = after_type;
                    // If next is a storage location or looks like a var name, accept this as type
                    if (std.mem.eql(u8, next, "memory") or std.mem.eql(u8, next, "storage") or std.mem.eql(u8, next, "calldata")) {
                        // Accept
                    } else if (!isKeyword(next)) {
                        // Looks like a user-defined type with a var name following —  accept
                    } else {
                        self.pos = save;
                        return null;
                    }
                } else {
                    self.pos = save;
                    return null;
                }
            }
        }

        // Handle array dimensions: uint256[], uint256[10]
        self.skipWS();
        const type_end = self.pos;
        _ = type_end;
        while (self.pos < self.source.len and self.source[self.pos] == '[') {
            while (self.pos < self.source.len and self.source[self.pos] != ']') self.pos += 1;
            if (self.pos < self.source.len) self.pos += 1;
        }

        return self.source[ident_start..self.pos];
    }

    fn tryParseAssignOp(self: *ExprParser) ?ast.AssignmentOp {
        if (self.pos >= self.source.len) return null;
        if (self.matchStr("<<=")) return .shl_assign;
        if (self.matchStr(">>=")) return .shr_assign;
        if (self.matchStr("+=")) return .add_assign;
        if (self.matchStr("-=")) return .sub_assign;
        if (self.matchStr("*=")) return .mul_assign;
        if (self.matchStr("/=")) return .div_assign;
        if (self.matchStr("%=")) return .mod_assign;
        if (self.matchStr("|=")) return .or_assign;
        if (self.matchStr("&=")) return .and_assign;
        if (self.matchStr("^=")) return .xor_assign;
        // Simple = but not ==
        if (self.source[self.pos] == '=' and (self.pos + 1 >= self.source.len or self.source[self.pos + 1] != '=')) {
            self.pos += 1;
            return .assign;
        }
        return null;
    }

    fn parseIdent(self: *ExprParser) []const u8 {
        const start = self.pos;
        while (self.pos < self.source.len and (std.ascii.isAlphanumeric(self.source[self.pos]) or self.source[self.pos] == '_' or self.source[self.pos] == '$')) {
            self.pos += 1;
        }
        return self.source[start..self.pos];
    }

    fn matchKeyword(self: *ExprParser, kw: []const u8) bool {
        if (self.pos + kw.len > self.source.len) return false;
        if (!std.mem.eql(u8, self.source[self.pos .. self.pos + kw.len], kw)) return false;
        // Make sure it's not a prefix of a longer identifier
        if (self.pos + kw.len < self.source.len and (std.ascii.isAlphanumeric(self.source[self.pos + kw.len]) or self.source[self.pos + kw.len] == '_')) return false;
        self.pos += kw.len;
        return true;
    }

    fn matchStr(self: *ExprParser, s: []const u8) bool {
        if (self.pos + s.len > self.source.len) return false;
        if (std.mem.eql(u8, self.source[self.pos .. self.pos + s.len], s)) {
            self.pos += s.len;
            return true;
        }
        return false;
    }

    fn skipWS(self: *ExprParser) void {
        while (self.pos < self.source.len) {
            const ch = self.source[self.pos];
            if (ch == ' ' or ch == '\t' or ch == '\r') {
                self.pos += 1;
            } else if (ch == '\n') {
                self.pos += 1;
                self.line += 1;
            } else if (ch == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '/') {
                while (self.pos < self.source.len and self.source[self.pos] != '\n') self.pos += 1;
            } else if (ch == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '*') {
                self.pos += 2;
                while (self.pos + 1 < self.source.len) {
                    if (self.source[self.pos] == '*' and self.source[self.pos + 1] == '/') {
                        self.pos += 2;
                        break;
                    }
                    if (self.source[self.pos] == '\n') self.line += 1;
                    self.pos += 1;
                }
            } else break;
        }
    }

    fn skipSemicolon(self: *ExprParser) void {
        self.skipWS();
        if (self.pos < self.source.len and self.source[self.pos] == ';') self.pos += 1;
    }
};

// ============================================================================
// Utility functions
// ============================================================================

fn isSolidityType(name: []const u8) bool {
    const types = [_][]const u8{
        "uint",    "uint8",   "uint16",  "uint24",  "uint32",  "uint40",  "uint48",
        "uint56",  "uint64",  "uint72",  "uint80",  "uint88",  "uint96",  "uint104",
        "uint112", "uint120", "uint128", "uint136", "uint144", "uint152", "uint160",
        "uint168", "uint176", "uint184", "uint192", "uint200", "uint208", "uint216",
        "uint224", "uint232", "uint240", "uint248", "uint256", "int",     "int8",
        "int16",   "int24",   "int32",   "int40",   "int48",   "int56",   "int64",
        "int72",   "int80",   "int88",   "int96",   "int104",  "int112",  "int120",
        "int128",  "int136",  "int144",  "int152",  "int160",  "int168",  "int176",
        "int184",  "int192",  "int200",  "int208",  "int216",  "int224",  "int232",
        "int240",  "int248",  "int256",  "address", "bool",    "string",  "bytes",
        "bytes1",  "bytes2",  "bytes3",  "bytes4",  "bytes5",  "bytes6",  "bytes7",
        "bytes8",  "bytes9",  "bytes10", "bytes11", "bytes12", "bytes13", "bytes14",
        "bytes15", "bytes16", "bytes17", "bytes18", "bytes19", "bytes20", "bytes21",
        "bytes22", "bytes23", "bytes24", "bytes25", "bytes26", "bytes27", "bytes28",
        "bytes29", "bytes30", "bytes31", "bytes32", "payable", "fixed",   "ufixed",
    };
    for (types) |t| {
        if (std.mem.eql(u8, name, t)) return true;
    }
    return false;
}

fn isKeyword(name: []const u8) bool {
    const keywords = [_][]const u8{
        "if",        "else",     "for",      "while",    "do",       "return",
        "break",     "continue", "emit",     "revert",   "require",  "assert",
        "function",  "event",    "modifier", "struct",   "enum",     "mapping",
        "public",    "private",  "internal", "external", "view",     "pure",
        "payable",   "virtual",  "override", "abstract", "contract", "interface",
        "library",   "is",       "new",      "delete",   "assembly", "unchecked",
        "try",       "catch",    "import",   "pragma",   "using",    "constant",
        "immutable", "memory",   "storage",  "calldata", "indexed",
    };
    for (keywords) |kw| {
        if (std.mem.eql(u8, name, kw)) return true;
    }
    return false;
}
