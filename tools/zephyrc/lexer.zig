// File: tools/zephyrc/lexer.zig
// ZephyrLang Lexer — Tokenizes ZephyrLang source code.
// Produces a stream of tokens from UTF-8 source text.
// Handles: keywords, identifiers, operators (including +%, +|), literals,
//          comments (line & block), string literals, hex literals.

const std = @import("std");

// ============================================================================
// Token Types
// ============================================================================

pub const TokenKind = enum(u16) {
    // --- Literals ---
    number_literal, // 123, 0xFF, 1_000_000
    string_literal, // "hello"
    hex_string_literal, // hex"deadbeef"
    unicode_string, // unicode"hello"
    identifier, // myVar, _foo

    // --- Punctuation ---
    lparen, // (
    rparen, // )
    lbrace, // {
    rbrace, // }
    lbracket, // [
    rbracket, // ]
    semicolon, // ;
    comma, // ,
    dot, // .
    arrow, // =>
    thin_arrow, // ->
    underscore_placeholder, // _ (in modifier bodies)
    question_mark, // ?
    colon, // :

    // --- Arithmetic Operators ---
    plus, // +
    minus, // -
    star, // *
    slash, // /
    percent, // %
    star_star, // **
    plus_percent, // +%  (wrapping add)
    minus_percent, // -%  (wrapping sub)
    star_percent, // *%  (wrapping mul)
    plus_pipe, // +|  (saturating add)
    minus_pipe, // -|  (saturating sub)

    // --- Comparison Operators ---
    eq_eq, // ==
    bang_eq, // !=
    lt, // <
    gt, // >
    lt_eq, // <=
    gt_eq, // >=

    // --- Logical Operators ---
    amp_amp, // &&
    pipe_pipe, // ||
    bang, // !

    // --- Bitwise Operators ---
    amp, // &
    pipe, // |
    caret, // ^
    tilde, // ~
    lt_lt, // <<
    gt_gt, // >>

    // --- Assignment Operators ---
    eq, // =
    plus_eq, // +=
    minus_eq, // -=
    star_eq, // *=
    slash_eq, // /=
    percent_eq, // %=
    amp_eq, // &=
    pipe_eq, // |=
    caret_eq, // ^=
    lt_lt_eq, // <<=
    gt_gt_eq, // >>=

    // --- Increment/Decrement ---
    plus_plus, // ++
    minus_minus, // --

    // --- Keywords: Contract Structure ---
    kw_pragma,
    kw_import,
    kw_contract,
    kw_interface,
    kw_library,
    kw_abstract,
    kw_is,
    kw_using,
    kw_for,

    // --- Keywords: Members ---
    kw_function,
    kw_modifier,
    kw_event,
    kw_error,
    kw_struct,
    kw_enum,
    kw_constructor,
    kw_fallback,
    kw_receive,
    kw_type,

    // --- Keywords: Visibility ---
    kw_public,
    kw_private,
    kw_internal,
    kw_external,

    // --- Keywords: Mutability ---
    kw_view,
    kw_pure,
    kw_payable,
    kw_constant,
    kw_immutable,

    // --- Keywords: Storage ---
    kw_storage,
    kw_memory,
    kw_calldata,
    kw_transient,

    // --- Keywords: Control Flow ---
    kw_if,
    kw_else,
    kw_while,
    kw_do,
    kw_break,
    kw_continue,
    kw_return,
    kw_returns,

    // --- Keywords: Error Handling ---
    kw_require,
    kw_assert,
    kw_revert,
    kw_try,
    kw_catch,
    kw_emit,

    // --- Keywords: Types ---
    kw_mapping,
    kw_bool,
    kw_address,
    kw_string,
    kw_bytes,

    // --- Keywords: Misc ---
    kw_new,
    kw_delete,
    kw_virtual,
    kw_override,
    kw_indexed,
    kw_anonymous,
    kw_unchecked,
    kw_assembly,

    // --- Keywords: ZephyrLang Extensions ---
    kw_option,
    kw_result,
    kw_resource,
    kw_role,
    kw_only,
    kw_grant,
    kw_revoke,
    kw_match,
    kw_some,
    kw_none,
    kw_move,
    kw_parallel,
    kw_atomic,
    kw_inherits,

    // --- Keywords: Values ---
    kw_true,
    kw_false,

    // --- Special ---
    eof,
    invalid,
};

pub const Token = struct {
    kind: TokenKind,
    start: u32,
    end: u32,
    line: u32,
    col: u32,

    pub fn text(self: Token, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

// ============================================================================
// Keyword Table
// ============================================================================

const KeywordEntry = struct {
    text: []const u8,
    kind: TokenKind,
};

const keywords = [_]KeywordEntry{
    // Contract structure
    .{ .text = "pragma", .kind = .kw_pragma },
    .{ .text = "import", .kind = .kw_import },
    .{ .text = "contract", .kind = .kw_contract },
    .{ .text = "interface", .kind = .kw_interface },
    .{ .text = "library", .kind = .kw_library },
    .{ .text = "abstract", .kind = .kw_abstract },
    .{ .text = "is", .kind = .kw_is },
    .{ .text = "using", .kind = .kw_using },
    // Members
    .{ .text = "function", .kind = .kw_function },
    .{ .text = "modifier", .kind = .kw_modifier },
    .{ .text = "event", .kind = .kw_event },
    .{ .text = "error", .kind = .kw_error },
    .{ .text = "struct", .kind = .kw_struct },
    .{ .text = "enum", .kind = .kw_enum },
    .{ .text = "constructor", .kind = .kw_constructor },
    .{ .text = "fallback", .kind = .kw_fallback },
    .{ .text = "receive", .kind = .kw_receive },
    .{ .text = "type", .kind = .kw_type },
    // Visibility
    .{ .text = "public", .kind = .kw_public },
    .{ .text = "private", .kind = .kw_private },
    .{ .text = "internal", .kind = .kw_internal },
    .{ .text = "external", .kind = .kw_external },
    // Mutability
    .{ .text = "view", .kind = .kw_view },
    .{ .text = "pure", .kind = .kw_pure },
    .{ .text = "payable", .kind = .kw_payable },
    .{ .text = "constant", .kind = .kw_constant },
    .{ .text = "immutable", .kind = .kw_immutable },
    // Storage locations
    .{ .text = "storage", .kind = .kw_storage },
    .{ .text = "memory", .kind = .kw_memory },
    .{ .text = "calldata", .kind = .kw_calldata },
    .{ .text = "transient", .kind = .kw_transient },
    // Control flow
    .{ .text = "if", .kind = .kw_if },
    .{ .text = "else", .kind = .kw_else },
    .{ .text = "for", .kind = .kw_for },
    .{ .text = "while", .kind = .kw_while },
    .{ .text = "do", .kind = .kw_do },
    .{ .text = "break", .kind = .kw_break },
    .{ .text = "continue", .kind = .kw_continue },
    .{ .text = "return", .kind = .kw_return },
    .{ .text = "returns", .kind = .kw_returns },
    // Error handling
    .{ .text = "require", .kind = .kw_require },
    .{ .text = "assert", .kind = .kw_assert },
    .{ .text = "revert", .kind = .kw_revert },
    .{ .text = "try", .kind = .kw_try },
    .{ .text = "catch", .kind = .kw_catch },
    .{ .text = "emit", .kind = .kw_emit },
    // Types
    .{ .text = "mapping", .kind = .kw_mapping },
    .{ .text = "bool", .kind = .kw_bool },
    .{ .text = "address", .kind = .kw_address },
    .{ .text = "string", .kind = .kw_string },
    .{ .text = "bytes", .kind = .kw_bytes },
    // Misc
    .{ .text = "new", .kind = .kw_new },
    .{ .text = "delete", .kind = .kw_delete },
    .{ .text = "virtual", .kind = .kw_virtual },
    .{ .text = "override", .kind = .kw_override },
    .{ .text = "indexed", .kind = .kw_indexed },
    .{ .text = "anonymous", .kind = .kw_anonymous },
    .{ .text = "unchecked", .kind = .kw_unchecked },
    .{ .text = "assembly", .kind = .kw_assembly },
    // ZephyrLang extensions
    .{ .text = "option", .kind = .kw_option },
    .{ .text = "result", .kind = .kw_result },
    .{ .text = "resource", .kind = .kw_resource },
    .{ .text = "role", .kind = .kw_role },
    .{ .text = "only", .kind = .kw_only },
    .{ .text = "grant", .kind = .kw_grant },
    .{ .text = "revoke", .kind = .kw_revoke },
    .{ .text = "match", .kind = .kw_match },
    .{ .text = "some", .kind = .kw_some },
    .{ .text = "none", .kind = .kw_none },
    .{ .text = "move", .kind = .kw_move },
    .{ .text = "parallel", .kind = .kw_parallel },
    .{ .text = "atomic", .kind = .kw_atomic },
    .{ .text = "inherits", .kind = .kw_inherits },
    // Values
    .{ .text = "true", .kind = .kw_true },
    .{ .text = "false", .kind = .kw_false },
};

// ============================================================================
// Lexer
// ============================================================================

pub const Lexer = struct {
    source: []const u8,
    pos: u32,
    line: u32,
    col: u32,

    pub fn init(source: []const u8) Lexer {
        return .{
            .source = source,
            .pos = 0,
            .line = 1,
            .col = 1,
        };
    }

    /// Get the next token from the source.
    pub fn nextToken(self: *Lexer) Token {
        self.skipWhitespaceAndComments();

        if (self.pos >= self.source.len) {
            return self.makeToken(.eof, self.pos, self.pos);
        }

        const start = self.pos;
        const start_line = self.line;
        const start_col = self.col;
        const c = self.source[self.pos];

        // --- String literals ---
        if (c == '"' or c == '\'') {
            return self.lexString(c, start, start_line, start_col);
        }

        // --- Number literals ---
        if (c >= '0' and c <= '9') {
            return self.lexNumber(start, start_line, start_col);
        }

        // --- Identifiers and keywords ---
        if (isIdentStart(c)) {
            return self.lexIdentifierOrKeyword(start, start_line, start_col);
        }

        // --- Operators and punctuation ---
        return self.lexOperator(start, start_line, start_col);
    }

    /// Tokenize the entire source into an array of tokens.
    pub fn tokenizeAll(self: *Lexer, allocator: std.mem.Allocator) ![]Token {
        var tokens: std.ArrayList(Token) = .{};
        errdefer tokens.deinit(allocator);

        while (true) {
            const tok = self.nextToken();
            try tokens.append(allocator, tok);
            if (tok.kind == .eof) break;
        }

        return tokens.toOwnedSlice(allocator);
    }

    // ========================================================================
    // Private lexing methods
    // ========================================================================

    fn lexString(self: *Lexer, quote: u8, start: u32, start_line: u32, start_col: u32) Token {
        self.advance(); // skip opening quote
        while (self.pos < self.source.len) {
            const ch = self.source[self.pos];
            if (ch == '\\') {
                self.advance(); // skip escape char
                if (self.pos < self.source.len) self.advance(); // skip escaped char
                continue;
            }
            if (ch == quote) {
                self.advance(); // skip closing quote
                return .{
                    .kind = .string_literal,
                    .start = start,
                    .end = self.pos,
                    .line = start_line,
                    .col = start_col,
                };
            }
            if (ch == '\n') {
                self.line += 1;
                self.col = 0;
            }
            self.advance();
        }
        // Unterminated string
        return .{ .kind = .invalid, .start = start, .end = self.pos, .line = start_line, .col = start_col };
    }

    fn lexNumber(self: *Lexer, start: u32, start_line: u32, start_col: u32) Token {
        // Check for hex: 0x...
        if (self.pos + 1 < self.source.len and self.source[self.pos] == '0' and
            (self.source[self.pos + 1] == 'x' or self.source[self.pos + 1] == 'X'))
        {
            self.advance(); // '0'
            self.advance(); // 'x'
            while (self.pos < self.source.len and isHexDigit(self.source[self.pos])) {
                self.advance();
            }
        } else {
            // Decimal number (with optional underscores for readability: 1_000_000)
            while (self.pos < self.source.len) {
                const ch = self.source[self.pos];
                if ((ch >= '0' and ch <= '9') or ch == '_') {
                    self.advance();
                } else break;
            }
            // Optional decimal point (for fixed-point)
            if (self.pos < self.source.len and self.source[self.pos] == '.') {
                const next = if (self.pos + 1 < self.source.len) self.source[self.pos + 1] else 0;
                if (next >= '0' and next <= '9') {
                    self.advance(); // '.'
                    while (self.pos < self.source.len and self.source[self.pos] >= '0' and self.source[self.pos] <= '9') {
                        self.advance();
                    }
                }
            }
            // Optional exponent
            if (self.pos < self.source.len and (self.source[self.pos] == 'e' or self.source[self.pos] == 'E')) {
                self.advance();
                if (self.pos < self.source.len and (self.source[self.pos] == '+' or self.source[self.pos] == '-')) {
                    self.advance();
                }
                while (self.pos < self.source.len and self.source[self.pos] >= '0' and self.source[self.pos] <= '9') {
                    self.advance();
                }
            }
        }

        return .{ .kind = .number_literal, .start = start, .end = self.pos, .line = start_line, .col = start_col };
    }

    fn lexIdentifierOrKeyword(self: *Lexer, start: u32, start_line: u32, start_col: u32) Token {
        while (self.pos < self.source.len and isIdentContinue(self.source[self.pos])) {
            self.advance();
        }

        const text = self.source[start..self.pos];

        // Check for hex"..." and unicode"..." string forms
        if (self.pos < self.source.len and self.source[self.pos] == '"') {
            if (std.mem.eql(u8, text, "hex")) {
                return self.lexHexString(start, start_line, start_col);
            }
            if (std.mem.eql(u8, text, "unicode")) {
                const tok = self.lexString('"', start, start_line, start_col);
                return .{ .kind = .unicode_string, .start = tok.start, .end = tok.end, .line = tok.line, .col = tok.col };
            }
        }

        // Check if it's a keyword
        const kind = lookupKeyword(text) orelse .identifier;

        return .{ .kind = kind, .start = start, .end = self.pos, .line = start_line, .col = start_col };
    }

    fn lexHexString(self: *Lexer, start: u32, start_line: u32, start_col: u32) Token {
        self.advance(); // skip opening "
        while (self.pos < self.source.len and self.source[self.pos] != '"') {
            self.advance();
        }
        if (self.pos < self.source.len) self.advance(); // skip closing "
        return .{ .kind = .hex_string_literal, .start = start, .end = self.pos, .line = start_line, .col = start_col };
    }

    fn lexOperator(self: *Lexer, start: u32, start_line: u32, start_col: u32) Token {
        const c = self.source[self.pos];
        const next: u8 = if (self.pos + 1 < self.source.len) self.source[self.pos + 1] else 0;
        const next2: u8 = if (self.pos + 2 < self.source.len) self.source[self.pos + 2] else 0;

        // Three-character operators
        if (c == '<' and next == '<' and next2 == '=') {
            self.advanceN(3);
            return self.makeTokenAt(.lt_lt_eq, start, start_line, start_col);
        }
        if (c == '>' and next == '>' and next2 == '=') {
            self.advanceN(3);
            return self.makeTokenAt(.gt_gt_eq, start, start_line, start_col);
        }

        // Two-character operators
        switch (c) {
            '+' => {
                if (next == '+') {
                    self.advanceN(2);
                    return self.makeTokenAt(.plus_plus, start, start_line, start_col);
                }
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.plus_eq, start, start_line, start_col);
                }
                if (next == '%') {
                    self.advanceN(2);
                    return self.makeTokenAt(.plus_percent, start, start_line, start_col);
                }
                if (next == '|') {
                    self.advanceN(2);
                    return self.makeTokenAt(.plus_pipe, start, start_line, start_col);
                }
            },
            '-' => {
                if (next == '-') {
                    self.advanceN(2);
                    return self.makeTokenAt(.minus_minus, start, start_line, start_col);
                }
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.minus_eq, start, start_line, start_col);
                }
                if (next == '%') {
                    self.advanceN(2);
                    return self.makeTokenAt(.minus_percent, start, start_line, start_col);
                }
                if (next == '|') {
                    self.advanceN(2);
                    return self.makeTokenAt(.minus_pipe, start, start_line, start_col);
                }
                if (next == '>') {
                    self.advanceN(2);
                    return self.makeTokenAt(.thin_arrow, start, start_line, start_col);
                }
            },
            '*' => {
                if (next == '*') {
                    self.advanceN(2);
                    return self.makeTokenAt(.star_star, start, start_line, start_col);
                }
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.star_eq, start, start_line, start_col);
                }
                if (next == '%') {
                    self.advanceN(2);
                    return self.makeTokenAt(.star_percent, start, start_line, start_col);
                }
            },
            '/' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.slash_eq, start, start_line, start_col);
                }
            },
            '%' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.percent_eq, start, start_line, start_col);
                }
            },
            '=' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.eq_eq, start, start_line, start_col);
                }
                if (next == '>') {
                    self.advanceN(2);
                    return self.makeTokenAt(.arrow, start, start_line, start_col);
                }
            },
            '!' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.bang_eq, start, start_line, start_col);
                }
            },
            '<' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.lt_eq, start, start_line, start_col);
                }
                if (next == '<') {
                    self.advanceN(2);
                    return self.makeTokenAt(.lt_lt, start, start_line, start_col);
                }
            },
            '>' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.gt_eq, start, start_line, start_col);
                }
                if (next == '>') {
                    self.advanceN(2);
                    return self.makeTokenAt(.gt_gt, start, start_line, start_col);
                }
            },
            '&' => {
                if (next == '&') {
                    self.advanceN(2);
                    return self.makeTokenAt(.amp_amp, start, start_line, start_col);
                }
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.amp_eq, start, start_line, start_col);
                }
            },
            '|' => {
                if (next == '|') {
                    self.advanceN(2);
                    return self.makeTokenAt(.pipe_pipe, start, start_line, start_col);
                }
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.pipe_eq, start, start_line, start_col);
                }
            },
            '^' => {
                if (next == '=') {
                    self.advanceN(2);
                    return self.makeTokenAt(.caret_eq, start, start_line, start_col);
                }
            },
            else => {},
        }

        // Single-character operators/punctuation
        self.advance();
        const kind: TokenKind = switch (c) {
            '(' => .lparen,
            ')' => .rparen,
            '{' => .lbrace,
            '}' => .rbrace,
            '[' => .lbracket,
            ']' => .rbracket,
            ';' => .semicolon,
            ',' => .comma,
            '.' => .dot,
            '~' => .tilde,
            '?' => .question_mark,
            ':' => .colon,
            '+' => .plus,
            '-' => .minus,
            '*' => .star,
            '/' => .slash,
            '%' => .percent,
            '=' => .eq,
            '!' => .bang,
            '<' => .lt,
            '>' => .gt,
            '&' => .amp,
            '|' => .pipe,
            '^' => .caret,
            else => .invalid,
        };

        return self.makeTokenAt(kind, start, start_line, start_col);
    }

    // ========================================================================
    // Whitespace and comment handling
    // ========================================================================

    fn skipWhitespaceAndComments(self: *Lexer) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];

            // Whitespace
            if (c == ' ' or c == '\t' or c == '\r') {
                self.advance();
                continue;
            }
            if (c == '\n') {
                self.advance();
                self.line += 1;
                self.col = 1;
                continue;
            }

            // Line comment: //
            if (c == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '/') {
                while (self.pos < self.source.len and self.source[self.pos] != '\n') {
                    self.advance();
                }
                continue;
            }

            // Block comment: /* ... */
            if (c == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '*') {
                self.advanceN(2); // skip /*
                while (self.pos + 1 < self.source.len) {
                    if (self.source[self.pos] == '\n') {
                        self.line += 1;
                        self.col = 0;
                    }
                    if (self.source[self.pos] == '*' and self.source[self.pos + 1] == '/') {
                        self.advanceN(2); // skip */
                        break;
                    }
                    self.advance();
                }
                continue;
            }

            break;
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn advance(self: *Lexer) void {
        self.pos += 1;
        self.col += 1;
    }

    fn advanceN(self: *Lexer, n: u32) void {
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            self.advance();
        }
    }

    fn makeToken(self: *const Lexer, kind: TokenKind, start: u32, end: u32) Token {
        return .{
            .kind = kind,
            .start = start,
            .end = end,
            .line = self.line,
            .col = self.col,
        };
    }

    fn makeTokenAt(self: *const Lexer, kind: TokenKind, start: u32, line: u32, col: u32) Token {
        return .{
            .kind = kind,
            .start = start,
            .end = self.pos,
            .line = line,
            .col = col,
        };
    }
};

// ============================================================================
// Utility functions
// ============================================================================

fn isIdentStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_' or c == '$';
}

fn isIdentContinue(c: u8) bool {
    return isIdentStart(c) or (c >= '0' and c <= '9');
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn lookupKeyword(text: []const u8) ?TokenKind {
    // Handle uint/int/bytes with sizes (uint8, uint256, int32, bytes4, etc.)
    if (text.len >= 4) {
        if (std.mem.startsWith(u8, text, "uint") and text.len > 4) {
            const suffix = text[4..];
            if (isValidIntSize(suffix)) return .identifier; // Treat as typed identifier
        }
        if (std.mem.startsWith(u8, text, "int") and text.len > 3) {
            const suffix = text[3..];
            if (isValidIntSize(suffix)) return .identifier;
        }
        if (std.mem.startsWith(u8, text, "bytes") and text.len > 5 and text.len <= 7) {
            const suffix = text[5..];
            if (isValidBytesSize(suffix)) return .identifier;
        }
    }

    for (keywords) |kw| {
        if (std.mem.eql(u8, text, kw.text)) return kw.kind;
    }
    return null;
}

fn isValidIntSize(s: []const u8) bool {
    if (s.len == 0 or s.len > 3) return false;
    const val = std.fmt.parseInt(u16, s, 10) catch return false;
    return val >= 8 and val <= 256 and val % 8 == 0;
}

fn isValidBytesSize(s: []const u8) bool {
    if (s.len == 0 or s.len > 2) return false;
    const val = std.fmt.parseInt(u8, s, 10) catch return false;
    return val >= 1 and val <= 32;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "lexer: empty input" {
    var lex = Lexer.init("");
    const tok = lex.nextToken();
    try testing.expectEqual(TokenKind.eof, tok.kind);
}

test "lexer: simple identifier" {
    var lex = Lexer.init("myVar");
    const tok = lex.nextToken();
    try testing.expectEqual(TokenKind.identifier, tok.kind);
    try testing.expectEqualStrings("myVar", tok.text(lex.source));
}

test "lexer: number literal" {
    var lex = Lexer.init("12345");
    const tok = lex.nextToken();
    try testing.expectEqual(TokenKind.number_literal, tok.kind);
    try testing.expectEqualStrings("12345", tok.text(lex.source));
}

test "lexer: hex number" {
    var lex = Lexer.init("0xFF");
    const tok = lex.nextToken();
    try testing.expectEqual(TokenKind.number_literal, tok.kind);
    try testing.expectEqualStrings("0xFF", tok.text(lex.source));
}

test "lexer: underscore number" {
    var lex = Lexer.init("1_000_000");
    const tok = lex.nextToken();
    try testing.expectEqual(TokenKind.number_literal, tok.kind);
    try testing.expectEqualStrings("1_000_000", tok.text(lex.source));
}

test "lexer: keywords" {
    var lex = Lexer.init("contract function mapping");
    const t1 = lex.nextToken();
    try testing.expectEqual(TokenKind.kw_contract, t1.kind);
    const t2 = lex.nextToken();
    try testing.expectEqual(TokenKind.kw_function, t2.kind);
    const t3 = lex.nextToken();
    try testing.expectEqual(TokenKind.kw_mapping, t3.kind);
}

test "lexer: zephyr keywords" {
    var lex = Lexer.init("role match option result resource");
    try testing.expectEqual(TokenKind.kw_role, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.kw_match, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.kw_option, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.kw_result, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.kw_resource, lex.nextToken().kind);
}

test "lexer: wrapping and saturating operators" {
    var lex = Lexer.init("+% -% *% +| -|");
    try testing.expectEqual(TokenKind.plus_percent, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.minus_percent, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.star_percent, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.plus_pipe, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.minus_pipe, lex.nextToken().kind);
}

test "lexer: string literal" {
    var lex = Lexer.init("\"hello world\"");
    const tok = lex.nextToken();
    try testing.expectEqual(TokenKind.string_literal, tok.kind);
    try testing.expectEqualStrings("\"hello world\"", tok.text(lex.source));
}

test "lexer: comparison operators" {
    var lex = Lexer.init("== != <= >= < >");
    try testing.expectEqual(TokenKind.eq_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.bang_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.lt_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.gt_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.lt, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.gt, lex.nextToken().kind);
}

test "lexer: skip comments" {
    var lex = Lexer.init("hello // this is a comment\nworld");
    const t1 = lex.nextToken();
    try testing.expectEqualStrings("hello", t1.text(lex.source));
    const t2 = lex.nextToken();
    try testing.expectEqualStrings("world", t2.text(lex.source));
}

test "lexer: skip block comments" {
    var lex = Lexer.init("hello /* multi\nline */ world");
    const t1 = lex.nextToken();
    try testing.expectEqualStrings("hello", t1.text(lex.source));
    const t2 = lex.nextToken();
    try testing.expectEqualStrings("world", t2.text(lex.source));
}

test "lexer: arrow operators" {
    var lex = Lexer.init("=> ->");
    try testing.expectEqual(TokenKind.arrow, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.thin_arrow, lex.nextToken().kind);
}

test "lexer: assignment operators" {
    var lex = Lexer.init("= += -= *= /= %=");
    try testing.expectEqual(TokenKind.eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.plus_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.minus_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.star_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.slash_eq, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.percent_eq, lex.nextToken().kind);
}

test "lexer: punctuation" {
    var lex = Lexer.init("( ) { } [ ] ; , .");
    try testing.expectEqual(TokenKind.lparen, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.rparen, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.lbrace, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.rbrace, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.lbracket, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.rbracket, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.semicolon, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.comma, lex.nextToken().kind);
    try testing.expectEqual(TokenKind.dot, lex.nextToken().kind);
}

test "lexer: line tracking" {
    var lex = Lexer.init("a\nb\nc");
    const t1 = lex.nextToken();
    try testing.expectEqual(@as(u32, 1), t1.line);
    const t2 = lex.nextToken();
    try testing.expectEqual(@as(u32, 2), t2.line);
    const t3 = lex.nextToken();
    try testing.expectEqual(@as(u32, 3), t3.line);
}

test "lexer: contract snippet" {
    const source =
        \\pragma zephyr ^1.0;
        \\contract MyToken {
        \\    uint256 public totalSupply;
        \\}
    ;
    var lex = Lexer.init(source);
    try testing.expectEqual(TokenKind.kw_pragma, lex.nextToken().kind); // pragma
    try testing.expectEqual(TokenKind.identifier, lex.nextToken().kind); // zephyr
    try testing.expectEqual(TokenKind.caret, lex.nextToken().kind); // ^
    // Version 1.0 is lexed as a single decimal number literal
    const ver_tok = lex.nextToken();
    try testing.expectEqual(TokenKind.number_literal, ver_tok.kind); // 1.0
    try testing.expectEqualStrings("1.0", ver_tok.text(lex.source));
    try testing.expectEqual(TokenKind.semicolon, lex.nextToken().kind); // ;
    try testing.expectEqual(TokenKind.kw_contract, lex.nextToken().kind); // contract
    try testing.expectEqual(TokenKind.identifier, lex.nextToken().kind); // MyToken
    try testing.expectEqual(TokenKind.lbrace, lex.nextToken().kind); // {
    try testing.expectEqual(TokenKind.identifier, lex.nextToken().kind); // uint256
    try testing.expectEqual(TokenKind.kw_public, lex.nextToken().kind); // public
    try testing.expectEqual(TokenKind.identifier, lex.nextToken().kind); // totalSupply
    try testing.expectEqual(TokenKind.semicolon, lex.nextToken().kind); // ;
    try testing.expectEqual(TokenKind.rbrace, lex.nextToken().kind); // }
    try testing.expectEqual(TokenKind.eof, lex.nextToken().kind);
}
