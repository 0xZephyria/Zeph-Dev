// File: tools/zephyrc/abi_gen.zig
// ZephyrLang ABI Generator — Produces Ethereum-compatible ABI JSON from AST.
// Generates function, event, error, constructor, fallback, receive entries.

const std = @import("std");
const ast = @import("ast.zig");

pub const AbiEntry = struct {
    entry_type: EntryType,
    name: []const u8,
    inputs: []const AbiParam,
    outputs: []const AbiParam,
    state_mutability: []const u8,
    anonymous: bool,

    pub const EntryType = enum { function, event, error_entry, constructor, fallback, receive };
};

pub const AbiParam = struct {
    name: []const u8,
    param_type: []const u8,
    indexed: bool,
    components: []const AbiParam,
};

pub const AbiGenerator = struct {
    alloc: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    entries: std.ArrayList(AbiEntry),

    pub fn init(alloc: std.mem.Allocator) AbiGenerator {
        return .{ .alloc = alloc, .arena = std.heap.ArenaAllocator.init(alloc), .entries = .{} };
    }

    pub fn deinit(self: *AbiGenerator) void {
        self.entries.deinit(self.alloc);
        self.arena.deinit();
    }

    pub fn generateFromContract(self: *AbiGenerator, contract: ast.ContractDef) !void {
        for (contract.members) |member| {
            switch (member) {
                .function => |f| try self.addFunction(f),
                .constructor => |f| try self.addConstructor(f),
                .fallback => |_| try self.entries.append(self.alloc, .{
                    .entry_type = .fallback,
                    .name = "fallback",
                    .inputs = &.{},
                    .outputs = &.{},
                    .state_mutability = "nonpayable",
                    .anonymous = false,
                }),
                .receive => |_| try self.entries.append(self.alloc, .{
                    .entry_type = .receive,
                    .name = "receive",
                    .inputs = &.{},
                    .outputs = &.{},
                    .state_mutability = "payable",
                    .anonymous = false,
                }),
                .event => |e| try self.addEvent(e),
                .error_def => |e| try self.addError(e),
                else => {},
            }
        }
    }

    fn addFunction(self: *AbiGenerator, f: ast.FunctionDef) !void {
        if (f.visibility == .private or f.visibility == .internal) return;
        const inputs = try self.convertParams(f.params);
        const outputs = try self.convertParams(f.returns);
        try self.entries.append(self.alloc, .{
            .entry_type = .function,
            .name = f.name,
            .inputs = inputs,
            .outputs = outputs,
            .state_mutability = @tagName(f.mutability),
            .anonymous = false,
        });
    }

    fn addConstructor(self: *AbiGenerator, f: ast.FunctionDef) !void {
        const inputs = try self.convertParams(f.params);
        try self.entries.append(self.alloc, .{
            .entry_type = .constructor,
            .name = "",
            .inputs = inputs,
            .outputs = &.{},
            .state_mutability = if (f.mutability == .payable) "payable" else "nonpayable",
            .anonymous = false,
        });
    }

    fn addEvent(self: *AbiGenerator, e: ast.EventDef) !void {
        const a = self.arena.allocator();
        var params: std.ArrayList(AbiParam) = .{};
        for (e.params) |p| {
            try params.append(a, .{
                .name = p.name,
                .param_type = typeExprToAbiString(p.type_expr),
                .indexed = p.is_indexed,
                .components = &.{},
            });
        }
        try self.entries.append(self.alloc, .{
            .entry_type = .event,
            .name = e.name,
            .inputs = params.items,
            .outputs = &.{},
            .state_mutability = "nonpayable",
            .anonymous = e.is_anonymous,
        });
    }

    fn addError(self: *AbiGenerator, e: ast.ErrorDef) !void {
        const inputs = try self.convertParams(e.params);
        try self.entries.append(self.alloc, .{
            .entry_type = .error_entry,
            .name = e.name,
            .inputs = inputs,
            .outputs = &.{},
            .state_mutability = "nonpayable",
            .anonymous = false,
        });
    }

    fn convertParams(self: *AbiGenerator, params: []const ast.ParamDecl) ![]const AbiParam {
        const a = self.arena.allocator();
        var result: std.ArrayList(AbiParam) = .{};
        for (params) |p| {
            try result.append(a, .{
                .name = p.name,
                .param_type = typeExprToAbiString(p.type_expr),
                .indexed = false,
                .components = &.{},
            });
        }
        return result.items;
    }

    /// Serialize all ABI entries to JSON format.
    pub fn toJson(self: *const AbiGenerator, alloc: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .{};
        var w = buf.writer(alloc);
        try w.writeAll("[");
        for (self.entries.items, 0..) |entry, i| {
            if (i > 0) try w.writeAll(",");
            try w.writeAll("{");
            try w.print("\"type\":\"{s}\"", .{entryTypeName(entry.entry_type)});
            if (entry.name.len > 0) try w.print(",\"name\":\"{s}\"", .{entry.name});
            try w.writeAll(",\"inputs\":[");
            try writeParams(w, alloc, entry.inputs);
            try w.writeAll("]");
            if (entry.entry_type == .function) {
                try w.writeAll(",\"outputs\":[");
                try writeParams(w, alloc, entry.outputs);
                try w.writeAll("]");
            }
            try w.print(",\"stateMutability\":\"{s}\"", .{entry.state_mutability});
            if (entry.entry_type == .event) {
                try w.print(",\"anonymous\":{}", .{entry.anonymous});
            }
            try w.writeAll("}");
        }
        try w.writeAll("]");
        return buf.toOwnedSlice(alloc);
    }
};

fn writeParams(w: anytype, alloc: std.mem.Allocator, params: []const AbiParam) !void {
    for (params, 0..) |p, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{{\"name\":\"{s}\",\"type\":\"{s}\"", .{ p.name, p.param_type });
        if (p.indexed) try w.writeAll(",\"indexed\":true");
        if (p.components.len > 0) {
            try w.writeAll(",\"components\":[");
            try writeParams(w, alloc, p.components);
            try w.writeAll("]");
        }
        try w.writeAll("}");
    }
}

fn entryTypeName(t: AbiEntry.EntryType) []const u8 {
    return switch (t) {
        .function => "function",
        .event => "event",
        .error_entry => "error",
        .constructor => "constructor",
        .fallback => "fallback",
        .receive => "receive",
    };
}

fn typeExprToAbiString(ty: ast.TypeExpr) []const u8 {
    return switch (ty) {
        .elementary => |e| @tagName(e),
        .user_defined => |name| name,
        .mapping => "mapping",
        .array => "array",
        .option_type => "bytes32",
        .result_type => "bytes32",
        .tuple_type => "tuple",
        .function_type => "function",
        .resource_type => |inner| typeExprToAbiString(inner.*),
    };
}
