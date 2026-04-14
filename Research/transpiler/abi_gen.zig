// File: tools/sol2zig/abi_gen.zig
// ABI JSON generator from Solidity AST
// Produces Solidity-compatible ABI for contract verification and frontend use

const std = @import("std");
const parser = @import("parser.zig");

pub fn generateABI(allocator: std.mem.Allocator, ast: *const parser.SolidityAST) ![]const u8 {
    var output = std.ArrayListUnmanaged(u8){};
    var writer = output.writer(allocator);

    try writer.writeAll("[");
    var first = true;

    for (ast.contracts.items) |contract| {
        for (contract.functions.items) |func| {
            switch (func.kind) {
                .constructor => {
                    if (!first) try writer.writeAll(",");
                    first = false;
                    try writeConstructorABI(writer, func);
                },
                .receive => {
                    if (!first) try writer.writeAll(",");
                    first = false;
                    try writer.writeAll("\n  {\"type\":\"receive\",\"stateMutability\":\"payable\"}");
                },
                .fallback => {
                    if (!first) try writer.writeAll(",");
                    first = false;
                    try writer.writeAll("\n  {\"type\":\"fallback\",\"stateMutability\":\"nonpayable\"}");
                },
                .function => {
                    if (func.visibility == .private or func.visibility == .internal) continue;
                    if (!first) try writer.writeAll(",");
                    first = false;
                    try writeFunctionABI(writer, func);
                },
            }
        }

        // Events
        for (contract.events.items) |event| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writeEventABI(writer, event);
        }

        // Custom errors
        for (contract.errors_list.items) |err| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writeErrorABI(writer, err);
        }
    }

    try writer.writeAll("\n]");
    return try output.toOwnedSlice(allocator);
}

fn writeConstructorABI(writer: anytype, ctor: parser.FunctionDef) !void {
    try writer.writeAll("\n  {\"type\":\"constructor\",\"inputs\":[");
    try writeParamArray(writer, ctor.params.items);
    try writer.writeAll("],\"stateMutability\":\"");
    try writer.writeAll(mutabilityStr(ctor.state_mutability));
    try writer.writeAll("\"}");
}

fn writeFunctionABI(writer: anytype, func: parser.FunctionDef) !void {
    try writer.writeAll("\n  {\"type\":\"function\",\"name\":\"");
    try writer.writeAll(func.name);
    try writer.writeAll("\",\"inputs\":[");
    try writeParamArray(writer, func.params.items);
    try writer.writeAll("],\"outputs\":[");
    try writeParamArray(writer, func.returns.items);
    try writer.writeAll("],\"stateMutability\":\"");
    try writer.writeAll(mutabilityStr(func.state_mutability));
    try writer.writeAll("\"}");
}

fn writeEventABI(writer: anytype, event: parser.EventDef) !void {
    try writer.writeAll("\n  {\"type\":\"event\",\"name\":\"");
    try writer.writeAll(event.name);
    try writer.writeAll("\",\"inputs\":[");

    for (event.params.items, 0..) |param, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{\"name\":\"");
        try writer.writeAll(param.name);
        try writer.writeAll("\",\"type\":\"");
        try writer.writeAll(param.type_name);
        try writer.writeAll("\",\"indexed\":");
        if (param.is_indexed) try writer.writeAll("true") else try writer.writeAll("false");
        try writer.writeAll("}");
    }

    try writer.writeAll("],\"anonymous\":");
    if (event.is_anonymous) try writer.writeAll("true") else try writer.writeAll("false");
    try writer.writeAll("}");
}

fn writeErrorABI(writer: anytype, err: parser.ErrorDef) !void {
    try writer.writeAll("\n  {\"type\":\"error\",\"name\":\"");
    try writer.writeAll(err.name);
    try writer.writeAll("\",\"inputs\":[");
    try writeParamArray(writer, err.params.items);
    try writer.writeAll("]}");
}

fn writeParamArray(writer: anytype, params: []const parser.ParamDef) !void {
    for (params, 0..) |param, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{\"name\":\"");
        try writer.writeAll(param.name);
        try writer.writeAll("\",\"type\":\"");
        try writer.writeAll(param.type_name);
        try writer.writeAll("\"}");
    }
}

fn mutabilityStr(m: parser.StateMutability) []const u8 {
    return switch (m) {
        .nonpayable => "nonpayable",
        .payable => "payable",
        .view => "view",
        .pure => "pure",
    };
}
