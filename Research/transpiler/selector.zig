// File: tools/sol2zig/selector.zig
// Computes Solidity function selectors (4-byte keccak256 prefixes)
// Used for dispatch table generation and ABI compatibility

const std = @import("std");
const parser = @import("parser.zig");

/// Compute the 4-byte function selector from a canonical signature string
/// e.g. "transfer(address,uint256)" → [0xa9, 0x05, 0x9c, 0xbb]
pub fn computeSelector(signature: []const u8) [4]u8 {
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(signature);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash[0..4].*;
}

/// Build the canonical signature from a function definition
/// e.g. FunctionDef{name="transfer", params=[{type="address"},{type="uint256"}]}
/// → "transfer(address,uint256)"
pub fn buildCanonicalSignature(allocator: std.mem.Allocator, func: parser.FunctionDef) ![]const u8 {
    var sig = std.ArrayListUnmanaged(u8){};

    try sig.appendSlice(allocator, func.name);
    try sig.append(allocator, '(');

    for (func.params.items, 0..) |param, i| {
        if (i > 0) try sig.append(allocator, ',');
        try sig.appendSlice(allocator, canonicalizeType(param.type_name));
    }

    try sig.append(allocator, ')');
    return sig.toOwnedSlice(allocator);
}

/// Compute selector from a function definition
pub fn computeFunctionSelector(allocator: std.mem.Allocator, func: parser.FunctionDef) ![4]u8 {
    const sig = try buildCanonicalSignature(allocator, func);
    defer allocator.free(sig);
    return computeSelector(sig);
}

/// Build the canonical event signature for topic0
pub fn buildEventSignature(allocator: std.mem.Allocator, event: parser.EventDef) ![]const u8 {
    var sig = std.ArrayListUnmanaged(u8){};

    try sig.appendSlice(allocator, event.name);
    try sig.append(allocator, '(');

    for (event.params.items, 0..) |param, i| {
        if (i > 0) try sig.append(allocator, ',');
        try sig.appendSlice(allocator, canonicalizeType(param.type_name));
    }

    try sig.append(allocator, ')');
    return sig.toOwnedSlice(allocator);
}

/// Compute event topic0 hash
pub fn computeEventTopic(allocator: std.mem.Allocator, event: parser.EventDef) ![32]u8 {
    const sig = try buildEventSignature(allocator, event);
    defer allocator.free(sig);
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(sig);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash;
}

/// Format a 4-byte selector as hex string for code generation
pub fn selectorToHex(selector: [4]u8) [10]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [10]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    inline for (0..4) |i| {
        result[2 + i * 2] = hex_chars[selector[i] >> 4];
        result[3 + i * 2] = hex_chars[selector[i] & 0x0f];
    }
    return result;
}

/// Generate a dispatch table entry as Zig source code
pub fn generateDispatchEntry(
    allocator: std.mem.Allocator,
    func: parser.FunctionDef,
) !DispatchEntry {
    const selector = try computeFunctionSelector(allocator, func);
    const sig = try buildCanonicalSignature(allocator, func);
    return DispatchEntry{
        .name = func.name,
        .selector = selector,
        .signature = sig,
        .visibility = func.visibility,
        .state_mutability = func.state_mutability,
    };
}

pub const DispatchEntry = struct {
    name: []const u8,
    selector: [4]u8,
    signature: []const u8,
    visibility: parser.Visibility,
    state_mutability: parser.StateMutability,
};

/// Generate the full dispatch table for a contract
pub fn generateDispatchTable(
    allocator: std.mem.Allocator,
    contract: parser.ContractDef,
) ![]DispatchEntry {
    var entries = std.ArrayListUnmanaged(DispatchEntry){};

    for (contract.functions.items) |func| {
        // Only external and public functions get selectors
        if (func.kind == .constructor or func.kind == .receive or func.kind == .fallback) continue;
        if (func.visibility != .external and func.visibility != .public) continue;

        const entry = try generateDispatchEntry(allocator, func);
        try entries.append(allocator, entry);
    }

    return entries.toOwnedSlice(allocator);
}

// ============================================================================
// Canonical Type Resolution
// ============================================================================

/// Canonicalize a Solidity type for signature hashing
/// e.g. "uint" → "uint256", "int" → "int256", "byte" → "bytes1"
fn canonicalizeType(type_name: []const u8) []const u8 {
    // uint without width = uint256
    if (std.mem.eql(u8, type_name, "uint")) return "uint256";
    if (std.mem.eql(u8, type_name, "int")) return "int256";
    if (std.mem.eql(u8, type_name, "byte")) return "bytes1";
    // address payable → address in signatures
    if (std.mem.eql(u8, type_name, "address payable")) return "address";
    return type_name;
}
