const std = @import("std");

pub const Error = error{
    InvalidLength,
    InvalidCharacter,
};

/// Encodes bytes to a 0x-prefixed hex string.
pub fn encode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, 2 + bytes.len * 2);
    out[0] = '0';
    out[1] = 'x';
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 + i * 2] = charset[b >> 4];
        out[2 + i * 2 + 1] = charset[b & 0x0F];
    }
    return out;
}

/// Decodes a hex string (with optional 0x prefix) to bytes.
pub fn decode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const input = if (std.mem.startsWith(u8, hex, "0x")) hex[2..] else hex;
    if (input.len % 2 != 0) return Error.InvalidLength;

    const out = try allocator.alloc(u8, input.len / 2);
    _ = try std.fmt.hexToBytes(out, input);
    return out;
}

/// Fixed-buffer version of hex encoding for bytes.
pub fn encodeBuffer(out: []u8, bytes: []const u8) ![]u8 {
    if (out.len < 2 + bytes.len * 2) return error.NoSpaceLeft;
    out[0] = '0';
    out[1] = 'x';
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 + i * 2] = charset[b >> 4];
        out[2 + i * 2 + 1] = charset[b & 0x0F];
    }
    return out[0 .. 2 + bytes.len * 2];
}

/// Encodes an integer to a 0x-prefixed hex string.
pub fn toHex(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const T = @TypeOf(value);
    const bits = @typeInfo(T).int.bits;
    const bytes_len = (bits + 7) / 8;
    var buf: [32]u8 = undefined; // Enough for u256
    std.mem.writeInt(T, buf[0..bytes_len], value, .big);

    // Trim leading zeros but keep at least one byte if value is 0
    var start: usize = 0;
    while (start < bytes_len - 1 and buf[start] == 0) : (start += 1) {}

    return try encode(allocator, buf[start..bytes_len]);
}

/// Fixed-buffer version for integers.
pub fn toHexBuffer(out: []u8, value: anytype) ![]u8 {
    const T = @TypeOf(value);
    const bits = @typeInfo(T).int.bits;
    const bytes_len = (bits + 7) / 8;
    var buf: [32]u8 = undefined;
    std.mem.writeInt(T, buf[0..bytes_len], value, .big);

    var start: usize = 0;
    while (start < bytes_len - 1 and buf[start] == 0) : (start += 1) {}

    return try encodeBuffer(out, buf[start..bytes_len]);
}

test "hex roundtrip" {
    const allocator = std.testing.allocator;
    const input = "hello world";
    const encoded = try encode(allocator, input);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings("0x68656c6c6f20776f726c64", encoded);

    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(input, decoded);
}
