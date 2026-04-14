// ============================================================================
// Zephyria — RLP (Recursive Length Prefix) Encoder/Decoder
// ============================================================================
//
// Deterministic binary encoding for blocks, transactions, and headers.
// Full implementation of Ethereum's RLP spec.

const std = @import("std");

// ── Encoding ────────────────────────────────────────────────────────────

/// Encode any Zig type into RLP bytes.
pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);
    try serialize(@TypeOf(value), allocator, value, &buf);
    return buf.toOwnedSlice(allocator);
}

/// Decode RLP bytes into a Zig type.
pub fn decode(allocator: std.mem.Allocator, comptime T: type, data: []const u8) !T {
    var result: T = undefined;
    _ = try deserialize(T, allocator, data, &result);
    return result;
}

/// Serialize a value into an RLP-encoded byte list.
pub fn serialize(comptime T: type, allocator: std.mem.Allocator, value: T, list: *std.ArrayListUnmanaged(u8)) !void {
    const info = @typeInfo(T);

    switch (info) {
        .int, .comptime_int => {
            try encodeUint(allocator, value, list);
        },
        .bool => {
            if (value) {
                try list.append(allocator, 0x01);
            } else {
                try list.append(allocator, 0x80);
            }
        },
        .optional => {
            if (value) |v| {
                try serialize(@typeInfo(T).optional.child, allocator, v, list);
            } else {
                try list.append(allocator, 0x80); // Empty string
            }
        },
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    // []const u8 — encode as string
                    try encodeString(allocator, value, list);
                } else {
                    // []T — encode as list
                    var inner = std.ArrayListUnmanaged(u8){};
                    defer inner.deinit(allocator);
                    for (value) |item| {
                        try serialize(ptr.child, allocator, item, &inner);
                    }
                    try encodeListHeader(allocator, inner.items.len, list);
                    try list.appendSlice(allocator, inner.items);
                }
            }
        },
        .array => |arr| {
            if (arr.child == u8) {
                try encodeString(allocator, &value, list);
            } else {
                var inner = std.ArrayListUnmanaged(u8){};
                defer inner.deinit(allocator);
                for (value) |item| {
                    try serialize(arr.child, allocator, item, &inner);
                }
                try encodeListHeader(allocator, inner.items.len, list);
                try list.appendSlice(allocator, inner.items);
            }
        },
        .@"struct" => |s| {
            if (@hasDecl(T, "encodeToRLP")) {
                try value.encodeToRLP(allocator, list);
            } else if (@hasDecl(T, "bytes") and s.fields.len == 1 and s.fields[0].name.len == 5 and std.mem.eql(u8, s.fields[0].name, "bytes")) {
                try encodeString(allocator, &value.bytes, list);
            } else if (T == @import("std").ArrayListUnmanaged(u8)) {
                try encodeString(allocator, value.items, list);
            } else {
                // Encode struct as RLP list
                var inner = std.ArrayListUnmanaged(u8){};
                defer inner.deinit(allocator);
                inline for (s.fields) |field| {
                    try serialize(field.type, allocator, @field(value, field.name), &inner);
                }
                try encodeListHeader(allocator, inner.items.len, list);
                try list.appendSlice(allocator, inner.items);
            }
        },
        .@"enum" => {
            try encodeUint(allocator, @intFromEnum(value), list);
        },
        else => {
            @compileError("RLP: unsupported type " ++ @typeName(T));
        },
    }
}

/// Deserialize RLP bytes into a value.
pub fn deserialize(comptime T: type, allocator: std.mem.Allocator, data: []const u8, result: *T) !usize {
    const info = @typeInfo(T);

    if (data.len == 0) return error.EmptyInput;

    const prefix = data[0];

    switch (info) {
        .int => {
            if (prefix < 0x80) {
                result.* = @intCast(prefix);
                return 1;
            } else if (prefix <= 0xb7) {
                const len = @as(usize, prefix - 0x80);
                if (len == 0) {
                    result.* = 0;
                    return 1;
                }
                if (1 + len > data.len) return error.Truncated;
                const bytes = data[1 .. 1 + len];
                var wide: u64 = 0;
                for (bytes) |b| {
                    wide = (wide << 8) | @as(u64, b);
                }
                result.* = @intCast(wide);
                return 1 + len;
            }
            return error.InvalidPrefix;
        },
        .bool => {
            if (prefix == 0x01) {
                result.* = true;
                return 1;
            } else {
                result.* = false;
                return 1;
            }
        },
        .optional => {
            if (prefix == 0x80) {
                result.* = null;
                return 1;
            }
            var inner: @typeInfo(T).optional.child = undefined;
            const consumed = try deserialize(@typeInfo(T).optional.child, allocator, data, &inner);
            result.* = inner;
            return consumed;
        },
        .array => |arr| {
            if (arr.child == u8) {
                if (prefix < 0x80) {
                    result.*[0] = prefix;
                    for (1..arr.len) |i| {
                        result.*[i] = 0;
                    }
                    return 1;
                }
                if (prefix <= 0xb7) {
                    const len = @as(usize, prefix - 0x80);
                    if (1 + len > data.len) return error.Truncated;
                    if (len <= arr.len) {
                        @memset(result, 0);
                        @memcpy(result.*[arr.len - len ..], data[1 .. 1 + len]);
                    }
                    return 1 + len;
                }
            }
            return error.InvalidArrayDecode;
        },
        .pointer => |ptr| {
            if (ptr.size == .slice and ptr.child == u8) {
                if (prefix < 0x80) {
                    const slice = try allocator.alloc(u8, 1);
                    slice[0] = prefix;
                    result.* = slice;
                    return 1;
                }
                if (prefix <= 0xb7) {
                    const len = @as(usize, prefix - 0x80);
                    if (1 + len > data.len) return error.Truncated;
                    const slice = try allocator.alloc(u8, len);
                    @memcpy(slice, data[1 .. 1 + len]);
                    result.* = slice;
                    return 1 + len;
                }
                if (prefix <= 0xbf) {
                    const ll = @as(usize, prefix - 0xb7);
                    if (1 + ll > data.len) return error.Truncated;
                    var len: usize = 0;
                    for (data[1 .. 1 + ll]) |b| len = (len << 8) | b;
                    if (1 + ll + len > data.len) return error.Truncated;
                    const slice = try allocator.alloc(u8, len);
                    @memcpy(slice, data[1 + ll .. 1 + ll + len]);
                    result.* = slice;
                    return 1 + ll + len;
                }
            }
            return error.UnsupportedPointerDecode;
        },
        .@"struct" => |s| {
            if (@hasDecl(T, "decodeFromRLP")) {
                return try result.decodeFromRLP(allocator, data);
            }
            // Decode struct from RLP list
            var offset: usize = 0;
            if (prefix >= 0xc0 and prefix <= 0xf7) {
                offset = 1;
            } else if (prefix >= 0xf8) {
                const ll = @as(usize, prefix - 0xf7);
                offset = 1 + ll;
            } else {
                return error.ExpectedList;
            }
            inline for (s.fields) |field| {
                const consumed = try deserialize(field.type, allocator, data[offset..], &@field(result, field.name));
                offset += consumed;
            }
            return offset;
        },
        .@"enum" => |e| {
            // Decode enum as its tag integer
            var tag: e.tag_type = undefined;
            const consumed = try deserialize(e.tag_type, allocator, data, &tag);
            result.* = @enumFromInt(tag);
            return consumed;
        },
        else => {
            return error.UnsupportedType;
        },
    }
}

// ── Internal Helpers ────────────────────────────────────────────────────

fn encodeUint(allocator: std.mem.Allocator, value: anytype, list: *std.ArrayListUnmanaged(u8)) !void {
    // Widen to u64 to avoid shift-amount issues with small integer types
    const wide: u64 = @intCast(value);

    if (wide == 0) {
        try list.append(allocator, 0x80);
        return;
    }

    if (wide < 0x80) {
        try list.append(allocator, @intCast(wide));
        return;
    }

    // Count bytes needed
    var buf: [8]u8 = undefined;
    var v = wide;
    var len: usize = 0;
    while (v > 0) : (len += 1) {
        buf[7 - len] = @intCast(v & 0xFF);
        v >>= 8;
    }

    if (len == 1 and buf[7] < 0x80) {
        try list.append(allocator, buf[7]);
    } else {
        try list.append(allocator, @intCast(0x80 + len));
        try list.appendSlice(allocator, buf[8 - len ..]);
    }
}

fn encodeString(allocator: std.mem.Allocator, bytes: []const u8, list: *std.ArrayListUnmanaged(u8)) !void {
    if (bytes.len == 1 and bytes[0] < 0x80) {
        try list.append(allocator, bytes[0]);
    } else if (bytes.len <= 55) {
        try list.append(allocator, @intCast(0x80 + bytes.len));
        try list.appendSlice(allocator, bytes);
    } else {
        var len_buf: [8]u8 = undefined;
        var len = bytes.len;
        var ll: usize = 0;
        while (len > 0) : (ll += 1) {
            len_buf[7 - ll] = @intCast(len & 0xFF);
            len >>= 8;
        }
        try list.append(allocator, @intCast(0xb7 + ll));
        try list.appendSlice(allocator, len_buf[8 - ll ..]);
        try list.appendSlice(allocator, bytes);
    }
}

pub fn encodeListHeader(allocator: std.mem.Allocator, payload_len: usize, list: *std.ArrayListUnmanaged(u8)) !void {
    if (payload_len <= 55) {
        try list.append(allocator, @intCast(0xc0 + payload_len));
    } else {
        var len_buf: [8]u8 = undefined;
        var len = payload_len;
        var ll: usize = 0;
        while (len > 0) : (ll += 1) {
            len_buf[7 - ll] = @intCast(len & 0xFF);
            len >>= 8;
        }
        try list.append(allocator, @intCast(0xf7 + ll));
        try list.appendSlice(allocator, len_buf[8 - ll ..]);
    }
}
