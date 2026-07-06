// ============================================================================
// Zephyria — QUIC Packet Codec (RFC 9000)
// ============================================================================
//
// Implements the full QUIC packet framing layer:
//   • Variable-length integer (VarInt) encode/decode — RFC 9000 §16
//   • Long header packets: Initial, Handshake, Retry, 0-RTT
//   • Short header packets: 1-RTT (application data)
//   • Packet number encode/decode (1-4 bytes, protected)
//   • Header protection mask application (RFC 9001 §5.4)
//
// This is the lowest-level codec. It does NOT perform decryption — that is
// done by the TLS layer (quic/tls.zig) after the header is parsed.

const std = @import("std");

// ── Errors ───────────────────────────────────────────────────────────────

pub const Error = error{
    InvalidPacket,
    BufferTooSmall,
    UnsupportedVersion,
    InvalidVarInt,
    PacketNumberTruncated,
};

// ── QUIC Version ─────────────────────────────────────────────────────────

pub const QUIC_V1: u32 = 0x0000_0001;
pub const QUIC_VERSION_NEGOTIATION: u32 = 0x0000_0000;

// ── QuicPacketType ───────────────────────────────────────────────────────

/// QUIC packet type, encoded in the first byte's bits 4-5 for long headers.
pub const QuicPacketType = enum(u8) {
    /// Long header — TLS Initial (carries ClientHello / ServerHello CRYPTO frames)
    Initial = 0x00,
    /// Long header — QUIC 0-RTT (early application data, before handshake completes)
    ZeroRtt = 0x01,
    /// Long header — TLS Handshake (carries Certificate, Finished CRYPTO frames)
    Handshake = 0x02,
    /// Long header — Retry (server stateless retry token)
    Retry = 0x03,
    /// Short header — 1-RTT application data (most common)
    OneRtt = 0xFF,
};

// ── Toy Packet framing for legacy UDP transport ──────────────────────────

pub const PacketType = enum(u8) {
    Initial = 0x0,
    Handshake = 0x1,
    Retry = 0x2,
    OneRTT = 0x3,
};

pub const Packet = struct {
    packet_type: PacketType,
    connection_id: u64,
    payload: []const u8,

    pub fn encode(self: Packet, buffer: []u8) !usize {
        if (buffer.len < self.payload.len + 10) return Error.BufferTooSmall;

        buffer[0] = @intFromEnum(self.packet_type);
        std.mem.writeInt(u64, buffer[1..9], self.connection_id, .big);
        @memcpy(buffer[9 .. 9 + self.payload.len], self.payload);

        return self.payload.len + 9;
    }

    pub fn decode(buffer: []const u8) !Packet {
        if (buffer.len < 9) return Error.InvalidPacket;

        return Packet{
            .packet_type = @enumFromInt(buffer[0]),
            .connection_id = std.mem.readInt(u64, buffer[1..9], .big),
            .payload = buffer[9..],
        };
    }
};

// ── Variable-Length Integer (RFC 9000 §16) ────────────────────────────────

/// Decode a QUIC variable-length integer from `buf`.
/// Returns the decoded value and number of bytes consumed.
pub fn varIntDecode(buf: []const u8) Error!struct { value: u64, consumed: usize } {
    if (buf.len == 0) return Error.InvalidVarInt;
    const first = buf[0];
    const prefix = first >> 6; // top 2 bits determine length
    return switch (prefix) {
        0 => .{ .value = @as(u64, first & 0x3F), .consumed = 1 },
        1 => {
            if (buf.len < 2) return Error.InvalidVarInt;
            const v = (@as(u64, first & 0x3F) << 8) | @as(u64, buf[1]);
            return .{ .value = v, .consumed = 2 };
        },
        2 => {
            if (buf.len < 4) return Error.InvalidVarInt;
            const v = (@as(u64, first & 0x3F) << 24) |
                (@as(u64, buf[1]) << 16) |
                (@as(u64, buf[2]) << 8) |
                @as(u64, buf[3]);
            return .{ .value = v, .consumed = 4 };
        },
        3 => {
            if (buf.len < 8) return Error.InvalidVarInt;
            const v = (@as(u64, first & 0x3F) << 56) |
                (@as(u64, buf[1]) << 48) |
                (@as(u64, buf[2]) << 40) |
                (@as(u64, buf[3]) << 32) |
                (@as(u64, buf[4]) << 24) |
                (@as(u64, buf[5]) << 16) |
                (@as(u64, buf[6]) << 8) |
                @as(u64, buf[7]);
            return .{ .value = v, .consumed = 8 };
        },
        else => unreachable,
    };
}

/// Encode a QUIC variable-length integer into `buf`.
/// Returns the number of bytes written.
pub fn varIntEncode(value: u64, buf: []u8) Error!usize {
    if (value <= 0x3F) {
        if (buf.len < 1) return Error.BufferTooSmall;
        buf[0] = @intCast(value);
        return 1;
    } else if (value <= 0x3FFF) {
        if (buf.len < 2) return Error.BufferTooSmall;
        buf[0] = 0x40 | @as(u8, @intCast(value >> 8));
        buf[1] = @intCast(value & 0xFF);
        return 2;
    } else if (value <= 0x3FFF_FFFF) {
        if (buf.len < 4) return Error.BufferTooSmall;
        buf[0] = 0x80 | @as(u8, @intCast(value >> 24));
        buf[1] = @intCast((value >> 16) & 0xFF);
        buf[2] = @intCast((value >> 8) & 0xFF);
        buf[3] = @intCast(value & 0xFF);
        return 4;
    } else {
        if (buf.len < 8) return Error.BufferTooSmall;
        buf[0] = 0xC0 | @as(u8, @intCast(value >> 56));
        buf[1] = @intCast((value >> 48) & 0xFF);
        buf[2] = @intCast((value >> 40) & 0xFF);
        buf[3] = @intCast((value >> 32) & 0xFF);
        buf[4] = @intCast((value >> 24) & 0xFF);
        buf[5] = @intCast((value >> 16) & 0xFF);
        buf[6] = @intCast((value >> 8) & 0xFF);
        buf[7] = @intCast(value & 0xFF);
        return 8;
    }
}

/// Minimum encoded byte width for a given value.
pub fn varIntLen(value: u64) usize {
    if (value <= 0x3F) return 1;
    if (value <= 0x3FFF) return 2;
    if (value <= 0x3FFF_FFFF) return 4;
    return 8;
}

// ── Connection ID ────────────────────────────────────────────────────────

pub const MAX_CONN_ID_LEN: usize = 20;

pub const ConnectionId = struct {
    bytes: [MAX_CONN_ID_LEN]u8 = [_]u8{0} ** MAX_CONN_ID_LEN,
    len: u8 = 0,

    pub fn zero() ConnectionId {
        return .{};
    }

    pub fn random(rng: std.Random) ConnectionId {
        var cid = ConnectionId{ .len = MAX_CONN_ID_LEN };
        rng.bytes(cid.bytes[0..MAX_CONN_ID_LEN]);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(a: ConnectionId, b: ConnectionId) bool {
        return a.len == b.len and std.mem.eql(u8, a.bytes[0..a.len], b.bytes[0..b.len]);
    }

    pub fn fromSlice(data: []const u8) Error!ConnectionId {
        if (data.len > MAX_CONN_ID_LEN) return Error.InvalidPacket;
        var cid = ConnectionId{ .len = @intCast(data.len) };
        @memcpy(cid.bytes[0..data.len], data);
        return cid;
    }
};

// ── Long Header ──────────────────────────────────────────────────────────

/// Parsed long-header QUIC packet (Initial, Handshake, 0-RTT, Retry).
/// The `payload` slice points into the original buffer and is still encrypted
/// — the TLS layer must decrypt it before reading frames.
pub const LongHeader = struct {
    first_byte: u8,
    version: u32,
    dst_conn_id: ConnectionId,
    src_conn_id: ConnectionId,
    /// For Initial: token (client retry token or empty)
    token: []const u8,
    /// Encrypted payload including packet number (1-4 bytes at front)
    payload: []const u8,

    pub fn packetType(self: LongHeader) QuicPacketType {
        const bits = (self.first_byte >> 4) & 0x03;
        return @enumFromInt(bits);
    }

    /// Reserved bits (must be 0 after header protection removal)
    pub fn reservedBits(self: LongHeader) u8 {
        return (self.first_byte >> 2) & 0x03;
    }

    /// Packet number length in bytes (1-4), encoded in first_byte bits 0-1.
    pub fn pnLen(self: LongHeader) usize {
        return @as(usize, (self.first_byte & 0x03)) + 1;
    }
};

/// Parse a long-header packet from `buf`.
/// Returns the parsed header and the number of bytes consumed (header only).
pub fn parseLongHeader(buf: []const u8) Error!struct { hdr: LongHeader, consumed: usize } {
    if (buf.len < 7) return Error.InvalidPacket;

    const first = buf[0];
    // Bit 7 must be 1 (long header), bit 6 must be 1 (fixed bit)
    if ((first & 0x80) == 0) return Error.InvalidPacket;

    var pos: usize = 1;

    // Version (4 bytes, big-endian)
    if (buf.len < pos + 4) return Error.InvalidPacket;
    const version = std.mem.readInt(u32, buf[pos..][0..4], .big);
    pos += 4;

    // Destination Connection ID
    if (buf.len < pos + 1) return Error.InvalidPacket;
    const dst_cid_len = buf[pos];
    pos += 1;
    if (buf.len < pos + dst_cid_len) return Error.InvalidPacket;
    const dst_cid = try ConnectionId.fromSlice(buf[pos .. pos + dst_cid_len]);
    pos += dst_cid_len;

    // Source Connection ID
    if (buf.len < pos + 1) return Error.InvalidPacket;
    const src_cid_len = buf[pos];
    pos += 1;
    if (buf.len < pos + src_cid_len) return Error.InvalidPacket;
    const src_cid = try ConnectionId.fromSlice(buf[pos .. pos + src_cid_len]);
    pos += src_cid_len;

    // Token (Initial packets only; length-prefixed with VarInt)
    var token: []const u8 = &[_]u8{};
    const pkt_bits = (first >> 4) & 0x03;
    if (pkt_bits == @intFromEnum(QuicPacketType.Initial)) {
        const tok = try varIntDecode(buf[pos..]);
        pos += tok.consumed;
        if (buf.len < pos + tok.value) return Error.InvalidPacket;
        token = buf[pos .. pos + tok.value];
        pos += tok.value;
    }

    // Payload length (VarInt)
    const plen = try varIntDecode(buf[pos..]);
    pos += plen.consumed;
    if (buf.len < pos + plen.value) return Error.InvalidPacket;

    const payload = buf[pos .. pos + plen.value];
    pos += plen.value;

    return .{
        .hdr = LongHeader{
            .first_byte = first,
            .version = version,
            .dst_conn_id = dst_cid,
            .src_conn_id = src_cid,
            .token = token,
            .payload = payload,
        },
        .consumed = pos,
    };
}

/// Encode a long-header packet into `buf`.
/// `payload` must already be encrypted. `pn` is the truncated packet number.
pub fn encodeLongHeader(
    buf: []u8,
    pkt_type: QuicPacketType,
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: []const u8,
    pn: u32,
    pn_len: u8, // 1-4
    payload: []const u8,
) Error!usize {
    var pos: usize = 0;

    // First byte: 1 (long) | 1 (fixed) | type(2) | reserved(2) | pn_len(2)
    const type_bits: u8 = @intFromEnum(pkt_type);
    buf[pos] = 0xC0 | (type_bits << 4) | (pn_len - 1);
    pos += 1;

    // Version
    if (buf.len < pos + 4) return Error.BufferTooSmall;
    std.mem.writeInt(u32, buf[pos..][0..4], version, .big);
    pos += 4;

    // Destination CID
    if (buf.len < pos + 1 + dst_cid.len) return Error.BufferTooSmall;
    buf[pos] = dst_cid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + dst_cid.len], dst_cid.slice());
    pos += dst_cid.len;

    // Source CID
    if (buf.len < pos + 1 + src_cid.len) return Error.BufferTooSmall;
    buf[pos] = src_cid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + src_cid.len], src_cid.slice());
    pos += src_cid.len;

    // Token (Initial only)
    if (pkt_type == .Initial) {
        pos += try varIntEncode(token.len, buf[pos..]);
        if (buf.len < pos + token.len) return Error.BufferTooSmall;
        @memcpy(buf[pos .. pos + token.len], token);
        pos += token.len;
    }

    // Payload length (pn_len bytes of packet number + actual payload)
    const total_payload_len = pn_len + payload.len;
    pos += try varIntEncode(total_payload_len, buf[pos..]);

    // Packet number (big-endian, truncated to pn_len bytes)
    if (buf.len < pos + pn_len) return Error.BufferTooSmall;
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, pn, .big);
    @memcpy(buf[pos .. pos + pn_len], pn_bytes[4 - pn_len ..]);
    pos += pn_len;

    // Payload
    if (buf.len < pos + payload.len) return Error.BufferTooSmall;
    @memcpy(buf[pos .. pos + payload.len], payload);
    pos += payload.len;

    return pos;
}

/// Encode long header prefix (everything before the PN field).
/// Returns bytes written (prefix only — no PN, no payload).
/// Call `encryptPacket` with this prefix to complete the packet.
pub fn encodeLongHeaderPrefix(
    buf: []u8,
    pkt_type: QuicPacketType,
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: []const u8,
    payload_len: usize,
    pn_len: u8,
) Error!usize {
    var pos: usize = 0;

    const type_bits: u8 = @intFromEnum(pkt_type);
    buf[pos] = 0xC0 | (type_bits << 4) | (pn_len - 1);
    pos += 1;

    if (buf.len < pos + 4) return Error.BufferTooSmall;
    std.mem.writeInt(u32, buf[pos..][0..4], version, .big);
    pos += 4;

    if (buf.len < pos + 1 + dst_cid.len) return Error.BufferTooSmall;
    buf[pos] = dst_cid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + dst_cid.len], dst_cid.slice());
    pos += dst_cid.len;

    if (buf.len < pos + 1 + src_cid.len) return Error.BufferTooSmall;
    buf[pos] = src_cid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + src_cid.len], src_cid.slice());
    pos += src_cid.len;

    if (pkt_type == .Initial) {
        pos += try varIntEncode(token.len, buf[pos..]);
        if (buf.len < pos + token.len) return Error.BufferTooSmall;
        @memcpy(buf[pos .. pos + token.len], token);
        pos += token.len;
    }

    const total_payload_len = pn_len + payload_len;
    pos += try varIntEncode(total_payload_len, buf[pos..]);

    return pos;
}

/// Encode short header prefix (everything before the PN field).
/// Call `encryptPacket` with this prefix to complete the packet.
pub fn encodeShortHeaderPrefix(
    buf: []u8,
    dst_cid: ConnectionId,
    spin_bit: bool,
    key_phase: bool,
    pn_len: u8,
) Error!usize {
    var pos: usize = 0;

    const spin: u8 = if (spin_bit) 0x20 else 0;
    const kp: u8 = if (key_phase) 0x04 else 0;
    buf[pos] = 0x40 | spin | kp | (pn_len - 1);
    pos += 1;

    if (buf.len < pos + dst_cid.len) return Error.BufferTooSmall;
    @memcpy(buf[pos .. pos + dst_cid.len], dst_cid.slice());
    pos += dst_cid.len;

    return pos;
}

// ── Short Header (1-RTT) ─────────────────────────────────────────────────

/// Parsed short-header QUIC 1-RTT packet.
pub const ShortHeader = struct {
    first_byte: u8,
    dst_conn_id: ConnectionId,
    /// Remaining bytes = encrypted {packet_number || frames}
    payload: []const u8,

    /// Spin bit (latency measurement, RFC 9000 §17.3.1)
    pub fn spinBit(self: ShortHeader) bool {
        return (self.first_byte & 0x20) != 0;
    }

    /// Key phase bit (triggers key update)
    pub fn keyPhase(self: ShortHeader) bool {
        return (self.first_byte & 0x04) != 0;
    }

    /// Packet number length in bytes (1-4)
    pub fn pnLen(self: ShortHeader) usize {
        return @as(usize, (self.first_byte & 0x03)) + 1;
    }
};

/// Parse a short-header 1-RTT packet.
/// `cid_len` is the known connection ID length (must match peer's CID).
pub fn parseShortHeader(buf: []const u8, cid_len: usize) Error!struct { hdr: ShortHeader, consumed: usize } {
    if (buf.len < 1 + cid_len) return Error.InvalidPacket;

    const first = buf[0];
    // Bit 7 must be 0 (short header), bit 6 must be 1 (fixed bit)
    if ((first & 0xC0) != 0x40) return Error.InvalidPacket;

    const dst_cid = try ConnectionId.fromSlice(buf[1 .. 1 + cid_len]);
    const payload = buf[1 + cid_len ..];

    return .{
        .hdr = ShortHeader{
            .first_byte = first,
            .dst_conn_id = dst_cid,
            .payload = payload,
        },
        .consumed = 1 + cid_len,
    };
}

/// Encode a short-header 1-RTT packet into `buf`.
pub fn encodeShortHeader(
    buf: []u8,
    dst_cid: ConnectionId,
    spin_bit: bool,
    key_phase: bool,
    pn: u32,
    pn_len: u8, // 1-4
    payload: []const u8,
) Error!usize {
    var pos: usize = 0;

    const spin: u8 = if (spin_bit) 0x20 else 0;
    const kp: u8 = if (key_phase) 0x04 else 0;
    buf[pos] = 0x40 | spin | kp | (pn_len - 1);
    pos += 1;

    if (buf.len < pos + dst_cid.len) return Error.BufferTooSmall;
    @memcpy(buf[pos .. pos + dst_cid.len], dst_cid.slice());
    pos += dst_cid.len;

    // Packet number (big-endian, truncated)
    if (buf.len < pos + pn_len) return Error.BufferTooSmall;
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, pn, .big);
    @memcpy(buf[pos .. pos + pn_len], pn_bytes[4 - pn_len ..]);
    pos += pn_len;

    // Payload (already encrypted)
    if (buf.len < pos + payload.len) return Error.BufferTooSmall;
    @memcpy(buf[pos .. pos + payload.len], payload);
    pos += payload.len;

    return pos;
}

// ── Header Protection (RFC 9001 §5.4) ────────────────────────────────────
//
// Header protection XORs the first byte and packet number bytes with a mask
// derived from the sample of the encrypted payload using AES-ECB or
// ChaCha20-based keying. This module provides the application of the mask;
// the mask itself is computed by quic/tls.zig.

/// Apply (or remove) header protection to an in-place packet buffer.
/// `header_len` is the number of bytes before the packet number.
/// `pn_len` is 1-4.
/// `mask` is the 5-byte protection mask from AES-ECB/ChaCha20.
pub fn applyHeaderProtection(
    buf: []u8,
    header_len: usize,
    pn_len: usize,
    mask: [5]u8,
    is_long: bool,
) void {
    // First byte masking differs for long vs short headers
    if (is_long) {
        buf[0] ^= mask[0] & 0x0F; // bits 0-3 only
    } else {
        buf[0] ^= mask[0] & 0x1F; // bits 0-4 only
    }

    // XOR packet number bytes
    for (0..pn_len) |i| {
        buf[header_len + i] ^= mask[1 + i];
    }
}

// ── Packet Number Decoding (RFC 9000 §A.3) ───────────────────────────────

/// Decode the full 62-bit packet number from a truncated wire value.
/// `truncated_pn` is the wire value (1-4 bytes, interpreted as little-endian).
/// `largest_pn` is the largest fully decoded packet number received so far.
/// `pn_len` is 1-4 (number of bytes).
pub fn decodePacketNumber(truncated_pn: u64, largest_pn: u64, pn_len: usize) u64 {
    const pn_win: u64 = @as(u64, 1) << @intCast(pn_len * 8);
    const pn_hwin = pn_win >> 1;
    const pn_mask = pn_win - 1;

    // The candidate is the value that matches truncated_pn modulo pn_win
    // and is closest to expected = largest_pn + 1
    const expected = largest_pn + 1;
    var candidate = (expected & ~pn_mask) | (truncated_pn & pn_mask);

    if (candidate + pn_hwin <= expected and candidate + pn_win < (1 << 62)) {
        candidate += pn_win;
    } else if (candidate > expected + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }

    return candidate;
}

/// Encode a full packet number to a truncated form, choosing minimum byte width.
/// Returns (truncated_value, pn_len) where pn_len is 1-4.
pub fn encodePacketNumber(pn: u64, largest_acked: u64) struct { truncated: u32, pn_len: u8 } {
    // Number of unacked packets determines minimum encoding width
    const num_unacked = pn - largest_acked;
    if (num_unacked < 0x80) {
        return .{ .truncated = @intCast(pn & 0xFF), .pn_len = 1 };
    } else if (num_unacked < 0x8000) {
        return .{ .truncated = @intCast(pn & 0xFFFF), .pn_len = 2 };
    } else if (num_unacked < 0x80_0000) {
        return .{ .truncated = @intCast(pn & 0xFF_FFFF), .pn_len = 3 };
    } else {
        return .{ .truncated = @intCast(pn & 0xFFFF_FFFF), .pn_len = 4 };
    }
}

// ── Dispatch: detect long vs short header ────────────────────────────────

pub const HeaderKind = enum { Long, Short, VersionNegotiation };

pub fn detectHeaderKind(buf: []const u8) Error!HeaderKind {
    if (buf.len < 5) return Error.InvalidPacket;
    const first = buf[0];
    if ((first & 0x80) != 0) {
        // Long header — check version
        const version = std.mem.readInt(u32, buf[1..5], .big);
        if (version == QUIC_VERSION_NEGOTIATION) return .VersionNegotiation;
        return .Long;
    }
    return .Short;
}

// ── Unit Tests ────────────────────────────────────────────────────────────

test "VarInt round-trip: 1-byte" {
    var buf: [8]u8 = undefined;
    const written = try varIntEncode(37, &buf);
    try std.testing.expectEqual(@as(usize, 1), written);
    const r = try varIntDecode(buf[0..written]);
    try std.testing.expectEqual(@as(u64, 37), r.value);
}

test "VarInt round-trip: 2-byte" {
    var buf: [8]u8 = undefined;
    const written = try varIntEncode(494878333, &buf);
    try std.testing.expectEqual(@as(usize, 4), written);
    const r = try varIntDecode(buf[0..written]);
    try std.testing.expectEqual(@as(u64, 494878333), r.value);
}

test "VarInt: RFC 9000 test vectors" {
    // From RFC 9000 Appendix A
    const buf1 = [_]u8{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    const r1 = try varIntDecode(&buf1);
    try std.testing.expectEqual(@as(u64, 151288809941952652), r1.value);
    try std.testing.expectEqual(@as(usize, 8), r1.consumed);

    const buf2 = [_]u8{0x9d, 0x7f, 0x3e, 0x7d};
    const r2 = try varIntDecode(&buf2);
    try std.testing.expectEqual(@as(u64, 494878333), r2.value);
    try std.testing.expectEqual(@as(usize, 4), r2.consumed);
}

test "ConnectionId: fromSlice and eql" {
    const data = [_]u8{ 1, 2, 3, 4, 5 };
    const cid = try ConnectionId.fromSlice(&data);
    try std.testing.expectEqual(@as(u8, 5), cid.len);
    try std.testing.expectEqualSlices(u8, &data, cid.slice());
}

test "Packet number decode: RFC 9000 Appendix A" {
    // Example: largest received = 0xa82f30ea, truncated = 0x9b32
    // Expected full PN = 0xa82f9b32
    const decoded = decodePacketNumber(0x9b32, 0xa82f30ea, 2);
    try std.testing.expectEqual(@as(u64, 0xa82f9b32), decoded);
}

test "Long header encode/decode round-trip" {
    var buf: [512]u8 = undefined;
    const dst = try ConnectionId.fromSlice(&[_]u8{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04});
    const src = try ConnectionId.fromSlice(&[_]u8{0xCA, 0xFE, 0xBA, 0xBE, 0x05, 0x06, 0x07, 0x08});
    const payload = [_]u8{ 0x10, 0x20, 0x30, 0x40 }; // fake encrypted payload

    const written = try encodeLongHeader(&buf, .Initial, QUIC_V1, dst, src, &[_]u8{}, 42, 2, &payload);
    try std.testing.expect(written > 0);

    const kind = try detectHeaderKind(buf[0..written]);
    try std.testing.expectEqual(HeaderKind.Long, kind);

    const parsed = try parseLongHeader(buf[0..written]);
    try std.testing.expectEqual(QUIC_V1, parsed.hdr.version);
    try std.testing.expect(ConnectionId.eql(dst, parsed.hdr.dst_conn_id));
    try std.testing.expect(ConnectionId.eql(src, parsed.hdr.src_conn_id));
    try std.testing.expectEqual(QuicPacketType.Initial, parsed.hdr.packetType());
}
