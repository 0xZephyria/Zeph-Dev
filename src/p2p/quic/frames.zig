// ============================================================================
// Zephyria — QUIC Frame Codec (RFC 9000 §12)
// ============================================================================
//
// Defines all QUIC frame types and their wire encoding/decoding.
// Frames appear inside decrypted QUIC packet payloads.
//
// Frame types implemented:
//   PADDING, PING, ACK, RESET_STREAM, STOP_SENDING, CRYPTO,
//   NEW_TOKEN, STREAM (+ FIN/LEN/OFF flags), MAX_DATA,
//   MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED,
//   STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
//   PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE

const std = @import("std");
const packet = @import("transport/packet.zig");
const varIntDecode = packet.varIntDecode;
const varIntEncode = packet.varIntEncode;
const varIntLen = packet.varIntLen;
const ConnectionId = packet.ConnectionId;

// ── Frame Type IDs (RFC 9000 Table 3) ────────────────────────────────────

pub const FrameTypeId = enum(u64) {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    // STREAM: type 0x08..0x0F with OFF/LEN/FIN flags
    Stream = 0x08,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUni = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1A,
    PathResponse = 0x1B,
    ConnectionClose = 0x1C,
    ConnectionCloseApp = 0x1D,
    HandshakeDone = 0x1E,
    _,
};

// ── ACK Range ────────────────────────────────────────────────────────────

pub const AckRange = struct {
    /// Number of contiguous packets acked below the gap
    gap: u64,
    /// Number of contiguous acked packets in this range
    ack_range_count: u64,
};

// ── Frame Union ───────────────────────────────────────────────────────────

pub const Frame = union(enum) {
    Padding: PaddingFrame,
    Ping: PingFrame,
    Ack: AckFrame,
    ResetStream: ResetStreamFrame,
    StopSending: StopSendingFrame,
    Crypto: CryptoFrame,
    NewToken: NewTokenFrame,
    Stream: StreamFrame,
    MaxData: MaxDataFrame,
    MaxStreamData: MaxStreamDataFrame,
    MaxStreams: MaxStreamsFrame,
    DataBlocked: DataBlockedFrame,
    StreamDataBlocked: StreamDataBlockedFrame,
    StreamsBlocked: StreamsBlockedFrame,
    NewConnectionId: NewConnectionIdFrame,
    RetireConnectionId: RetireConnectionIdFrame,
    PathChallenge: PathChallengeFrame,
    PathResponse: PathResponseFrame,
    ConnectionClose: ConnectionCloseFrame,
    HandshakeDone: HandshakeDoneFrame,

    /// Decode a single frame from `buf`. Returns the frame and bytes consumed.
    pub fn decode(buf: []const u8, allocator: std.mem.Allocator) !struct { frame: Frame, consumed: usize } {
        if (buf.len == 0) return error.InvalidFrame;

        const type_vi = varIntDecode(buf) catch return error.InvalidFrame;
        var pos = type_vi.consumed;
        const frame_type_id: u64 = type_vi.value;

        // STREAM frames: 0x08..0x0F with flags in lower 3 bits
        if (frame_type_id >= 0x08 and frame_type_id <= 0x0F) {
            const flags = frame_type_id & 0x07;
            const has_off = (flags & 0x04) != 0;
            const has_len = (flags & 0x02) != 0;
            const has_fin = (flags & 0x01) != 0;

            const sid = try varIntDecodeAt(buf, &pos);
            const offset: u64 = if (has_off) try varIntDecodeAt(buf, &pos) else 0;
            const data: []const u8 = if (has_len) blk: {
                const dlen = try varIntDecodeAt(buf, &pos);
                if (buf.len < pos + dlen) return error.InvalidFrame;
                const d = buf[pos .. pos + dlen];
                pos += dlen;
                break :blk d;
            } else buf[pos..]; // rest of packet

            return .{ .frame = .{ .Stream = StreamFrame{
                .stream_id = sid,
                .offset = offset,
                .data = data,
                .fin = has_fin,
            } }, .consumed = pos };
        }

        const ftype: FrameTypeId = @enumFromInt(frame_type_id);

        return switch (ftype) {
            .Padding => .{ .frame = .{ .Padding = .{} }, .consumed = 1 },
            .Ping => .{ .frame = .{ .Ping = .{} }, .consumed = pos },
            .Ack, .AckEcn => {
                const largest = try varIntDecodeAt(buf, &pos);
                const delay = try varIntDecodeAt(buf, &pos);
                const range_count = try varIntDecodeAt(buf, &pos);
                const first_range = try varIntDecodeAt(buf, &pos);
                const ranges = try allocator.alloc(AckRange, range_count);
                for (ranges) |*r| {
                    r.gap = try varIntDecodeAt(buf, &pos);
                    r.ack_range_count = try varIntDecodeAt(buf, &pos);
                }
                return .{ .frame = .{ .Ack = AckFrame{
                    .largest_acknowledged = largest,
                    .ack_delay = delay,
                    .first_ack_range = first_range,
                    .ack_ranges = ranges,
                } }, .consumed = pos };
            },
            .ResetStream => {
                const sid = try varIntDecodeAt(buf, &pos);
                const err_code = try varIntDecodeAt(buf, &pos);
                const final_size = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .ResetStream = .{
                    .stream_id = sid,
                    .application_protocol_error_code = err_code,
                    .final_size = final_size,
                } }, .consumed = pos };
            },
            .StopSending => {
                const sid = try varIntDecodeAt(buf, &pos);
                const err_code = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .StopSending = .{
                    .stream_id = sid,
                    .application_protocol_error_code = err_code,
                } }, .consumed = pos };
            },
            .Crypto => {
                const offset = try varIntDecodeAt(buf, &pos);
                const dlen = try varIntDecodeAt(buf, &pos);
                if (buf.len < pos + dlen) return error.InvalidFrame;
                const data = buf[pos .. pos + dlen];
                pos += dlen;
                return .{ .frame = .{ .Crypto = .{
                    .offset = offset,
                    .data = data,
                } }, .consumed = pos };
            },
            .NewToken => {
                const tlen = try varIntDecodeAt(buf, &pos);
                if (buf.len < pos + tlen) return error.InvalidFrame;
                const tok = buf[pos .. pos + tlen];
                pos += tlen;
                return .{ .frame = .{ .NewToken = .{ .token = tok } }, .consumed = pos };
            },
            .MaxData => {
                const max = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .MaxData = .{ .maximum_data = max } }, .consumed = pos };
            },
            .MaxStreamData => {
                const sid = try varIntDecodeAt(buf, &pos);
                const max = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .MaxStreamData = .{
                    .stream_id = sid,
                    .maximum_stream_data = max,
                } }, .consumed = pos };
            },
            .MaxStreamsBidi, .MaxStreamsUni => {
                const max = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .MaxStreams = .{
                    .bidi = ftype == .MaxStreamsBidi,
                    .maximum_streams = max,
                } }, .consumed = pos };
            },
            .DataBlocked => {
                const limit = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .DataBlocked = .{ .data_limit = limit } }, .consumed = pos };
            },
            .StreamDataBlocked => {
                const sid = try varIntDecodeAt(buf, &pos);
                const limit = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .StreamDataBlocked = .{
                    .stream_id = sid,
                    .stream_data_limit = limit,
                } }, .consumed = pos };
            },
            .StreamsBlockedBidi, .StreamsBlockedUni => {
                const limit = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .StreamsBlocked = .{
                    .bidi = ftype == .StreamsBlockedBidi,
                    .stream_limit = limit,
                } }, .consumed = pos };
            },
            .NewConnectionId => {
                const seq = try varIntDecodeAt(buf, &pos);
                const retire_prior = try varIntDecodeAt(buf, &pos);
                if (buf.len < pos + 1) return error.InvalidFrame;
                const cid_len = buf[pos];
                pos += 1;
                if (buf.len < pos + cid_len + 16) return error.InvalidFrame;
                const cid = try ConnectionId.fromSlice(buf[pos .. pos + cid_len]);
                pos += cid_len;
                var token: [16]u8 = undefined;
                @memcpy(&token, buf[pos .. pos + 16]);
                pos += 16;
                return .{ .frame = .{ .NewConnectionId = .{
                    .sequence_number = seq,
                    .retire_prior_to = retire_prior,
                    .connection_id = cid,
                    .stateless_reset_token = token,
                } }, .consumed = pos };
            },
            .RetireConnectionId => {
                const seq = try varIntDecodeAt(buf, &pos);
                return .{ .frame = .{ .RetireConnectionId = .{ .sequence_number = seq } }, .consumed = pos };
            },
            .PathChallenge => {
                if (buf.len < pos + 8) return error.InvalidFrame;
                var data: [8]u8 = undefined;
                @memcpy(&data, buf[pos .. pos + 8]);
                pos += 8;
                return .{ .frame = .{ .PathChallenge = .{ .data = data } }, .consumed = pos };
            },
            .PathResponse => {
                if (buf.len < pos + 8) return error.InvalidFrame;
                var data: [8]u8 = undefined;
                @memcpy(&data, buf[pos .. pos + 8]);
                pos += 8;
                return .{ .frame = .{ .PathResponse = .{ .data = data } }, .consumed = pos };
            },
            .ConnectionClose, .ConnectionCloseApp => {
                const err_code = try varIntDecodeAt(buf, &pos);
                const frame_t: u64 = if (ftype == .ConnectionClose) try varIntDecodeAt(buf, &pos) else 0;
                const reason_len = try varIntDecodeAt(buf, &pos);
                if (buf.len < pos + reason_len) return error.InvalidFrame;
                const reason = buf[pos .. pos + reason_len];
                pos += reason_len;
                return .{ .frame = .{ .ConnectionClose = .{
                    .error_code = err_code,
                    .frame_type = frame_t,
                    .reason_phrase = reason,
                } }, .consumed = pos };
            },
            .Stream => unreachable, // handled above in the 0x08..0x0F range check
            .HandshakeDone => .{ .frame = .{ .HandshakeDone = .{} }, .consumed = pos },
            _ => error.UnknownFrameType,
        };
    }

    /// Encode a frame into `buf`. Returns bytes written.
    pub fn encode(self: Frame, buf: []u8) !usize {
        var pos: usize = 0;

        switch (self) {
            .Padding => {
                if (buf.len < 1) return error.BufferTooSmall;
                buf[pos] = 0x00;
                pos += 1;
            },
            .Ping => {
                pos += try varIntEncode(0x01, buf[pos..]);
            },
            .Ack => |f| {
                pos += try varIntEncode(0x02, buf[pos..]);
                pos += try varIntEncode(f.largest_acknowledged, buf[pos..]);
                pos += try varIntEncode(f.ack_delay, buf[pos..]);
                pos += try varIntEncode(f.ack_ranges.len, buf[pos..]);
                pos += try varIntEncode(f.first_ack_range, buf[pos..]);
                for (f.ack_ranges) |r| {
                    pos += try varIntEncode(r.gap, buf[pos..]);
                    pos += try varIntEncode(r.ack_range_count, buf[pos..]);
                }
            },
            .Crypto => |f| {
                pos += try varIntEncode(0x06, buf[pos..]);
                pos += try varIntEncode(f.offset, buf[pos..]);
                pos += try varIntEncode(f.data.len, buf[pos..]);
                if (buf.len < pos + f.data.len) return error.BufferTooSmall;
                @memcpy(buf[pos .. pos + f.data.len], f.data);
                pos += f.data.len;
            },
            .Stream => |f| {
                // Compute flags
                const off_flag: u64 = if (f.offset != 0) 0x04 else 0;
                const len_flag: u64 = 0x02; // always include length for framing clarity
                const fin_flag: u64 = if (f.fin) 0x01 else 0;
                const type_id: u64 = 0x08 | off_flag | len_flag | fin_flag;
                pos += try varIntEncode(type_id, buf[pos..]);
                pos += try varIntEncode(f.stream_id, buf[pos..]);
                if (f.offset != 0) {
                    pos += try varIntEncode(f.offset, buf[pos..]);
                }
                pos += try varIntEncode(f.data.len, buf[pos..]);
                if (buf.len < pos + f.data.len) return error.BufferTooSmall;
                @memcpy(buf[pos .. pos + f.data.len], f.data);
                pos += f.data.len;
            },
            .MaxData => |f| {
                pos += try varIntEncode(0x10, buf[pos..]);
                pos += try varIntEncode(f.maximum_data, buf[pos..]);
            },
            .MaxStreamData => |f| {
                pos += try varIntEncode(0x11, buf[pos..]);
                pos += try varIntEncode(f.stream_id, buf[pos..]);
                pos += try varIntEncode(f.maximum_stream_data, buf[pos..]);
            },
            .ConnectionClose => |f| {
                pos += try varIntEncode(0x1C, buf[pos..]);
                pos += try varIntEncode(f.error_code, buf[pos..]);
                pos += try varIntEncode(f.frame_type, buf[pos..]);
                pos += try varIntEncode(f.reason_phrase.len, buf[pos..]);
                if (buf.len < pos + f.reason_phrase.len) return error.BufferTooSmall;
                @memcpy(buf[pos .. pos + f.reason_phrase.len], f.reason_phrase);
                pos += f.reason_phrase.len;
            },
            .HandshakeDone => {
                pos += try varIntEncode(0x1E, buf[pos..]);
            },
            .NewConnectionId => |f| {
                pos += try varIntEncode(0x18, buf[pos..]);
                pos += try varIntEncode(f.sequence_number, buf[pos..]);
                pos += try varIntEncode(f.retire_prior_to, buf[pos..]);
                if (buf.len < pos + 1 + f.connection_id.len + 16) return error.BufferTooSmall;
                buf[pos] = f.connection_id.len;
                pos += 1;
                @memcpy(buf[pos .. pos + f.connection_id.len], f.connection_id.slice());
                pos += f.connection_id.len;
                @memcpy(buf[pos .. pos + 16], &f.stateless_reset_token);
                pos += 16;
            },
            .PathChallenge => |f| {
                pos += try varIntEncode(0x1A, buf[pos..]);
                if (buf.len < pos + 8) return error.BufferTooSmall;
                @memcpy(buf[pos .. pos + 8], &f.data);
                pos += 8;
            },
            .PathResponse => |f| {
                pos += try varIntEncode(0x1B, buf[pos..]);
                if (buf.len < pos + 8) return error.BufferTooSmall;
                @memcpy(buf[pos .. pos + 8], &f.data);
                pos += 8;
            },
            else => return error.UnsupportedFrame,
        }

        return pos;
    }
};

// ── Frame Structs ─────────────────────────────────────────────────────────

pub const PaddingFrame = struct {};
pub const PingFrame = struct {};
pub const HandshakeDoneFrame = struct {};

pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ack_ranges: []AckRange,
};

pub const ResetStreamFrame = struct {
    stream_id: u64,
    application_protocol_error_code: u64,
    final_size: u64,
};

pub const StopSendingFrame = struct {
    stream_id: u64,
    application_protocol_error_code: u64,
};

/// CRYPTO frame — carries TLS handshake data (ClientHello, etc.)
pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

pub const NewTokenFrame = struct {
    token: []const u8,
};

/// STREAM frame — carries application data
pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
};

pub const MaxDataFrame = struct {
    maximum_data: u64,
};

pub const MaxStreamDataFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const MaxStreamsFrame = struct {
    bidi: bool,
    maximum_streams: u64,
};

pub const DataBlockedFrame = struct {
    data_limit: u64,
};

pub const StreamDataBlockedFrame = struct {
    stream_id: u64,
    stream_data_limit: u64,
};

pub const StreamsBlockedFrame = struct {
    bidi: bool,
    stream_limit: u64,
};

pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnectionId,
    stateless_reset_token: [16]u8,
};

pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
};

pub const PathChallengeFrame = struct {
    data: [8]u8,
};

pub const PathResponseFrame = struct {
    data: [8]u8,
};

pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: u64,
    reason_phrase: []const u8,
};

// ── Zephyria Stream ID Conventions ───────────────────────────────────────

/// Well-known stream IDs used by Zephyria's QUIC protocol.
pub const StreamIds = struct {
    /// Stream 0: TLS Auth / Committee Handshake (bidi)
    pub const HANDSHAKE: u64 = 0;
    /// Stream 4: Gossip (MsgStatus, MsgPeers, Ping/Pong) (bidi)
    pub const GOSSIP: u64 = 4;
    /// Stream 8: Block propagation (MsgNewBlock, MsgShred, MsgVote) (bidi)
    pub const BLOCKS: u64 = 8;
    /// Stream 12: Transaction forwarding via Gulf Stream (uni, client-initiated)
    pub const GULF_STREAM: u64 = 12;
};

// ── Helper ────────────────────────────────────────────────────────────────

fn varIntDecodeAt(buf: []const u8, pos: *usize) !u64 {
    const r = varIntDecode(buf[pos.*..]) catch return error.InvalidFrame;
    pos.* += r.consumed;
    return r.value;
}

// ── Unit Tests ────────────────────────────────────────────────────────────

test "CRYPTO frame round-trip" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xAA, 0xBB, 0xCC };
    const original = Frame{ .Crypto = CryptoFrame{ .offset = 100, .data = &data } };

    var buf: [64]u8 = undefined;
    const written = try original.encode(&buf);

    const decoded = try Frame.decode(buf[0..written], allocator);
    try std.testing.expectEqual(@as(u64, 100), decoded.frame.Crypto.offset);
    try std.testing.expectEqualSlices(u8, &data, decoded.frame.Crypto.data);
}

test "STREAM frame round-trip" {
    const allocator = std.testing.allocator;
    const payload = "hello quic world";
    const original = Frame{ .Stream = StreamFrame{
        .stream_id = StreamIds.GULF_STREAM,
        .offset = 0,
        .data = payload,
        .fin = false,
    } };

    var buf: [128]u8 = undefined;
    const written = try original.encode(&buf);

    const decoded = try Frame.decode(buf[0..written], allocator);
    try std.testing.expectEqual(StreamIds.GULF_STREAM, decoded.frame.Stream.stream_id);
    try std.testing.expectEqualSlices(u8, payload, decoded.frame.Stream.data);
    try std.testing.expectEqual(false, decoded.frame.Stream.fin);
}

test "CONNECTION_CLOSE frame round-trip" {
    const allocator = std.testing.allocator;
    const reason = "idle timeout";
    const original = Frame{ .ConnectionClose = ConnectionCloseFrame{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = reason,
    } };

    var buf: [64]u8 = undefined;
    const written = try original.encode(&buf);
    const decoded = try Frame.decode(buf[0..written], allocator);
    try std.testing.expectEqualSlices(u8, reason, decoded.frame.ConnectionClose.reason_phrase);
}
