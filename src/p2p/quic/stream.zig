// ============================================================================
// Zephyria — QUIC Stream Multiplexer (RFC 9000 §2, §4)
// ============================================================================
//
// A QuicStream represents a single ordered, reliable byte stream within a
// QUIC connection. QUIC streams are multiplexed: multiple streams can be
// in-flight simultaneously over the same UDP connection.
//
// Zephyria stream ID conventions (from frames.zig StreamIds):
//   Stream 0:  Committee Handshake / Auth     (bidi)
//   Stream 4:  Gossip (ping, peer discovery)  (bidi)
//   Stream 8:  Block propagation              (bidi)
//   Stream 12: Gulf Stream TX forwarding      (uni, send-only)
//
// Stream types (RFC 9000 §2.1):
//   Client-initiated bidi:  stream_id & 0x3 == 0
//   Server-initiated bidi:  stream_id & 0x3 == 1
//   Client-initiated uni:   stream_id & 0x3 == 2
//   Server-initiated uni:   stream_id & 0x3 == 3

const std = @import("std");
const frames = @import("frames.zig");

// ── Stream State ──────────────────────────────────────────────────────────

pub const StreamState = enum {
    /// Ready to use.
    Open,
    /// We sent FIN, awaiting peer ACK.
    HalfClosedLocal,
    /// Peer sent FIN, we can still send.
    HalfClosedRemote,
    /// Both sides have sent FIN; stream is done.
    Closed,
    /// Peer sent RESET_STREAM.
    ResetByPeer,
    /// We sent RESET_STREAM.
    ResetByUs,
};

// ── Reassembly Buffer ─────────────────────────────────────────────────────

/// A segment of received data at a specific stream offset.
const RecvSegment = struct {
    offset: u64,
    data: []u8, // owned slice
};

// ── QuicStream ────────────────────────────────────────────────────────────

pub const QuicStream = struct {
    allocator: std.mem.Allocator,

    /// Stream identifier (RFC 9000 §2.1)
    id: u64,
    state: StreamState,

    // ── Send side ──────────────────────────────────────────────────────
    /// Offset of next byte we will send
    send_offset: u64,
    /// Buffer of data waiting to be transmitted (owned)
    send_buf: std.ArrayListUnmanaged(u8),
    /// Peer's receive window limit
    send_max: u64,
    /// Whether we've queued a FIN
    send_fin: bool,

    // ── Receive side ───────────────────────────────────────────────────
    /// Offset up to which we have contiguous data (delivered to app)
    recv_offset: u64,
    /// Out-of-order segments waiting to be reassembled
    recv_segments: std.ArrayListUnmanaged(RecvSegment),
    /// Our receive window limit advertised to peer
    recv_max: u64,
    /// Whether peer sent FIN (and at what final offset)
    recv_fin: bool,
    recv_fin_offset: u64,

    // ── Accept tracking ─────────────────────────────────────────────
    /// Whether this stream has been accepted via acceptStream()
    accepted: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, id: u64, initial_max_stream_data: u64) Self {
        return Self{
            .allocator = allocator,
            .id = id,
            .state = .Open,
            .send_offset = 0,
            .send_buf = .{},
            .send_max = initial_max_stream_data,
            .send_fin = false,
            .recv_offset = 0,
            .recv_segments = .{},
            .recv_max = initial_max_stream_data,
            .recv_fin = false,
            .recv_fin_offset = 0,
            .accepted = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.send_buf.deinit(self.allocator);
        for (self.recv_segments.items) |seg| {
            self.allocator.free(seg.data);
        }
        self.recv_segments.deinit(self.allocator);
    }

    // ── Send Path ───────────────────────────────────────────────────────

    /// Enqueue `data` for sending. Respects flow control (`send_max`).
    /// Returns number of bytes accepted (may be less than data.len if window full).
    pub fn write(self: *Self, data: []const u8) !usize {
        if (self.state != .Open and self.state != .HalfClosedRemote)
            return error.StreamClosed;

        const available = if (self.send_max > self.send_offset + self.send_buf.items.len)
            self.send_max - self.send_offset - self.send_buf.items.len
        else
            0;

        const take = @min(data.len, available);
        if (take == 0) return 0;

        try self.send_buf.appendSlice(self.allocator, data[0..take]);
        return take;
    }

    /// Signal end-of-stream (FIN).
    pub fn finish(self: *Self) void {
        self.send_fin = true;
    }

    /// Build STREAM frames to fill up to `max_bytes` of output capacity.
    /// Writes encoded frames into `out_buf`. Returns bytes written.
    /// Call repeatedly until returns 0 (nothing more to send).
    pub fn buildStreamFrames(self: *Self, out_buf: []u8, max_payload: usize) !usize {
        if (self.send_buf.items.len == 0 and !self.send_fin) return 0;

        const payload_len = @min(self.send_buf.items.len, max_payload);
        const is_fin = self.send_fin and payload_len == self.send_buf.items.len;

        if (payload_len == 0 and !is_fin) return 0;

        const frame = frames.Frame{ .Stream = frames.StreamFrame{
            .stream_id = self.id,
            .offset = self.send_offset,
            .data = self.send_buf.items[0..payload_len],
            .fin = is_fin,
        } };

        const written = try frame.encode(out_buf);

        // Advance send state
        self.send_offset += payload_len;
        // Remove sent bytes from buffer (shift left — simple but fine for now)
        const remaining = self.send_buf.items.len - payload_len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.send_buf.items[0..remaining], self.send_buf.items[payload_len..]);
        }
        self.send_buf.shrinkRetainingCapacity(remaining);

        if (is_fin) {
            self.state = if (self.state == .HalfClosedRemote) .Closed else .HalfClosedLocal;
        }

        return written;
    }

    // ── Receive Path ────────────────────────────────────────────────────

    /// Process an incoming STREAM frame. Handles out-of-order delivery
    /// by buffering segments and delivering contiguous data in order.
    pub fn receiveStreamFrame(self: *Self, frm: frames.StreamFrame) !void {
        if (frm.stream_id != self.id) return error.WrongStream;
        if (frm.fin) {
            self.recv_fin = true;
            self.recv_fin_offset = frm.offset + frm.data.len;
        }

        if (frm.data.len == 0) {
            // Pure FIN frame
            if (frm.fin) self.tryCloseOnFin();
            return;
        }

        // Reject data beyond flow control window
        if (frm.offset + frm.data.len > self.recv_max) {
            return error.FlowControlViolation;
        }

        // Drop data we already have
        if (frm.offset + frm.data.len <= self.recv_offset) return;

        // Insert into sorted reassembly queue
        const owned_data = try self.allocator.dupe(u8, frm.data);
        const seg = RecvSegment{ .offset = frm.offset, .data = owned_data };

        // Find insertion point (sorted by offset)
        var insert_pos: usize = self.recv_segments.items.len;
        for (self.recv_segments.items, 0..) |s, i| {
            if (s.offset > frm.offset) {
                insert_pos = i;
                break;
            }
        }
        try self.recv_segments.insert(self.allocator, insert_pos, seg);

        if (frm.fin) self.tryCloseOnFin();
    }

    /// Read contiguous received bytes into `buf`. Returns bytes read.
    /// Advances recv_offset. Call repeatedly until returns 0.
    pub fn read(self: *Self, buf: []u8) usize {
        var written: usize = 0;

        while (self.recv_segments.items.len > 0 and written < buf.len) {
            const seg = &self.recv_segments.items[0];

            // Does this segment start where we expect?
            if (seg.offset > self.recv_offset) break;

            // How many bytes of this segment are new?
            const skip = if (seg.offset < self.recv_offset)
                self.recv_offset - seg.offset
            else
                0;

            if (skip >= seg.data.len) {
                // Fully overlapping — discard
                self.allocator.free(seg.data);
                _ = self.recv_segments.orderedRemove(0);
                continue;
            }

            const available = seg.data[skip..];
            const take = @min(available.len, buf.len - written);
            @memcpy(buf[written .. written + take], available[0..take]);
            written += take;
            self.recv_offset += take;

            if (take == available.len) {
                // Consumed entire segment
                self.allocator.free(seg.data);
                _ = self.recv_segments.orderedRemove(0);
            } else {
                // Partial read — update offset but leave segment
                break;
            }
        }

        return written;
    }

    /// Check if all data up to FIN has been received and consumed.
    pub fn isRecvComplete(self: *const Self) bool {
        return self.recv_fin and self.recv_offset >= self.recv_fin_offset;
    }

    /// Update our local credit limit and return a MAX_STREAM_DATA frame if needed.
    pub fn updateRecvWindow(self: *Self, new_max: u64) ?frames.Frame {
        if (new_max <= self.recv_max) return null;
        self.recv_max = new_max;
        return frames.Frame{ .MaxStreamData = frames.MaxStreamDataFrame{
            .stream_id = self.id,
            .maximum_stream_data = new_max,
        } };
    }

    /// Update send window from peer's MAX_STREAM_DATA.
    pub fn updateSendWindow(self: *Self, max: u64) void {
        if (max > self.send_max) self.send_max = max;
    }

    fn tryCloseOnFin(self: *Self) void {
        if (!self.recv_fin) return;
        if (self.recv_offset >= self.recv_fin_offset) {
            self.state = switch (self.state) {
                .Open => .HalfClosedRemote,
                .HalfClosedLocal => .Closed,
                else => self.state,
            };
        }
    }
};

// ── Stream ID Utilities ───────────────────────────────────────────────────

pub const StreamDir = enum { ClientBidi, ServerBidi, ClientUni, ServerUni };

pub fn streamDir(id: u64) StreamDir {
    return switch (id & 0x3) {
        0 => .ClientBidi,
        1 => .ServerBidi,
        2 => .ClientUni,
        3 => .ServerUni,
        else => unreachable,
    };
}

pub fn isLocallyInitiated(id: u64, is_server: bool) bool {
    const initiator_bit: u64 = if (is_server) 1 else 0;
    return (id & 1) == initiator_bit;
}

// ── Unit Tests ────────────────────────────────────────────────────────────

test "Stream basic send/receive" {
    const allocator = std.testing.allocator;

    // Sender side
    var sender = QuicStream.init(allocator, 0, 65535);
    defer sender.deinit();

    const msg = "hello from zephyria";
    _ = try sender.write(msg);

    var frame_buf: [256]u8 = undefined;
    const fw = try sender.buildStreamFrames(&frame_buf, 256);
    try std.testing.expect(fw > 0);
    try std.testing.expectEqual(@as(u64, msg.len), sender.send_offset);

    // Decode the frame
    const decoded = try frames.Frame.decode(frame_buf[0..fw], allocator);
    try std.testing.expectEqual(@as(u64, 0), decoded.frame.Stream.stream_id);
    try std.testing.expectEqualSlices(u8, msg, decoded.frame.Stream.data);

    // Receiver side
    var receiver = QuicStream.init(allocator, 0, 65535);
    defer receiver.deinit();

    try receiver.receiveStreamFrame(decoded.frame.Stream);

    var recv_buf: [256]u8 = undefined;
    const bytes_read = receiver.read(&recv_buf);
    try std.testing.expectEqualSlices(u8, msg, recv_buf[0..bytes_read]);
}

test "Stream out-of-order reassembly" {
    const allocator = std.testing.allocator;
    var stream = QuicStream.init(allocator, 4, 65535);
    defer stream.deinit();

    // Deliver segment 2 before segment 1 (out of order)
    try stream.receiveStreamFrame(frames.StreamFrame{
        .stream_id = 4,
        .offset = 5,
        .data = " world",
        .fin = false,
    });

    // Nothing readable yet (missing bytes 0-4)
    var buf: [32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), stream.read(&buf));

    // Now deliver segment 1
    try stream.receiveStreamFrame(frames.StreamFrame{
        .stream_id = 4,
        .offset = 0,
        .data = "hello",
        .fin = true,
    });

    // Now both should be readable in order
    const n = stream.read(&buf);
    try std.testing.expectEqualSlices(u8, "hello world", buf[0..n]);
    try std.testing.expect(stream.isRecvComplete());
}

test "Stream flow control: write blocked" {
    const allocator = std.testing.allocator;
    var stream = QuicStream.init(allocator, 0, 10); // tiny 10-byte window
    defer stream.deinit();

    const accepted = try stream.write("hello world!!"); // 13 bytes
    try std.testing.expectEqual(@as(usize, 10), accepted); // only 10 accepted
}

test "Stream direction classification" {
    try std.testing.expectEqual(StreamDir.ClientBidi, streamDir(0));
    try std.testing.expectEqual(StreamDir.ServerBidi, streamDir(1));
    try std.testing.expectEqual(StreamDir.ClientUni, streamDir(2));
    try std.testing.expectEqual(StreamDir.ServerUni, streamDir(3));
}
