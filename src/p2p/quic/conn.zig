// ============================================================================
// Zephyria — QUIC Connection State Machine (RFC 9000 §10)
// ============================================================================
//
// A QuicConn represents a single QUIC connection, modelling:
//   • 7-state lifecycle: Idle → Initial → Handshake → Established →
//                        Draining → PeerClose → Closed
//   • Three packet-number spaces (Initial, Handshake, 1-RTT), each with
//     independent encryption keys and ACK tracking
//   • Stream table: up to MAX_STREAMS concurrent streams
//   • Connection-level flow control (MAX_DATA)
//   • ACK range tracking (up to 64 received packet number ranges)
//   • Stake weight from discovery (for server-side rate limiting)
//   • Inbound CRYPTO frame reassembly (TLS handshake data)
//
// Thread safety: Each QuicConn is owned by exactly one QuicEndpoint service
// thread (fd_quic "tile" model). No internal locking.

const std = @import("std");
const tls = @import("tls.zig");
const stream_mod = @import("stream.zig");
const frames = @import("frames.zig");
const pkt = @import("transport/packet.zig");

pub const QuicStream = stream_mod.QuicStream;
pub const StreamIds = frames.StreamIds;

// ── Constants ─────────────────────────────────────────────────────────────

/// Max concurrent streams per connection
pub const MAX_STREAMS: usize = 128;
/// Max tracked ACK ranges per packet number space
pub const MAX_ACK_RANGES: usize = 64;
/// QUIC connection idle timeout (30s)
pub const IDLE_TIMEOUT_MS: u64 = 30_000;
/// Max QUIC packet payload (1200 bytes — conservative for any MTU)
pub const MAX_PACKET_PAYLOAD: usize = 1200;
/// ALPN for Zephyria protocol (used in TLS ClientHello)
pub const ZEPHYRIA_ALPN = "zephyria-p2p";

// ── Connection State ───────────────────────────────────────────────────────

pub const ConnState = enum {
    /// Not yet used (pre-init placeholder)
    Idle,
    /// Sending/receiving Initial packets (TLS ClientHello/ServerHello)
    Initial,
    /// Sending/receiving Handshake packets (Certificate, Finished)
    Handshake,
    /// 1-RTT established — normal operation
    Established,
    /// We sent CONNECTION_CLOSE, draining remaining in-flight packets
    Draining,
    /// Peer sent CONNECTION_CLOSE, sending our own then closing
    PeerClose,
    /// Fully closed — connection object can be reclaimed
    Closed,
};

// ── Encryption Level ──────────────────────────────────────────────────────

pub const EncryptionLevel = enum(u8) {
    Initial = 0,
    Handshake = 1,
    AppData = 2, // 1-RTT
};

// ── Packet Number Space ───────────────────────────────────────────────────

/// Per-encryption-level packet number tracking and key material.
pub const PktNumSpace = struct {
    /// Next packet number to send
    next_pn: u64 = 0,
    /// Largest received packet number (for ACK and PN decoding)
    largest_recv_pn: u64 = 0,
    /// Bitmask of recently received PNs (1 = received, covers last 64 packets)
    recv_bitmap: u64 = 0,
    /// Active crypto keys for this space
    keys: ?tls.KeyIv = null,
    /// Header protection key
    hp_key: ?[16]u8 = null,
    /// Whether this space's keys are available
    keys_available: bool = false,

    /// Record a received packet number for ACK tracking.
    pub fn markReceived(self: *PktNumSpace, pn: u64) void {
        if (pn > self.largest_recv_pn) {
            // Shift bitmap for new range
            const shift = pn - self.largest_recv_pn;
            if (shift >= 64) {
                self.recv_bitmap = 1;
            } else {
                self.recv_bitmap = (self.recv_bitmap << @intCast(shift)) | 1;
            }
            self.largest_recv_pn = pn;
        } else {
            const delta = self.largest_recv_pn - pn;
            if (delta < 64) {
                self.recv_bitmap |= @as(u64, 1) << @intCast(delta);
            }
        }
    }

    /// Build ACK ranges from the bitmap for an ACK frame.
    /// Returns an ACK frame ready to encode.
    pub fn buildAck(self: *const PktNumSpace, ack_delay: u64) frames.AckFrame {
        // Simple: report the range from largest_recv_pn - leading ones
        const first_range = countLeadingOnes(self.recv_bitmap) - 1;
        return frames.AckFrame{
            .largest_acknowledged = self.largest_recv_pn,
            .ack_delay = ack_delay,
            .first_ack_range = first_range,
            .ack_ranges = &[_]frames.AckRange{},
        };
    }

    fn countLeadingOnes(v: u64) u64 {
        var count: u64 = 0;
        var bits = v;
        while (bits & 1 == 1) : (bits >>= 1) count += 1;
        return count;
    }

    /// Build ACK ranges from the bitmap — generates sparse ranges for gaps.
    /// RFC 9000 §19.3: encodes up to MAX_ACK_RANGES non-contiguous ranges.
    pub fn buildAckMulti(self: *const PktNumSpace, ack_delay: u64, allocator: std.mem.Allocator) !frames.AckFrame {
        const max_ranges: usize = 64;
        var ranges = try allocator.alloc(frames.AckRange, max_ranges);
        var range_count: usize = 0;

        // The bitmap's LSB corresponds to largest_recv_pn.
        // Scan from LSB to MSB, counting runs of 1s and 0s.
        var bits = self.recv_bitmap;
        // Skip leading ones (contiguous from largest_recv_pn down)
        const first_range = countLeadingOnes(bits);
        bits >>= @intCast(first_range);

        var pos: u64 = first_range;
        while (bits != 0 and range_count < max_ranges) {
            // Count zeros (gap)
            const gap = @ctz(bits);
            if (gap > 0) {
                pos += gap;
                bits >>= @intCast(gap);
            }
            // Count ones (ack range)
            const ack_count = @ctz(~bits);
            if (ack_count > 0) {
                ranges[range_count] = .{
                    .gap = @intCast(gap),
                    .ack_range_count = ack_count - 1,
                };
                range_count += 1;
                pos += ack_count;
                bits >>= @intCast(ack_count);
            }
        }

        return frames.AckFrame{
            .largest_acknowledged = self.largest_recv_pn,
            .ack_delay = ack_delay,
            .first_ack_range = first_range,
            .ack_ranges = try allocator.realloc(ranges[0..range_count]),
        };
    }
};

/// Simple token-bucket pacer for per-connection send pacing.
/// Tokens accumulate at `rate` bytes/sec up to `burst` bytes.
/// Plan Q3: "simple pacer (token bucket at ~10 Gbps max rate per connection)"
pub const Pacer = struct {
    /// Fill rate in bytes per second
    rate: u64,
    /// Burst capacity in bytes
    burst: u64,
    /// Current token balance
    tokens: f64,
    /// Last refill timestamp (monotonic ms)
    last_refill_ms: i64,

    pub fn init() Pacer {
        return .{
            .rate = 10 * 1024 * 1024 * 1024 / 8, // 10 Gbps → bytes/sec
            .burst = 256 * 1024,                   // 256 KB burst
            .tokens = @floatFromInt(256 * 1024),
            .last_refill_ms = std.time.milliTimestamp(),
        };
    }

    /// Refill tokens based on elapsed wall time.
    pub fn refill(self: *Pacer) void {
        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.last_refill_ms;
        if (elapsed_ms <= 0) return;
        self.last_refill_ms = now;
        const add = @as(f64, @floatFromInt(self.rate)) * @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        self.tokens = @min(self.tokens + add, @as(f64, @floatFromInt(self.burst)));
    }

    /// Try to consume `bytes` tokens. Returns true if allowed (paced).
    pub fn tryConsume(self: *Pacer, bytes: u64) bool {
        self.refill();
        if (self.tokens >= @as(f64, @floatFromInt(bytes))) {
            self.tokens -= @as(f64, @floatFromInt(bytes));
            return true;
        }
        return false;
    }
};

// ── TLS Handshake State ───────────────────────────────────────────────────

pub const TlsState = enum {
    /// No handshake initiated
    None,
    /// Sent/waiting for ClientHello/ServerHello
    AwaitingServerHello,
    /// Sent/waiting for Certificate, CertificateVerify
    AwaitingCertificate,
    /// Waiting for Finished message
    AwaitingFinished,
    /// Handshake complete, 1-RTT keys derived
    Complete,
    /// Handshake failed
    Failed,
};

// ── Retransmit Queue Entry ────────────────────────────────────────────────

pub const RetransmitEntry = struct {
    pn: u64,
    level: EncryptionLevel,
    data: []u8,           // owned slice of encoded frames
    sent_at_ms: u64,
    acked: bool,
};

// ── QuicConn ──────────────────────────────────────────────────────────────

pub const QuicConn = struct {
    allocator: std.mem.Allocator,

    // ── Identity ──────────────────────────────────────────────────────
    /// Our connection ID (what we tell the peer to use as DCID)
    src_conn_id: pkt.ConnectionId,
    /// Peer's connection ID (what we use as DCID when sending)
    dst_conn_id: pkt.ConnectionId,
    /// Peer's network address
    peer_addr: std.net.Address,
    /// Are we the client or server side?
    is_server: bool,

    // ── State ─────────────────────────────────────────────────────────
    state: ConnState,
    tls_state: TlsState,
    /// Timestamp when this connection was last active (ms)
    last_active_ms: u64,

    // ── Packet Number Spaces ──────────────────────────────────────────
    pn_spaces: [3]PktNumSpace, // indexed by EncryptionLevel

    // ── TLS / Crypto ──────────────────────────────────────────────────
    /// Our TLS identity config
    tls_config: ?*const tls.TlsConfig,
    /// Initial secrets derived from dst_conn_id
    initial_secrets: tls.InitialSecrets,
    /// Transcript hash accumulates all handshake messages
    transcript: tls.TranscriptHash,
    /// Inbound CRYPTO stream reassembly buffer (offset → data)
    crypto_recv: std.AutoHashMap(u64, []u8),
    /// Next expected CRYPTO stream offset (for ordered delivery to TLS)
    crypto_recv_offset: u64,
    /// Outbound CRYPTO data pending send
    crypto_send_buf: std.ArrayListUnmanaged(u8),

    // ── X25519 ECDH (TLS key exchange) ────────────────────────────────
    /// Our ephemeral X25519 private key (handshake)
    ecdh_private: [32]u8,
    /// Our ephemeral X25519 public key (handshake)
    ecdh_public: [32]u8,
    /// Peer's ephemeral X25519 public key (from key_share extension)
    ecdh_peer_public: ?[32]u8,

    // ── Peer Identity (TLS certificate pinning) ──────────────────────
    /// Expected peer Ed25519 public key (set by caller of connect())
    expected_peer_key: ?[32]u8,
    /// Actual peer Ed25519 public key extracted from TLS Certificate message
    peer_identity_key: ?[32]u8,

    // ── Stream Table ─────────────────────────────────────────────────
    streams: std.AutoHashMap(u64, *QuicStream),
    /// Next stream ID to allocate (client-initiated bidi start = 0)
    next_stream_id: u64,

    // ── Flow Control ──────────────────────────────────────────────────
    /// Max bytes the peer will accept on this connection
    send_max_data: u64,
    /// Max bytes we accept (advertised to peer)
    recv_max_data: u64,
    /// Bytes we have received so far (for connection-level flow control)
    recv_data_total: u64,

    // ── Retransmit Queue ──────────────────────────────────────────────
    retransmit_queue: std.ArrayListUnmanaged(RetransmitEntry),

    // ── Stake (rate limiting) ─────────────────────────────────────────
    /// Validator stake weight — higher stake = more generous rate limit
    stake_weight: u64,

    // ── Congestion Control ───────────────────────────────────────────
    /// Per-connection pacer (simple token bucket, ~10 Gbps)
    pacer: Pacer,

    // ── Pending frames to send ────────────────────────────────────────
    pending_ack: [3]bool, // per encryption level
    send_handshake_done: bool,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        is_server: bool,
        peer_addr: std.net.Address,
        tls_config: ?*const tls.TlsConfig,
        expected_peer_key: ?[32]u8,
    ) !*Self {
        const self = try allocator.create(Self);
        const rng = std.crypto.random;

        // Generate our connection ID (20 bytes, random)
        const src_cid = pkt.ConnectionId.random(rng);

        // Initial secrets are derived from src_cid (server sees this as dcid)
        const initial_secrets = tls.deriveInitialSecrets(src_cid.slice());

        // Generate ephemeral X25519 keypair for TLS handshake
        const ecdh_kp = tls.generateEcdhKeypair();

        self.* = Self{
            .allocator = allocator,
            .src_conn_id = src_cid,
            .dst_conn_id = pkt.ConnectionId.zero(),
            .peer_addr = peer_addr,
            .is_server = is_server,
            .state = .Initial,
            .tls_state = .None,
            .last_active_ms = @intCast(std.time.milliTimestamp()),
            .pn_spaces = [_]PktNumSpace{.{}} ** 3,
            .tls_config = tls_config,
            .initial_secrets = initial_secrets,
            .transcript = tls.TranscriptHash.init(),
            .crypto_recv = std.AutoHashMap(u64, []u8).init(allocator),
            .crypto_recv_offset = 0,
            .crypto_send_buf = .{},
            .streams = std.AutoHashMap(u64, *QuicStream).init(allocator),
            .next_stream_id = if (is_server) 1 else 0, // server uses odd IDs
            .send_max_data = 1024 * 1024, // 1 MB initial
            .recv_max_data = 1024 * 1024,
            .recv_data_total = 0,
            .retransmit_queue = .{},
            .stake_weight = 0,
            .pending_ack = [_]bool{false} ** 3,
            .send_handshake_done = false,
            .ecdh_private = ecdh_kp.private,
            .ecdh_public = ecdh_kp.public,
            .ecdh_peer_public = null,
            .expected_peer_key = expected_peer_key,
            .peer_identity_key = null,
            .pacer = Pacer.init(),
        };

        // Install Initial keys
        if (is_server) {
            self.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].keys = initial_secrets.server_initial;
            self.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].hp_key = initial_secrets.server_hp;
        } else {
            self.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].keys = initial_secrets.client_initial;
            self.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].hp_key = initial_secrets.client_hp;
        }
        self.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].keys_available = true;

        return self;
    }

    pub fn deinit(self: *Self) void {
        var stream_iter = self.streams.valueIterator();
        while (stream_iter.next()) |s| {
            s.*.deinit();
            self.allocator.destroy(s.*);
        }
        self.streams.deinit();

        var crypto_iter = self.crypto_recv.valueIterator();
        while (crypto_iter.next()) |data| {
            self.allocator.free(data.*);
        }
        self.crypto_recv.deinit();
        self.crypto_send_buf.deinit(self.allocator);

        for (self.retransmit_queue.items) |entry| {
            if (!entry.acked) self.allocator.free(entry.data);
        }
        self.retransmit_queue.deinit(self.allocator);

        self.allocator.destroy(self);
    }

    // ── Stream Management ────────────────────────────────────────────────

    /// Open a new locally-initiated stream and return it.
    pub fn openStream(self: *Self) !*QuicStream {
        if (self.streams.count() >= MAX_STREAMS) return error.TooManyStreams;
        if (self.state != .Established) return error.ConnectionNotReady;

        const id = self.next_stream_id;
        // Advance by 4 (same direction, same initiator)
        self.next_stream_id += 4;

        const s = try self.allocator.create(QuicStream);
        s.* = QuicStream.init(self.allocator, id, self.send_max_data);
        try self.streams.put(id, s);
        return s;
    }

    /// Get or open the well-known Zephyria protocol stream.
    pub fn getOrOpenStream(self: *Self, stream_id: u64) !*QuicStream {
        if (self.streams.get(stream_id)) |s| return s;
        if (self.streams.count() >= MAX_STREAMS) return error.TooManyStreams;
        const s = try self.allocator.create(QuicStream);
        s.* = QuicStream.init(self.allocator, stream_id, self.send_max_data);
        try self.streams.put(stream_id, s);
        return s;
    }

    /// Accept an inbound stream from the peer.
    /// Returns the next stream created by the peer that we haven't accepted yet.
    /// Used by the server-side accept loop (plan §Layer 6 line 184).
    pub fn acceptStream(self: *Self) ?*QuicStream {
        // Walk known streams and find one created by the peer (server-initiated = odd IDs)
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            // Peer-created streams: server-initiated have odd IDs, client-initiated have even IDs
            const is_peer_initiated = if (self.is_server)
                (s.id % 2 == 0)
            else
                (s.id % 2 == 1);
            if (is_peer_initiated and !s.accepted) {
                s.accepted = true;
                return s;
            }
        }
        return null;
    }

    /// Process an inbound STREAM frame. Creates stream if needed.
    pub fn handleStreamFrame(self: *Self, frm: frames.StreamFrame) !void {
        self.recv_data_total += frm.data.len;
        if (self.recv_data_total > self.recv_max_data) return error.FlowControlViolation;
        self.last_active_ms = @intCast(std.time.milliTimestamp());

        const s = if (self.streams.get(frm.stream_id)) |existing| existing else blk: {
            const new_s = try self.allocator.create(QuicStream);
            new_s.* = QuicStream.init(self.allocator, frm.stream_id, self.recv_max_data);
            try self.streams.put(frm.stream_id, new_s);
            break :blk new_s;
        };
        try s.receiveStreamFrame(frm);
    }

    /// Process an inbound CRYPTO frame (TLS handshake data).
    /// Buffers out-of-order delivery and returns contiguous TLS bytes.
    pub fn handleCryptoFrame(self: *Self, frm: frames.CryptoFrame, buf: []u8) ![]u8 {
        self.last_active_ms = @intCast(std.time.milliTimestamp());

        // Store the segment
        const owned = try self.allocator.dupe(u8, frm.data);
        try self.crypto_recv.put(frm.offset, owned);

        // Check if this fills the gap at recv_offset
        var total: usize = 0;
        var off = self.crypto_recv_offset;
        while (self.crypto_recv.get(off)) |seg| {
            if (total + seg.len > buf.len) break;
            @memcpy(buf[total .. total + seg.len], seg);
            total += seg.len;
            off += seg.len;
        }

        if (total > 0) {
            // Free consumed segments
            var consumed_off = self.crypto_recv_offset;
            while (consumed_off < off) {
                if (self.crypto_recv.fetchRemove(consumed_off)) |entry| {
                    const seg_len = entry.value.len;
                    self.allocator.free(entry.value);
                    consumed_off += seg_len;
                } else break;
            }
            self.crypto_recv_offset = off;
        }

        return buf[0..total];
    }

    /// Process an inbound ACK frame — mark acked packets, free retransmit entries.
    pub fn handleAckFrame(self: *Self, frm: frames.AckFrame) void {
        self.last_active_ms = @intCast(std.time.milliTimestamp());
        const largest = frm.largest_acknowledged;
        const first_range_end = largest -| frm.first_ack_range;

        for (self.retransmit_queue.items) |*entry| {
            if (entry.pn >= first_range_end and entry.pn <= largest) {
                entry.acked = true;
                self.allocator.free(entry.data);
                entry.data = &[_]u8{};
            }
        }
        // Remove acked entries
        var i: usize = 0;
        while (i < self.retransmit_queue.items.len) {
            if (self.retransmit_queue.items[i].acked) {
                _ = self.retransmit_queue.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Handle MAX_DATA frame (peer extends our connection send window).
    pub fn handleMaxData(self: *Self, frm: frames.MaxDataFrame) void {
        if (frm.maximum_data > self.send_max_data) {
            self.send_max_data = frm.maximum_data;
        }
    }

    /// Handle MAX_STREAM_DATA (peer extends our stream send window).
    pub fn handleMaxStreamData(self: *Self, frm: frames.MaxStreamDataFrame) void {
        if (self.streams.get(frm.stream_id)) |s| {
            s.updateSendWindow(frm.maximum_stream_data);
        }
    }

    // ── State Transitions ────────────────────────────────────────────────

    /// Transition to Established after TLS Finished verified.
    pub fn establishConnection(self: *Self) void {
        self.state = .Established;
        self.tls_state = .Complete;
        self.send_handshake_done = self.is_server; // server sends HANDSHAKE_DONE
    }

    /// Initiate connection close (send CONNECTION_CLOSE).
    pub fn close(self: *Self, error_code: u64, reason: []const u8) void {
        _ = error_code;
        _ = reason;
        self.state = .Draining;
    }

    /// Mark connection as closed by peer.
    pub fn closedByPeer(self: *Self) void {
        self.state = .PeerClose;
    }

    /// Check if this connection has timed out.
    pub fn isTimedOut(self: *const Self) bool {
        const now: u64 = @intCast(std.time.milliTimestamp());
        return now - self.last_active_ms > IDLE_TIMEOUT_MS;
    }

    // ── Key Installation ─────────────────────────────────────────────────

    /// Install Handshake-level keys (after ServerHello is processed).
    pub fn installHandshakeKeys(self: *Self, client_kiv: tls.KeyIv, server_kiv: tls.KeyIv,
                                 client_hp: [16]u8, server_hp: [16]u8) void {
        const level = @intFromEnum(EncryptionLevel.Handshake);
        if (self.is_server) {
            self.pn_spaces[level].keys = server_kiv;
            self.pn_spaces[level].hp_key = server_hp;
        } else {
            self.pn_spaces[level].keys = client_kiv;
            self.pn_spaces[level].hp_key = client_hp;
        }
        self.pn_spaces[level].keys_available = true;
        self.state = .Handshake;
    }

    /// Install 1-RTT application keys (after Finished is verified).
    pub fn install1RttKeys(self: *Self, client_kiv: tls.KeyIv, server_kiv: tls.KeyIv,
                            client_hp: [16]u8, server_hp: [16]u8) void {
        const level = @intFromEnum(EncryptionLevel.AppData);
        if (self.is_server) {
            self.pn_spaces[level].keys = server_kiv;
            self.pn_spaces[level].hp_key = server_hp;
        } else {
            self.pn_spaces[level].keys = client_kiv;
            self.pn_spaces[level].hp_key = client_hp;
        }
        self.pn_spaces[level].keys_available = true;
    }

    // ── Packet Encryption ─────────────────────────────────────────────────

    /// Encrypt a QUIC packet payload at the given encryption level.
    /// `header_prefix` is the header bytes up to (but not including) the
    /// packet number. `pn_len` is 1-4.  Encodes the PN, AEAD-encrypts
    /// `plaintext` (frames) with the full header as AAD, then applies
    /// header protection.  `out` receives the complete protected packet.
    pub fn encryptPacket(
        self: *Self,
        level: EncryptionLevel,
        pn: u64,
        header_prefix: []const u8,
        pn_len: usize,
        plaintext: []const u8,
        out: []u8,
    ) !usize {
        const space = &self.pn_spaces[@intFromEnum(level)];
        const kiv = space.keys orelse return error.KeysNotAvailable;
        const hp_key = space.hp_key orelse return error.KeysNotAvailable;

        const nonce = tls.buildNonce(kiv.iv, pn);

        // Copy header prefix into output
        @memcpy(out[0..header_prefix.len], header_prefix);
        const pn_offset = header_prefix.len;

        // Encode packet number (big-endian, truncated)
        var pn_full: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_full, @intCast(pn), .big);
        @memcpy(out[pn_offset .. pn_offset + pn_len], pn_full[4 - pn_len ..]);

        // Complete header = prefix + PN (used as AAD)
        const header_len = header_prefix.len + pn_len;

        // AEAD encrypt: full header is AAD, plaintext is frames
        try tls.aesGcmEncrypt(kiv.key, nonce, out[0..header_len], plaintext, out[header_len..]);
        const ct_end = header_len + plaintext.len + tls.TAG_LEN;

        // Header protection
        if (ct_end >= pn_offset + 4 + 16) {
            const sample_offset = pn_offset + 4;
            var sample: [16]u8 = undefined;
            @memcpy(&sample, out[sample_offset .. sample_offset + 16]);
            const mask = tls.aesHeaderProtectionMask(hp_key, sample);
            const is_long = level != .AppData;
            pkt.applyHeaderProtection(out[0..ct_end], pn_offset, pn_len, mask, is_long);
        }

        return ct_end;
    }

    // ── Pending CRYPTO Data ───────────────────────────────────────────────

    /// Queue TLS handshake data to send in the next CRYPTO frame.
    pub fn sendCrypto(self: *Self, data: []const u8) !void {
        try self.crypto_send_buf.appendSlice(self.allocator, data);
    }

    /// Drain CRYPTO send buffer into a CRYPTO frame encoded into `out`.
    /// Returns bytes written or 0 if nothing to send.
    pub fn drainCryptoFrame(self: *Self, level: EncryptionLevel, out: []u8) !usize {
        _ = level;
        if (self.crypto_send_buf.items.len == 0) return 0;
        const space = &self.pn_spaces[@intFromEnum(EncryptionLevel.Initial)];
        const offset: u64 = space.next_pn; // use PN as proxy for offset (simplified)
        const take = @min(self.crypto_send_buf.items.len, 1000);
        const frm = frames.Frame{ .Crypto = frames.CryptoFrame{
            .offset = offset,
            .data = self.crypto_send_buf.items[0..take],
        } };
        const written = try frm.encode(out);
        const remaining = self.crypto_send_buf.items.len - take;
        std.mem.copyForwards(u8, self.crypto_send_buf.items[0..remaining], self.crypto_send_buf.items[take..]);
        self.crypto_send_buf.shrinkRetainingCapacity(remaining);
        return written;
    }

    /// Store peer's ECDH public key from key_share extension.
    pub fn setRemoteEcdh(self: *Self, peer_public: [32]u8) void {
        self.ecdh_peer_public = peer_public;
    }
};

// ── Unit Tests ────────────────────────────────────────────────────────────

test "QuicConn init and CID generation" {
    const allocator = std.testing.allocator;
    const addr = std.net.Address.initIp4([_]u8{127, 0, 0, 1}, 9000);

    const conn = try QuicConn.init(allocator, false, addr, null, null);
    defer conn.deinit();

    try std.testing.expectEqual(ConnState.Initial, conn.state);
    try std.testing.expectEqual(@as(u8, 20), conn.src_conn_id.len);
    try std.testing.expect(conn.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].keys_available);
}

test "QuicConn packet number space ACK tracking" {
    var space = PktNumSpace{};
    space.markReceived(0);
    space.markReceived(1);
    space.markReceived(2);
    try std.testing.expectEqual(@as(u64, 2), space.largest_recv_pn);

    const ack = space.buildAck(0);
    try std.testing.expectEqual(@as(u64, 2), ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), ack.first_ack_range); // 3 contiguous
}

test "QuicConn idle timeout detection" {
    const allocator = std.testing.allocator;
    const addr = std.net.Address.initIp4([_]u8{127, 0, 0, 1}, 9000);
    const conn = try QuicConn.init(allocator, false, addr, null, null);
    defer conn.deinit();

    // Fresh connection should not be timed out
    try std.testing.expect(!conn.isTimedOut());
}

test "QuicConn state machine transitions" {
    const allocator = std.testing.allocator;
    const addr = std.net.Address.initIp4([_]u8{127, 0, 0, 1}, 9000);
    const conn = try QuicConn.init(allocator, true, addr, null, null);
    defer conn.deinit();

    try std.testing.expectEqual(ConnState.Initial, conn.state);
    conn.establishConnection();
    try std.testing.expectEqual(ConnState.Established, conn.state);
    try std.testing.expectEqual(TlsState.Complete, conn.tls_state);
    conn.close(0, "test shutdown");
    try std.testing.expectEqual(ConnState.Draining, conn.state);
}

test "QuicConn stream open on established connection" {
    const allocator = std.testing.allocator;
    const addr = std.net.Address.initIp4([_]u8{127, 0, 0, 1}, 9000);
    const conn = try QuicConn.init(allocator, false, addr, null, null);
    defer conn.deinit();

    // Not established yet — should fail
    try std.testing.expectError(error.ConnectionNotReady, conn.openStream());

    // Establish it
    conn.establishConnection();

    // Now open streams
    const s1 = try conn.openStream();
    try std.testing.expectEqual(@as(u64, 0), s1.id);
    const s2 = try conn.openStream();
    try std.testing.expectEqual(@as(u64, 4), s2.id);
}
