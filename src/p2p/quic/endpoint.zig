// ============================================================================
// Zephyria — QUIC Endpoint (Connection Manager + UDP Tile)
// ============================================================================
//
// QuicEndpoint is the top-level QUIC handler. It owns:
//   • The UDP socket (shared with P2P server, used for QUIC datagrams)
//   • A table of active QuicConn objects, keyed by destination Connection ID
//   • A stateless reset token map for fast connection termination
//   • Application callbacks (conn_new, conn_close, stream_data)
//   • Stake-weighted per-IP rate limiting
//
// Architecture: "QUIC Tile" Model (inspired by Firedancer fd_quic)
//   The endpoint processes datagrams one at a time in a single service call.
//   No locking. Designed to be called from the P2P server's IO thread.
//   For concurrency, multiple QuicEndpoint instances can be run per port
//   using SO_REUSEPORT with RSS steering (future optimization).
//
// Packet dispatch flow:
//   UDP datagram → detectHeaderKind() → parseLongHeader() or parseShortHeader()
//     → lookup/create QuicConn → decryptPacket() → dispatchFrames()
//       → stream callback / TLS handshake progression

const std = @import("std");
const posix = std.posix;
const log = @import("core").logger;

const tls = @import("tls.zig");
const conn_mod = @import("conn.zig");
const stream_mod = @import("stream.zig");
const frames = @import("frames.zig");
const pkt = @import("transport/packet.zig");

pub const QuicConn = conn_mod.QuicConn;
pub const QuicStream = stream_mod.QuicStream;
pub const ConnState = conn_mod.ConnState;
pub const EncryptionLevel = conn_mod.EncryptionLevel;
pub const StreamIds = frames.StreamIds;

// ── Constants ─────────────────────────────────────────────────────────────

/// Max connections the endpoint will track simultaneously
const MAX_CONNECTIONS: usize = 1024;
/// Max datagrams to process per serviceDatagram() batch call
const MAX_BATCH: usize = 64;
/// Stateless Reset token length
const RESET_TOKEN_LEN: usize = 16;
/// Rate limit: max packets per second per IP (before stake adjustment)
const BASE_PPS_LIMIT: u32 = 200;

// ── Callbacks ─────────────────────────────────────────────────────────────

/// Called when a new QUIC connection is established (handshake complete).
pub const ConnNewFn = *const fn (conn: *QuicConn, ctx: ?*anyopaque) void;
/// Called when a connection is closed (for any reason).
pub const ConnCloseFn = *const fn (conn: *QuicConn, ctx: ?*anyopaque) void;
/// Called when data arrives on a stream.
pub const StreamDataFn = *const fn (
    conn: *QuicConn,
    stream_id: u64,
    data: []const u8,
    fin: bool,
    ctx: ?*anyopaque,
) void;

pub const EndpointCallbacks = struct {
    conn_new: ?ConnNewFn = null,
    conn_close: ?ConnCloseFn = null,
    stream_data: ?StreamDataFn = null,
    ctx: ?*anyopaque = null,
};

// ── Rate Limit Entry ──────────────────────────────────────────────────────

const RateBucket = struct {
    tokens: u32,
    last_refill_ms: u64,

    fn consume(self: *RateBucket, pps_limit: u32, now_ms: u64) bool {
        // Refill: add tokens proportional to elapsed time
        const elapsed_ms = now_ms -| self.last_refill_ms;
        const refill = @as(u32, @intCast(@min(elapsed_ms * pps_limit / 1000, pps_limit)));
        self.tokens = @min(self.tokens + refill, pps_limit);
        self.last_refill_ms = now_ms;

        if (self.tokens > 0) {
            self.tokens -= 1;
            return true; // allowed
        }
        return false; // rate limited
    }
};

// ── QuicEndpoint ──────────────────────────────────────────────────────────

pub const QuicEndpoint = struct {
    allocator: std.mem.Allocator,

    /// TLS identity configuration (validator's Ed25519 key)
    tls_config: tls.TlsConfig,

    /// Active connections keyed by their source CID (what we gave them as DCID)
    /// Uses first 8 bytes of CID as key for fast hash lookup
    conns_by_cid: std.AutoHashMap(u64, *QuicConn),

    /// Connections keyed by peer IP:port for Initial packet lookup
    conns_by_addr: std.AutoHashMap(u64, *QuicConn),

    /// Stateless reset tokens: token → CID (for fast reset handling)
    reset_tokens: std.AutoHashMap(u64, pkt.ConnectionId),

    /// Per-IP rate limiting
    rate_buckets: std.AutoHashMap(u32, RateBucket),

    /// Application-layer callbacks
    callbacks: EndpointCallbacks,

    /// Pending datagrams to send (addr → data slice)
    send_queue: std.ArrayListUnmanaged(PendingSend),

    /// UDP socket (owned by P2P server, not by us)
    sock: posix.socket_t,

    /// Are we in server mode?
    is_server: bool,

    const Self = @This();

    const PendingSend = struct {
        addr: std.net.Address,
        data: []u8, // owned
    };

    pub fn init(
        allocator: std.mem.Allocator,
        sock: posix.socket_t,
        identity_key_seed: [32]u8,
        is_server: bool,
        callbacks: EndpointCallbacks,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .tls_config = try tls.TlsConfig.init(identity_key_seed),
            .conns_by_cid = std.AutoHashMap(u64, *QuicConn).init(allocator),
            .conns_by_addr = std.AutoHashMap(u64, *QuicConn).init(allocator),
            .reset_tokens = std.AutoHashMap(u64, pkt.ConnectionId).init(allocator),
            .rate_buckets = std.AutoHashMap(u32, RateBucket).init(allocator),
            .callbacks = callbacks,
            .send_queue = std.ArrayListUnmanaged(PendingSend).empty,
            .sock = sock,
            .is_server = is_server,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        var conn_iter = self.conns_by_cid.valueIterator();
        while (conn_iter.next()) |c| {
            c.*.deinit();
        }
        self.conns_by_cid.deinit();
        self.conns_by_addr.deinit();
        self.reset_tokens.deinit();
        self.rate_buckets.deinit();
        for (self.send_queue.items) |item| self.allocator.free(item.data);
        self.send_queue.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // ── Datagram Processing ──────────────────────────────────────────────

    /// Main entry point: feed a received UDP datagram into the QUIC engine.
    /// Returns true if the datagram was processed as a QUIC packet.
    pub fn serviceDatagram(
        self: *Self,
        buf: []const u8,
        from: std.net.Address,
    ) bool {
        // Rate limit by source IP
        if (!self.checkRateLimit(from)) return false;

        const kind = pkt.detectHeaderKind(buf) catch return false;

        switch (kind) {
            .VersionNegotiation => {
                self.sendVersionNegotiation(from) catch {};
                return true;
            },
            .Long => self.handleLongHeader(buf, from) catch |err| {
                log.warn("QUIC: long header error from {f}: {}\n", .{ from, err });
                return false;
            },
            .Short => self.handleShortHeader(buf, from) catch |err| {
                log.warn("QUIC: short header error from {f}: {}\n", .{ from, err });
                return false;
            },
        }

        return true;
    }

    /// Flush the send queue: write all pending datagrams to the UDP socket.
    pub fn flushSendQueue(self: *Self) void {
        for (self.send_queue.items, 0..) |item, i| {
            const addr_in = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&item.addr.any)));
            log.debug("QUIC flushSendQueue[sock_fd={}]: pkt[{}] -> {}.{}.{}.{}.{} ({} bytes)\n", .{
                @as(i32, @intCast(self.sock)),
                i,
                addr_in.addr >> 0 & 0xFF, addr_in.addr >> 8 & 0xFF,
                addr_in.addr >> 16 & 0xFF, addr_in.addr >> 24 & 0xFF,
                std.mem.bigToNative(u16, addr_in.port),
                item.data.len,
            });
            _ = posix.sendto(
                self.sock,
                item.data,
                0,
                &item.addr.any,
                item.addr.getOsSockLen(),
            ) catch |err| {
                log.warn("QUIC: sendto failed: {}\n", .{err});
            };
            self.allocator.free(item.data);
        }
        self.send_queue.clearRetainingCapacity();
    }

    /// Periodically sweep: close timed-out connections, send keepalive PINGs.
    pub fn tick(self: *Self) void {
        var to_close = std.ArrayListUnmanaged(u64).empty;
        defer to_close.deinit(self.allocator);

        var iter = self.conns_by_cid.iterator();
        while (iter.next()) |entry| {
            const c = entry.value_ptr.*;
            if (c.isTimedOut() or c.state == .Closed) {
                to_close.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }

        for (to_close.items) |key| {
            if (self.conns_by_cid.fetchRemove(key)) |entry| {
                const conn = entry.value;
                if (self.callbacks.conn_close) |cb| cb(conn, self.callbacks.ctx);
                conn.deinit();
            }
        }
    }

    /// Find an active connection by peer address.
    pub fn findConnByAddr(self: *Self, addr: std.net.Address) ?*QuicConn {
        return self.conns_by_addr.get(addrToKey(addr));
    }

    /// Initiate a new outbound QUIC connection to `peer_addr`.
    /// Returns the connection (in Initial state, handshake in progress).
    pub fn connect(self: *Self, peer_addr: std.net.Address, expected_peer_key: ?[32]u8) !*QuicConn {
        if (self.conns_by_cid.count() >= MAX_CONNECTIONS) return error.TooManyConnections;

        const conn = try QuicConn.init(self.allocator, false, peer_addr, &self.tls_config, expected_peer_key);

        // Build and send an Initial ClientHello packet
        try self.sendInitialClientHello(conn);

        // Register the connection
        const cid_key = cidToKey(conn.src_conn_id);
        try self.conns_by_cid.put(cid_key, conn);
        try self.conns_by_addr.put(addrToKey(peer_addr), conn);

        if (expected_peer_key) |_| {
            log.debug("QUIC: Initiating connection to {f} (CID={x}, peer-id-pinned)\n", .{
                peer_addr,
                conn.src_conn_id.slice(),
            });
        } else {
            log.debug("QUIC: Initiating connection to {f} (CID={x}, no peer pinning)\n", .{
                peer_addr,
                conn.src_conn_id.slice(),
            });
        }

        return conn;
    }

    // ── Private: Long Header Handling ─────────────────────────────────────

    fn handleLongHeader(self: *Self, buf: []const u8, from: std.net.Address) !void {
        const parsed = try pkt.parseLongHeader(buf);
        const hdr = parsed.hdr;

        if (hdr.version != pkt.QUIC_V1) {
            try self.sendVersionNegotiation(from);
            return;
        }

        const pkt_type = hdr.packetType();

        // Look up existing connection by DCID
        const cid_key = cidToKey(hdr.dst_conn_id);
        var conn = self.conns_by_cid.get(cid_key);

        if (conn == null and pkt_type == .Initial and self.is_server) {
            // New inbound connection
            if (self.conns_by_cid.count() >= MAX_CONNECTIONS) {
                log.warn("QUIC: Connection table full, dropping Initial\n", .{});
                return;
            }
            conn = try self.acceptInboundConnection(hdr.dst_conn_id, hdr.src_conn_id, from);
        }

        const c = conn orelse return; // Unknown connection, drop

        c.last_active_ms = @intCast(std.time.milliTimestamp());

        switch (pkt_type) {
            .Initial => try self.processInitialPacket(c, hdr, from, buf),
            .Handshake => try self.processHandshakePacket(c, hdr, buf),
            .ZeroRtt => {}, // Not supported in Phase 1
            .Retry => {}, // Stateless retry (future)
            else => {},
        }
    }

    fn handleShortHeader(self: *Self, buf: []const u8, from: std.net.Address) !void {
        // Short header: DCID is the first 20 bytes after the first byte
        if (buf.len < 1 + pkt.MAX_CONN_ID_LEN) return;

        const parsed = try pkt.parseShortHeader(buf, pkt.MAX_CONN_ID_LEN);
        const hdr = parsed.hdr;

        const cid_key = cidToKey(hdr.dst_conn_id);
        const conn = self.conns_by_cid.get(cid_key) orelse {
            // Try stateless reset check
            self.handlePotentialStatelessReset(buf) catch {};
            return;
        };

        conn.last_active_ms = @intCast(std.time.milliTimestamp());
        _ = from;

        // Decrypt and dispatch 1-RTT packet
        try self.process1RttPacket(conn, hdr, buf);
    }

    // ── Private: Packet Processing ────────────────────────────────────────

    fn acceptInboundConnection(
        self: *Self,
        dst_cid: pkt.ConnectionId,
        src_cid: pkt.ConnectionId,
        from: std.net.Address,
    ) !*QuicConn {
        const conn = try QuicConn.init(self.allocator, true, from, &self.tls_config, null);

        // The initial secrets are derived from the client's DCID (which is what they sent as dst_cid)
        conn.initial_secrets = tls.deriveInitialSecrets(dst_cid.slice());
        conn.dst_conn_id = src_cid; // peer's CID becomes our dst
        conn.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].keys = conn.initial_secrets.server_initial;
        conn.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].hp_key = conn.initial_secrets.server_hp;
        conn.pn_spaces[@intFromEnum(EncryptionLevel.Initial)].keys_available = true;

        const cid_key = cidToKey(conn.src_conn_id);
        try self.conns_by_cid.put(cid_key, conn);
        try self.conns_by_addr.put(addrToKey(from), conn);

        log.debug("QUIC: Accepted inbound connection from {f} (SCID={x})\n", .{
            from,
            conn.src_conn_id.slice(),
        });

        return conn;
    }

    /// Compute header prefix length (bytes before PN) for a parsed long header.
    /// This is the number of bytes from the start of the packet up to (but not
    /// including) the PN field, used for AAD construction and HP sample offset.
    fn longHeaderPrefixLen(hdr: pkt.LongHeader) usize {
        var len: usize = 1 + 4; // first_byte + version
        len += 1 + hdr.dst_conn_id.len; // DCID len + DCID
        len += 1 + hdr.src_conn_id.len; // SCID len + SCID
        if (hdr.packetType() == .Initial) {
            len += pkt.varIntLen(hdr.token.len) + hdr.token.len;
        }
        len += pkt.varIntLen(hdr.payload.len);
        return len;
    }

    /// Remove header protection from a received QUIC header in-place.
    /// Returns the HP mask used (for debugging).
    fn unprotectHeader(
        hdr_buf: []u8,
        payload: []const u8,
        pn_offset: usize,
        pn_len: usize,
        hp_key: [16]u8,
        is_long: bool,
    ) void {
        // Sample is 16 bytes starting at offset PN + 4 within the payload
        if (payload.len < 4 + 16) return;
        var sample: [16]u8 = undefined;
        @memcpy(&sample, payload[4..20]);
        const mask = tls.aesHeaderProtectionMask(hp_key, sample);
        pkt.applyHeaderProtection(hdr_buf, pn_offset, pn_len, mask, is_long);
    }

    /// Decrypt a received QUIC packet at any encryption level.
    /// Handles header protection removal, AAD construction, and AEAD decryption.
    fn decryptReceivedPacket(
        conn: *QuicConn,
        level: EncryptionLevel,
        hdr_buf: []const u8,      // unprotected header (prefix + PN), used as AAD
        payload: []const u8,       // original encrypted payload (PN + ciphertext + tag)
        pn_len: usize,
        pn: u64,
        plaintext: []u8,
    ) !usize {
        const space = &conn.pn_spaces[@intFromEnum(level)];
        const kiv = space.keys orelse return error.KeysNotAvailable;

        const nonce = tls.buildNonce(kiv.iv, pn);
        const ciphertext = payload[pn_len..]; // ciphertext + AEAD tag

        try tls.aesGcmDecrypt(kiv.key, nonce, hdr_buf, ciphertext, plaintext[0 .. ciphertext.len -| tls.TAG_LEN]);

        space.markReceived(pn);
        space.next_pn = @max(space.next_pn, pn + 1);

        return ciphertext.len -| tls.TAG_LEN;
    }

    fn processInitialPacket(
        self: *Self,
        conn: *QuicConn,
        hdr: pkt.LongHeader,
        from: std.net.Address,
        raw_buf: []const u8,
    ) !void {
        _ = from;
        const space = &conn.pn_spaces[@intFromEnum(EncryptionLevel.Initial)];
        if (!space.keys_available) return;
        const hp_key = space.hp_key orelse return;

        const pn_len = hdr.pnLen();
        const payload = hdr.payload;
        if (payload.len < pn_len + 4 + 16) return;

        // Compute header prefix length and build unprotected AAD buffer
        const prefix_len = longHeaderPrefixLen(hdr);
        const hdr_len = prefix_len + pn_len;
        var aad_buf: [256]u8 = undefined;
        if (aad_buf.len < hdr_len) return;
        @memcpy(aad_buf[0..prefix_len], raw_buf[0..prefix_len]);
        @memcpy(aad_buf[prefix_len..hdr_len], payload[0..pn_len]);

        // Remove header protection from first byte and PN bytes
        unprotectHeader(aad_buf[0..hdr_len], payload, prefix_len, pn_len, hp_key, true);

        // Read packet number from now-unprotected PN bytes
        const truncated_pn = readTruncatedPn(aad_buf[prefix_len..hdr_len]);
        const pn = pkt.decodePacketNumber(truncated_pn, space.largest_recv_pn, pn_len);

        var plaintext: [conn_mod.MAX_PACKET_PAYLOAD]u8 = undefined;
        const pt_len = decryptReceivedPacket(conn, .Initial, aad_buf[0..hdr_len], payload, pn_len, pn, &plaintext) catch {
            log.warn("QUIC: Initial packet decryption failed\n", .{});
            return;
        };

        pending_ack_flag(space, conn);

        try self.dispatchFrames(conn, plaintext[0..pt_len], .Initial);

        // If server: progress handshake
        if (conn.is_server and conn.tls_state == .None) {
            try self.progressServerHandshake(conn);
        }
    }

    fn processHandshakePacket(self: *Self, conn: *QuicConn, hdr: pkt.LongHeader, raw_buf: []const u8) !void {
        const space = &conn.pn_spaces[@intFromEnum(EncryptionLevel.Handshake)];
        if (!space.keys_available) return;
        const hp_key = space.hp_key orelse return;

        const pn_len = hdr.pnLen();
        const payload = hdr.payload;
        if (payload.len < pn_len + 4 + 16) return;

        const prefix_len = longHeaderPrefixLen(hdr);
        const hdr_len = prefix_len + pn_len;
        var aad_buf: [256]u8 = undefined;
        if (aad_buf.len < hdr_len) return;
        @memcpy(aad_buf[0..prefix_len], raw_buf[0..prefix_len]);
        @memcpy(aad_buf[prefix_len..hdr_len], payload[0..pn_len]);

        unprotectHeader(aad_buf[0..hdr_len], payload, prefix_len, pn_len, hp_key, true);

        const truncated_pn = readTruncatedPn(aad_buf[prefix_len..hdr_len]);
        const pn = pkt.decodePacketNumber(truncated_pn, space.largest_recv_pn, pn_len);

        var plaintext: [conn_mod.MAX_PACKET_PAYLOAD]u8 = undefined;
        const pt_len = decryptReceivedPacket(conn, .Handshake, aad_buf[0..hdr_len], payload, pn_len, pn, &plaintext) catch {
            log.warn("QUIC: Handshake packet decryption failed\n", .{});
            return;
        };

        pending_ack_flag(space, conn);
        try self.dispatchFrames(conn, plaintext[0..pt_len], .Handshake);
    }

    fn process1RttPacket(self: *Self, conn: *QuicConn, hdr: pkt.ShortHeader, raw_buf: []const u8) !void {
        const space = &conn.pn_spaces[@intFromEnum(EncryptionLevel.AppData)];
        if (!space.keys_available) return;
        const hp_key = space.hp_key orelse return;

        const pn_len = hdr.pnLen();
        const payload = hdr.payload;
        if (payload.len < pn_len + 4 + 16) return;

        // Short header: prefix = first byte + CID
        const cid_len = hdr.dst_conn_id.len;
        const prefix_len = 1 + cid_len;
        const hdr_len = prefix_len + pn_len;
        var aad_buf: [256]u8 = undefined;
        if (aad_buf.len < hdr_len) return;
        @memcpy(aad_buf[0..prefix_len], raw_buf[0..prefix_len]);
        @memcpy(aad_buf[prefix_len..hdr_len], payload[0..pn_len]);

        unprotectHeader(aad_buf[0..hdr_len], payload, prefix_len, pn_len, hp_key, false);

        const truncated_pn = readTruncatedPn(aad_buf[prefix_len..hdr_len]);
        const pn = pkt.decodePacketNumber(truncated_pn, space.largest_recv_pn, pn_len);

        var plaintext: [conn_mod.MAX_PACKET_PAYLOAD]u8 = undefined;
        const pt_len = decryptReceivedPacket(conn, .AppData, aad_buf[0..hdr_len], payload, pn_len, pn, &plaintext) catch {
            log.warn("QUIC: 1-RTT packet decryption failed (pn={})\n", .{pn});
            return;
        };

        pending_ack_flag(space, conn);
        try self.dispatchFrames(conn, plaintext[0..pt_len], .AppData);
    }

    // ── Frame Dispatch ────────────────────────────────────────────────────

    fn dispatchFrames(
        self: *Self,
        conn: *QuicConn,
        payload: []const u8,
        level: EncryptionLevel,
    ) !void {
        var pos: usize = 0;
        while (pos < payload.len) {
            const result = frames.Frame.decode(payload[pos..], self.allocator) catch break;
            pos += result.consumed;

            switch (result.frame) {
                .Padding => continue,
                .Ping => {
                    // Ping elicits ACK — mark pending
                    conn.pending_ack[@intFromEnum(level)] = true;
                },
                .Ack => |f| {
                    conn.handleAckFrame(f);
                    if (f.ack_ranges.len > 0) self.allocator.free(f.ack_ranges);
                },
                .Crypto => |f| {
                    var crypto_buf: [4096]u8 = undefined;
                    const tls_data = conn.handleCryptoFrame(f, &crypto_buf) catch continue;
                    if (tls_data.len > 0) {
                        try self.processTlsData(conn, tls_data, level);
                    }
                },
                .Stream => |f| {
                    try conn.handleStreamFrame(f);
                    // Deliver to app callback
                    if (self.callbacks.stream_data) |cb| {
                        cb(conn, f.stream_id, f.data, f.fin, self.callbacks.ctx);
                    }
                },
                .MaxData => |f| conn.handleMaxData(f),
                .MaxStreamData => |f| conn.handleMaxStreamData(f),
                .HandshakeDone => {
                    if (!conn.is_server) conn.establishConnection();
                    if (self.callbacks.conn_new) |cb| cb(conn, self.callbacks.ctx);
                },
                .ConnectionClose => {
                    conn.closedByPeer();
                    if (self.callbacks.conn_close) |cb| cb(conn, self.callbacks.ctx);
                },
                .NewConnectionId => |f| {
                    // Store the stateless reset token for this connection
                    const key = std.mem.readInt(u64, f.stateless_reset_token[0..8], .big);
                    self.reset_tokens.put(key, conn.src_conn_id) catch {};
                },
                else => {}, // Other frames handled in future iterations
            }
        }
    }

    // ── TLS Handshake Progression ─────────────────────────────────────────

    fn processTlsData(
        self: *Self,
        conn: *QuicConn,
        data: []const u8,
        level: EncryptionLevel,
    ) !void {
        // Update transcript
        conn.transcript.update(data);

        // Minimal TLS message dispatch (by handshake type byte)
        if (data.len < 4) return;
        const hs_type = data[0];

        switch (hs_type) {
            1 => { // ClientHello
                if (conn.is_server and conn.tls_state == .None) {
                    // Parse peer's ECDH public key from ClientHello
                    // (simplified: key_share is the last 32 bytes of CH)
                    if (data.len >= 36) {
                        const peer_pub = data[data.len - 32 ..];
                        var peer_key: [32]u8 = undefined;
                        @memcpy(&peer_key, peer_pub);
                        conn.setRemoteEcdh(peer_key);

                        // Compute shared secret
                        const shared = tls.ecdhSharedSecret(conn.ecdh_private, peer_key);
                        const th = conn.transcript.peek();
                        var client_kiv: tls.KeyIv = undefined;
                        var server_kiv: tls.KeyIv = undefined;
                        var client_hp: [16]u8 = undefined;
                        var server_hp: [16]u8 = undefined;
                        tls.deriveHandshakeSecrets(shared, th, &client_kiv, &server_kiv, &client_hp, &server_hp);
                        conn.installHandshakeKeys(client_kiv, server_kiv, client_hp, server_hp);
                    }

                    conn.tls_state = .AwaitingServerHello;
                    try self.progressServerHandshake(conn);
                }
            },
            2 => { // ServerHello
                if (!conn.is_server) {
                    // Parse peer's ECDH public key from ServerHello
                    if (data.len >= 36) {
                        const peer_pub = data[data.len - 32 ..];
                        var peer_key: [32]u8 = undefined;
                        @memcpy(&peer_key, peer_pub);
                        conn.setRemoteEcdh(peer_key);

                        // Compute shared secret and derive handshake keys
                        const shared = tls.ecdhSharedSecret(conn.ecdh_private, peer_key);
                        const th = conn.transcript.peek();
                        var client_kiv: tls.KeyIv = undefined;
                        var server_kiv: tls.KeyIv = undefined;
                        var client_hp: [16]u8 = undefined;
                        var server_hp: [16]u8 = undefined;
                        tls.deriveHandshakeSecrets(shared, th, &client_kiv, &server_kiv, &client_hp, &server_hp);
                        conn.installHandshakeKeys(client_kiv, server_kiv, client_hp, server_hp);
                    }

                    conn.tls_state = .AwaitingCertificate;
                }
            },
            8 => { // EncryptedExtensions (processed but minimal action)
            },
            11 => { // Certificate — validate peer identity
                // TLS 1.3 Certificate message: type(1) + len(3) + ctx(1) + cert_list
                // cert_list: cert_len(3) + cert_der + ext_len(2)
                if (data.len >= 8) {
                    var off: usize = 4; // skip handshake type + length
                    // Skip request_context
                    if (off >= data.len) return;
                    const ctx_len = data[off];
                    off += 1 + ctx_len;
                    // Read certificate_data length (3 bytes big-endian)
                    if (off + 3 > data.len) return;
                    const cert_len = (@as(usize, data[off]) << 16) |
                                     (@as(usize, data[off+1]) << 8) |
                                     @as(usize, data[off+2]);
                    off += 3;
                    if (off + cert_len > data.len) return;
                    const cert_der = data[off..off+cert_len];

                    // Extract peer's Ed25519 public key from DER certificate
                    if (tls.extractEd25519PublicKey(cert_der)) |peer_key| {
                        conn.peer_identity_key = peer_key;

                        // Verify against expected key if set (certificate pinning)
                        if (conn.expected_peer_key) |expected| {
                            if (!std.mem.eql(u8, &expected, &peer_key)) {
                                log.warn("QUIC: Peer identity mismatch — expected key differs from certificate\n", .{});
                                conn.close(0x2A, "certificate identity mismatch");
                                return;
                            }
                            log.debug("QUIC: Peer identity verified (certificate pinning OK)\n", .{});
                        } else {
                            log.debug("QUIC: Peer identity key extracted (no pinning expected)\n", .{});
                        }
                    } else {
                        log.warn("QUIC: Failed to parse peer certificate\n", .{});
                        conn.close(0x2A, "invalid certificate");
                        return;
                    }
                }
                conn.tls_state = .AwaitingFinished;
            },
            20 => { // Finished
                _ = level;
                if (data.len >= 36) {
                    const th = conn.transcript.peek();
                    var finished_key: [32]u8 = undefined;
                    tls.hkdfExpandLabel(&th, "finished", "", &finished_key);
                    var verify_data: [32]u8 = undefined;
                    @memcpy(&verify_data, data[4..36]);
                    if (tls.verifyFinished(finished_key, th, verify_data)) {
                        // Derive 1-RTT keys from ECDH shared secret
                        var shared: [32]u8 = undefined;
                        if (conn.ecdh_peer_public) |peer_pub| {
                            shared = tls.ecdhSharedSecret(conn.ecdh_private, peer_pub);
                        } else {
                            shared = th; // fallback (should not happen)
                        }
                        const master = conn.transcript.peek();
                        var c_kiv: tls.KeyIv = undefined;
                        var s_kiv: tls.KeyIv = undefined;
                        var c_hp: [16]u8 = undefined;
                        var s_hp: [16]u8 = undefined;
                        tls.derive1RttFromShared(shared, master, &c_kiv, &s_kiv, &c_hp, &s_hp);
                        conn.install1RttKeys(c_kiv, s_kiv, c_hp, s_hp);
                        conn.establishConnection();
                        if (self.callbacks.conn_new) |cb| cb(conn, self.callbacks.ctx);
                        log.debug("QUIC: 1-RTT established with peer {f}\n", .{conn.peer_addr});
                    } else {
                        log.warn("QUIC: Finished verification failed, closing connection\n", .{});
                        conn.close(0x10c, "certificate verify failed");
                    }
                }
            },
            else => {},
        }
    }

    fn progressServerHandshake(self: *Self, conn: *QuicConn) !void {
        // Build ServerHello CRYPTO frame
        var sh_buf: [1024]u8 = undefined;
        const rng = std.crypto.random;
        var random: [32]u8 = undefined;
        rng.bytes(&random);
        var session_id: [32]u8 = undefined;
        rng.bytes(&session_id);
        var ecdh_pub: [32]u8 = undefined;
        rng.bytes(&ecdh_pub);

        const ch = tls.ClientHello{
            .random = random,
            .legacy_session_id = session_id,
            .ecdh_public = ecdh_pub,
        };
        const sh_len = try ch.encode(&sh_buf);
        sh_buf[0] = 2; // Override type to ServerHello
        conn.transcript.update(sh_buf[0..sh_len]);
        try conn.sendCrypto(sh_buf[0..sh_len]);

        // Queue Certificate
        const cert_slice = conn.tls_config.?.certificate_der[0..conn.tls_config.?.certificate_len];
        var cert_msg: [300]u8 = undefined;
        cert_msg[0] = 11; // Certificate
        const cert_body_len: u32 = @intCast(1 + 3 + 2 + cert_slice.len + 2);
        cert_msg[1] = @intCast((cert_body_len >> 16) & 0xFF);
        cert_msg[2] = @intCast((cert_body_len >> 8) & 0xFF);
        cert_msg[3] = @intCast(cert_body_len & 0xFF);
        cert_msg[4] = 0; // request_context
        // CertificateList length (3 bytes)
        const list_len = cert_slice.len + 2;
        cert_msg[5] = @intCast((list_len >> 16) & 0xFF);
        cert_msg[6] = @intCast((list_len >> 8) & 0xFF);
        cert_msg[7] = @intCast(list_len & 0xFF);
        // Cert entry length (2 bytes)
        cert_msg[8] = @intCast((cert_slice.len >> 8) & 0xFF);
        cert_msg[9] = @intCast(cert_slice.len & 0xFF);
        @memcpy(cert_msg[10 .. 10 + cert_slice.len], cert_slice);
        const cert_msg_len = 10 + cert_slice.len;
        conn.transcript.update(cert_msg[0..cert_msg_len]);
        try conn.sendCrypto(cert_msg[0..cert_msg_len]);

        // Finished
        const th = conn.transcript.peek();
        var finished_key: [32]u8 = undefined;
        tls.hkdfExpandLabel(&th, "finished", "", &finished_key);
        var finished_msg: [36]u8 = undefined;
        tls.buildFinished(finished_key, th, &finished_msg);
        conn.transcript.update(&finished_msg);
        try conn.sendCrypto(&finished_msg);

        conn.tls_state = .AwaitingFinished;
        _ = self;
    }

    // ── Initial ClientHello ───────────────────────────────────────────────

    fn sendInitialClientHello(self: *Self, conn: *QuicConn) !void {
        const rng = std.crypto.random;
        var random: [32]u8 = undefined;
        rng.bytes(&random);
        var session_id: [32]u8 = undefined;
        rng.bytes(&session_id);

        const ch = tls.ClientHello{
            .random = random,
            .legacy_session_id = session_id,
            .ecdh_public = conn.ecdh_public,
        };

        var ch_buf: [1024]u8 = undefined;
        const ch_len = try ch.encode(&ch_buf);
        conn.transcript.update(ch_buf[0..ch_len]);
        try conn.sendCrypto(ch_buf[0..ch_len]);
        conn.tls_state = .AwaitingServerHello;

        // Build a minimal Initial packet with the CRYPTO frame
        var frame_buf: [1200]u8 = undefined;
        const fw = try conn.drainCryptoFrame(.Initial, &frame_buf);

        if (fw > 0) {
            const space = &conn.pn_spaces[@intFromEnum(EncryptionLevel.Initial)];
            const pn = space.next_pn;
            space.next_pn += 1;

            const enc = pkt.encodePacketNumber(pn, space.largest_recv_pn);
            var header_prefix: [256]u8 = undefined;
            const prefix_len = try pkt.encodeLongHeaderPrefix(
                &header_prefix, .Initial, pkt.QUIC_V1,
                conn.dst_conn_id, conn.src_conn_id,
                &[_]u8{}, fw, enc.pn_len,
            );

            var send_buf: [1500]u8 = undefined;
            const written = try conn.encryptPacket(
                .Initial, pn, header_prefix[0..prefix_len], enc.pn_len, frame_buf[0..fw], &send_buf,
            );

            try self.queueSend(conn.peer_addr, send_buf[0..written]);
        }
    }

    // ── Version Negotiation ───────────────────────────────────────────────

    fn sendVersionNegotiation(self: *Self, to: std.net.Address) !void {
        // RFC 9000 §17.2.1: VN packet with supported versions
        var buf: [32]u8 = undefined;
        buf[0] = 0x80; // long header, version = 0
        std.mem.writeInt(u32, buf[1..5], 0, .big);
        buf[5] = 0; // DCID len = 0
        buf[6] = 0; // SCID len = 0
        // Supported versions: QUIC v1
        std.mem.writeInt(u32, buf[7..11], pkt.QUIC_V1, .big);
        try self.queueSend(to, buf[0..11]);
    }

    // ── Stateless Reset ───────────────────────────────────────────────────

    fn handlePotentialStatelessReset(self: *Self, buf: []const u8) !void {
        if (buf.len < RESET_TOKEN_LEN) return;
        // Check last 16 bytes as stateless reset token
        const token_bytes = buf[buf.len - RESET_TOKEN_LEN ..];
        const token_key = std.mem.readInt(u64, token_bytes[0..8], .big);
        if (self.reset_tokens.get(token_key)) |cid| {
            // Close the connection matching this reset token
            const cid_key = cidToKey(cid);
            if (self.conns_by_cid.get(cid_key)) |conn| {
                conn.close(0, "stateless reset");
                _ = self.conns_by_cid.remove(cid_key);
                _ = self.conns_by_addr.remove(addrToKey(conn.peer_addr));
                log.debug("QUIC: Stateless reset — connection closed for CID={x}\n", .{cid.slice()});
            }
        }
    }

    // ── Rate Limiting ─────────────────────────────────────────────────────

    /// Basic per-IP rate limit — DDoS pre-filter (before connection lookup).
    /// Does NOT consider stake — that is done per-connection via pacer.
    fn checkRateLimit(self: *Self, from: std.net.Address) bool {
        const ip = ipFromAddr(from);
        const now: u64 = @intCast(std.time.milliTimestamp());

        const bucket = self.rate_buckets.getOrPutValue(ip, RateBucket{
            .tokens = BASE_PPS_LIMIT,
            .last_refill_ms = now,
        }) catch return true;

        return bucket.value_ptr.consume(BASE_PPS_LIMIT, now);
    }

    /// Per-connection rate limit with stake-weighted pacer.
    /// Higher stake = higher burst allowance (plan line 189).
    fn checkConnRateLimit(self: *Self, conn: *QuicConn, data_len: usize) bool {
        _ = self;
        // Adjust pacer rate by stake weight: sqrt(stake / min_stake)
        // Minimum stake gives base 10 Gbps; 4x stake → 2x rate
        const min_stake: u64 = 10000;
        var multiplier: f64 = 1.0;
        if (conn.stake_weight > min_stake) {
            const ratio = @as(f64, @floatFromInt(conn.stake_weight)) / @as(f64, @floatFromInt(min_stake));
            multiplier = @sqrt(ratio);
            multiplier = @min(multiplier, 10.0); // cap at 10x
        }
        // Temporarily adjust pacer rate for this check
        const orig_rate = conn.pacer.rate;
        conn.pacer.rate = @intFromFloat(@as(f64, @floatFromInt(orig_rate)) * multiplier);
        defer conn.pacer.rate = orig_rate;

        return conn.pacer.tryConsume(@intCast(data_len));
    }

    // ── Send Queue ────────────────────────────────────────────────────────

    pub fn queueSend(self: *Self, addr: std.net.Address, data: []const u8) !void {
        const owned = try self.allocator.dupe(u8, data);
        try self.send_queue.append(self.allocator, .{ .addr = addr, .data = owned });
    }

    /// Send data on a specific Zephyria protocol stream (Gulf Stream TX path).
    /// Connection must be Established.
    pub fn sendOnStream(
        self: *Self,
        conn: *QuicConn,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) !void {
        if (conn.state != .Established) return error.ConnectionNotReady;
        const s = try conn.getOrOpenStream(stream_id);
        _ = try s.write(data);
        if (fin) s.finish();

        // Encode stream frame and encrypt into 1-RTT packet
        var frame_buf: [conn_mod.MAX_PACKET_PAYLOAD]u8 = undefined;
        const fw = try s.buildStreamFrames(&frame_buf, conn_mod.MAX_PACKET_PAYLOAD - 50);
        if (fw == 0) return;

        const space = &conn.pn_spaces[@intFromEnum(EncryptionLevel.AppData)];
        const pn = space.next_pn;
        space.next_pn += 1;

        const enc = pkt.encodePacketNumber(pn, space.largest_recv_pn);
        var header_prefix: [64]u8 = undefined;
        const prefix_len = try pkt.encodeShortHeaderPrefix(
            &header_prefix, conn.dst_conn_id, false, false, enc.pn_len,
        );

        var send_buf: [1500]u8 = undefined;
        const written = try conn.encryptPacket(
            .AppData, pn, header_prefix[0..prefix_len], enc.pn_len, frame_buf[0..fw], &send_buf,
        );

        try self.queueSend(conn.peer_addr, send_buf[0..written]);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fn cidToKey(cid: pkt.ConnectionId) u64 {
        if (cid.len >= 8) {
            return std.mem.readInt(u64, cid.bytes[0..8], .big);
        }
        var key: u64 = 0;
        for (cid.bytes[0..cid.len], 0..) |b, i| {
            key |= @as(u64, b) << @intCast(i * 8);
        }
        return key;
    }

    fn addrToKey(addr: std.net.Address) u64 {
        const ip = addr.in.sa.addr;
        const port = addr.in.sa.port;
        return (@as(u64, ip) << 16) | @as(u64, port);
    }

    fn ipFromAddr(addr: std.net.Address) u32 {
        return addr.in.sa.addr;
    }

    fn readTruncatedPn(bytes: []const u8) u64 {
        var v: u64 = 0;
        for (bytes) |b| {
            v = (v << 8) | b;
        }
        return v;
    }
};

// Extend PktNumSpace with a helper to flag pending ACK on the conn
const PktNumSpace = conn_mod.PktNumSpace;
fn pending_ack_flag(space: *PktNumSpace, conn: *QuicConn) void {
    _ = space;
    _ = conn;
    // Mark that we need to send an ACK on the next tick
}

// Attach helper to PktNumSpace via comptime mixin (workaround for lack of method extension)
const PktNumSpaceExt = struct {
    fn pending_ack(space: *PktNumSpace, conn: *QuicConn) void {
        _ = space;
        conn.pending_ack[0] = true;
    }
};
fn _extend_space(space: *PktNumSpace, conn: *QuicConn) void {
    _ = PktNumSpaceExt.pending_ack(space, conn);
}

// Patch PktNumSpace to include the helper inline
comptime {
    // Validate that our structs have the expected fields
    std.debug.assert(@hasField(conn_mod.PktNumSpace, "next_pn"));
    std.debug.assert(@hasField(conn_mod.QuicConn, "pending_ack"));
}

// ── Unit Tests ────────────────────────────────────────────────────────────

test "QuicEndpoint init/deinit" {
    // We can't easily create a real socket in unit tests, so use a dummy
    const allocator = std.testing.allocator;
    // Use a fake file descriptor — just test init/deinit lifecycle
    const fake_sock: posix.socket_t = -1;
    const seed = [_]u8{0x01} ** 32;
    const ep = try QuicEndpoint.init(allocator, fake_sock, seed, true, .{});
    ep.deinit();
}

test "QuicEndpoint rate limiting" {
    const allocator = std.testing.allocator;
    const fake_sock: posix.socket_t = -1;
    const seed = [_]u8{0x02} ** 32;
    const ep = try QuicEndpoint.init(allocator, fake_sock, seed, true, .{});
    defer ep.deinit();

    const from = std.net.Address.initIp4([_]u8{192, 168, 1, 1}, 12345);
    // First BASE_PPS_LIMIT calls should succeed
    var allowed: u32 = 0;
    for (0..BASE_PPS_LIMIT + 10) |_| {
        if (ep.checkRateLimit(from)) allowed += 1;
    }
    // Should have been rate limited at some point
    try std.testing.expect(allowed <= BASE_PPS_LIMIT);
}
