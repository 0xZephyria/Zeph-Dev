// ============================================================================
// Zephyria — P2P Peer Management (Production)
// ============================================================================
//
// Committee-aware peer with:
//   • Stake-weighted reputation scoring with decay
//   • Subnet membership tracking (gossip + aggregation)
//   • Connection budget enforcement (max 512 per node)
//   • Bandwidth metering per peer
//   • Automatic disconnect on low score
//   • Committee role awareness for priority handling

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const p2p = @import("mod.zig");
const zquic = p2p.quic;
const rlp = @import("encoding").rlp;
const log = core.logger;

// ── Peer ────────────────────────────────────────────────────────────────

pub const Peer = struct {
    allocator: std.mem.Allocator,

    // Identity
    id: [64]u8,
    ip: [46]u8,
    ip_len: u8,
    port: u16,
    validator_address: core.types.Address,
    bls_pubkey: [48]u8,

    // Authentication State
    authenticated: bool,
    handshake_complete: bool,
    challenge: [32]u8,
    peer_role: types.PeerRole,

    // Connection
    quic_conn: ?zquic.transport.connection.Connection,
    quic_stream: ?zquic.transport.stream.QuicStream,
    connected: bool,

    // Outbox
    outbox: std.ArrayListUnmanaged([]const u8),
    lock: std.Thread.Mutex,

    // Chain State
    head_hash: core.types.Hash,
    head_number: u64,
    protocol_version: u32,

    // Scoring & Reputation
    score: i32,
    score_last_decay: i64,

    // Stake
    stake_amount: u64,

    // Subnet Membership
    subscribed_subnets: [8]u8, // 64-bit bitmap for gossip subnets
    is_committee_member: bool,
    committee_assignment: ?types.CommitteeAssignment,

    // Bandwidth Tracking
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    last_message_time: i64,
    connect_time: i64,

    // Rate limiting per peer
    rate_tokens: f64,
    rate_last_update: i64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, ip: []const u8, port: u16) !*Self {
        const self = try allocator.create(Self);

        var ip_buf: [46]u8 = [_]u8{0} ** 46;
        const copy_len = @min(ip.len, 46);
        @memcpy(ip_buf[0..copy_len], ip[0..copy_len]);

        const now = std.time.milliTimestamp();

        self.* = Self{
            .allocator = allocator,
            .id = [_]u8{0} ** 64,
            .ip = ip_buf,
            .ip_len = @intCast(copy_len),
            .port = port,
            .validator_address = core.types.Address.zero(),
            .bls_pubkey = [_]u8{0} ** 48,
            .authenticated = false,
            .handshake_complete = false,
            .challenge = [_]u8{0} ** 32,
            .peer_role = .FullNode,
            .quic_conn = null,
            .quic_stream = null,
            .connected = true,
            .outbox = .{},
            .lock = .{},
            .head_hash = core.types.Hash.zero(),
            .head_number = 0,
            .protocol_version = 0,
            .score = 0,
            .score_last_decay = now,
            .stake_amount = 0,
            .subscribed_subnets = [_]u8{0} ** 8,
            .is_committee_member = false,
            .committee_assignment = null,
            .bytes_sent = 0,
            .bytes_received = 0,
            .packets_sent = 0,
            .packets_received = 0,
            .last_message_time = now,
            .connect_time = now,
            .rate_tokens = 20.0, // types.RateLimitConfig default base_capacity
            .rate_last_update = now,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.quic_stream) |*stream| {
            stream.close();
        }
        if (self.quic_conn) |*conn| {
            conn.close();
        }
        for (self.outbox.items) |msg| {
            self.allocator.free(msg);
        }
        self.outbox.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // ── IP Access ───────────────────────────────────────────────────────

    pub fn ipSlice(self: *const Self) []const u8 {
        return self.ip[0..self.ip_len];
    }

    // ── QUIC Connection Management ──────────────────────────────────────

    pub fn attachQuic(self: *Self, conn: zquic.transport.connection.Connection) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.quic_conn = conn;
    }

    pub fn openStream(self: *Self, id: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();
        self.quic_stream = try zquic.transport.stream.QuicStream.init(self.allocator, id, .Bidirectional);
    }

    // ── Sending ─────────────────────────────────────────────────────────

    /// Send a message with the given code. Serializes payload via RLP.
    pub fn send(self: *Self, msg_code: u64, data: anytype) !void {
        const bytes = try rlp.encode(self.allocator, data);
        errdefer self.allocator.free(bytes);

        self.lock.lock();
        defer self.lock.unlock();

        if (self.quic_stream) |*stream| {
            var code_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &code_buf, msg_code, .big);
            _ = try stream.write(&code_buf);
            _ = try stream.write(bytes);
            self.allocator.free(bytes);

            self.bytes_sent += 8 + bytes.len;
            self.packets_sent += 1;
        } else {
            self.allocator.free(bytes);
            return error.NoQuicStream;
        }
    }

    /// Send raw bytes with a message code header. Does not RLP encode.
    pub fn sendRaw(self: *Self, msg_code: u64, raw_data: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.quic_stream) |*stream| {
            var code_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &code_buf, msg_code, .big);
            _ = try stream.write(&code_buf);
            _ = try stream.write(raw_data);

            self.bytes_sent += 8 + raw_data.len;
            self.packets_sent += 1;
        } else {
            return error.NoQuicStream;
        }
    }

    // ── Scoring ─────────────────────────────────────────────────────────

    /// Update peer score with bounds checking and automatic decay.
    pub fn updateScore(self: *Self, delta: i32) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.updateScoreLocked(delta);
    }

    pub fn updateScoreLocked(self: *Self, delta: i32) void {
        // Apply decay first
        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.score_last_decay;
        if (elapsed_ms >= @as(i64, @intCast(types.PEER_SCORE_DECAY_INTERVAL_MS))) {
            const decay_periods = @divTrunc(elapsed_ms, @as(i64, @intCast(types.PEER_SCORE_DECAY_INTERVAL_MS)));
            const decay = @as(i32, @intCast(@min(decay_periods, 100))) * types.PEER_SCORE_DECAY_AMOUNT;
            // Decay toward zero
            if (self.score > 0) {
                self.score = @max(0, self.score - decay);
            } else if (self.score < 0) {
                self.score = @min(0, self.score + decay);
            }
            self.score_last_decay = now;
        }

        // Apply delta with clamping
        const new_score = @as(i64, self.score) + @as(i64, delta);
        self.score = @intCast(std.math.clamp(new_score, types.PEER_SCORE_DISCONNECT_THRESHOLD - 50, types.PEER_SCORE_MAX));
    }

    /// Check if this peer should be disconnected due to low score.
    pub fn shouldDisconnect(self: *const Self) bool {
        return self.score <= types.PEER_SCORE_DISCONNECT_THRESHOLD;
    }

    // ── Chain State ─────────────────────────────────────────────────────

    pub fn updateHead(self: *Self, hash: core.types.Hash, number: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.head_hash = hash;
        self.head_number = number;
        self.last_message_time = std.time.milliTimestamp();
    }

    // ── Subnet Management ───────────────────────────────────────────────

    pub fn subscribeSubnet(self: *Self, subnet: types.SubnetID) void {
        self.lock.lock();
        defer self.lock.unlock();
        types.setSubnetBit(&self.subscribed_subnets, subnet);
    }

    pub fn unsubscribeSubnet(self: *Self, subnet: types.SubnetID) void {
        self.lock.lock();
        defer self.lock.unlock();
        types.clearSubnetBit(&self.subscribed_subnets, subnet);
    }

    pub fn isInSubnet(self: *const Self, subnet: types.SubnetID) bool {
        return types.isSubnetSubscribed(self.subscribed_subnets, subnet);
    }

    /// Get list of subscribed subnet IDs (max 64).
    pub fn getSubscribedSubnets(self: *const Self, out_buf: *[64]types.SubnetID) u32 {
        var count: u32 = 0;
        for (0..64) |i| {
            if (types.isSubnetSubscribed(self.subscribed_subnets, @intCast(i))) {
                out_buf[count] = @intCast(i);
                count += 1;
            }
        }
        return count;
    }

    // ── Committee ───────────────────────────────────────────────────────

    pub fn setCommitteeAssignment(self: *Self, assignment: types.CommitteeAssignment) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.committee_assignment = assignment;
        self.is_committee_member = true;
    }

    pub fn clearCommitteeAssignment(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.committee_assignment = null;
        self.is_committee_member = false;
    }

    // ── Rate Limiting ───────────────────────────────────────────────────

    /// Check and consume a rate limit token. Returns true if allowed.
    pub fn checkRateLimit(self: *Self, config: types.RateLimitConfig) bool {
        self.lock.lock();
        defer self.lock.unlock();

        const now = std.time.milliTimestamp();
        const elapsed_sec = @as(f64, @floatFromInt(now - self.rate_last_update)) / 1000.0;

        // Calculate refill rate based on stake
        var refill = config.base_refill;
        if (self.stake_amount > 0) {
            const stake_f = @as(f64, @floatFromInt(self.stake_amount));
            // sqrt(stake) scaling, capped
            const multiplier = @min(@sqrt(stake_f / 10000.0), config.max_stake_multiplier);
            refill = config.base_refill * @max(1.0, multiplier);
        }

        // Committee burst bonus
        var capacity = config.base_capacity;
        if (self.is_committee_member) {
            capacity *= config.committee_burst_multiplier;
            refill *= config.committee_burst_multiplier;
        }

        // Refill tokens
        self.rate_tokens = @min(self.rate_tokens + elapsed_sec * refill, capacity);
        self.rate_last_update = now;

        if (self.rate_tokens >= 1.0) {
            self.rate_tokens -= 1.0;
            return true;
        }
        return false;
    }

    // ── Staleness ───────────────────────────────────────────────────────

    pub fn isStale(self: *const Self) bool {
        const now = std.time.milliTimestamp();
        const elapsed_s = @divTrunc(now - self.last_message_time, 1000);
        return elapsed_s > types.STALE_PEER_TIMEOUT_S;
    }

    // ── Bandwidth Stats ─────────────────────────────────────────────────

    pub fn recordReceived(self: *Self, bytes: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.bytes_received += bytes;
        self.packets_received += 1;
        self.last_message_time = std.time.milliTimestamp();
    }

    pub const PeerStats = struct {
        score: i32,
        bytes_sent: u64,
        bytes_received: u64,
        packets_sent: u64,
        packets_received: u64,
        uptime_ms: i64,
        role: types.PeerRole,
        authenticated: bool,
        is_committee: bool,
        stake: u64,
    };

    pub fn getStats(self: *const Self) PeerStats {
        const now = std.time.milliTimestamp();
        return .{
            .score = self.score,
            .bytes_sent = self.bytes_sent,
            .bytes_received = self.bytes_received,
            .packets_sent = self.packets_sent,
            .packets_received = self.packets_received,
            .uptime_ms = now - self.connect_time,
            .role = self.peer_role,
            .authenticated = self.authenticated,
            .is_committee = self.is_committee_member,
            .stake = self.stake_amount,
        };
    }
};
