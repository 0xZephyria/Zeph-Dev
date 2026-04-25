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
    ipLen: u8,
    port: u16,
    validatorAddress: core.types.Address,
    blsPubKey: [48]u8,

    // Authentication State
    authenticated: bool,
    handshakeComplete: bool,
    challenge: [32]u8,
    peerRole: types.PeerRole,

    // Connection
    quicConn: ?zquic.transport.connection.Connection,
    quicStream: ?zquic.transport.stream.QuicStream,
    connected: bool,

    // Outbox
    outbox: std.ArrayListUnmanaged([]const u8),
    mutex: std.Thread.Mutex,

    // Chain State
    headHash: core.types.Hash,
    headNumber: u64,
    protocolVersion: u32,

    // Scoring & Reputation
    score: i32,
    scoreLastDecay: i64,

    // Stake
    stakeAmount: u64,

    // Subnet Membership
    subscribedSubnets: [8]u8, // 64-bit bitmap for gossip subnets
    isCommitteeMember: bool,
    committeeAssignment: ?types.CommitteeAssignment,

    // Bandwidth Tracking
    bytesSent: u64,
    bytesReceived: u64,
    packetsSent: u64,
    packetsReceived: u64,
    lastMessageTime: i64,
    connectTime: i64,

    // Rate limiting per peer
    rateTokens: f64,
    rateLastUpdate: i64,

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
            .ipLen = @intCast(copy_len),
            .port = port,
            .validatorAddress = core.types.Address.zero(),
            .blsPubKey = [_]u8{0} ** 48,
            .authenticated = false,
            .handshakeComplete = false,
            .challenge = [_]u8{0} ** 32,
            .peerRole = .FullNode,
            .quicConn = null,
            .quicStream = null,
            .connected = true,
            .outbox = .{},
            .mutex = .{},
            .headHash = core.types.Hash.zero(),
            .headNumber = 0,
            .protocolVersion = 0,
            .score = 0,
            .scoreLastDecay = now,
            .stakeAmount = 0,
            .subscribedSubnets = [_]u8{0} ** 8,
            .isCommitteeMember = false,
            .committeeAssignment = null,
            .bytesSent = 0,
            .bytesReceived = 0,
            .packetsSent = 0,
            .packetsReceived = 0,
            .lastMessageTime = now,
            .connectTime = now,
            .rateTokens = 20.0, // types.RateLimitConfig default baseCapacity
            .rateLastUpdate = now,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.quicStream) |*stream| {
            stream.close();
        }
        if (self.quicConn) |*conn| {
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
        return self.ip[0..self.ipLen];
    }

    // ── QUIC Connection Management ──────────────────────────────────────

    pub fn attachQuic(self: *Self, conn: zquic.transport.connection.Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.quicConn = conn;
    }

    pub fn openStream(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.quicStream = try zquic.transport.stream.QuicStream.init(self.allocator, id, .Bidirectional);
    }

    // ── Sending ─────────────────────────────────────────────────────────

    /// Send a message with the given code. Serializes payload via RLP.
    pub fn send(self: *Self, msgCode: u64, data: anytype) !void {
        const bytes = try rlp.encode(self.allocator, data);
        errdefer self.allocator.free(bytes);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.quicStream) |*stream| {
            var code_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &code_buf, msgCode, .big);
            _ = try stream.write(&code_buf);
            _ = try stream.write(bytes);
            self.allocator.free(bytes);

            self.bytesSent += 8 + bytes.len;
            self.packetsSent += 1;
        } else {
            self.allocator.free(bytes);
            return error.NoQuicStream;
        }
    }

    /// Send raw bytes with a message code header. Does not RLP encode.
    pub fn sendRaw(self: *Self, msgCode: u64, raw_data: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.quicStream) |*stream| {
            var code_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &code_buf, msgCode, .big);
            _ = try stream.write(&code_buf);
            _ = try stream.write(raw_data);

            self.bytesSent += 8 + raw_data.len;
            self.packetsSent += 1;
        } else {
            return error.NoQuicStream;
        }
    }

    // ── Scoring ─────────────────────────────────────────────────────────

    /// Update peer score with bounds checking and automatic decay.
    pub fn updateScore(self: *Self, delta: i32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.updateScoreLocked(delta);
    }

    pub fn updateScoreLocked(self: *Self, delta: i32) void {
        // Apply decay first
        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.scoreLastDecay;
        if (elapsed_ms >= @as(i64, @intCast(types.PEER_SCORE_DECAY_INTERVAL_MS))) {
            const decay_periods = @divTrunc(elapsed_ms, @as(i64, @intCast(types.PEER_SCORE_DECAY_INTERVAL_MS)));
            const decay = @as(i32, @intCast(@min(decay_periods, 100))) * types.PEER_SCORE_DECAY_AMOUNT;
            // Decay toward zero
            if (self.score > 0) {
                self.score = @max(0, self.score - decay);
            } else if (self.score < 0) {
                self.score = @min(0, self.score + decay);
            }
            self.scoreLastDecay = now;
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
        self.mutex.lock();
        defer self.mutex.unlock();
        self.headHash = hash;
        self.headNumber = number;
        self.lastMessageTime = std.time.milliTimestamp();
    }

    // ── Subnet Management ───────────────────────────────────────────────

    pub fn subscribeSubnet(self: *Self, subnet: types.SubnetID) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        types.setSubnetBit(&self.subscribedSubnets, subnet);
    }

    pub fn unsubscribeSubnet(self: *Self, subnet: types.SubnetID) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        types.clearSubnetBit(&self.subscribedSubnets, subnet);
    }

    pub fn isInSubnet(self: *const Self, subnet: types.SubnetID) bool {
        return types.isSubnetSubscribed(self.subscribedSubnets, subnet);
    }

    /// Get list of subscribed subnet IDs (max 64).
    pub fn getSubscribedSubnets(self: *const Self, out_buf: *[64]types.SubnetID) u32 {
        var count: u32 = 0;
        for (0..64) |i| {
            if (types.isSubnetSubscribed(self.subscribedSubnets, @intCast(i))) {
                out_buf[count] = @intCast(i);
                count += 1;
            }
        }
        return count;
    }

    // ── Committee ───────────────────────────────────────────────────────

    pub fn setCommitteeAssignment(self: *Self, assignment: types.CommitteeAssignment) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.committeeAssignment = assignment;
        self.isCommitteeMember = true;
    }

    pub fn clearCommitteeAssignment(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.committeeAssignment = null;
        self.isCommitteeMember = false;
    }

    // ── Rate Limiting ───────────────────────────────────────────────────

    /// Check and consume a rate limit token. Returns true if allowed.
    pub fn checkRateLimit(self: *Self, config: types.RateLimitConfig) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        const elapsed_sec = @as(f64, @floatFromInt(now - self.rateLastUpdate)) / 1000.0;

        // Calculate refill rate based on stake
        var refill = config.baseRefill;
        if (self.stakeAmount > 0) {
            const stake_f = @as(f64, @floatFromInt(self.stakeAmount));
            // sqrt(stake) scaling, capped
            const multiplier = @min(@sqrt(stake_f / 10000.0), config.maxStakeMultiplier);
            refill = config.baseRefill * @max(1.0, multiplier);
        }

        // Committee burst bonus
        var capacity = config.baseCapacity;
        if (self.isCommitteeMember) {
            capacity *= config.committeeBurstMultiplier;
            refill *= config.committeeBurstMultiplier;
        }

        // Refill tokens
        self.rateTokens = @min(self.rateTokens + elapsed_sec * refill, capacity);
        self.rateLastUpdate = now;

        if (self.rateTokens >= 1.0) {
            self.rateTokens -= 1.0;
            return true;
        }
        return false;
    }

    // ── Staleness ───────────────────────────────────────────────────────

    pub fn isStale(self: *const Self) bool {
        const now = std.time.milliTimestamp();
        const elapsed_s = @divTrunc(now - self.lastMessageTime, 1000);
        return elapsed_s > types.STALE_PEER_TIMEOUT_S;
    }

    // ── Bandwidth Stats ─────────────────────────────────────────────────

    pub fn recordReceived(self: *Self, bytes: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.bytesReceived += bytes;
        self.packetsReceived += 1;
        self.lastMessageTime = std.time.milliTimestamp();
    }

    pub const PeerStats = struct {
        score: i32,
        bytesSent: u64,
        bytesReceived: u64,
        packetsSent: u64,
        packetsReceived: u64,
        uptimeMs: i64,
        role: types.PeerRole,
        authenticated: bool,
        isCommittee: bool,
        stake: u64,
    };

    pub fn getStats(self: *const Self) PeerStats {
        const now = std.time.milliTimestamp();
        return .{
            .score = self.score,
            .bytesSent = self.bytesSent,
            .bytesReceived = self.bytesReceived,
            .packetsSent = self.packetsSent,
            .packetsReceived = self.packetsReceived,
            .uptimeMs = now - self.connectTime,
            .role = self.peerRole,
            .authenticated = self.authenticated,
            .isCommittee = self.isCommitteeMember,
            .stake = self.stakeAmount,
        };
    }
};
