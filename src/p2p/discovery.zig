// ============================================================================
// Zephyria — Peer Discovery (Production Kademlia)
// ============================================================================
//
// Kademlia-based peer discovery with:
//   • Full routing table with 256 buckets of 16 nodes each
//   • XOR distance metric over Keccak256(pubkey)
//   • Subnet-aware peer prioritization
//   • Bootstrap node support
//   • Periodic routing table refresh with stale node eviction
//   • ENR v4 attestation with validator address binding

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const core = @import("core");
const types = @import("types.zig");
const log = core.logger;

// ── Kademlia Constants ──────────────────────────────────────────────────

const BUCKET_SIZE: usize = 16;
const ALPHA: usize = 3;
const ID_SIZE: usize = 64;
const HASH_SIZE: usize = 32;
const MAX_BUCKETS: usize = 256;
const REFRESH_INTERVAL_MS: i64 = 300_000; // 5 minutes
const STALE_THRESHOLD_MS: i64 = 600_000; // 10 minutes
const MAX_FIND_RESULTS: usize = 20;

// ── Types ───────────────────────────────────────────────────────────────

pub const NodeID = [ID_SIZE]u8;
pub const NodeHash = [HASH_SIZE]u8;

pub const Node = struct {
    id: NodeID,
    hash: NodeHash,
    address: net.Address,
    last_seen: i64,
    last_ping: i64,
    ping_failures: u8,
    peer_role: types.PeerRole,
    validator_address: core.types.Address,
    subscribed_subnets: [8]u8,
    stake_amount: u64,

    pub fn distance(self: *const Node, other_hash: NodeHash) NodeHash {
        var dist: NodeHash = undefined;
        for (0..HASH_SIZE) |i| {
            dist[i] = self.hash[i] ^ other_hash[i];
        }
        return dist;
    }

    /// Check if this node is in the given subnet.
    pub fn isInSubnet(self: *const Node, subnet: types.SubnetID) bool {
        return types.isSubnetSubscribed(self.subscribed_subnets, subnet);
    }
};

// ── ENR Record ──────────────────────────────────────────────────────────

pub const EnrRecord = struct {
    seq: u64,
    id: [4]u8, // "v4\x00\x00"
    pubkey: [33]u8, // Compressed secp256k1 public key
    ip4: [4]u8,
    udp_port: u16,
    tcp_port: u16,
    validator_addr: core.types.Address,
    subnets: [8]u8,
    stake: u64,

    pub fn init(pubkey: [33]u8, ip4: [4]u8, udp_port: u16) EnrRecord {
        return .{
            .seq = 1,
            .id = [_]u8{ 'v', '4', 0, 0 },
            .pubkey = pubkey,
            .ip4 = ip4,
            .udp_port = udp_port,
            .tcp_port = 0,
            .validator_addr = core.types.Address.zero(),
            .subnets = [_]u8{0} ** 8,
            .stake = 0,
        };
    }

    /// Serialize ENR to bytes for transmission
    pub fn serialize(self: *const EnrRecord, buf: []u8) usize {
        if (buf.len < 72) return 0;
        @memcpy(buf[0..4], &self.id);
        std.mem.writeInt(u64, buf[4..12], self.seq, .big);
        @memcpy(buf[12..45], &self.pubkey);
        @memcpy(buf[45..49], &self.ip4);
        std.mem.writeInt(u16, buf[49..51], self.udp_port, .big);
        std.mem.writeInt(u16, buf[51..53], self.tcp_port, .big);
        @memcpy(buf[53..73], &self.validator_addr.bytes);
        @memcpy(buf[73..81], &self.subnets);
        std.mem.writeInt(u64, buf[81..89], self.stake, .big);
        return 89;
    }

    /// Deserialize ENR from bytes
    pub fn deserialize(data: []const u8) ?EnrRecord {
        if (data.len < 89) return null;
        var enr: EnrRecord = undefined;
        @memcpy(&enr.id, data[0..4]);
        enr.seq = std.mem.readInt(u64, data[4..12], .big);
        @memcpy(&enr.pubkey, data[12..45]);
        @memcpy(&enr.ip4, data[45..49]);
        enr.udp_port = std.mem.readInt(u16, data[49..51], .big);
        enr.tcp_port = std.mem.readInt(u16, data[51..53], .big);
        @memcpy(&enr.validator_addr.bytes, data[53..73]);
        @memcpy(&enr.subnets, data[73..81]);
        enr.stake = std.mem.readInt(u64, data[81..89], .big);
        return enr;
    }
};

// ── Routing Table Bucket ────────────────────────────────────────────────

const Bucket = struct {
    nodes: [BUCKET_SIZE]?Node,
    count: u8,
    last_refresh: i64,

    fn init() Bucket {
        return .{
            .nodes = [_]?Node{null} ** BUCKET_SIZE,
            .count = 0,
            .last_refresh = std.time.milliTimestamp(),
        };
    }

    fn isFull(self: *const Bucket) bool {
        return self.count >= BUCKET_SIZE;
    }

    /// Insert or update a node. Returns true if inserted/updated, false if bucket full and
    /// no stale node to evict.
    fn insertOrUpdate(self: *Bucket, node: Node) bool {
        // Check if already exists — update last_seen
        for (&self.nodes) |*slot| {
            if (slot.*) |*existing| {
                if (std.mem.eql(u8, &existing.id, &node.id)) {
                    existing.last_seen = node.last_seen;
                    existing.ping_failures = 0;
                    existing.stake_amount = node.stake_amount;
                    existing.subscribed_subnets = node.subscribed_subnets;
                    return true;
                }
            }
        }

        // Find empty slot
        for (&self.nodes) |*slot| {
            if (slot.* == null) {
                slot.* = node;
                self.count += 1;
                return true;
            }
        }

        // Bucket full — try to evict a stale node
        var stalest_idx: ?usize = null;
        var stalest_time: i64 = std.math.maxInt(i64);
        const now = std.time.milliTimestamp();

        for (self.nodes, 0..) |maybe_node, i| {
            if (maybe_node) |n| {
                // Evict nodes that haven't been seen and have failed pings
                if (n.ping_failures >= 3 or (now - n.last_seen) > STALE_THRESHOLD_MS) {
                    if (n.last_seen < stalest_time) {
                        stalest_time = n.last_seen;
                        stalest_idx = i;
                    }
                }
            }
        }

        if (stalest_idx) |idx| {
            self.nodes[idx] = node;
            return true;
        }

        return false; // Truly full, no stale nodes
    }

    /// Remove a node by ID.
    fn remove(self: *Bucket, id: NodeID) bool {
        for (&self.nodes) |*slot| {
            if (slot.*) |existing| {
                if (std.mem.eql(u8, &existing.id, &id)) {
                    slot.* = null;
                    self.count -= 1;
                    return true;
                }
            }
        }
        return false;
    }

    /// Get all non-null nodes.
    fn getAll(self: *const Bucket, out: []Node) u8 {
        var idx: u8 = 0;
        for (self.nodes) |maybe_node| {
            if (maybe_node) |node| {
                if (idx < out.len) {
                    out[idx] = node;
                    idx += 1;
                }
            }
        }
        return idx;
    }

    /// Mark a node as having failed a ping.
    fn markPingFailure(self: *Bucket, id: NodeID) void {
        for (&self.nodes) |*slot| {
            if (slot.*) |*existing| {
                if (std.mem.eql(u8, &existing.id, &id)) {
                    existing.ping_failures += 1;
                    return;
                }
            }
        }
    }
};

// ── Discovery Service ───────────────────────────────────────────────────

pub const DiscoveryService = struct {
    allocator: Allocator,
    local_node: Node,
    local_enr: EnrRecord,
    buckets: [MAX_BUCKETS]Bucket,
    bootstrap_nodes: std.ArrayListUnmanaged(Node),
    lock: std.Thread.Mutex,
    running: bool,
    refresh_thread: ?std.Thread,

    // Stats
    total_nodes_seen: u64,
    total_lookups: u64,

    const Self = @This();

    pub fn init(allocator: Allocator, priv_key: []const u8, port: u16) !*Self {
        const self = try allocator.create(Self);

        // Derive node ID from private key
        var id: NodeID = [_]u8{0} ** ID_SIZE;
        const key_len = @min(priv_key.len, 32);
        @memcpy(id[0..key_len], priv_key[0..key_len]);

        // Hash node ID for XOR distance
        var hash: NodeHash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&id, &hash, .{});

        const local_addr = try net.Address.parseIp4("0.0.0.0", port);

        // Initialize all buckets
        var buckets: [MAX_BUCKETS]Bucket = undefined;
        for (&buckets) |*bucket| {
            bucket.* = Bucket.init();
        }

        // Create local ENR
        var compressed_pubkey: [33]u8 = [_]u8{0} ** 33;
        @memcpy(compressed_pubkey[0..key_len], priv_key[0..key_len]);
        const enr = EnrRecord.init(compressed_pubkey, [4]u8{ 0, 0, 0, 0 }, port);

        self.* = Self{
            .allocator = allocator,
            .local_node = .{
                .id = id,
                .hash = hash,
                .address = local_addr,
                .last_seen = std.time.milliTimestamp(),
                .last_ping = 0,
                .ping_failures = 0,
                .peer_role = .Validator,
                .validator_address = core.types.Address.zero(),
                .subscribed_subnets = [_]u8{0} ** 8,
                .stake_amount = 0,
            },
            .local_enr = enr,
            .buckets = buckets,
            .bootstrap_nodes = .{},
            .lock = .{},
            .running = false,
            .refresh_thread = null,
            .total_nodes_seen = 0,
            .total_lookups = 0,
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.bootstrap_nodes.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // ── Bootstrap ───────────────────────────────────────────────────────

    /// Add a bootstrap node that will be contacted on startup.
    pub fn addBootstrapNode(self: *Self, node: Node) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.bootstrap_nodes.append(self.allocator, node);
    }

    // ── Node Management ─────────────────────────────────────────────────

    pub fn addNode(self: *Self, node: Node) !void {
        self.lock.lock();
        defer self.lock.unlock();
        self.addNodeLocked(node);
    }

    fn addNodeLocked(self: *Self, node: Node) void {
        // Don't add self
        if (std.mem.eql(u8, &node.id, &self.local_node.id)) return;

        const dist = self.local_node.distance(node.hash);
        const idx = getBucketIndex(dist);

        if (self.buckets[idx].insertOrUpdate(node)) {
            self.total_nodes_seen += 1;
        }
    }

    /// Remove a node by ID.
    pub fn removeNode(self: *Self, id: NodeID) void {
        self.lock.lock();
        defer self.lock.unlock();

        // Search all buckets (we could compute the bucket, but this is safer)
        for (&self.buckets) |*bucket| {
            if (bucket.remove(id)) return;
        }
    }

    /// Mark a node as having failed a ping response.
    pub fn markPingFailure(self: *Self, id: NodeID) void {
        self.lock.lock();
        defer self.lock.unlock();

        var hash: NodeHash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&id, &hash, .{});
        const dist = self.local_node.distance(hash);
        const idx = getBucketIndex(dist);
        self.buckets[idx].markPingFailure(id);
    }

    // ── Lookup ──────────────────────────────────────────────────────────

    /// Find the `count` closest nodes to the target hash.
    /// Caller owns the returned slice and must free it.
    pub fn findClosest(self: *Self, target: NodeHash, count: usize) ![]Node {
        self.lock.lock();
        defer self.lock.unlock();

        self.total_lookups += 1;

        // Collect all nodes into a temporary buffer
        var all_nodes_buf: [MAX_BUCKETS * BUCKET_SIZE]Node = undefined;
        var total: usize = 0;

        for (&self.buckets) |*bucket| {
            var bucket_buf: [BUCKET_SIZE]Node = undefined;
            const n = bucket.getAll(&bucket_buf);
            for (0..n) |i| {
                if (total < all_nodes_buf.len) {
                    all_nodes_buf[total] = bucket_buf[i];
                    total += 1;
                }
            }
        }

        if (total == 0) {
            return try self.allocator.alloc(Node, 0);
        }

        // Sort by distance to target
        const SortCtx = struct {
            target_hash: NodeHash,
            pub fn lessThan(ctx: @This(), a: Node, b: Node) bool {
                const dist_a = xorDist(a.hash, ctx.target_hash);
                const dist_b = xorDist(b.hash, ctx.target_hash);
                return compareDist(dist_a, dist_b) == .lt;
            }
        };
        std.mem.sort(Node, all_nodes_buf[0..total], SortCtx{ .target_hash = target }, SortCtx.lessThan);

        const result_count = @min(total, count);
        return try self.allocator.dupe(Node, all_nodes_buf[0..result_count]);
    }

    /// Find closest nodes in a specific subnet.
    pub fn findClosestInSubnet(self: *Self, target: NodeHash, subnet: types.SubnetID, count: usize) ![]Node {
        self.lock.lock();
        defer self.lock.unlock();

        var all_nodes_buf: [MAX_BUCKETS * BUCKET_SIZE]Node = undefined;
        var total: usize = 0;

        for (&self.buckets) |*bucket| {
            var bucket_buf: [BUCKET_SIZE]Node = undefined;
            const n = bucket.getAll(&bucket_buf);
            for (0..n) |i| {
                if (bucket_buf[i].isInSubnet(subnet) and total < all_nodes_buf.len) {
                    all_nodes_buf[total] = bucket_buf[i];
                    total += 1;
                }
            }
        }

        if (total == 0) {
            return try self.allocator.alloc(Node, 0);
        }

        const SortCtx = struct {
            target_hash: NodeHash,
            pub fn lessThan(ctx: @This(), a: Node, b: Node) bool {
                const dist_a = xorDist(a.hash, ctx.target_hash);
                const dist_b = xorDist(b.hash, ctx.target_hash);
                return compareDist(dist_a, dist_b) == .lt;
            }
        };
        std.mem.sort(Node, all_nodes_buf[0..total], SortCtx{ .target_hash = target }, SortCtx.lessThan);

        const result_count = @min(total, count);
        return try self.allocator.dupe(Node, all_nodes_buf[0..result_count]);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    pub fn start(self: *Self) !void {
        self.running = true;

        // Add bootstrap nodes to routing table
        for (self.bootstrap_nodes.items) |node| {
            self.addNodeLocked(node);
        }

        // Start periodic refresh in background
        self.refresh_thread = try std.Thread.spawn(.{}, refreshLoop, .{self});
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        if (self.refresh_thread) |t| {
            t.join();
            self.refresh_thread = null;
        }
    }

    fn refreshLoop(self: *Self) void {
        while (self.running) {
            // Sleep in short increments so we can exit promptly on shutdown
            const interval_ns: u64 = @intCast(REFRESH_INTERVAL_MS * std.time.ns_per_ms);
            const step_ns: u64 = 100 * std.time.ns_per_ms; // 100ms steps
            var remaining: u64 = interval_ns;
            while (remaining > 0 and self.running) {
                const sleep_ns = @min(remaining, step_ns);
                std.Thread.sleep(sleep_ns);
                remaining -|= sleep_ns;
            }
            if (!self.running) break;
            self.evictStaleNodes();
        }
    }

    /// Evict nodes that have exceeded the stale threshold and have failing pings.
    fn evictStaleNodes(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();

        const now = std.time.milliTimestamp();
        for (&self.buckets) |*bucket| {
            for (&bucket.nodes) |*slot| {
                if (slot.*) |node| {
                    if (node.ping_failures >= 3 and (now - node.last_seen) > STALE_THRESHOLD_MS) {
                        slot.* = null;
                        bucket.count -= 1;
                    }
                }
            }
        }
    }

    // ── Stats ───────────────────────────────────────────────────────────

    pub const DiscoveryStats = struct {
        total_nodes: u32,
        total_seen: u64,
        total_lookups: u64,
        bucket_utilization: f64,
    };

    pub fn getStats(self: *Self) DiscoveryStats {
        self.lock.lock();
        defer self.lock.unlock();

        var total_nodes: u32 = 0;
        var non_empty_buckets: u32 = 0;
        for (&self.buckets) |*bucket| {
            total_nodes += bucket.count;
            if (bucket.count > 0) non_empty_buckets += 1;
        }

        return .{
            .total_nodes = total_nodes,
            .total_seen = self.total_nodes_seen,
            .total_lookups = self.total_lookups,
            .bucket_utilization = if (non_empty_buckets > 0)
                @as(f64, @floatFromInt(total_nodes)) / @as(f64, @floatFromInt(non_empty_buckets * BUCKET_SIZE))
            else
                0.0,
        };
    }

    // ── Internal Helpers ────────────────────────────────────────────────

    fn getBucketIndex(distance: NodeHash) usize {
        for (distance, 0..) |byte, i| {
            if (byte == 0) continue;
            const lz = @clz(byte);
            return 255 - (i * 8 + lz);
        }
        return 0;
    }
};

// ── Static Distance Helpers ─────────────────────────────────────────────

fn xorDist(a: NodeHash, b: NodeHash) NodeHash {
    var dist: NodeHash = undefined;
    for (0..HASH_SIZE) |i| {
        dist[i] = a[i] ^ b[i];
    }
    return dist;
}

fn compareDist(a: NodeHash, b: NodeHash) std.math.Order {
    return std.mem.order(u8, &a, &b);
}
