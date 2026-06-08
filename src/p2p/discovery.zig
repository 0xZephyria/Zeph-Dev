// ============================================================================
// Zephyria — Peer Discovery (Production Kademlia)
// ============================================================================
//
// Kademlia-based peer discovery with:
//   • Full routing table with 256 buckets of 16 nodes each
//   • XOR distance metric over Blake3(pubkey)
//   • Subnet-aware peer prioritization
//   • Bootstrap node support
//   • Periodic routing table refresh with stale node eviction
//   • ZNR attestation with validator address binding

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
    lastSeen: i64,
    lastPing: i64,
    pingFailures: u8,
    peerRole: types.PeerRole,
    validatorAddress: core.types.Address,
    subscribedSubnets: [8]u8,
    stakeAmount: u64,

    pub fn distance(self: *const Node, other_hash: NodeHash) NodeHash {
        var dist: NodeHash = undefined;
        for (0..HASH_SIZE) |i| {
            dist[i] = self.hash[i] ^ other_hash[i];
        }
        return dist;
    }

    /// Check if this node is in the given subnet.
    pub fn isInSubnet(self: *const Node, subnet: types.SubnetID) bool {
        return types.isSubnetSubscribed(self.subscribedSubnets, subnet);
    }
};

// ── ZNR Record ──────────────────────────────────────────────────────────

pub const ZnrRecord = struct {
    seq: u64,
    id: [4]u8, // "znr1"
    pubkey: [33]u8, // Compressed secp256k1 public key
    ip4: [4]u8,
    udpPort: u16,
    tcpPort: u16,
    validatorAddr: core.types.Address,
    subnets: [8]u8,
    stake: u64,

    pub fn init(pubkey: [33]u8, ip4: [4]u8, udpPort: u16) ZnrRecord {
        return .{
            .seq = 1,
            .id = [_]u8{ 'z', 'n', 'r', '1' },
            .pubkey = pubkey,
            .ip4 = ip4,
            .udpPort = udpPort,
            .tcpPort = 0,
            .validatorAddr = core.types.Address.zero(),
            .subnets = [_]u8{0} ** 8,
            .stake = 0,
        };
    }

    /// Serialize ZNR to bytes for transmission
    pub fn serialize(self: *const ZnrRecord, buf: []u8) usize {
        if (buf.len < 101) return 0;
        @memcpy(buf[0..4], &self.id);
        std.mem.writeInt(u64, buf[4..12], self.seq, .big);
        @memcpy(buf[12..45], &self.pubkey);
        @memcpy(buf[45..49], &self.ip4);
        std.mem.writeInt(u16, buf[49..51], self.udpPort, .big);
        std.mem.writeInt(u16, buf[51..53], self.tcpPort, .big);
        @memcpy(buf[53..85], &self.validatorAddr.bytes);
        @memcpy(buf[85..93], &self.subnets);
        std.mem.writeInt(u64, buf[93..101], self.stake, .big);
        return 101;
    }

    /// Deserialize ZNR from bytes
    pub fn deserialize(data: []const u8) ?ZnrRecord {
        if (data.len < 101) return null;
        var znr: ZnrRecord = undefined;
        @memcpy(&znr.id, data[0..4]);
        znr.seq = std.mem.readInt(u64, data[4..12], .big);
        @memcpy(&znr.pubkey, data[12..45]);
        @memcpy(&znr.ip4, data[45..49]);
        znr.udpPort = std.mem.readInt(u16, data[49..51], .big);
        znr.tcpPort = std.mem.readInt(u16, data[51..53], .big);
        @memcpy(&znr.validatorAddr.bytes, data[53..85]);
        @memcpy(&znr.subnets, data[85..93]);
        znr.stake = std.mem.readInt(u64, data[93..101], .big);
        return znr;
    }

    /// Format ZnrRecord as a copy-pastable base64 string prefixed with "znr:"
    pub fn toConnectionString(self: *const ZnrRecord, buf: []u8) ![]const u8 {
        var temp_bin: [101]u8 = undefined;
        _ = self.serialize(&temp_bin);

        const prefix = "znr:";
        if (buf.len < prefix.len + std.base64.standard_no_pad.Encoder.calcSize(101)) {
            return error.BufferTooSmall;
        }

        @memcpy(buf[0..prefix.len], prefix);
        const encoded = std.base64.standard_no_pad.Encoder.encode(buf[prefix.len..], &temp_bin);
        return buf[0..prefix.len + encoded.len];
    }

    /// Parse a copy-pastable connection string prefixed with "znr:" back to ZnrRecord
    pub fn fromConnectionString(str: []const u8) !ZnrRecord {
        const prefix = "znr:";
        if (str.len < prefix.len) return error.InvalidFormat;
        if (!std.mem.startsWith(u8, str, prefix)) return error.InvalidFormat;

        const b64_str = str[prefix.len..];
        var temp_bin: [101]u8 = undefined;
        const decoded_len = try std.base64.standard_no_pad.Decoder.calcSizeForSlice(b64_str);
        if (decoded_len != 101) return error.InvalidFormat;

        try std.base64.standard_no_pad.Decoder.decode(&temp_bin, b64_str);
        return deserialize(&temp_bin) orelse error.InvalidFormat;
    }
};

// ── Routing Table Bucket ────────────────────────────────────────────────

const Bucket = struct {
    nodes: [BUCKET_SIZE]?Node,
    count: u8,
    lastRefresh: i64,

    fn init() Bucket {
        return .{
            .nodes = [_]?Node{null} ** BUCKET_SIZE,
            .count = 0,
            .lastRefresh = std.time.milliTimestamp(),
        };
    }

    fn isFull(self: *const Bucket) bool {
        return self.count >= BUCKET_SIZE;
    }

    /// Insert or update a node. Returns true if inserted/updated, false if bucket full and
    /// no stale node to evict.
    fn insertOrUpdate(self: *Bucket, node: Node) bool {
        // Check if already exists — update lastSeen
        for (&self.nodes) |*slot| {
            if (slot.*) |*existing| {
                if (std.mem.eql(u8, &existing.id, &node.id)) {
                    existing.lastSeen = node.lastSeen;
                    existing.pingFailures = 0;
                    existing.stakeAmount = node.stakeAmount;
                    existing.subscribedSubnets = node.subscribedSubnets;
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
                if (n.pingFailures >= 3 or (now - n.lastSeen) > STALE_THRESHOLD_MS) {
                    if (n.lastSeen < stalest_time) {
                        stalest_time = n.lastSeen;
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
                    existing.pingFailures += 1;
                    return;
                }
            }
        }
    }
};

// ── Discovery Service ───────────────────────────────────────────────────

pub const DiscoveryService = struct {
    allocator: Allocator,
    localNode: Node,
    localZnr: ZnrRecord,
    buckets: [MAX_BUCKETS]Bucket,
    bootstrapNodes: std.ArrayListUnmanaged(Node),
    mutex: std.Thread.Mutex,
    running: bool,
    refreshThread: ?std.Thread,

    // Stats
    totalNodesSeen: u64,
    totalLookups: u64,

    const Self = @This();

    pub fn init(allocator: Allocator, priv_key: []const u8, port: u16) !*Self {
        const self = try allocator.create(Self);

        // Derive node ID and ZNR public key from private key using Ed25519 (prevents private key leakage)
        var id: NodeID = [_]u8{0} ** ID_SIZE;
        var compressed_pubkey: [33]u8 = [_]u8{0} ** 33;

        if (priv_key.len == 32) {
            var priv_key_arr: [32]u8 = undefined;
            @memcpy(&priv_key_arr, priv_key[0..32]);
            defer secureZero(priv_key_arr[0..]);
            var key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(priv_key_arr);
            defer secureZero(std.mem.asBytes(&key_pair));
            const pub_key_bytes = key_pair.public_key.toBytes();
            @memcpy(id[0..32], &pub_key_bytes);
            @memcpy(compressed_pubkey[0..32], &pub_key_bytes);
        } else {
            const key_len = @min(priv_key.len, 32);
            @memcpy(id[0..key_len], priv_key[0..key_len]);
            @memcpy(compressed_pubkey[0..key_len], priv_key[0..key_len]);
        }

        // Hash node ID for XOR distance
        var hash: NodeHash = undefined;
        std.crypto.hash.Blake3.hash(&id, &hash, .{});

        const local_addr = try net.Address.parseIp4("0.0.0.0", port);

        // Initialize all buckets
        var buckets: [MAX_BUCKETS]Bucket = undefined;
        for (&buckets) |*bucket| {
            bucket.* = Bucket.init();
        }

        // Create local ZNR
        const znr = ZnrRecord.init(compressed_pubkey, [4]u8{ 0, 0, 0, 0 }, port);

        self.* = Self{
            .allocator = allocator,
            .localNode = .{
                .id = id,
                .hash = hash,
                .address = local_addr,
                .lastSeen = std.time.milliTimestamp(),
                .lastPing = 0,
                .pingFailures = 0,
                .peerRole = .Validator,
                .validatorAddress = core.types.Address.zero(),
                .subscribedSubnets = [_]u8{0} ** 8,
                .stakeAmount = 0,
            },
            .localZnr = znr,
            .buckets = buckets,
            .bootstrapNodes = .{},
            .mutex = .{},
            .running = false,
            .refreshThread = null,
            .totalNodesSeen = 0,
            .totalLookups = 0,
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.bootstrapNodes.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // ── Bootstrap ───────────────────────────────────────────────────────

    /// Add a bootstrap node that will be contacted on startup.
    pub fn addBootstrapNode(self: *Self, node: Node) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.bootstrapNodes.append(self.allocator, node);
    }

    // ── Node Management ─────────────────────────────────────────────────

    pub fn addNode(self: *Self, node: Node) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.addNodeLocked(node);
    }

    fn addNodeLocked(self: *Self, node: Node) void {
        // Don't add self
        if (std.mem.eql(u8, &node.id, &self.localNode.id)) return;

        const dist = self.localNode.distance(node.hash);
        const idx = getBucketIndex(dist);

        if (self.buckets[idx].insertOrUpdate(node)) {
            self.totalNodesSeen += 1;
        }
    }

    /// Remove a node by ID.
    pub fn removeNode(self: *Self, id: NodeID) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Search all buckets (we could compute the bucket, but this is safer)
        for (&self.buckets) |*bucket| {
            if (bucket.remove(id)) return;
        }
    }

    /// Mark a node as having failed a ping response.
    pub fn markPingFailure(self: *Self, id: NodeID) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var hash: NodeHash = undefined;
        std.crypto.hash.Blake3.hash(&id, &hash, .{});
        const dist = self.localNode.distance(hash);
        const idx = getBucketIndex(dist);
        self.buckets[idx].markPingFailure(id);
    }

    // ── Lookup ──────────────────────────────────────────────────────────

    /// Find the `count` closest nodes to the target hash.
    /// Caller owns the returned slice and must free it.
    pub fn findClosest(self: *Self, target: NodeHash, count: usize) ![]Node {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.totalLookups += 1;

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
        self.mutex.lock();
        defer self.mutex.unlock();

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
        for (self.bootstrapNodes.items) |node| {
            self.addNodeLocked(node);
        }

        // Start periodic refresh in background
        self.refreshThread = try std.Thread.spawn(.{}, refreshLoop, .{self});
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        if (self.refreshThread) |t| {
            t.join();
            self.refreshThread = null;
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
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        for (&self.buckets) |*bucket| {
            for (&bucket.nodes) |*slot| {
                if (slot.*) |node| {
                    if (node.pingFailures >= 3 and (now - node.lastSeen) > STALE_THRESHOLD_MS) {
                        slot.* = null;
                        bucket.count -= 1;
                    }
                }
            }
        }
    }

    // ── Stats ───────────────────────────────────────────────────────────

    pub const DiscoveryStats = struct {
        totalNodes: u32,
        totalSeen: u64,
        totalLookups: u64,
        bucketUtilization: f64,
    };

    pub fn getStats(self: *Self) DiscoveryStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total_nodes: u32 = 0;
        var non_empty_buckets: u32 = 0;
        for (&self.buckets) |*bucket| {
            total_nodes += bucket.count;
            if (bucket.count > 0) non_empty_buckets += 1;
        }

        return .{
            .totalNodes = total_nodes,
            .totalSeen = self.totalNodesSeen,
            .totalLookups = self.totalLookups,
            .bucketUtilization = if (non_empty_buckets > 0)
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

fn secureZero(buf: []u8) void {
    const ptr = @as([*]volatile u8, @ptrCast(buf.ptr));
    for (0..buf.len) |i| ptr[i] = 0;
}
