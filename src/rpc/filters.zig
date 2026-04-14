// Log Filters — Bloom filter-based log matching for eth_getLogs and eth_newFilter
//
// Implements Ethereum-compatible log filtering:
//   - Address filter: match logs from specific contract addresses
//   - Topic filter: match logs with specific event signatures
//   - Block range filter: match logs within a block range
//
// Uses a Bloom filter per block for fast elimination of non-matching blocks.

const std = @import("std");
const core = @import("core");
const types = core.types;

/// A log entry (Ethereum-compatible)
pub const Log = struct {
    address: types.Address,
    topics: []types.Hash,
    data: []const u8,
    block_number: u64,
    tx_hash: types.Hash,
    tx_index: u32,
    log_index: u32,
    block_hash: types.Hash,
    removed: bool,
};

/// Filter specification for eth_newFilter / eth_getLogs
pub const FilterSpec = struct {
    id: u64,
    from_block: ?u64,
    to_block: ?u64,
    addresses: []const types.Address,
    topics: [4]?[]const types.Hash, // topics[i] = OR set for position i
    created_at: u64,
    last_poll_block: u64,
};

/// Bloom filter for fast block-level log filtering (2048-bit, 3 hash functions)
pub const LogBloom = struct {
    bits: [256]u8, // 2048 bits

    const Self = @This();

    pub fn empty() Self {
        return Self{ .bits = [_]u8{0} ** 256 };
    }

    /// Add an item to the bloom filter
    pub fn add(self: *Self, data: []const u8) void {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(data);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        // 3 hash functions, each using 11 bits (2048 = 2^11)
        for (0..3) |i| {
            const bit_pos = (@as(u16, hash[i * 2]) << 3 | @as(u16, hash[i * 2 + 1]) >> 5) & 0x7FF;
            self.bits[bit_pos / 8] |= @as(u8, 1) << @intCast(bit_pos % 8);
        }
    }

    /// Add an address to the bloom filter
    pub fn addAddress(self: *Self, addr: types.Address) void {
        self.add(&addr.bytes);
    }

    /// Add a topic to the bloom filter
    pub fn addTopic(self: *Self, topic: types.Hash) void {
        self.add(&topic.bytes);
    }

    /// Check if an item might be in the bloom filter
    pub fn mightContain(self: *const Self, data: []const u8) bool {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(data);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        for (0..3) |i| {
            const bit_pos = (@as(u16, hash[i * 2]) << 3 | @as(u16, hash[i * 2 + 1]) >> 5) & 0x7FF;
            if (self.bits[bit_pos / 8] & (@as(u8, 1) << @intCast(bit_pos % 8)) == 0) {
                return false;
            }
        }
        return true;
    }

    /// Check if a bloom matches an address
    pub fn mightContainAddress(self: *const Self, addr: types.Address) bool {
        return self.mightContain(&addr.bytes);
    }

    /// Check if a bloom matches a topic
    pub fn mightContainTopic(self: *const Self, topic: types.Hash) bool {
        return self.mightContain(&topic.bytes);
    }
};

/// Filter engine — manages active filters and processes log queries
pub const FilterEngine = struct {
    allocator: std.mem.Allocator,
    /// Active filters (keyed by filter ID)
    filters: std.AutoHashMap(u64, FilterSpec),
    /// Block bloom filters (recent blocks only)
    block_blooms: std.AutoHashMap(u64, LogBloom),
    /// Next filter ID
    next_id: u64,
    /// Stats
    queries: u64,
    matches: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .filters = std.AutoHashMap(u64, FilterSpec).init(allocator),
            .block_blooms = std.AutoHashMap(u64, LogBloom).init(allocator),
            .next_id = 1,
            .queries = 0,
            .matches = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.filters.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.addresses);
            for (&entry.value_ptr.topics) |topic_set| {
                if (topic_set) |ts| self.allocator.free(ts);
            }
        }
        self.filters.deinit();
        self.block_blooms.deinit();
    }

    /// Create a new filter (eth_newFilter)
    pub fn createFilter(
        self: *Self,
        from_block: ?u64,
        to_block: ?u64,
        addresses: []const types.Address,
        topics: [4]?[]const types.Hash,
    ) !u64 {
        const id = self.next_id;
        self.next_id += 1;

        // Copy addresses
        const addrs = try self.allocator.alloc(types.Address, addresses.len);
        @memcpy(addrs, addresses);

        // Copy topics
        var topic_copies: [4]?[]const types.Hash = .{ null, null, null, null };
        for (0..4) |i| {
            if (topics[i]) |ts| {
                const tc = try self.allocator.alloc(types.Hash, ts.len);
                @memcpy(tc, ts);
                topic_copies[i] = tc;
            }
        }

        try self.filters.put(id, FilterSpec{
            .id = id,
            .from_block = from_block,
            .to_block = to_block,
            .addresses = addrs,
            .topics = topic_copies,
            .created_at = @intCast(std.time.timestamp()),
            .last_poll_block = from_block orelse 0,
        });

        return id;
    }

    /// Remove a filter (eth_uninstallFilter)
    pub fn removeFilter(self: *Self, id: u64) bool {
        if (self.filters.fetchRemove(id)) |entry| {
            self.allocator.free(entry.value.addresses);
            for (entry.value.topics) |topic_set| {
                if (topic_set) |ts| self.allocator.free(ts);
            }
            return true;
        }
        return false;
    }

    /// Record a block's bloom filter
    pub fn setBlockBloom(self: *Self, block_number: u64, bloom: LogBloom) !void {
        try self.block_blooms.put(block_number, bloom);
    }

    /// Check if a log matches a filter specification
    pub fn matchesFilter(filter: *const FilterSpec, log: *const Log) bool {
        // Check block range
        if (filter.from_block) |from| {
            if (log.block_number < from) return false;
        }
        if (filter.to_block) |to| {
            if (log.block_number > to) return false;
        }

        // Check address filter
        if (filter.addresses.len > 0) {
            var found = false;
            for (filter.addresses) |addr| {
                if (std.mem.eql(u8, &addr.bytes, &log.address.bytes)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        // Check topic filters (AND across positions, OR within each position)
        for (0..4) |i| {
            if (filter.topics[i]) |required| {
                if (i >= log.topics.len) return false;
                var topic_match = false;
                for (required) |topic| {
                    if (std.mem.eql(u8, &topic.bytes, &log.topics[i].bytes)) {
                        topic_match = true;
                        break;
                    }
                }
                if (!topic_match) return false;
            }
        }

        return true;
    }

    /// Get filter by ID
    pub fn getFilter(self: *Self, id: u64) ?*FilterSpec {
        return self.filters.getPtr(id);
    }

    /// Get statistics
    pub fn getStats(self: *const Self) struct {
        active_filters: u32,
        total_queries: u64,
        total_matches: u64,
    } {
        return .{
            .active_filters = @intCast(self.filters.count()),
            .total_queries = self.queries,
            .total_matches = self.matches,
        };
    }
};
