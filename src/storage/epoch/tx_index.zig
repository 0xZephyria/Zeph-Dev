// Transaction Index - Bloom filter per epoch with account mapping
// Enables efficient query: "Did account X have activity in epoch N?"

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const Address = types.Address;
const Hash = types.Hash;

/// Bloom filter for transaction existence checks
/// False positive rate ~1% with 10 hash functions for typical epoch sizes
pub const BloomFilter = struct {
    const Self = @This();

    // 2^20 bits = 128 KB per epoch (covers ~100K txs with 1% false positive)
    const BLOOM_BITS = 1 << 20;
    const BLOOM_BYTES = BLOOM_BITS / 8;
    const HASH_COUNT = 10;

    bits: []u8,
    allocator: Allocator,
    item_count: u64,

    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.bits = try allocator.alloc(u8, BLOOM_BYTES);
        @memset(self.bits, 0);
        self.item_count = 0;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bits);
        self.allocator.destroy(self);
    }

    /// Insert a key into the bloom filter
    pub fn insert(self: *Self, key: []const u8) void {
        for (0..HASH_COUNT) |i| {
            const hash = computeHash(key, i);
            const bit_index = hash % BLOOM_BITS;
            const byte_index = bit_index / 8;
            const bit_offset: u3 = @intCast(bit_index % 8);
            self.bits[byte_index] |= @as(u8, 1) << bit_offset;
        }
        self.item_count += 1;
    }

    /// Check if a key might be in the filter
    pub fn mightContain(self: *const Self, key: []const u8) bool {
        for (0..HASH_COUNT) |i| {
            const hash = computeHash(key, i);
            const bit_index = hash % BLOOM_BITS;
            const byte_index = bit_index / 8;
            const bit_offset: u3 = @intCast(bit_index % 8);
            if (self.bits[byte_index] & (@as(u8, 1) << bit_offset) == 0) {
                return false;
            }
        }
        return true;
    }

    /// Merge another bloom filter into this one
    pub fn merge(self: *Self, other: *const Self) void {
        for (self.bits, other.bits) |*dst, src| {
            dst.* |= src;
        }
        self.item_count += other.item_count;
    }

    /// Serialize to bytes
    pub fn serialize(self: *const Self) []const u8 {
        return self.bits;
    }

    /// Deserialize from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) !*Self {
        if (data.len != BLOOM_BYTES) return error.InvalidSize;

        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.bits = try allocator.dupe(u8, data);
        self.item_count = 0; // Unknown after deserialize
        return self;
    }

    fn computeHash(key: []const u8, seed: usize) u64 {
        // Use simple hash with seed XOR
        const h = std.hash.Wyhash.hash(@as(u64, seed), key);
        return h;
    }
};

/// Account -> Epoch mapping for fast historical queries
pub const AccountEpochIndex = struct {
    const Self = @This();

    allocator: Allocator,
    // address -> list of epochs with activity
    index: std.AutoHashMap(Address, std.ArrayListUnmanaged(u64)),
    // Epoch bloom filters
    epoch_blooms: std.AutoHashMap(u64, *BloomFilter),

    // Persistence
    dirty_epochs: std.AutoHashMap(u64, void),

    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.index = std.AutoHashMap(Address, std.ArrayListUnmanaged(u64)).init(allocator);
        self.epoch_blooms = std.AutoHashMap(u64, *BloomFilter).init(allocator);
        self.dirty_epochs = std.AutoHashMap(u64, void).init(allocator);
        return self;
    }

    pub fn deinit(self: *Self) void {
        var index_iter = self.index.iterator();
        while (index_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.index.deinit();

        var bloom_iter = self.epoch_blooms.iterator();
        while (bloom_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.epoch_blooms.deinit();

        self.dirty_epochs.deinit();
        self.allocator.destroy(self);
    }

    /// Record that an account had activity in an epoch
    pub fn recordActivity(
        self: *Self,
        address: Address,
        epoch: u64,
        tx_hash: ?Hash,
    ) !void {
        // Update account -> epoch mapping
        const gop = try self.index.getOrPut(address);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }

        // Check if epoch already recorded
        var already_recorded = false;
        for (gop.value_ptr.items) |e| {
            if (e == epoch) {
                already_recorded = true;
                break;
            }
        }
        if (!already_recorded) {
            try gop.value_ptr.append(self.allocator, epoch);
        }

        // Update bloom filter
        const bloom_gop = try self.epoch_blooms.getOrPut(epoch);
        if (!bloom_gop.found_existing) {
            bloom_gop.value_ptr.* = try BloomFilter.init(self.allocator);
        }

        // Add address to bloom
        bloom_gop.value_ptr.*.insert(&address);

        // Add tx hash to bloom if provided
        if (tx_hash) |hash| {
            bloom_gop.value_ptr.*.insert(&hash);
        }

        // Mark epoch as dirty
        try self.dirty_epochs.put(epoch, {});
    }

    /// Get all epochs where an account had activity
    pub fn getAccountEpochs(self: *const Self, address: Address) ?[]const u64 {
        if (self.index.get(address)) |epochs| {
            return epochs.items;
        }
        return null;
    }

    /// Check if a transaction hash exists in an epoch
    pub fn mightHaveTransaction(self: *const Self, epoch: u64, tx_hash: Hash) bool {
        if (self.epoch_blooms.get(epoch)) |bloom| {
            return bloom.mightContain(&tx_hash);
        }
        return false;
    }

    /// Check if an address had activity in an epoch
    pub fn mightHaveActivity(self: *const Self, epoch: u64, address: Address) bool {
        if (self.epoch_blooms.get(epoch)) |bloom| {
            return bloom.mightContain(&address);
        }
        return false;
    }

    /// Find epochs where an account likely had activity
    pub fn findAccountEpochs(
        self: *const Self,
        address: Address,
        start_epoch: u64,
        end_epoch: u64,
    ) ![]u64 {
        var results: std.ArrayListUnmanaged(u64) = .{};
        errdefer results.deinit(self.allocator);

        // First check the direct index
        if (self.index.get(address)) |epochs| {
            for (epochs.items) |e| {
                if (e >= start_epoch and e <= end_epoch) {
                    try results.append(self.allocator, e);
                }
            }
            return try results.toOwnedSlice(self.allocator);
        }

        // Fallback to bloom filter scan
        for (start_epoch..end_epoch + 1) |epoch| {
            if (self.epoch_blooms.get(epoch)) |bloom| {
                if (bloom.mightContain(&address)) {
                    try results.append(self.allocator, epoch);
                }
            }
        }

        return try results.toOwnedSlice(self.allocator);
    }

    /// Persist dirty epochs to storage
    pub fn persist(self: *Self, db: anytype) !void {
        var iter = self.dirty_epochs.iterator();
        while (iter.next()) |entry| {
            const epoch = entry.key_ptr.*;

            // Persist bloom filter
            if (self.epoch_blooms.get(epoch)) |bloom| {
                const key = try std.fmt.allocPrint(
                    self.allocator,
                    "tx-bloom-{d}",
                    .{epoch},
                );
                defer self.allocator.free(key);

                try db.write(key, bloom.serialize());
            }
        }

        // Clear dirty set
        self.dirty_epochs.clearRetainingCapacity();

        // Persist account index (simplified - in production use incremental updates)
        var index_buf: std.ArrayListUnmanaged(u8) = .{};
        defer index_buf.deinit(self.allocator);

        var count: u32 = 0;
        var index_iter = self.index.iterator();
        while (index_iter.next()) |_| {
            count += 1;
        }

        var count_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &count_bytes, count, .big);
        try index_buf.appendSlice(self.allocator, &count_bytes);

        index_iter = self.index.iterator();
        while (index_iter.next()) |e| {
            try index_buf.appendSlice(self.allocator, &e.key_ptr.*);

            var epoch_count_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &epoch_count_bytes, @intCast(e.value_ptr.items.len), .big);
            try index_buf.appendSlice(self.allocator, &epoch_count_bytes);

            for (e.value_ptr.items) |epoch_num| {
                var epoch_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &epoch_bytes, epoch_num, .big);
                try index_buf.appendSlice(self.allocator, &epoch_bytes);
            }
        }

        try db.write("account-epoch-index", index_buf.items);
    }

    /// Load from storage
    pub fn load(allocator: Allocator, db: anytype) !*Self {
        const self = try Self.init(allocator);
        errdefer self.deinit();

        // Load account index
        if (db.read("account-epoch-index")) |data| {
            if (data.len < 4) return self;

            const count = std.mem.readInt(u32, data[0..4], .big);
            var offset: usize = 4;

            for (0..count) |_| {
                if (offset + 24 > data.len) break;

                var addr: Address = undefined;
                @memcpy(&addr, data[offset..][0..20]);
                offset += 20;

                const epoch_count = std.mem.readInt(u32, data[offset..][0..4], .big);
                offset += 4;

                var epochs: std.ArrayListUnmanaged(u64) = .{};
                for (0..epoch_count) |_| {
                    if (offset + 8 > data.len) break;
                    const epoch_num = std.mem.readInt(u64, data[offset..][0..8], .big);
                    try epochs.append(allocator, epoch_num);
                    offset += 8;
                }

                try self.index.put(addr, epochs);
            }
        }

        return self;
    }

    /// Statistics
    pub fn getStats(self: *const Self) struct {
        accounts: usize,
        epochs: usize,
        total_mappings: usize,
    } {
        var total_mappings: usize = 0;
        var iter = self.index.iterator();
        while (iter.next()) |entry| {
            total_mappings += entry.value_ptr.items.len;
        }

        return .{
            .accounts = self.index.count(),
            .epochs = self.epoch_blooms.count(),
            .total_mappings = total_mappings,
        };
    }
};

// Tests
test "BloomFilter basic operations" {
    const allocator = std.testing.allocator;

    var bloom = try BloomFilter.init(allocator);
    defer bloom.deinit();

    const key1 = "transaction_hash_1";
    const key2 = "transaction_hash_2";

    bloom.insert(key1);
    bloom.insert(key2);

    try std.testing.expect(bloom.mightContain(key1));
    try std.testing.expect(bloom.mightContain(key2));
}

test "AccountEpochIndex tracking" {
    const allocator = std.testing.allocator;

    var index = try AccountEpochIndex.init(allocator);
    defer index.deinit();

    const addr1 = [_]u8{0x01} ** 20;
    const addr2 = [_]u8{0x02} ** 20;

    try index.recordActivity(addr1, 0, null);
    try index.recordActivity(addr1, 1, null);
    try index.recordActivity(addr2, 1, null);

    const epochs1 = index.getAccountEpochs(addr1);
    try std.testing.expect(epochs1 != null);
    try std.testing.expectEqual(@as(usize, 2), epochs1.?.len);

    const epochs2 = index.getAccountEpochs(addr2);
    try std.testing.expect(epochs2 != null);
    try std.testing.expectEqual(@as(usize, 1), epochs2.?.len);
}
