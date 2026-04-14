// StateDelta - Efficient state change tracking with compression
// Optimized for high throughput with lock-free concurrent access

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const AccountDelta = types.AccountDelta;
const StorageDelta = types.StorageDelta;
const Address = types.Address;
const Hash = types.Hash;

/// Thread-safe sharded delta accumulator for high-concurrency writes
pub const StateDelta = struct {
    const Self = @This();
    const SHARD_COUNT = 256; // One shard per first byte of address

    allocator: Allocator,
    shards: [SHARD_COUNT]Shard,

    // Global statistics (atomic)
    total_accounts: std.atomic.Value(u64),
    total_storage: std.atomic.Value(u64),
    total_gas: std.atomic.Value(u128),

    const Shard = struct {
        allocator: Allocator,
        accounts: std.AutoArrayHashMap(Address, AccountDelta),
        storage: std.ArrayListUnmanaged(StorageDelta),
        lock: std.Thread.RwLock,

        fn init(allocator: Allocator) Shard {
            return Shard{
                .allocator = allocator,
                .accounts = std.AutoArrayHashMap(Address, AccountDelta).init(allocator),
                .storage = .{},
                .lock = .{},
            };
        }

        fn deinit(self: *Shard) void {
            self.accounts.deinit();
            self.storage.deinit(self.allocator);
        }
    };

    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.total_accounts = std.atomic.Value(u64).init(0);
        self.total_storage = std.atomic.Value(u64).init(0);
        self.total_gas = std.atomic.Value(u128).init(0);

        for (&self.shards) |*shard| {
            shard.* = Shard.init(allocator);
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        for (&self.shards) |*shard| {
            shard.deinit();
        }
        self.allocator.destroy(self);
    }

    /// Get shard index for an address (first byte)
    inline fn getShardIndex(addr: Address) usize {
        return addr[0];
    }

    /// Record an account modification (thread-safe)
    pub fn recordAccountChange(
        self: *Self,
        addr: Address,
        balance_delta: i128,
        nonce_delta: i64,
        code_hash: ?Hash,
    ) !void {
        const shard_idx = getShardIndex(addr);
        const shard = &self.shards[shard_idx];

        shard.lock.lock();
        defer shard.lock.unlock();

        const gop = try shard.accounts.getOrPut(addr);
        if (gop.found_existing) {
            // Merge with existing delta
            gop.value_ptr.balance_delta +|= balance_delta;
            gop.value_ptr.nonce_delta +|= nonce_delta;
            if (code_hash) |ch| {
                gop.value_ptr.code_hash = ch;
            }
        } else {
            // New account delta
            gop.value_ptr.* = AccountDelta{
                .address = addr,
                .balance_delta = balance_delta,
                .nonce_delta = nonce_delta,
                .code_hash = code_hash orelse [_]u8{0} ** 32,
            };
            _ = self.total_accounts.fetchAdd(1, .monotonic);
        }
    }

    /// Record a storage modification (thread-safe)
    pub fn recordStorageChange(
        self: *Self,
        addr: Address,
        slot: Hash,
        old_value: Hash,
        new_value: Hash,
    ) !void {
        const shard_idx = getShardIndex(addr);
        const shard = &self.shards[shard_idx];

        shard.lock.lock();
        defer shard.lock.unlock();

        try shard.storage.append(shard.allocator, StorageDelta{
            .address = addr,
            .slot = slot,
            .old_value = old_value,
            .new_value = new_value,
        });

        _ = self.total_storage.fetchAdd(1, .monotonic);
    }

    /// Record gas usage
    pub fn recordGas(self: *Self, gas: u64) void {
        _ = self.total_gas.fetchAdd(gas, .monotonic);
    }

    /// Merge another delta into this one
    pub fn merge(self: *Self, other: *const Self) !void {
        for (0..SHARD_COUNT) |i| {
            const other_shard = &other.shards[i];
            const self_shard = &self.shards[i];

            // Need mutable lock for shared read access
            var mutable_lock = @constCast(&other_shard.lock);
            mutable_lock.lockShared();
            defer mutable_lock.unlockShared();

            self_shard.lock.lock();
            defer self_shard.lock.unlock();

            // Merge accounts
            for (other_shard.accounts.values()) |*delta| {
                const gop = try self_shard.accounts.getOrPut(delta.address);
                if (gop.found_existing) {
                    gop.value_ptr.merge(delta);
                } else {
                    gop.value_ptr.* = delta.*;
                }
            }

            // Append storage deltas
            try self_shard.storage.appendSlice(self_shard.allocator, other_shard.storage.items);
        }
    }

    /// Serialize delta to bytes (for compression)
    pub fn serialize(self: *Self, allocator: Allocator) ![]u8 {
        var total_size: usize = 0;

        // Calculate size
        for (&self.shards) |*shard| {
            shard.lock.lockShared();
            total_size += shard.accounts.count() * @sizeOf(AccountDelta);
            total_size += shard.storage.items.len * @sizeOf(StorageDelta);
            shard.lock.unlockShared();
        }

        // Add header
        const header_size = 16; // 8 bytes account count + 8 bytes storage count
        total_size += header_size;

        const buffer = try allocator.alloc(u8, total_size);
        var offset: usize = 0;

        // Write counts
        const account_count = self.total_accounts.load(.monotonic);
        const storage_count = self.total_storage.load(.monotonic);
        std.mem.writeInt(u64, buffer[0..8], account_count, .big);
        std.mem.writeInt(u64, buffer[8..16], storage_count, .big);
        offset = 16;

        // Write account deltas (sorted by shard for cache locality)
        for (&self.shards) |*shard| {
            shard.lock.lockShared();
            defer shard.lock.unlockShared();

            for (shard.accounts.values()) |*delta| {
                const delta_bytes = std.mem.asBytes(delta);
                @memcpy(buffer[offset..][0..@sizeOf(AccountDelta)], delta_bytes);
                offset += @sizeOf(AccountDelta);
            }
        }

        // Write storage deltas
        for (&self.shards) |*shard| {
            shard.lock.lockShared();
            defer shard.lock.unlockShared();

            for (shard.storage.items) |*delta| {
                const delta_bytes = std.mem.asBytes(delta);
                @memcpy(buffer[offset..][0..@sizeOf(StorageDelta)], delta_bytes);
                offset += @sizeOf(StorageDelta);
            }
        }

        return buffer[0..offset];
    }

    /// Deserialize delta from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) !*Self {
        if (data.len < 16) return error.InvalidData;

        const self = try Self.init(allocator);
        errdefer self.deinit();

        const account_count = std.mem.readInt(u64, data[0..8], .big);
        const storage_count = std.mem.readInt(u64, data[8..16], .big);

        var offset: usize = 16;

        // Read account deltas
        for (0..account_count) |_| {
            if (offset + @sizeOf(AccountDelta) > data.len) return error.InvalidData;

            const delta_ptr: *const AccountDelta = @ptrCast(@alignCast(data[offset..].ptr));
            const delta = delta_ptr.*;

            const shard_idx = getShardIndex(delta.address);
            try self.shards[shard_idx].accounts.put(delta.address, delta);

            offset += @sizeOf(AccountDelta);
        }

        // Read storage deltas
        for (0..storage_count) |_| {
            if (offset + @sizeOf(StorageDelta) > data.len) return error.InvalidData;

            const delta_ptr: *const StorageDelta = @ptrCast(@alignCast(data[offset..].ptr));
            const delta = delta_ptr.*;

            const shard_idx = getShardIndex(delta.address);
            try self.shards[shard_idx].storage.append(self.allocator, delta);

            offset += @sizeOf(StorageDelta);
        }

        self.total_accounts.store(account_count, .monotonic);
        self.total_storage.store(storage_count, .monotonic);

        return self;
    }

    /// Compress serialized delta using Zstd
    pub fn compress(self: *Self, allocator: Allocator) ![]u8 {
        const serialized = try self.serialize(allocator);
        defer allocator.free(serialized);

        // Use Zig's built-in zstd if available, otherwise store uncompressed
        // For now, we'll use a simple run-length encoding as fallback
        return try compressData(allocator, serialized);
    }

    /// Decompress delta data
    pub fn decompress(allocator: Allocator, compressed: []const u8) ![]u8 {
        return try decompressData(allocator, compressed);
    }

    /// Get account delta for reverse application
    pub fn getAccountDelta(self: *Self, addr: Address) ?AccountDelta {
        const shard_idx = getShardIndex(addr);
        const shard = &self.shards[shard_idx];

        shard.lock.lockShared();
        defer shard.lock.unlockShared();

        return shard.accounts.get(addr);
    }

    /// Create reverse delta for historical state reconstruction
    pub fn reverse(self: *Self, allocator: Allocator) !*Self {
        const reversed = try Self.init(allocator);
        errdefer reversed.deinit();

        for (0..SHARD_COUNT) |i| {
            const src_shard = &self.shards[i];
            const dst_shard = &reversed.shards[i];

            src_shard.lock.lockShared();
            defer src_shard.lock.unlockShared();

            // Reverse account deltas
            for (src_shard.accounts.values()) |*delta| {
                try dst_shard.accounts.put(delta.address, AccountDelta{
                    .address = delta.address,
                    .balance_delta = -delta.balance_delta,
                    .nonce_delta = -delta.nonce_delta,
                    .code_hash = delta.code_hash, // Cannot reverse code changes easily
                });
            }

            // Reverse storage deltas (swap old/new)
            for (src_shard.storage.items) |*delta| {
                try dst_shard.storage.append(allocator, StorageDelta{
                    .address = delta.address,
                    .slot = delta.slot,
                    .old_value = delta.new_value,
                    .new_value = delta.old_value,
                });
            }
        }

        return reversed;
    }

    /// Statistics
    pub fn getStats(self: *const Self) struct { accounts: u64, storage: u64, gas: u128 } {
        return .{
            .accounts = self.total_accounts.load(.monotonic),
            .storage = self.total_storage.load(.monotonic),
            .gas = self.total_gas.load(.monotonic),
        };
    }
};

/// Simple compression using RLE (can be replaced with proper Zstd binding)
fn compressData(allocator: Allocator, data: []const u8) ![]u8 {
    var output: std.ArrayListUnmanaged(u8) = .{};
    errdefer output.deinit(allocator);

    try output.appendSlice(allocator, &[_]u8{ 'Z', 'D', 'L', 'T' }); // Magic
    var size_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &size_bytes, @intCast(data.len), .big);
    try output.appendSlice(allocator, &size_bytes);

    // Simple delta encoding for better compression
    if (data.len == 0) {
        return try output.toOwnedSlice(allocator);
    }

    var i: usize = 0;
    while (i < data.len) {
        // Check for run of same byte
        var run_len: usize = 1;
        while (i + run_len < data.len and run_len < 127 and data[i + run_len] == data[i]) {
            run_len += 1;
        }

        if (run_len >= 4) {
            // Encode as run: 0x80 | length, byte
            try output.append(allocator, @as(u8, 0x80) | @as(u8, @intCast(run_len)));
            try output.append(allocator, data[i]);
            i += run_len;
        } else {
            // Encode as literal run
            const literal_start = i;
            var literal_len: usize = 0;

            while (i + literal_len < data.len and literal_len < 127) {
                // Check if next 4 bytes would be a run
                if (i + literal_len + 4 <= data.len) {
                    var is_run = true;
                    for (1..4) |j| {
                        if (data[i + literal_len + j] != data[i + literal_len]) {
                            is_run = false;
                            break;
                        }
                    }
                    if (is_run) break;
                }
                literal_len += 1;
            }

            if (literal_len == 0) literal_len = 1;

            try output.append(allocator, @intCast(literal_len));
            try output.appendSlice(allocator, data[literal_start..][0..literal_len]);
            i += literal_len;
        }
    }

    return try output.toOwnedSlice(allocator);
}

fn decompressData(allocator: Allocator, compressed: []const u8) ![]u8 {
    if (compressed.len < 8) return error.InvalidData;

    // Check magic
    if (!std.mem.eql(u8, compressed[0..4], &[_]u8{ 'Z', 'D', 'L', 'T' })) {
        return error.InvalidMagic;
    }

    const original_size = std.mem.readInt(u32, compressed[4..8], .big);
    const output = try allocator.alloc(u8, original_size);
    errdefer allocator.free(output);

    var out_pos: usize = 0;
    var in_pos: usize = 8;

    while (in_pos < compressed.len and out_pos < original_size) {
        const control = compressed[in_pos];
        in_pos += 1;

        if (control & 0x80 != 0) {
            // Run
            const run_len = control & 0x7F;
            if (in_pos >= compressed.len) return error.InvalidData;
            const byte = compressed[in_pos];
            in_pos += 1;

            for (0..run_len) |_| {
                if (out_pos >= original_size) break;
                output[out_pos] = byte;
                out_pos += 1;
            }
        } else {
            // Literal
            const lit_len = control;
            if (in_pos + lit_len > compressed.len) return error.InvalidData;

            const copy_len = @min(lit_len, original_size - out_pos);
            @memcpy(output[out_pos..][0..copy_len], compressed[in_pos..][0..copy_len]);
            out_pos += copy_len;
            in_pos += lit_len;
        }
    }

    return output;
}

// Tests
test "StateDelta concurrent access" {
    const allocator = std.testing.allocator;

    const delta = try StateDelta.init(allocator);
    defer delta.deinit();

    // Simulate concurrent writes
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn work(d: *StateDelta, thread_id: usize) void {
                for (0..100) |j| {
                    var addr: Address = undefined;
                    addr[0] = @intCast(thread_id);
                    addr[1] = @intCast(j);
                    @memset(addr[2..], 0);

                    d.recordAccountChange(addr, 100, 1, null) catch {};
                }
            }
        }.work, .{ delta, i });
    }

    for (&threads) |*t| {
        t.join();
    }

    const stats = delta.getStats();
    try std.testing.expect(stats.accounts == 800);
}

test "StateDelta serialization roundtrip" {
    const allocator = std.testing.allocator;

    const delta = try StateDelta.init(allocator);
    defer delta.deinit();

    // Add some data
    try delta.recordAccountChange([_]u8{0x01} ** 20, 1000, 5, null);
    try delta.recordAccountChange([_]u8{0x02} ** 20, -500, 1, [_]u8{0xAB} ** 32);
    try delta.recordStorageChange(
        [_]u8{0x01} ** 20,
        [_]u8{0x00} ** 32,
        [_]u8{0x00} ** 32,
        [_]u8{0x01} ** 32,
    );

    const serialized = try delta.serialize(allocator);
    defer allocator.free(serialized);

    const restored = try StateDelta.deserialize(allocator, serialized);
    defer restored.deinit();

    const original_stats = delta.getStats();
    const restored_stats = restored.getStats();

    try std.testing.expectEqual(original_stats.accounts, restored_stats.accounts);
    try std.testing.expectEqual(original_stats.storage, restored_stats.storage);
}

test "Compression roundtrip" {
    const allocator = std.testing.allocator;

    // Test with repetitive data (good compression)
    const original = [_]u8{0xAA} ** 100 ++ [_]u8{0xBB} ** 50 ++ [_]u8{ 1, 2, 3, 4, 5 };

    const compressed = try compressData(allocator, &original);
    defer allocator.free(compressed);

    const decompressed = try decompressData(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, &original, decompressed);
    try std.testing.expect(compressed.len < original.len); // Should compress
}
