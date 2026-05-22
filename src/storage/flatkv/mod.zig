const std = @import("std");
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const WalRing = @import("../zephyrdb/wal_ring.zig").WalRing;
const WalConfig = @import("../zephyrdb/wal_ring.zig").WalConfig;
const abstract_db = @import("../mod.zig").DB;

pub const Config = struct {
    num_shards: usize = 64,
    enable_wal: bool = true,
    wal: WalConfig = .{},
    enable_stats: bool = true,
    data_dir: []const u8 = "",
};

pub const Stats = struct {
    puts: u64,
    gets: u64,
    deletes: u64,
    bytes_written: u64,
    bytes_read: u64,
    shard_count: usize,
    approx_entry_count: usize,
};

const Shard = struct {
    data: std.AutoHashMap([32]u8, []u8),
    lock: std.Thread.RwLock,
    count: Atomic(u64),

    fn init(allocator: Allocator) Shard {
        return .{
            .data = std.AutoHashMap([32]u8, []u8).init(allocator),
            .lock = .{},
            .count = Atomic(u64).init(0),
        };
    }

    fn deinit(self: *Shard) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.data.allocator.free(entry.value_ptr.*);
        }
        self.data.deinit();
    }

    fn put(self: *Shard, key: [32]u8, value: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.data.get(key)) |old| {
            self.data.allocator.free(old);
        } else {
            _ = self.count.fetchAdd(1, .monotonic);
        }
        const val_copy = try self.data.allocator.dupe(u8, value);
        errdefer self.data.allocator.free(val_copy);
        try self.data.put(key, val_copy);
    }

    fn get(self: *Shard, key: [32]u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return if (self.data.get(key)) |entry| entry else null;
    }

    fn delete(self: *Shard, key: [32]u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.data.fetchRemove(key)) |entry| {
            self.data.allocator.free(entry.value);
            _ = self.count.fetchSub(1, .monotonic);
        }
    }
};

pub const FlatKV = struct {
    allocator: Allocator,
    shards: []Shard,
    num_shards: usize,
    wal: ?*WalRing,
    config: Config,
    puts: Atomic(u64),
    gets: Atomic(u64),
    deletes: Atomic(u64),
    bytes_written: Atomic(u64),
    bytes_read: Atomic(u64),

    const Self = @This();

    pub fn init(allocator: Allocator, config: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const num_shards = if (config.num_shards == 0) 64 else config.num_shards;
        const shards = try allocator.alloc(Shard, num_shards);
        errdefer allocator.free(shards);

        for (0..num_shards) |i| {
            shards[i] = Shard.init(allocator);
        }

        var wal: ?*WalRing = null;
        if (config.enable_wal and config.data_dir.len > 0) {
            var wal_config = config.wal;
            const wal_path = try std.fmt.allocPrint(allocator, "{s}/flatkv.wal", .{config.data_dir});
            defer allocator.free(wal_path);
            wal_config.file_path = wal_path;
            wal_config.enable_background_flush = true;
            wal = try allocator.create(WalRing);
            wal.* = try WalRing.init(allocator, wal_config);
        }

        self.* = .{
            .allocator = allocator,
            .shards = shards,
            .num_shards = num_shards,
            .wal = wal,
            .config = config,
            .puts = Atomic(u64).init(0),
            .gets = Atomic(u64).init(0),
            .deletes = Atomic(u64).init(0),
            .bytes_written = Atomic(u64).init(0),
            .bytes_read = Atomic(u64).init(0),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.wal) |wal| {
            wal.deinit();
            self.allocator.destroy(wal);
        }
        for (self.shards) |*s| s.deinit();
        self.allocator.free(self.shards);
        self.allocator.destroy(self);
    }

    inline fn shardIndex(key: []const u8) usize {
        var hash: u64 = 0;
        for (key, 0..) |b, i| {
            if (i >= 8) break;
            hash ^= @as(u64, b) << @intCast((i % 8) * 8);
        }
        return @intCast(hash);
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) !void {
        var k: [32]u8 = undefined;
        if (key.len >= 32) {
            @memcpy(&k, key[0..32]);
        } else {
            @memset(&k, 0);
            @memcpy(&k, key);
        }
        const idx = shardIndex(key) % self.shards.len;
        try self.shards[idx].put(k, value);
        _ = self.puts.fetchAdd(1, .monotonic);
        _ = self.bytes_written.fetchAdd(value.len, .monotonic);

        if (self.wal) |wal| {
            var wal_key: [32]u8 = undefined;
            @memcpy(&wal_key, &k);
            var wal_val: [32]u8 = undefined;
            @memset(&wal_val, 0);
            const copy_len = @min(value.len, 32);
            @memcpy(wal_val[0..copy_len], value[0..copy_len]);
            wal.append(.StoragePut, wal_key, wal_val) catch {};
        }
    }

    pub fn get(self: *Self, key: []const u8) ?[]const u8 {
        var k: [32]u8 = undefined;
        if (key.len >= 32) {
            @memcpy(&k, key[0..32]);
        } else {
            @memset(&k, 0);
            @memcpy(&k, key);
        }
        const idx = shardIndex(key) % self.shards.len;
        _ = self.gets.fetchAdd(1, .monotonic);
        const result = self.shards[idx].get(k);
        if (result) |v| {
            _ = self.bytes_read.fetchAdd(v.len, .monotonic);
        }
        return result;
    }

    pub fn delete(self: *Self, key: []const u8) !void {
        var k: [32]u8 = undefined;
        if (key.len >= 32) {
            @memcpy(&k, key[0..32]);
        } else {
            @memset(&k, 0);
            @memcpy(&k, key);
        }
        const idx = shardIndex(key) % self.shards.len;
        try self.shards[idx].delete(k);
        _ = self.deletes.fetchAdd(1, .monotonic);
    }

    pub fn getStats(self: *const Self) Stats {
        var total_entries: usize = 0;
        for (self.shards) |*s| {
            total_entries += @intCast(s.count.load(.acquire));
        }
        return .{
            .puts = self.puts.load(.acquire),
            .gets = self.gets.load(.acquire),
            .deletes = self.deletes.load(.acquire),
            .bytes_written = self.bytes_written.load(.acquire),
            .bytes_read = self.bytes_read.load(.acquire),
            .shard_count = self.num_shards,
            .approx_entry_count = total_entries,
        };
    }

    pub fn asAbstractDB(self: *Self) abstract_db {
        return .{
            .ptr = self,
            .writeFn = abstractWrite,
            .readFn = abstractRead,
            .deleteFn = abstractDelete,
        };
    }

    fn abstractWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        try self.put(key, value);
    }

    fn abstractRead(ptr: *anyopaque, key: []const u8) ?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.get(key);
    }

    fn abstractDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        try self.delete(key);
    }
};

test "FlatKV basic put/get" {
    const allocator = std.testing.allocator;
    var kv = try FlatKV.init(allocator, .{ .enable_wal = false, .num_shards = 4 });
    defer kv.deinit();

    const key = [_]u8{0xAA} ** 32;
    try kv.put(&key, "hello flatkv");

    const result = kv.get(&key);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("hello flatkv", result.?);
}

test "FlatKV concurrent shards" {
    const allocator = std.testing.allocator;
    var kv = try FlatKV.init(allocator, .{ .enable_wal = false, .num_shards = 4 });
    defer kv.deinit();

    for (0..100) |i| {
        var k: [32]u8 = undefined;
        @memset(&k, @intCast(i));
        try kv.put(&k, "val");
    }

    try std.testing.expectEqual(@as(u64, 100), kv.getStats().puts);
}

test "FlatKV delete" {
    const allocator = std.testing.allocator;
    var kv = try FlatKV.init(allocator, .{ .enable_wal = false, .num_shards = 2 });
    defer kv.deinit();

    const key = [_]u8{0xBB} ** 32;
    try kv.put(&key, "to_delete");
    try std.testing.expect(kv.get(&key) != null);

    try kv.delete(&key);
    try std.testing.expect(kv.get(&key) == null);
}
