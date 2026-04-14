// High-Performance LSM Database
// Designed for 1M+ TPS with sharded memtables, SSTables, and background compaction

const std = @import("std");
const Allocator = std.mem.Allocator;
const fs = std.fs;

// Components
const ShardedMemTable = @import("memtable_shard.zig").ShardedMemTable;
const MemTableConfig = @import("memtable_shard.zig").Config;
const WriteBatch = @import("memtable_shard.zig").WriteBatch;
const Entry = @import("memtable_shard.zig").Entry;
const SSTableWriter = @import("sstable.zig").SSTableWriter;
const SSTableReader = @import("sstable.zig").SSTableReader;
const CompactionManager = @import("compaction.zig").CompactionManager;
const CompactionConfig = @import("compaction.zig").CompactionConfig;
const WAL = @import("wal.zig").WAL;
const io = @import("io.zig");

/// Database configuration
pub const DBConfig = struct {
    /// Number of memtable shards (power of 2)
    memtable_shards: usize = 16,
    /// Max size per shard before flush
    max_shard_size: usize = 16 * 1024 * 1024, // 16MB
    /// Enable WAL for durability
    enable_wal: bool = true,
    /// Sync WAL on every write (slower but safer)
    sync_wal: bool = false,
    /// Enable background compaction
    enable_compaction: bool = true,
    /// Compaction configuration
    compaction: CompactionConfig = .{},
    /// Enable bloom filters for read optimization
    enable_bloom_filters: bool = true,
    /// Block cache size
    block_cache_size: usize = 64 * 1024 * 1024, // 64MB
    /// Enable statistics collection
    enable_stats: bool = true,
};

/// High-Performance Database
pub const HighPerfDB = struct {
    allocator: Allocator,
    config: DBConfig,
    data_dir: []const u8,

    // Write path
    active_memtable: *ShardedMemTable,
    immutable_memtables: std.ArrayList(*ShardedMemTable),
    wal: ?*WAL,

    // Read path
    compaction_manager: *CompactionManager,
    sstable_cache: std.AutoHashMap(u64, *SSTableReader),

    // I/O
    io_engine: io.IoEngine,

    // Synchronization
    write_lock: std.Thread.RwLock,
    flush_mutex: std.Thread.Mutex,

    // Background threads
    running: std.atomic.Value(bool),
    flush_thread: ?std.Thread,

    // Statistics
    stats: Stats,

    const Self = @This();

    pub const Stats = struct {
        writes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        reads: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        cache_hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        cache_misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        flushes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        bytes_written: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        bytes_read: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    pub fn open(allocator: Allocator, data_dir: []const u8, config: DBConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Create data directory
        fs.cwd().makePath(data_dir) catch {};

        // Initialize I/O engine
        const io_engine = try io.create(allocator);

        // Initialize WAL
        var wal: ?*WAL = null;
        if (config.enable_wal) {
            const wal_path = try std.fmt.allocPrint(allocator, "{s}/wal.log", .{data_dir});
            defer allocator.free(wal_path);
            wal = try WAL.init(allocator, io_engine, wal_path);
        }

        // Initialize memtable
        const memtable_config = MemTableConfig{
            .num_shards = config.memtable_shards,
            .max_shard_size = config.max_shard_size,
        };
        const active_memtable = try ShardedMemTable.init(allocator, memtable_config);

        // Initialize compaction manager
        const compaction_manager = try CompactionManager.init(allocator, data_dir, config.compaction);

        self.* = Self{
            .allocator = allocator,
            .config = config,
            .data_dir = try allocator.dupe(u8, data_dir),
            .active_memtable = active_memtable,
            .immutable_memtables = std.ArrayList(*ShardedMemTable).init(allocator),
            .wal = wal,
            .compaction_manager = compaction_manager,
            .sstable_cache = std.AutoHashMap(u64, *SSTableReader).init(allocator),
            .io_engine = io_engine,
            .write_lock = std.Thread.RwLock{},
            .flush_mutex = std.Thread.Mutex{},
            .running = std.atomic.Value(bool).init(false),
            .flush_thread = null,
            .stats = Stats{},
        };

        // Recover from WAL if needed
        if (wal != null) {
            try self.recoverFromWAL();
        }

        // Start background threads
        try self.start();

        return self;
    }

    pub fn close(self: *Self) void {
        self.stop();

        // Flush remaining data
        self.flushAllMemtables() catch {};

        // Cleanup
        self.active_memtable.deinit();
        for (self.immutable_memtables.items) |memtable| {
            memtable.deinit();
        }
        self.immutable_memtables.deinit();

        if (self.wal) |wal| {
            wal.deinit();
        }

        self.compaction_manager.deinit();

        var it = self.sstable_cache.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.sstable_cache.deinit();

        self.io_engine.deinit();
        self.allocator.free(self.data_dir);
        self.allocator.destroy(self);
    }

    /// Put a key/value pair
    pub fn put(self: *Self, key: [32]u8, value: []const u8) !void {
        self.write_lock.lockShared();
        defer self.write_lock.unlockShared();

        // Write to WAL first (if enabled)
        if (self.wal) |wal| {
            var wal_entry = std.ArrayList(u8).init(self.allocator);
            defer wal_entry.deinit();
            try wal_entry.append(1); // PUT operation
            try wal_entry.appendSlice(&key);
            try wal_entry.appendSlice(std.mem.asBytes(&@as(u32, @intCast(value.len))));
            try wal_entry.appendSlice(value);
            try wal.append(wal_entry.items, 0);
        }

        // Write to memtable
        try self.active_memtable.put(key, value);

        // Update stats
        _ = self.stats.writes.fetchAdd(1, .monotonic);
        _ = self.stats.bytes_written.fetchAdd(32 + value.len, .monotonic);

        // Check if flush needed
        try self.maybeScheduleFlush();
    }

    /// Delete a key
    pub fn delete(self: *Self, key: [32]u8) !void {
        self.write_lock.lockShared();
        defer self.write_lock.unlockShared();

        // Write to WAL
        if (self.wal) |wal| {
            var wal_entry = std.ArrayList(u8).init(self.allocator);
            defer wal_entry.deinit();
            try wal_entry.append(0); // DELETE operation
            try wal_entry.appendSlice(&key);
            try wal.append(wal_entry.items, 0);
        }

        // Write tombstone to memtable
        try self.active_memtable.delete(key);
    }

    /// Get a value
    pub fn get(self: *Self, key: [32]u8) !?[]u8 {
        self.write_lock.lockShared();
        defer self.write_lock.unlockShared();

        _ = self.stats.reads.fetchAdd(1, .monotonic);

        // Check active memtable first
        if (self.active_memtable.get(key)) |value| {
            _ = self.stats.bytes_read.fetchAdd(value.len, .monotonic);
            return try self.allocator.dupe(u8, value);
        }

        // Check immutable memtables (newest first)
        var i = self.immutable_memtables.items.len;
        while (i > 0) {
            i -= 1;
            if (self.immutable_memtables.items[i].get(key)) |value| {
                _ = self.stats.bytes_read.fetchAdd(value.len, .monotonic);
                return try self.allocator.dupe(u8, value);
            }
        }

        // Check SSTables (level 0 first, then other levels)
        for (self.compaction_manager.levels) |level| {
            // Check newest files first
            var j = level.files.items.len;
            while (j > 0) {
                j -= 1;
                const file = level.files.items[j];

                // Get or open reader
                const reader = try self.getSSTableReader(file.file_number, file.path);

                // Check bloom filter first
                if (!reader.mightContain(key)) {
                    continue;
                }

                // Try to get value
                if (try reader.get(key)) |value| {
                    defer self.allocator.free(value);
                    _ = self.stats.cache_hits.fetchAdd(1, .monotonic);
                    _ = self.stats.bytes_read.fetchAdd(value.len, .monotonic);
                    return try self.allocator.dupe(u8, value);
                }
            }
        }

        _ = self.stats.cache_misses.fetchAdd(1, .monotonic);
        return null;
    }

    /// Write batch for atomic multi-key operations
    pub fn writeBatch(self: *Self, batch: *WriteBatch) !void {
        self.write_lock.lockShared();
        defer self.write_lock.unlockShared();

        // Write all to WAL as single entry
        if (self.wal) |wal| {
            var wal_entry = std.ArrayList(u8).init(self.allocator);
            defer wal_entry.deinit();

            try wal_entry.append(2); // BATCH operation
            try wal_entry.appendSlice(std.mem.asBytes(&@as(u32, @intCast(batch.count()))));

            for (batch.ops.items) |op| {
                try wal_entry.append(if (op.is_delete) @as(u8, 0) else @as(u8, 1));
                try wal_entry.appendSlice(&op.key);
                if (!op.is_delete) {
                    if (op.value) |value| {
                        try wal_entry.appendSlice(std.mem.asBytes(&@as(u32, @intCast(value.len))));
                        try wal_entry.appendSlice(value);
                    }
                }
            }
            try wal.append(wal_entry.items, 0);
        }

        // Apply to memtable
        try batch.apply(self.active_memtable);

        try self.maybeScheduleFlush();
    }

    /// Get database statistics
    pub fn getStats(self: *const Self) DBStats {
        const compaction_stats = self.compaction_manager.getStats();
        const memtable_stats = self.active_memtable.getStats();

        return DBStats{
            .writes = self.stats.writes.load(.acquire),
            .reads = self.stats.reads.load(.acquire),
            .cache_hits = self.stats.cache_hits.load(.acquire),
            .cache_misses = self.stats.cache_misses.load(.acquire),
            .flushes = self.stats.flushes.load(.acquire),
            .bytes_written = self.stats.bytes_written.load(.acquire),
            .bytes_read = self.stats.bytes_read.load(.acquire),
            .memtable_size = memtable_stats.total_size,
            .memtable_count = memtable_stats.total_count,
            .sstable_count = compaction_stats.total_files,
            .sstable_size = compaction_stats.total_size,
            .immutable_memtables = self.immutable_memtables.items.len,
        };
    }

    pub const DBStats = struct {
        writes: u64,
        reads: u64,
        cache_hits: u64,
        cache_misses: u64,
        flushes: u64,
        bytes_written: u64,
        bytes_read: u64,
        memtable_size: usize,
        memtable_count: u64,
        sstable_count: usize,
        sstable_size: u64,
        immutable_memtables: usize,
    };

    /// Compact asAbstractDB interface
    pub fn asAbstractDB(self: *Self) @import("../mod.zig").DB {
        return @import("../mod.zig").DB{
            .ptr = self,
            .writeFn = abstractWrite,
            .readFn = abstractRead,
        };
    }

    fn abstractWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // Hash key to 32 bytes
        var hashed_key: [32]u8 = undefined;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(key);
        hasher.final(&hashed_key);

        try self.put(hashed_key, value);
    }

    fn abstractRead(ptr: *anyopaque, key: []const u8) ?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));

        var hashed_key: [32]u8 = undefined;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(key);
        hasher.final(&hashed_key);

        return self.get(hashed_key) catch null;
    }

    // Internal methods

    fn start(self: *Self) !void {
        if (self.running.load(.acquire)) return;

        self.running.store(true, .release);
        self.flush_thread = try std.Thread.spawn(.{}, flushLoop, .{self});

        if (self.config.enable_compaction) {
            try self.compaction_manager.start();
        }
    }

    fn stop(self: *Self) void {
        self.running.store(false, .release);

        if (self.flush_thread) |thread| {
            thread.join();
            self.flush_thread = null;
        }

        self.compaction_manager.stop();
    }

    fn flushLoop(self: *Self) void {
        while (self.running.load(.acquire)) {
            // Check for immutable memtables to flush
            self.flush_mutex.lock();
            const memtable_opt = if (self.immutable_memtables.items.len > 0)
                self.immutable_memtables.orderedRemove(0)
            else
                null;
            self.flush_mutex.unlock();

            if (memtable_opt) |memtable| {
                self.flushMemtable(memtable) catch |err| {
                    std.log.err("Flush error: {}", .{err});
                };
            } else {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
        }
    }

    fn maybeScheduleFlush(self: *Self) !void {
        const shards_to_flush = try self.active_memtable.getShardsNeedingFlush();
        defer shards_to_flush.deinit();

        if (shards_to_flush.items.len > 0) {
            // Rotate memtable
            self.write_lock.lock();
            defer self.write_lock.unlock();

            const old_memtable = self.active_memtable;

            const memtable_config = MemTableConfig{
                .num_shards = self.config.memtable_shards,
                .max_shard_size = self.config.max_shard_size,
            };
            self.active_memtable = try ShardedMemTable.init(self.allocator, memtable_config);

            self.flush_mutex.lock();
            try self.immutable_memtables.append(old_memtable);
            self.flush_mutex.unlock();
        }
    }

    fn flushMemtable(self: *Self, memtable: *ShardedMemTable) !void {
        const file_number = self.compaction_manager.getNextFileNumber();
        const path = try self.compaction_manager.getSSTablePath(file_number);
        defer self.allocator.free(path);

        // Collect all entries from all shards
        var all_entries = std.ArrayList(Entry).init(self.allocator);
        defer {
            for (all_entries.items) |*entry| {
                entry.free(self.allocator);
            }
            all_entries.deinit();
        }

        for (memtable.shards) |shard| {
            const sorted = try shard.getSorted(self.allocator);
            defer {
                for (sorted) |*e| {
                    var entry = e;
                    entry.free(self.allocator);
                }
                self.allocator.free(sorted);
            }
            for (sorted) |entry| {
                try all_entries.append(try entry.dupe(self.allocator));
            }
        }

        // Sort all entries
        std.mem.sort(Entry, all_entries.items, {}, struct {
            fn lessThan(_: void, a: Entry, b: Entry) bool {
                return std.mem.order(u8, &a.key, &b.key) == .lt;
            }
        }.lessThan);

        // Write SSTable
        var writer = try SSTableWriter.init(self.allocator, path, all_entries.items.len);
        defer writer.deinit();

        var smallest_key: [32]u8 = [_]u8{0xFF} ** 32;
        var largest_key: [32]u8 = [_]u8{0x00} ** 32;

        for (all_entries.items) |entry| {
            if (entry.value) |value| { // Skip tombstones in level 0
                try writer.add(entry.key, value);

                if (std.mem.order(u8, &entry.key, &smallest_key) == .lt) {
                    smallest_key = entry.key;
                }
                if (std.mem.order(u8, &entry.key, &largest_key) == .gt) {
                    largest_key = entry.key;
                }
            }
        }

        _ = try writer.finish();

        // Add to compaction manager
        const stat = try fs.cwd().statFile(path);
        try self.compaction_manager.addSSTable(.{
            .file_number = file_number,
            .file_size = stat.size,
            .smallest_key = smallest_key,
            .largest_key = largest_key,
            .level = 0,
            .path = try self.allocator.dupe(u8, path),
            .key_count = all_entries.items.len,
        });

        // Cleanup memtable
        memtable.deinit();

        _ = self.stats.flushes.fetchAdd(1, .monotonic);
    }

    fn flushAllMemtables(self: *Self) !void {
        // Flush active memtable
        const memtable_config = MemTableConfig{
            .num_shards = self.config.memtable_shards,
            .max_shard_size = self.config.max_shard_size,
        };

        self.write_lock.lock();
        const old_active = self.active_memtable;
        self.active_memtable = try ShardedMemTable.init(self.allocator, memtable_config);
        self.write_lock.unlock();

        try self.flushMemtable(old_active);

        // Flush all immutable memtables
        self.flush_mutex.lock();
        const immutables = self.immutable_memtables.toOwnedSlice() catch return;
        self.flush_mutex.unlock();
        defer self.allocator.free(immutables);

        for (immutables) |memtable| {
            try self.flushMemtable(memtable);
        }
    }

    fn recoverFromWAL(self: *Self) !void {
        if (self.wal) |wal| {
            try wal.replay(self, recoverEntry);
        }
    }

    fn recoverEntry(self: *Self, data: []const u8) !void {
        if (data.len < 1) return;

        const op = data[0];

        switch (op) {
            0 => { // DELETE
                if (data.len < 33) return;
                var key: [32]u8 = undefined;
                @memcpy(&key, data[1..33]);
                try self.active_memtable.delete(key);
            },
            1 => { // PUT
                if (data.len < 37) return;
                var key: [32]u8 = undefined;
                @memcpy(&key, data[1..33]);
                const value_len = std.mem.readInt(u32, data[33..37], .little);
                if (data.len < 37 + value_len) return;
                const value = data[37..][0..value_len];
                try self.active_memtable.put(key, value);
            },
            2 => { // BATCH
                // Parse and apply batch
                if (data.len < 5) return;
                const count = std.mem.readInt(u32, data[1..5], .little);
                var offset: usize = 5;
                for (0..count) |_| {
                    if (offset >= data.len) break;
                    const batch_op = data[offset];
                    offset += 1;
                    if (offset + 32 > data.len) break;
                    var key: [32]u8 = undefined;
                    @memcpy(&key, data[offset..][0..32]);
                    offset += 32;

                    if (batch_op == 1) {
                        if (offset + 4 > data.len) break;
                        const val_len = std.mem.readInt(u32, data[offset..][0..4], .little);
                        offset += 4;
                        if (offset + val_len > data.len) break;
                        const value = data[offset..][0..val_len];
                        offset += val_len;
                        try self.active_memtable.put(key, value);
                    } else {
                        try self.active_memtable.delete(key);
                    }
                }
            },
            else => {},
        }
    }

    fn getSSTableReader(self: *Self, file_number: u64, path: []const u8) !*SSTableReader {
        if (self.sstable_cache.get(file_number)) |reader| {
            return reader;
        }

        const reader = try SSTableReader.open(self.allocator, path);
        try self.sstable_cache.put(file_number, reader);
        return reader;
    }
};

// Tests

test "HighPerfDB basic operations" {
    const allocator = std.testing.allocator;

    const test_dir = "/tmp/test_highperf_db";
    fs.cwd().deleteTree(test_dir) catch {};
    defer fs.cwd().deleteTree(test_dir) catch {};

    const config = DBConfig{
        .memtable_shards = 4,
        .max_shard_size = 1024, // Small for testing
        .enable_wal = true,
        .enable_compaction = false, // Disable for simple test
    };

    var db = try HighPerfDB.open(allocator, test_dir, config);
    defer db.close();

    const key: [32]u8 = [_]u8{0xAA} ** 32;
    const value = "hello high performance db";

    try db.put(key, value);

    if (try db.get(key)) |got| {
        defer allocator.free(got);
        try std.testing.expectEqualStrings(value, got);
    } else {
        return error.ValueNotFound;
    }

    const stats = db.getStats();
    try std.testing.expect(stats.writes == 1);
    try std.testing.expect(stats.reads == 1);
}

test "HighPerfDB batch operations" {
    const allocator = std.testing.allocator;

    const test_dir = "/tmp/test_highperf_batch";
    fs.cwd().deleteTree(test_dir) catch {};
    defer fs.cwd().deleteTree(test_dir) catch {};

    const config = DBConfig{
        .memtable_shards = 2,
        .enable_wal = false,
        .enable_compaction = false,
    };

    var db = try HighPerfDB.open(allocator, test_dir, config);
    defer db.close();

    var batch = WriteBatch.init(allocator);
    defer batch.deinit();

    const key1: [32]u8 = [_]u8{0x01} ** 32;
    const key2: [32]u8 = [_]u8{0x02} ** 32;

    try batch.put(key1, "value1");
    try batch.put(key2, "value2");

    try db.writeBatch(&batch);

    const v1 = try db.get(key1);
    defer if (v1) |v| allocator.free(v);
    try std.testing.expect(v1 != null);

    const v2 = try db.get(key2);
    defer if (v2) |v| allocator.free(v);
    try std.testing.expect(v2 != null);
}
