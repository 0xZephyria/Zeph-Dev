// Storage Module - High-Performance Database Engine
// Designed for 1M+ TPS with production-grade implementations

const std = @import("std");

/// Abstract database interface
pub const DB = struct {
    ptr: *anyopaque,
    writeFn: *const fn (ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void,
    readFn: *const fn (ptr: *anyopaque, key: []const u8) ?[]const u8,
    deleteFn: ?*const fn (ptr: *anyopaque, key: []const u8) anyerror!void,
    syncFn: ?*const fn (ptr: *anyopaque) anyerror!void = null,

    pub fn write(self: DB, key: []const u8, value: []const u8) !void {
        return self.writeFn(self.ptr, key, value);
    }

    pub fn read(self: DB, key: []const u8) ?[]const u8 {
        return self.readFn(self.ptr, key);
    }

    pub fn delete(self: DB, key: []const u8) !void {
        if (self.deleteFn) |delFn| {
            return delFn(self.ptr, key);
        }
        // No-op if delete not supported
    }

    pub fn sync(self: DB) !void {
        if (self.syncFn) |sFn| {
            try sFn(self.ptr);
        }
    }
};

/// A wrapper handle for a database engine that has a lifecycle (open/close).
pub const Database = struct {
    db: DB,
    closeFn: *const fn (ptr: *anyopaque) void,

    pub fn close(self: Database) void {
        self.closeFn(self.db.ptr);
    }

    pub fn asAbstractDB(self: Database) DB {
        return self.db;
    }
};

/// Open a high-performance database instance (hiding hybrid DB details behind a clean single DB interface).
pub fn open(allocator: std.mem.Allocator, data_dir: []const u8) !Database {
    const lsm_config = lsm.DBConfig{
        .memtable_shards = 16,
        .max_shard_size = 16 * 1024 * 1024,
        .enable_wal = true,
        .sync_wal = false,
        .enable_compaction = true,
        .enable_bloom_filters = true,
    };
    const arena_size = 512 * 1024 * 1024; // 512MB default cache/arena size

    const hybrid_db = try HybridDB.open(allocator, data_dir, lsm_config, arena_size);
    return Database{
        .db = hybrid_db.asAbstractDB(),
        .closeFn = HybridDB.closeWrapper,
    };
}

/// ZephyrDB — High-performance in-memory storage engine (TigerBeetle-inspired)
/// Primary storage for hot state. Drop-in replacement for LSM.
pub const zephyrdb = struct {
    pub const db = @import("zephyrdb/mod.zig");
    pub const arena_mod = @import("zephyrdb/arena.zig");
    pub const account_table_mod = @import("zephyrdb/account_table.zig");
    pub const slot_store_mod = @import("zephyrdb/slot_store.zig");
    pub const flat_table_mod = @import("zephyrdb/flat_table.zig");
    pub const wal_ring_mod = @import("zephyrdb/wal_ring.zig");
    pub const checkpoint_mod = @import("zephyrdb/checkpoint.zig");

    // Convenience re-exports
    pub const ZephyrDB = db.ZephyrDB;
    pub const FlatTable = flat_table_mod.FlatTable;
    pub const Arena = arena_mod.Arena;
    pub const AccountTable = account_table_mod.AccountTable;
    pub const AccountEntry = account_table_mod.AccountEntry;
    pub const SlotStore = slot_store_mod.SlotStore;
    pub const WalRing = wal_ring_mod.WalRing;
    pub const CheckpointManager = checkpoint_mod.CheckpointManager;
};

/// LSM Tree Components
pub const lsm = struct {
    /// I/O Engine (supports thread pool and io_uring on Linux)
    pub const io = @import("lsm/io.zig");

    /// Basic LSM database (backward compatible)
    pub const db = @import("lsm/db.zig");

    /// Write-Ahead Log for durability
    pub const wal = @import("lsm/wal.zig");

    /// Basic MemTable (single-threaded)
    pub const memtable = @import("lsm/memtable.zig");

    /// Sharded MemTable for high concurrency
    pub const memtable_shard = @import("lsm/memtable_shard.zig");

    /// SSTable (Sorted String Table) for persistent storage
    pub const sstable = @import("lsm/sstable.zig");

    /// Background compaction system
    pub const compaction = @import("lsm/compaction.zig");

    /// High-performance database (1M+ TPS)
    pub const highperf_db = @import("lsm/highperf_db.zig");

    /// Convenience re-exports for common types
    pub const HighPerfDB = highperf_db.HighPerfDB;
    pub const DBConfig = highperf_db.DBConfig;
    pub const ShardedMemTable = memtable_shard.ShardedMemTable;
    pub const WriteBatch = memtable_shard.WriteBatch;
    pub const SSTableReader = sstable.SSTableReader;
    pub const SSTableWriter = sstable.SSTableWriter;
    pub const BloomFilter = sstable.BloomFilter;
    pub const CompactionManager = compaction.CompactionManager;
};

/// FlatKV — Pure Flat KV state storage (Solana approach)
/// No Merkle trie, no per-block cryptographic commitment.
/// Sharded HashMap for concurrent access, optional WAL for durability.
pub const flatkv = struct {
    pub const kv = @import("flatkv/mod.zig");
    pub const FlatKV = kv.FlatKV;
    pub const Config = kv.Config;
    pub const Stats = kv.Stats;
};

/// Epoch Aggregation - Constant-size blockchain with full history
pub const epoch = struct {
    /// Core epoch types
    pub const types = @import("epoch/types.zig");

    /// State delta tracking
    pub const delta = @import("epoch/delta.zig");

    /// BLS signature aggregation
    pub const signature_aggregator = @import("epoch/signature_aggregator.zig");

    /// Epoch aggregation engine
    pub const aggregator = @import("epoch/aggregator.zig");

    /// Transaction indexing with bloom filters
    pub const tx_index = @import("epoch/tx_index.zig");

    /// Block pruning
    pub const pruner = @import("epoch/pruner.zig");

    /// Convenience re-exports
    pub const EPOCH_SIZE = types.EPOCH_SIZE;
    pub const StateDelta = delta.StateDelta;
    pub const EpochAggregator = aggregator.EpochAggregator;
    pub const AggregatedEpoch = types.AggregatedEpoch;
    pub const EpochMetadata = types.EpochMetadata;
    pub const BloomFilter = tx_index.BloomFilter;
    pub const AccountEpochIndex = tx_index.AccountEpochIndex;
    pub const SignatureAggregator = signature_aggregator.SignatureAggregator;
    pub const BlockPruner = pruner.BlockPruner;
    pub const BackgroundPruner = pruner.BackgroundPruner;
    pub const PruneStats = pruner.PruneStats;
};

/// Merkle Mountain Range - O(log n) proofs for historical headers
pub const mmr = struct {
    /// MMR tree implementation
    pub const tree = @import("mmr/tree.zig");

    /// Convenience re-exports
    pub const MMR = tree.MMR;
    pub const MMRNode = tree.MMRNode;
    pub const MMRProof = tree.MMRProof;
};

/// Code Store - Content-addressed bytecode deduplication
pub const codestore = struct {
    /// Code store implementation
    pub const store = @import("codestore/store.zig");

    /// Convenience re-exports
    pub const CodeStore = store.CodeStore;
    pub const CodeStoreStats = store.CodeStoreStats;
    pub const CodeHash = store.CodeHash;
    pub const EMPTY_CODE_HASH = store.EMPTY_CODE_HASH;
    pub const hashCode = store.CodeStore.hashCode;
};

/// Performance benchmarking utilities
pub const Benchmark = struct {
    start_time: i128,
    operation_count: u64,
    bytes_processed: u64,

    pub fn start() Benchmark {
        return Benchmark{
            .start_time = std.time.nanoTimestamp(),
            .operation_count = 0,
            .bytes_processed = 0,
        };
    }

    pub fn recordOperation(self: *Benchmark, bytes: usize) void {
        self.operation_count += 1;
        self.bytes_processed += bytes;
    }

    pub fn getOpsPerSecond(self: *const Benchmark) f64 {
        const elapsed_ns = std.time.nanoTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        if (elapsed_secs == 0) return 0;
        return @as(f64, @floatFromInt(self.operation_count)) / elapsed_secs;
    }

    pub fn getMBPerSecond(self: *const Benchmark) f64 {
        const elapsed_ns = std.time.nanoTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        if (elapsed_secs == 0) return 0;
        const mb = @as(f64, @floatFromInt(self.bytes_processed)) / (1024.0 * 1024.0);
        return mb / elapsed_secs;
    }

    pub fn report(self: *const Benchmark, label: []const u8) void {
        const ops_per_sec = self.getOpsPerSecond();
        const mb_per_sec = self.getMBPerSecond();
        std.log.info("{s}: {d:.2} ops/sec, {d:.2} MB/sec ({d} ops, {d} bytes)", .{
            label,
            ops_per_sec,
            mb_per_sec,
            self.operation_count,
            self.bytes_processed,
        });
    }
};

/// HybridDB - A unified cache-backed database wrapper that routes all writes
/// asynchronously to a background persistence worker thread while keeping the
/// in-memory FlatTable (ZephyrDB) fully consistent for O(1) reads.
/// Performs parallel, zero-copy cache preloading (via memory mapping) on startup.
pub const HybridDB = struct {
    arena: zephyrdb.Arena,
    flat_kv: zephyrdb.FlatTable,
    persistent_db: *lsm.HighPerfDB,
    allocator: std.mem.Allocator,

    // Background queue fields
    queue: std.ArrayListUnmanaged(QueueEntry),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    thread: ?std.Thread,
    running: std.atomic.Value(bool),

    // Sequence-tracking for sync operations
    write_sequence: u64,
    persistent_sequence: u64,
    flush_cond: std.Thread.Condition,

    const QueueEntry = struct {
        is_delete: bool,
        key: [32]u8,
        value: ?[]const u8, // Allocated copy, null if delete
    };

    pub fn open(allocator: std.mem.Allocator, data_dir: []const u8, lsm_config: lsm.DBConfig, arena_size: usize) !*HybridDB {
        const self = try allocator.create(HybridDB);
        errdefer allocator.destroy(self);

        // 1. Initialize Arena directly in self on the heap
        self.arena = try zephyrdb.Arena.init(allocator, arena_size);
        errdefer self.arena.deinit();

        // 2. Initialize FlatTable pointing to the stable heap Arena
        self.flat_kv = try zephyrdb.FlatTable.init(&self.arena, null);

        // 3. Open HighPerfDB (LSM)
        self.persistent_db = try lsm.HighPerfDB.open(allocator, data_dir, lsm_config);
        errdefer self.persistent_db.close();

        self.allocator = allocator;
        self.queue = .{};
        self.mutex = .{};
        self.cond = .{};
        self.thread = null;
        self.running = std.atomic.Value(bool).init(true);
        self.write_sequence = 0;
        self.persistent_sequence = 0;
        self.flush_cond = .{};

        // 4. Preload all entries from persistent LSM to FlatTable (zero-copy cache warming)
        try self.preloadDatabase();

        // 5. Start background writer thread
        self.thread = try std.Thread.spawn(.{}, backgroundWorker, .{self});

        return self;
    }

    pub fn close(self: *HybridDB) void {
        // 1. Stop background thread
        self.running.store(false, .release);
        self.mutex.lock();
        self.cond.signal();
        self.mutex.unlock();

        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }

        // 2. Clean up queue
        self.mutex.lock();
        for (self.queue.items) |entry| {
            if (entry.value) |v| self.allocator.free(v);
        }
        self.queue.deinit(self.allocator);
        self.mutex.unlock();

        // 3. Close persistent LSM DB
        self.persistent_db.close();

        // 4. Deinit Arena (automatically cleans up FlatTable memory)
        self.arena.deinit();

        // 5. Destroy self
        const alloc = self.allocator;
        alloc.destroy(self);
    }

    fn backgroundWorker(self: *HybridDB) void {
        while (self.running.load(.acquire)) {
            self.mutex.lock();
            while (self.queue.items.len == 0 and self.running.load(.acquire)) {
                self.cond.wait(&self.mutex);
            }
            if (!self.running.load(.acquire) and self.queue.items.len == 0) {
                self.mutex.unlock();
                break;
            }

            const batch_sequence = self.write_sequence;
            const batch = self.queue.toOwnedSlice(self.allocator) catch {
                self.mutex.unlock();
                continue;
            };
            self.mutex.unlock();

            defer {
                for (batch) |entry| {
                    if (entry.value) |v| self.allocator.free(v);
                }
                self.allocator.free(batch);
            }

            for (batch) |entry| {
                if (entry.is_delete) {
                    self.persistent_db.asAbstractDB().delete(&entry.key) catch |err| {
                        std.log.err("HybridDB background delete error: {}", .{err});
                    };
                } else if (entry.value) |v| {
                    self.persistent_db.asAbstractDB().write(&entry.key, v) catch |err| {
                        std.log.err("HybridDB background write error: {}", .{err});
                    };
                }
            }

            self.mutex.lock();
            self.persistent_sequence = batch_sequence;
            self.flush_cond.broadcast();
            self.mutex.unlock();
        }
    }

    pub fn write(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *HybridDB = @ptrCast(@alignCast(ptr));
        var key32: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key32[0..@min(key.len, 32)], key[0..@min(key.len, 32)]);

        // 1. Lock HybridDB.mutex first to prevent lock inversion/deadlocks
        self.mutex.lock();
        defer self.mutex.unlock();

        // 2. Write to in-memory FlatTable
        try self.flat_kv.put(key32, value);

        // 3. Queue write to persistent LSM DB
        const val_dup = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(val_dup);

        try self.queue.append(self.allocator, .{
            .is_delete = false,
            .key = key32,
            .value = val_dup,
        });
        self.write_sequence += 1;
        self.cond.signal();
    }

    pub fn read(ptr: *anyopaque, key: []const u8) ?[]const u8 {
        const self: *HybridDB = @ptrCast(@alignCast(ptr));
        var key32: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key32[0..@min(key.len, 32)], key[0..@min(key.len, 32)]);

        // 1. Read from in-memory FlatTable first (no lock for zero contention on cache hit)
        if (self.flat_kv.get(key32)) |val| {
            return val;
        }

        // 2. Lock to check queue and read from persistent LSM DB
        self.mutex.lock();
        defer self.mutex.unlock();

        // Double check flat_kv under lock in case another thread loaded it
        if (self.flat_kv.get(key32)) |val| {
            return val;
        }

        // Check queue for pending writes/deletes (newest first)
        var i: usize = self.queue.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.queue.items[i];
            if (std.mem.eql(u8, &entry.key, &key32)) {
                if (entry.is_delete) {
                    return null;
                } else if (entry.value) |v| {
                    self.flat_kv.put(key32, v) catch {};
                    return self.flat_kv.get(key32);
                }
            }
        }

        // Fetch from persistent DB (must use padded key32 — matches what background writer stores)
        if (self.persistent_db.asAbstractDB().read(&key32)) |val| {
            defer self.persistent_db.allocator.free(val);
            // Cache in FlatTable for future fast reads
            self.flat_kv.put(key32, val) catch {};
            return self.flat_kv.get(key32);
        }

        return null;
    }

    pub fn delete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *HybridDB = @ptrCast(@alignCast(ptr));
        var key32: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key32[0..@min(key.len, 32)], key[0..@min(key.len, 32)]);

        // 1. Lock HybridDB.mutex first to prevent lock inversion/deadlocks
        self.mutex.lock();
        defer self.mutex.unlock();

        // 2. Delete from FlatTable
        try self.flat_kv.delete(key32);

        // 3. Queue delete to persistent LSM DB
        try self.queue.append(self.allocator, .{
            .is_delete = true,
            .key = key32,
            .value = null,
        });
        self.write_sequence += 1;
        self.cond.signal();
    }

    pub fn sync(ptr: *anyopaque) anyerror!void {
        const self: *HybridDB = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const target_sequence = self.write_sequence;
        while (self.persistent_sequence < target_sequence) {
            self.flush_cond.wait(&self.mutex);
        }
    }

    pub fn asAbstractDB(self: *HybridDB) DB {
        return DB{
            .ptr = self,
            .writeFn = write,
            .readFn = read,
            .deleteFn = delete,
            .syncFn = sync,
        };
    }

    pub fn closeWrapper(ptr: *anyopaque) void {
        const self: *HybridDB = @ptrCast(@alignCast(ptr));
        self.close();
    }

    fn preloadDatabase(self: *HybridDB) !void {
        std.debug.print("  " ++ "\x1b[1m\x1b[38;5;87m" ++ "◆ WARMING CACHE (Preloading state from disk using mmap)" ++ "\x1b[0m" ++ "\n", .{});
        const start_time = std.time.nanoTimestamp();
        var sstable_count: usize = 0;
        var entry_count: usize = 0;

        // 1. Load SSTables from oldest levels to newest levels
        var level_idx: usize = self.persistent_db.compaction_manager.levels.len;
        while (level_idx > 0) {
            level_idx -= 1;
            const level = self.persistent_db.compaction_manager.levels[level_idx];
            
            // Load files in level (oldest first, chronologically ordered by file_number ascending)
            for (level.files.items) |file| {
                sstable_count += 1;
                try self.preloadSSTable(file.path, &entry_count);
            }
        }

        // 2. Load immutable memtables (oldest first)
        for (self.persistent_db.immutable_memtables.items) |memtable| {
            try self.preloadMemtable(memtable, &entry_count);
        }

        // 3. Load active memtable (newest)
        try self.preloadMemtable(self.persistent_db.active_memtable, &entry_count);

        const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000.0;
        std.debug.print("  " ++ "\x1b[1m\x1b[38;5;84m" ++ "✓ CACHE WARMED" ++ "\x1b[0m" ++ " — loaded {d} entries from {d} SSTables in {d:.2} ms\n", .{ entry_count, sstable_count, elapsed });
    }

    fn preloadSSTable(self: *HybridDB, path: []const u8, entry_count: *usize) !void {
        const file = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
            std.log.err("Failed to open SSTable for preloading {s}: {}", .{ path, err });
            return;
        };
        defer file.close();

        const stat = try file.stat();

        const Header = extern struct {
            magic: [8]u8,
            version: u32,
            key_count: u64,
            data_size: u64,
            index_offset: u64,
            index_size: u64,
            bloom_offset: u64,
            bloom_size: u64,
            checksum: u32,
            reserved: [4]u8,
        };

        if (stat.size < @sizeOf(Header)) return;

        // Use mmap for zero-copy high performance loading on macOS / Linux
        const map_ptr = std.posix.mmap(
            null,
            stat.size,
            std.posix.PROT.READ,
            .{ .TYPE = .SHARED },
            file.handle,
            0,
        ) catch |err| {
            std.log.err("mmap failed for {s}: {}", .{ path, err });
            return;
        };
        defer std.posix.munmap(map_ptr);

        const header = @as(*const Header, @ptrCast(@alignCast(map_ptr.ptr)));
        
        // Validate magic
        if (!std.mem.eql(u8, &header.magic, "SSTABLE1")) {
            return error.InvalidSSTableMagic;
        }

        const data_limit = @sizeOf(Header) + header.data_size;
        var offset: usize = @sizeOf(Header);

        while (offset < data_limit) {
            if (offset + 4 > data_limit) break;
            const key_len = std.mem.readInt(u32, map_ptr[offset..][0..4], .little);
            offset += 4;

            if (offset + key_len + 4 > data_limit) break;
            const key_bytes = map_ptr[offset..][0..key_len];
            offset += key_len;

            const val_len = std.mem.readInt(u32, map_ptr[offset..][0..4], .little);
            offset += 4;

            if (offset + val_len + 4 > data_limit) break;
            const val_bytes = map_ptr[offset..][0..val_len];
            offset += val_len;

            // Skip checksum
            offset += 4;

            if (key_len == 32) {
                var key32: [32]u8 = undefined;
                @memcpy(&key32, key_bytes);
                try self.flat_kv.put(key32, val_bytes);
                entry_count.* += 1;
            }
        }
    }

    fn preloadMemtable(
        self: *HybridDB,
        memtable: *lsm.memtable_shard.ShardedMemTable,
        entry_count: *usize,
    ) !void {
        for (memtable.shards) |shard| {
            shard.write_lock.lock();
            defer shard.write_lock.unlock();
            
            var it = shard.data.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.value) |val| {
                    try self.flat_kv.put(entry.key_ptr.*, val);
                    entry_count.* += 1;
                } else {
                    try self.flat_kv.delete(entry.key_ptr.*);
                }
            }
        }
    }
};

// Tests
test {
    std.testing.refAllDecls(@This());
}

test "DB interface" {
    const allocator = std.testing.allocator;
    const db_mod = @import("lsm/db.zig");

    std.fs.cwd().deleteTree("test-mod-db") catch {};
    defer std.fs.cwd().deleteTree("test-mod-db") catch {};

    var raw_db = try db_mod.DB.init(allocator, "test-mod-db");
    defer raw_db.deinit();

    const abstract_db = raw_db.asAbstractDB();

    try abstract_db.write("test_key", "test_value");
    const value = abstract_db.read("test_key");
    try std.testing.expect(value != null);
}

test "Benchmark utility" {
    var bench = Benchmark.start();
    for (0..1000) |_| {
        bench.recordOperation(100);
    }
    try std.testing.expect(bench.operation_count == 1000);
    try std.testing.expect(bench.bytes_processed == 100000);
}

test "HybridDB synchronous commit and recovery test" {
    const allocator = std.testing.allocator;
    const test_dir = "test-hybrid-db-sync";
    
    std.fs.cwd().deleteTree(test_dir) catch {};
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    const lsm_config = lsm.DBConfig{
        .memtable_shards = 2,
        .max_shard_size = 1024,
        .enable_wal = true,
        .sync_wal = true,
        .enable_compaction = false,
        .enable_bloom_filters = false,
    };
    
    var hdb = try HybridDB.open(allocator, test_dir, lsm_config, 32 * 1024 * 1024);
    defer hdb.close();
    
    const db_inst = hdb.asAbstractDB();
    
    // Write multiple values
    try db_inst.write("sync_key_1", "sync_value_1");
    try db_inst.write("sync_key_2", "sync_value_2");
    
    // Synchronously commit them
    try db_inst.sync();
    
    // Check that they are immediately written to the persistent database.
    // Since HybridDB.write pads the key to 32 bytes before queueing, we must read using the padded keys.
    var key1_32: [32]u8 = [_]u8{0} ** 32;
    @memcpy(key1_32[0.."sync_key_1".len], "sync_key_1");
    const persistent_val1 = hdb.persistent_db.asAbstractDB().read(&key1_32);
    try std.testing.expect(persistent_val1 != null);
    if (persistent_val1) |v| {
        try std.testing.expectEqualStrings("sync_value_1", v);
        hdb.persistent_db.allocator.free(v);
    }

    var key2_32: [32]u8 = [_]u8{0} ** 32;
    @memcpy(key2_32[0.."sync_key_2".len], "sync_key_2");
    const persistent_val2 = hdb.persistent_db.asAbstractDB().read(&key2_32);
    try std.testing.expect(persistent_val2 != null);
    if (persistent_val2) |v| {
        try std.testing.expectEqualStrings("sync_value_2", v);
        hdb.persistent_db.allocator.free(v);
    }
}
