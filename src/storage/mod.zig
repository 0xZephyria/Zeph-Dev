// Storage Module - High-Performance Database and Verkle Trie
// Designed for 1M+ TPS with production-grade implementations

const std = @import("std");

/// Abstract database interface
pub const DB = struct {
    ptr: *anyopaque,
    writeFn: *const fn (ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void,
    readFn: *const fn (ptr: *anyopaque, key: []const u8) ?[]const u8,
    deleteFn: ?*const fn (ptr: *anyopaque, key: []const u8) anyerror!void,

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
};

/// ZephyrDB — High-performance in-memory storage engine (TigerBeetle-inspired)
/// Primary storage for hot state. Drop-in replacement for LSM.
pub const zephyrdb = struct {
    pub const db = @import("zephyrdb/mod.zig");
    pub const arena_mod = @import("zephyrdb/arena.zig");
    pub const account_table_mod = @import("zephyrdb/account_table.zig");
    pub const slot_store_mod = @import("zephyrdb/slot_store.zig");
    pub const wal_ring_mod = @import("zephyrdb/wal_ring.zig");
    pub const checkpoint_mod = @import("zephyrdb/checkpoint.zig");

    // Convenience re-exports
    pub const ZephyrDB = db.ZephyrDB;
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

/// Verkle Trie Components (for state storage)
pub const verkle = struct {
    /// Node types (Internal, Leaf, Hashed)
    pub const node = @import("verkle/node.zig");

    /// Verkle Trie implementation
    pub const trie = @import("verkle/trie.zig");

    /// Cryptographic primitives (Banderwagon, IPA, CRS)
    pub const crypto = @import("verkle/lib/main.zig");

    /// Convenience re-exports
    pub const VerkleTrie = trie.VerkleTrie;
    pub const VerkleProof = trie.VerkleProof;
    pub const VerkleWriteBatch = trie.WriteBatch;
    pub const InternalNode = node.InternalNode;
    pub const LeafNode = node.LeafNode;
    pub const Node = node.Node;
    pub const Element = node.Element;
    pub const Fr = node.Fr;
    pub const CRS = node.CRS;
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
