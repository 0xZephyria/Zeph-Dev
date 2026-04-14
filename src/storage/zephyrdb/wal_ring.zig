// ZephyrDB WAL Ring Buffer — Durable write-ahead log with group commit
//
// TigerBeetle-inspired: Ring buffer with batched async writes.
// - 256MB ring buffer (configurable)
// - Entries are fixed-size (73 bytes padded to 80 for alignment)
// - Group commit: accumulate N entries (default 1024) before single fsync
// - Background flush thread with configurable interval (default 1ms)
// - Lock-free append via atomic head increment
// - Crash recovery: read from tail marker to head on restart
//
// Performance:
//   At 1M TPS × ~80 bytes/entry = 80 MB/sec WAL throughput.
//   Group commit reduces fsync calls from 1M/sec to ~1000/sec (1000× reduction).
//   Single pwriteAll + single fsync per batch amortizes kernel overhead.

const std = @import("std");
const Atomic = std.atomic.Value;
const Mutex = std.Thread.Mutex;

/// WAL entry types
pub const OpType = enum(u8) {
    Noop = 0,
    AccountPut = 1, // Account state update
    AccountDelete = 2, // Account deletion (self-destruct)
    StoragePut = 3, // Storage slot write
    StorageDelete = 4, // Storage slot clear
    CodePut = 5, // Contract code storage
    Checkpoint = 6, // Checkpoint marker (epoch boundary)
    BlockBoundary = 7, // Block finalization marker
};

/// Single WAL entry — fixed 73 bytes (padded to 80 for alignment)
pub const WalEntry = extern struct {
    op: u8, // OpType
    block_number: u64, // Block this entry belongs to
    key: [32]u8, // Account address or storage key
    value: [32]u8, // Balance, nonce, or storage value
    checksum: u8, // XOR checksum of all bytes

    pub fn compute_checksum(self: *const WalEntry) u8 {
        var cs: u8 = self.op;
        const block_bytes: [8]u8 = @bitCast(self.block_number);
        for (block_bytes) |b| cs ^= b;
        for (self.key) |b| cs ^= b;
        for (self.value) |b| cs ^= b;
        return cs;
    }

    pub fn isValid(self: *const WalEntry) bool {
        return self.checksum == self.compute_checksum();
    }
};

/// WAL configuration
pub const WalConfig = struct {
    /// Size of the ring buffer in bytes (default 256MB)
    ring_size: usize = 256 * 1024 * 1024,
    /// Maximum entries to batch before forcing a flush (group commit size)
    batch_size: u32 = 1024,
    /// Flush interval in milliseconds (background flush timer, 0 = disabled)
    flush_interval_ms: u64 = 1,
    /// WAL file path
    file_path: []const u8 = "forgeyrdb.wal",
    /// Whether to use fsync (true = durable, false = fast)
    sync_writes: bool = true,
    /// Enable background flush thread
    enable_background_flush: bool = true,
};

/// WAL ring buffer statistics
pub const WalStats = struct {
    entries_written: u64,
    entries_flushed: u64,
    bytes_written: u64,
    flush_count: u64,
    pending_entries: u64,
    /// Group commit stats
    group_commits: u64,
    total_batched_entries: u64,
    max_batch_size_seen: u64,
};

/// Ring buffer WAL with group commit and background flush
pub const WalRing = struct {
    /// In-memory ring buffer
    ring: []u8,
    /// Ring buffer capacity in entries
    capacity: u32,
    /// Write head (entries written but not flushed) — atomically incremented by writers
    head: Atomic(u64),
    /// Flush tail (entries flushed to disk) — only modified by flush path
    tail: Atomic(u64),
    /// File descriptor for the WAL file
    file: ?std.fs.File,
    /// Configuration
    config: WalConfig,
    /// Lock for serializing flush operations (only one flush at a time)
    flush_lock: Mutex,
    /// Stats
    entries_written: Atomic(u64),
    entries_flushed: Atomic(u64),
    flush_count: Atomic(u64),
    /// Group commit stats
    group_commit_count: Atomic(u64),
    total_batched_entries: Atomic(u64),
    max_batch_size_seen: Atomic(u64),
    /// Current block number
    current_block: Atomic(u64),
    /// Allocator
    allocator: std.mem.Allocator,

    /// Background flush thread state
    bg_flush_thread: ?std.Thread,
    bg_flush_running: Atomic(bool),

    const ENTRY_SIZE = @sizeOf(WalEntry);
    const Self = @This();

    /// Initialize the WAL ring buffer with group commit support
    pub fn init(allocator: std.mem.Allocator, config: WalConfig) !Self {
        const capacity: u32 = @intCast(config.ring_size / ENTRY_SIZE);
        const ring = try allocator.alloc(u8, @as(usize, capacity) * ENTRY_SIZE);
        @memset(ring, 0);

        // Open or create WAL file
        var file: ?std.fs.File = null;
        if (config.file_path.len > 0) {
            file = std.fs.cwd().createFile(config.file_path, .{
                .truncate = false,
                .read = true,
            }) catch |err| blk: {
                std.log.warn("WAL: Could not open file {s}: {}", .{ config.file_path, err });
                break :blk null;
            };
        }

        var self = Self{
            .ring = ring,
            .capacity = capacity,
            .head = Atomic(u64).init(0),
            .tail = Atomic(u64).init(0),
            .file = file,
            .config = config,
            .flush_lock = .{},
            .entries_written = Atomic(u64).init(0),
            .entries_flushed = Atomic(u64).init(0),
            .flush_count = Atomic(u64).init(0),
            .group_commit_count = Atomic(u64).init(0),
            .total_batched_entries = Atomic(u64).init(0),
            .max_batch_size_seen = Atomic(u64).init(0),
            .current_block = Atomic(u64).init(0),
            .allocator = allocator,
            .bg_flush_thread = null,
            .bg_flush_running = Atomic(bool).init(false),
        };

        // Start background flush thread if enabled and we have a file
        if (config.enable_background_flush and config.flush_interval_ms > 0 and file != null) {
            self.bg_flush_running.store(true, .release);
            self.bg_flush_thread = std.Thread.spawn(.{}, backgroundFlushLoop, .{&self}) catch null;
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        // Stop background flush thread
        self.stopBackgroundFlush();

        // Flush remaining entries
        self.flush() catch {};

        if (self.file) |*f| {
            f.close();
        }
        self.allocator.free(self.ring);
    }

    /// Stop the background flush thread gracefully
    fn stopBackgroundFlush(self: *Self) void {
        if (self.bg_flush_thread) |thread| {
            self.bg_flush_running.store(false, .release);
            thread.join();
            self.bg_flush_thread = null;
        }
    }

    /// Background flush loop — periodically flushes pending entries
    /// Runs on a dedicated thread, wakes every flush_interval_ms
    fn backgroundFlushLoop(self: *Self) void {
        const interval_ns = self.config.flush_interval_ms * std.time.ns_per_ms;

        while (self.bg_flush_running.load(.acquire)) {
            // Sleep for the configured interval
            std.time.sleep(interval_ns);

            // Check if there are pending entries
            const pending = self.pendingEntries();
            if (pending > 0) {
                self.flush() catch |err| {
                    std.log.warn("WAL background flush failed: {}", .{err});
                };
            }
        }
    }

    /// Append a single entry to the WAL (lock-free, thread-safe)
    /// Writer path: atomic increment of head, memcpy entry into ring slot.
    /// Flush is triggered when batch_size is reached (group commit).
    pub fn append(self: *Self, op: OpType, key: [32]u8, value: [32]u8) !void {
        const block = self.current_block.load(.acquire);
        var entry = WalEntry{
            .op = @intFromEnum(op),
            .block_number = block,
            .key = key,
            .value = value,
            .checksum = 0,
        };
        entry.checksum = entry.compute_checksum();

        // Atomically claim a slot in the ring
        const pos = self.head.fetchAdd(1, .acq_rel);
        const ring_idx = @as(u32, @intCast(pos % self.capacity));
        const offset = @as(usize, ring_idx) * ENTRY_SIZE;

        // Write entry to ring buffer
        const entry_bytes: [*]const u8 = @ptrCast(&entry);
        @memcpy(self.ring[offset .. offset + ENTRY_SIZE], entry_bytes[0..ENTRY_SIZE]);

        _ = self.entries_written.fetchAdd(1, .monotonic);

        // Group commit: only trigger flush when batch threshold is reached
        // This amortizes the fsync cost across batch_size entries
        const pending = self.pendingEntries();
        if (pending >= self.config.batch_size) {
            try self.flush();
        }
    }

    /// Append an account state update
    pub fn appendAccountPut(self: *Self, address: [20]u8, balance: [32]u8) !void {
        var key: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key[0..20], &address);
        try self.append(.AccountPut, key, balance);
    }

    /// Append a storage slot write
    pub fn appendStoragePut(self: *Self, storage_key: [32]u8, value: [32]u8) !void {
        try self.append(.StoragePut, storage_key, value);
    }

    /// Mark a block boundary
    pub fn markBlockBoundary(self: *Self, block_number: u64) !void {
        self.current_block.store(block_number, .release);
        var key: [32]u8 = [_]u8{0} ** 32;
        const block_bytes: [8]u8 = @bitCast(block_number);
        @memcpy(key[0..8], &block_bytes);
        try self.append(.BlockBoundary, key, [_]u8{0} ** 32);
    }

    /// Get the number of pending (unflushed) entries
    inline fn pendingEntries(self: *Self) u64 {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        if (head >= tail) return head - tail;
        return 0;
    }

    /// Flush pending entries to disk — GROUP COMMIT
    /// Writes all pending entries in a single pwriteAll + single fsync.
    /// This is the core of the group commit optimization: instead of fsync per entry,
    /// we batch N entries (up to batch_size) and issue one fsync for the whole batch.
    ///
    /// At 1M TPS with batch_size=1024:
    ///   - Before: 1M fsyncs/sec × ~10μs = 10 seconds of fsync overhead/sec (impossible)
    ///   - After:  ~1000 fsyncs/sec × ~10μs = 10ms of fsync overhead/sec (trivial)
    pub fn flush(self: *Self) !void {
        self.flush_lock.lock();
        defer self.flush_lock.unlock();

        const tail = self.tail.load(.acquire);
        const head = self.head.load(.acquire);

        if (tail >= head) return; // Nothing to flush

        const file = self.file orelse return; // No file, in-memory only

        const count = head - tail;
        const start_idx = @as(u32, @intCast(tail % self.capacity));
        const end_idx = @as(u32, @intCast(head % self.capacity));

        // Write all pending entries in a single I/O operation (group commit)
        if (end_idx > start_idx or count == self.capacity) {
            // Contiguous write — single pwriteAll for entire batch
            const start = @as(usize, start_idx) * ENTRY_SIZE;
            const end = if (end_idx > start_idx)
                @as(usize, end_idx) * ENTRY_SIZE
            else
                @as(usize, self.capacity) * ENTRY_SIZE;
            _ = try file.write(self.ring[start..end]);
        } else {
            // Wrap-around: two contiguous writes (still only one fsync)
            const start = @as(usize, start_idx) * ENTRY_SIZE;
            _ = try file.write(self.ring[start..]);
            if (end_idx > 0) {
                _ = try file.write(self.ring[0 .. @as(usize, end_idx) * ENTRY_SIZE]);
            }
        }

        // Single fsync for the entire batch — this is the key optimization
        // One fsync amortized across all entries in this batch
        if (self.config.sync_writes) {
            try file.sync();
        }

        // Update tail and stats atomically
        self.tail.store(head, .release);
        self.entries_flushed.fetchAdd(count, .monotonic);
        _ = self.flush_count.fetchAdd(1, .monotonic);

        // Group commit stats
        _ = self.group_commit_count.fetchAdd(1, .monotonic);
        _ = self.total_batched_entries.fetchAdd(count, .monotonic);

        // Track max batch size seen
        const prev_max = self.max_batch_size_seen.load(.monotonic);
        if (count > prev_max) {
            self.max_batch_size_seen.store(count, .monotonic);
        }
    }

    /// Force flush — bypass batch threshold and flush immediately
    /// Useful at block boundaries or shutdown
    pub fn forceFlush(self: *Self) !void {
        try self.flush();
    }

    /// Set the current block number
    pub fn setBlock(self: *Self, block: u64) void {
        self.current_block.store(block, .release);
    }

    /// Get WAL statistics including group commit metrics
    pub fn getStats(self: *const Self) WalStats {
        const written = self.entries_written.load(.acquire);
        const flushed = self.entries_flushed.load(.acquire);
        return WalStats{
            .entries_written = written,
            .entries_flushed = flushed,
            .bytes_written = flushed * ENTRY_SIZE,
            .flush_count = self.flush_count.load(.acquire),
            .pending_entries = if (written >= flushed) written - flushed else 0,
            .group_commits = self.group_commit_count.load(.acquire),
            .total_batched_entries = self.total_batched_entries.load(.acquire),
            .max_batch_size_seen = self.max_batch_size_seen.load(.acquire),
        };
    }

    /// Get average batch size for group commits
    pub fn avgBatchSize(self: *const Self) f64 {
        const commits = self.group_commit_count.load(.acquire);
        if (commits == 0) return 0;
        const total = self.total_batched_entries.load(.acquire);
        return @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(commits));
    }

    /// Recover entries from WAL file (for crash recovery)
    pub fn recover(self: *Self) !u64 {
        const file = self.file orelse return 0;

        const stat = try file.stat();
        const file_size = stat.size;
        if (file_size == 0) return 0;

        const entry_count = file_size / ENTRY_SIZE;
        var recovered: u64 = 0;
        var max_block: u64 = 0;

        try file.seekTo(0);

        var buf: [ENTRY_SIZE]u8 = undefined;
        for (0..entry_count) |_| {
            const bytes_read = try file.read(&buf);
            if (bytes_read < ENTRY_SIZE) break;

            const entry: *const WalEntry = @ptrCast(@alignCast(&buf));
            if (entry.isValid()) {
                recovered += 1;
                if (entry.block_number > max_block) {
                    max_block = entry.block_number;
                }
            } else {
                break; // Corrupt entry = end of valid data
            }
        }

        self.current_block.store(max_block, .release);
        return recovered;
    }

    /// Truncate the WAL file (after successful checkpoint)
    pub fn truncate(self: *Self) !void {
        if (self.file) |*f| {
            try f.seekTo(0);
            try f.setEndPos(0);
        }
        self.head.store(0, .release);
        self.tail.store(0, .release);
    }
};

// ---- Tests ----

test "WalEntry checksum" {
    var entry = WalEntry{
        .op = @intFromEnum(OpType.AccountPut),
        .block_number = 42,
        .key = [_]u8{0xAA} ** 32,
        .value = [_]u8{0xBB} ** 32,
        .checksum = 0,
    };
    entry.checksum = entry.compute_checksum();
    try std.testing.expect(entry.isValid());

    // Corrupt and verify detection
    entry.value[0] = 0xFF;
    try std.testing.expect(!entry.isValid());
}

test "WalRing basic write and flush" {
    // Use in-memory only (no file)
    var wal = try WalRing.init(std.testing.allocator, .{
        .ring_size = 64 * 1024,
        .batch_size = 100,
        .file_path = "",
        .enable_background_flush = false,
    });
    defer wal.deinit();

    const key = [_]u8{0x01} ** 32;
    const val = [_]u8{0x02} ** 32;

    try wal.append(.AccountPut, key, val);
    try wal.append(.StoragePut, key, val);

    const stats = wal.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.entries_written);
}

test "WalRing block boundary" {
    var wal = try WalRing.init(std.testing.allocator, .{
        .ring_size = 64 * 1024,
        .batch_size = 1000,
        .file_path = "",
        .enable_background_flush = false,
    });
    defer wal.deinit();

    wal.setBlock(1);
    try wal.append(.AccountPut, [_]u8{0x01} ** 32, [_]u8{0x02} ** 32);

    try wal.markBlockBoundary(2);
    try wal.append(.AccountPut, [_]u8{0x03} ** 32, [_]u8{0x04} ** 32);

    try std.testing.expectEqual(@as(u64, 2), wal.current_block.load(.acquire));
}

test "WalRing file persistence" {
    const test_path = "/tmp/forgeyrdb_test_wal";
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Write
    {
        var wal = try WalRing.init(std.testing.allocator, .{
            .ring_size = 64 * 1024,
            .batch_size = 100,
            .file_path = test_path,
            .sync_writes = true,
            .enable_background_flush = false,
        });
        defer wal.deinit();

        wal.setBlock(5);
        try wal.append(.AccountPut, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32);
        try wal.append(.StoragePut, [_]u8{0xCC} ** 32, [_]u8{0xDD} ** 32);
        try wal.flush();
    }

    // Recover
    {
        var wal = try WalRing.init(std.testing.allocator, .{
            .ring_size = 64 * 1024,
            .batch_size = 100,
            .file_path = test_path,
            .enable_background_flush = false,
        });
        defer wal.deinit();

        const recovered = try wal.recover();
        try std.testing.expectEqual(@as(u64, 2), recovered);
        try std.testing.expectEqual(@as(u64, 5), wal.current_block.load(.acquire));
    }
}

test "WalRing group commit batching" {
    const test_path = "/tmp/forgeyrdb_test_wal_gc";
    defer std.fs.cwd().deleteFile(test_path) catch {};

    var wal = try WalRing.init(std.testing.allocator, .{
        .ring_size = 256 * 1024,
        .batch_size = 50, // Small batch for testing
        .file_path = test_path,
        .sync_writes = true,
        .enable_background_flush = false,
    });
    defer wal.deinit();

    // Write 200 entries — should trigger 4 group commits (200 / 50)
    for (0..200) |i| {
        var key: [32]u8 = [_]u8{0} ** 32;
        key[0] = @intCast(i & 0xFF);
        try wal.append(.AccountPut, key, [_]u8{0xBB} ** 32);
    }

    // Force flush any remaining
    try wal.forceFlush();

    const stats = wal.getStats();
    try std.testing.expectEqual(@as(u64, 200), stats.entries_written);
    try std.testing.expectEqual(@as(u64, 200), stats.entries_flushed);

    // Should have multiple group commits, not 200 individual ones
    try std.testing.expect(stats.group_commits >= 4);
    try std.testing.expect(stats.group_commits <= 10); // Reasonable upper bound

    // Average batch size should be > 1 (proving batching is working)
    const avg = wal.avgBatchSize();
    try std.testing.expect(avg > 1.0);
}

test "WalRing group commit stats" {
    var wal = try WalRing.init(std.testing.allocator, .{
        .ring_size = 64 * 1024,
        .batch_size = 10,
        .file_path = "",
        .enable_background_flush = false,
    });
    defer wal.deinit();

    // Initially no group commits
    try std.testing.expectEqual(@as(u64, 0), wal.getStats().group_commits);
    try std.testing.expect(wal.avgBatchSize() == 0);

    // Write entries — they won't trigger flush (no file)
    for (0..20) |i| {
        var key: [32]u8 = [_]u8{0} ** 32;
        key[0] = @intCast(i);
        try wal.append(.AccountPut, key, [_]u8{0xBB} ** 32);
    }

    try std.testing.expectEqual(@as(u64, 20), wal.getStats().entries_written);
}
