// Block Pruner - Removes old block data after epoch finalization
// Core component for constant-size blockchain storage

const std = @import("std");
const Allocator = std.mem.Allocator;
const storage = @import("../mod.zig");
const types = @import("types.zig");

const AggregatedEpoch = types.AggregatedEpoch;
const EpochMetadata = types.EpochMetadata;
const EPOCH_SIZE = types.EPOCH_SIZE;

/// Statistics from a prune operation
pub const PruneStats = struct {
    blocks_pruned: u64,
    bytes_freed: u64,
    receipts_pruned: u64,
    duration_ms: u64,
};

/// Block Pruner - Deletes old block data after epoch aggregation
///
/// After an epoch is finalized and stored as an AggregatedEpoch,
/// we can safely delete the individual block data since all
/// information is preserved in the compressed epoch delta.
pub const BlockPruner = struct {
    const Self = @This();

    allocator: Allocator,
    db: storage.DB,

    // Configuration
    retain_recent_epochs: u64, // Keep N most recent epochs unpruned
    dry_run: bool, // If true, only calculate stats without deleting

    // Statistics
    total_bytes_pruned: u64,
    total_blocks_pruned: u64,
    epochs_pruned: u64,

    pub fn init(allocator: Allocator, db: storage.DB) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .db = db,
            .retain_recent_epochs = 0, // Prune everything by default
            .dry_run = false,
            .total_bytes_pruned = 0,
            .total_blocks_pruned = 0,
            .epochs_pruned = 0,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// Set number of recent epochs to retain (not prune)
    pub fn setRetentionPolicy(self: *Self, epochs: u64) void {
        self.retain_recent_epochs = epochs;
    }

    /// Enable dry-run mode (calculate stats without deleting)
    pub fn setDryRun(self: *Self, enable: bool) void {
        self.dry_run = enable;
    }

    /// Prune blocks belonging to a finalized epoch
    /// Called after EpochAggregator.finalizeEpoch()
    pub fn pruneEpoch(self: *Self, epoch: *const AggregatedEpoch) !PruneStats {
        const start_time = std.time.milliTimestamp();

        var stats = PruneStats{
            .blocks_pruned = 0,
            .bytes_freed = 0,
            .receipts_pruned = 0,
            .duration_ms = 0,
        };

        const start_block = epoch.metadata.start_block;
        const end_block = epoch.metadata.end_block;

        std.log.info(
            "[Pruner] Pruning epoch {d}: blocks {d}-{d}",
            .{ epoch.metadata.epoch_number, start_block, end_block },
        );

        // Iterate through all blocks in the epoch
        var block_num = start_block;
        while (block_num <= end_block) : (block_num += 1) {
            const pruned = try self.pruneBlock(block_num);
            stats.blocks_pruned += @intFromBool(pruned.success);
            stats.bytes_freed += pruned.bytes_freed;
            stats.receipts_pruned += pruned.receipts_pruned;
        }

        stats.duration_ms = @intCast(std.time.milliTimestamp() - start_time);

        // Update cumulative stats
        self.total_blocks_pruned += stats.blocks_pruned;
        self.total_bytes_pruned += stats.bytes_freed;
        self.epochs_pruned += 1;

        std.log.info(
            "[Pruner] Epoch {d} pruned: {d} blocks, {d} KB freed in {d}ms",
            .{
                epoch.metadata.epoch_number,
                stats.blocks_pruned,
                stats.bytes_freed / 1024,
                stats.duration_ms,
            },
        );

        return stats;
    }

    const BlockPruneResult = struct {
        success: bool,
        bytes_freed: u64,
        receipts_pruned: u64,
    };

    /// Prune a single block by number
    fn pruneBlock(self: *Self, block_number: u64) !BlockPruneResult {
        var result = BlockPruneResult{
            .success = false,
            .bytes_freed = 0,
            .receipts_pruned = 0,
        };

        // 1. Get block hash from canonical mapping (H-{number})
        var num_key: [10]u8 = undefined;
        @memcpy(num_key[0..2], "H-");
        std.mem.writeInt(u64, num_key[2..10], block_number, .big);

        const hash_bytes = self.db.read(&num_key) orelse return result;
        if (hash_bytes.len != 32) return result;

        var block_hash: [32]u8 = undefined;
        @memcpy(&block_hash, hash_bytes[0..32]);

        // 2. Delete block data (b-{hash})
        var block_key: [34]u8 = undefined;
        @memcpy(block_key[0..2], "b-");
        @memcpy(block_key[2..34], &block_hash);

        // Measure size before deletion
        if (self.db.read(&block_key)) |block_data| {
            result.bytes_freed += block_data.len;
        }

        if (!self.dry_run) {
            try self.db.delete(&block_key);
        }

        // 3. Delete receipts (r-{hash})
        var receipt_key: [34]u8 = undefined;
        @memcpy(receipt_key[0..2], "r-");
        @memcpy(receipt_key[2..34], &block_hash);

        if (self.db.read(&receipt_key)) |receipt_data| {
            result.bytes_freed += receipt_data.len;
            result.receipts_pruned = 1;

            if (!self.dry_run) {
                try self.db.delete(&receipt_key);
            }
        }

        // Note: We keep the canonical mapping (H-{number} -> hash)
        // so we can still look up which block was at each height

        result.success = true;
        return result;
    }

    /// Prune all epochs before a given epoch number
    pub fn pruneBeforeEpoch(self: *Self, epoch_number: u64) !PruneStats {
        var total_stats = PruneStats{
            .blocks_pruned = 0,
            .bytes_freed = 0,
            .receipts_pruned = 0,
            .duration_ms = 0,
        };

        const start_time = std.time.milliTimestamp();

        // Calculate block range
        if (epoch_number == 0) return total_stats;

        const end_block = epoch_number * EPOCH_SIZE - 1;

        var block_num: u64 = 0;
        while (block_num <= end_block) : (block_num += 1) {
            const pruned = try self.pruneBlock(block_num);
            total_stats.blocks_pruned += @intFromBool(pruned.success);
            total_stats.bytes_freed += pruned.bytes_freed;
            total_stats.receipts_pruned += pruned.receipts_pruned;
        }

        total_stats.duration_ms = @intCast(std.time.milliTimestamp() - start_time);

        return total_stats;
    }

    /// Get cumulative pruning statistics
    pub fn getStats(self: *const Self) struct {
        total_bytes_pruned: u64,
        total_blocks_pruned: u64,
        epochs_pruned: u64,
    } {
        return .{
            .total_bytes_pruned = self.total_bytes_pruned,
            .total_blocks_pruned = self.total_blocks_pruned,
            .epochs_pruned = self.epochs_pruned,
        };
    }

    /// Estimate storage savings from pruning
    pub fn estimateSavings(epochs_to_prune: u64) struct {
        blocks: u64,
        estimated_bytes: u64,
    } {
        const blocks = epochs_to_prune * EPOCH_SIZE;
        // Average block size estimate: ~2KB
        const avg_block_size: u64 = 2048;
        return .{
            .blocks = blocks,
            .estimated_bytes = blocks * avg_block_size,
        };
    }
};

// Background pruner that runs periodically
pub const BackgroundPruner = struct {
    const Self = @This();

    allocator: Allocator,
    pruner: *BlockPruner,
    running: std.atomic.Value(bool),
    thread: ?std.Thread,

    // Configuration
    check_interval_ms: u64,
    current_epoch: *std.atomic.Value(u64),

    pub fn init(
        allocator: Allocator,
        pruner: *BlockPruner,
        current_epoch: *std.atomic.Value(u64),
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .pruner = pruner,
            .running = std.atomic.Value(bool).init(false),
            .thread = null,
            .check_interval_ms = 60_000, // Check every minute
            .current_epoch = current_epoch,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.allocator.destroy(self);
    }

    pub fn start(self: *Self) !void {
        if (self.running.load(.seq_cst)) return;

        self.running.store(true, .seq_cst);
        self.thread = try std.Thread.spawn(.{}, Self.run, .{self});
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .seq_cst);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn run(self: *Self) void {
        var last_pruned_epoch: u64 = 0;

        while (self.running.load(.seq_cst)) {
            const current = self.current_epoch.load(.seq_cst);

            // Prune epochs that are old enough
            if (current > self.pruner.retain_recent_epochs + 1) {
                const prune_up_to = current - self.pruner.retain_recent_epochs - 1;

                if (prune_up_to > last_pruned_epoch) {
                    // Prune one epoch at a time to avoid blocking
                    const epoch_to_prune = last_pruned_epoch + 1;

                    // Load epoch metadata and prune
                    // Note: In production, we'd load the epoch from DB
                    const metadata = EpochMetadata{
                        .epoch_number = epoch_to_prune,
                        .start_block = epoch_to_prune * EPOCH_SIZE,
                        .end_block = (epoch_to_prune + 1) * EPOCH_SIZE - 1,
                        .start_timestamp = 0,
                        .end_timestamp = 0,
                        .pre_state_root = [_]u8{0} ** 32,
                        .post_state_root = [_]u8{0} ** 32,
                        .account_count = 0,
                        .storage_count = 0,
                        .tx_count = 0,
                        .gas_used = 0,
                        .aggregated_sig = [_]u8{0} ** 96,
                        .signers_bitmap = &[_]u8{},
                        .compressed_size = 0,
                        .uncompressed_size = 0,
                    };

                    var epoch = AggregatedEpoch{
                        .metadata = metadata,
                        .compressed_delta = &[_]u8{},
                        .net_transfers = &[_]AggregatedEpoch.NetTransfer{},
                    };

                    _ = self.pruner.pruneEpoch(&epoch) catch |err| {
                        std.log.err("[BackgroundPruner] Failed to prune epoch {d}: {}", .{ epoch_to_prune, err });
                        continue;
                    };

                    last_pruned_epoch = epoch_to_prune;
                }
            }

            std.Thread.sleep(self.check_interval_ms * std.time.ns_per_ms);
        }
    }
};

// Tests
test "BlockPruner basic" {
    // This would require a mock DB for proper testing
    // For now, just verify struct creation
    const allocator = std.testing.allocator;
    _ = allocator;

    // Test estimateSavings
    const savings = BlockPruner.estimateSavings(10);
    try std.testing.expectEqual(@as(u64, 10 * EPOCH_SIZE), savings.blocks);
}
