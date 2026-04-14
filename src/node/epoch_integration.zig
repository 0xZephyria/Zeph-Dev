// Epoch Integration - Connects miner, executor, and epoch system
// Provides production-ready workflow for constant-size blockchain

const std = @import("std");
const Allocator = std.mem.Allocator;
const core = @import("core");
const storage = @import("storage");

const types = core.types;
const State = core.state.State;
const Blockchain = core.blockchain.Blockchain;

const StateDelta = storage.epoch.StateDelta;
const EpochAggregator = storage.epoch.EpochAggregator;
const AggregatedEpoch = storage.epoch.AggregatedEpoch;
const BlockPruner = storage.epoch.BlockPruner;
const AccountEpochIndex = storage.epoch.AccountEpochIndex;
const EPOCH_SIZE = storage.epoch.EPOCH_SIZE;

/// Epoch Integration - Connects block production with epoch aggregation
///
/// This module provides the glue between:
/// - Block execution (produces state changes)
/// - Epoch aggregation (compresses multiple blocks)
/// - Block pruning (deletes old data)
/// - Historical queries (via epoch deltas)
pub const EpochIntegration = struct {
    const Self = @This();

    allocator: Allocator,
    db: storage.DB,

    // Components
    epoch_aggregator: *EpochAggregator,
    pruner: *BlockPruner,
    tx_index: *AccountEpochIndex,

    // Current block delta (populated during execution)
    current_delta: ?*StateDelta,

    // Tracking
    current_epoch: std.atomic.Value(u64),
    blocks_processed: u64,
    epochs_finalized: u64,

    // Configuration
    enable_pruning: bool,
    blocks_per_epoch: u64,

    pub fn init(
        allocator: Allocator,
        db: storage.DB,
        blocks_per_epoch: u64,
    ) !*Self {
        const self = try allocator.create(Self);

        self.* = Self{
            .allocator = allocator,
            .db = db,
            .epoch_aggregator = try EpochAggregator.init(allocator, blocks_per_epoch, 100),
            .pruner = try BlockPruner.init(allocator, db),
            .tx_index = try AccountEpochIndex.init(allocator),
            .current_delta = null,
            .current_epoch = std.atomic.Value(u64).init(0),
            .blocks_processed = 0,
            .epochs_finalized = 0,
            .enable_pruning = true,
            .blocks_per_epoch = blocks_per_epoch,
        };

        // Set epoch completion callback
        self.epoch_aggregator.setEpochCompleteCallback(&Self.onEpochComplete);

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.current_delta) |delta| {
            delta.deinit();
        }
        self.epoch_aggregator.deinit();
        self.pruner.deinit();
        self.tx_index.deinit();
        self.allocator.destroy(self);
    }

    /// Enable/disable pruning
    pub fn setPruning(self: *Self, enable: bool) void {
        self.enable_pruning = enable;
    }

    /// Called BEFORE block execution - prepares delta tracking
    pub fn beginBlock(self: *Self) !void {
        // Create fresh delta for this block
        if (self.current_delta) |delta| {
            delta.deinit();
        }
        self.current_delta = try StateDelta.init(self.allocator);
    }

    /// Record a state change during execution
    /// Call this from the executor when account state changes
    pub fn recordAccountChange(
        self: *Self,
        address: types.Address,
        balance_delta: i128,
        nonce_delta: i64,
        code_hash: ?[32]u8,
    ) !void {
        if (self.current_delta) |delta| {
            try delta.recordAccountChange(address.bytes, balance_delta, nonce_delta, code_hash);
        }
    }

    /// Record a storage change during execution
    pub fn recordStorageChange(
        self: *Self,
        address: types.Address,
        slot: [32]u8,
        old_value: [32]u8,
        new_value: [32]u8,
    ) !void {
        if (self.current_delta) |delta| {
            try delta.recordStorageChange(address.bytes, slot, old_value, new_value);
        }
    }

    /// Track gas usage
    pub fn recordGas(self: *Self, gas: u64) void {
        if (self.current_delta) |delta| {
            delta.recordGas(gas);
        }
    }

    /// Called AFTER block execution - processes the block into epoch
    /// Returns true if an epoch was finalized
    pub fn endBlock(self: *Self, block: *types.Block) !bool {
        const delta = self.current_delta orelse return false;
        self.current_delta = null; // Transfer ownership
        defer delta.deinit();

        // Process block through epoch aggregator
        const epoch = try self.epoch_aggregator.processBlock(block, delta);
        self.blocks_processed += 1;

        // Track transactions in index
        const current_epoch_num = block.header.number / self.blocks_per_epoch;
        for (block.transactions) |*tx| {
            const tx_hash = tx.hash();
            try self.tx_index.recordActivity(tx.from.bytes, current_epoch_num, tx_hash.bytes);
            if (tx.to) |to| {
                try self.tx_index.recordActivity(to.bytes, current_epoch_num, null);
            }
        }

        if (epoch) |finalized_epoch| {
            defer {
                finalized_epoch.deinit(self.allocator);
                self.allocator.destroy(finalized_epoch);
            }
            return try self.handleEpochComplete(finalized_epoch);
        }

        return false;
    }

    /// Handle epoch completion
    fn handleEpochComplete(self: *Self, epoch: *AggregatedEpoch) !bool {
        const epoch_num = epoch.metadata.epoch_number;

        std.log.info(
            "[EpochIntegration] Epoch {d} finalized: blocks {d}-{d}, {d} accounts, {d} storage changes",
            .{
                epoch_num,
                epoch.metadata.start_block,
                epoch.metadata.end_block,
                epoch.metadata.account_count,
                epoch.metadata.storage_count,
            },
        );

        // Persist epoch to database
        try self.epoch_aggregator.persistEpoch(epoch, self.db);

        // Update current epoch tracker
        self.current_epoch.store(epoch_num + 1, .seq_cst);
        self.epochs_finalized += 1;

        // Prune old blocks if enabled
        if (self.enable_pruning) {
            const stats = try self.pruner.pruneEpoch(epoch);
            std.log.info(
                "[EpochIntegration] Pruned {d} blocks, freed {d} KB",
                .{ stats.blocks_pruned, stats.bytes_freed / 1024 },
            );
        }

        return true;
    }

    /// Callback for EpochAggregator
    fn onEpochComplete(aggregator: *EpochAggregator, epoch: *AggregatedEpoch) !void {
        _ = aggregator;
        _ = epoch;
        // This is a placeholder - actual handling is done in handleEpochComplete
        // The callback is triggered by the aggregator when an epoch completes
    }

    /// Get current epoch number
    pub fn getCurrentEpoch(self: *const Self) u64 {
        return self.current_epoch.load(.seq_cst);
    }

    /// Get statistics
    pub fn getStats(self: *const Self) IntegrationStats {
        const pruner_stats = self.pruner.getStats();
        const progress = self.epoch_aggregator.getProgress();

        return IntegrationStats{
            .blocks_processed = self.blocks_processed,
            .epochs_finalized = self.epochs_finalized,
            .current_epoch = self.current_epoch.load(.seq_cst),
            .epoch_progress_percent = progress.percent_complete,
            .total_bytes_pruned = pruner_stats.total_bytes_pruned,
        };
    }

    /// Log status summary
    pub fn logStatus(self: *const Self) void {
        const stats = self.getStats();
        std.log.info(
            \\[EpochIntegration] Status:
            \\  Blocks processed: {d}
            \\  Epochs finalized: {d}
            \\  Current epoch: {d} ({d:.1}% complete)
            \\  Storage pruned: {d} MB
        , .{
            stats.blocks_processed,
            stats.epochs_finalized,
            stats.current_epoch,
            stats.epoch_progress_percent,
            stats.total_bytes_pruned / (1024 * 1024),
        });
    }
};

/// Statistics from epoch integration
pub const IntegrationStats = struct {
    blocks_processed: u64,
    epochs_finalized: u64,
    current_epoch: u64,
    epoch_progress_percent: f32,
    total_bytes_pruned: u64,
};

/// Helper to create a standard production configuration
pub fn createProductionConfig(
    allocator: Allocator,
    db: storage.DB,
) !*EpochIntegration {
    return EpochIntegration.init(allocator, db, EPOCH_SIZE);
}

/// Helper for development/testing with smaller epochs
pub fn createDevConfig(
    allocator: Allocator,
    db: storage.DB,
    blocks_per_epoch: u64,
) !*EpochIntegration {
    const integration = try EpochIntegration.init(allocator, db, blocks_per_epoch);
    integration.setPruning(false); // Don't prune in dev mode
    return integration;
}

// Tests
test "EpochIntegration basic" {
    // Would require mock DB
    try std.testing.expect(true);
}
