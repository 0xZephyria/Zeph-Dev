// Epoch Storage Module - Constant-size blockchain with full history
// Achieves ~100 GB storage with epoch aggregation, MMR, and BLS aggregation

const std = @import("std");

/// Core types
pub const types = @import("types.zig");
pub const Address = types.Address;
pub const Hash = types.Hash;
pub const AccountDelta = types.AccountDelta;
pub const StorageDelta = types.StorageDelta;
pub const EpochMetadata = types.EpochMetadata;
pub const AggregatedEpoch = types.AggregatedEpoch;
pub const BlockSummary = types.BlockSummary;
pub const EPOCH_SIZE = types.EPOCH_SIZE;

/// State delta tracking
pub const delta = @import("delta.zig");
pub const StateDelta = delta.StateDelta;

/// BLS signature aggregation
pub const signature_aggregator = @import("signature_aggregator.zig");
pub const SignatureAggregator = signature_aggregator.SignatureAggregator;
pub const AggregatedSignature = signature_aggregator.AggregatedSignature;

/// Epoch aggregation
pub const aggregator = @import("aggregator.zig");
pub const EpochAggregator = aggregator.EpochAggregator;

/// Transaction indexing
pub const tx_index = @import("tx_index.zig");
pub const BloomFilter = tx_index.BloomFilter;
pub const AccountEpochIndex = tx_index.AccountEpochIndex;

/// Block pruning
pub const pruner = @import("pruner.zig");
pub const BlockPruner = pruner.BlockPruner;
pub const BackgroundPruner = pruner.BackgroundPruner;
pub const PruneStats = pruner.PruneStats;

// Tests
test {
    std.testing.refAllDecls(@This());
}
