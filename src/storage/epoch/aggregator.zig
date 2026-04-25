// Epoch Aggregator - Aggregates blocks into compressed epochs
// Core component for constant-size blockchain with full history

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const delta_mod = @import("delta.zig");
const sig_agg = @import("signature_aggregator.zig");

const StateDelta = delta_mod.StateDelta;
const AggregatedEpoch = types.AggregatedEpoch;
const EpochMetadata = types.EpochMetadata;
const BlockSummary = types.BlockSummary;
const Address = types.Address;
const Hash = types.Hash;
const EPOCH_SIZE = types.EPOCH_SIZE;

/// Epoch aggregator for constant-size blockchain
pub const EpochAggregator = struct {
    const Self = @This();

    allocator: Allocator,
    epoch_size: u64,

    // Current epoch accumulation
    current_epoch: u64,
    blocks_in_epoch: std.ArrayListUnmanaged(BlockSummary),
    epoch_delta: *StateDelta,
    signature_aggregator: *sig_agg.SignatureAggregator,

    // Transfer tracking
    transfers: std.AutoHashMap(TransferKey, TransferValue),

    // Statistics
    tx_count: u64,
    gas_used: u128,

    // Persistence callback
    on_epoch_complete: ?*const fn (*Self, *AggregatedEpoch) anyerror!void,

    const TransferKey = struct {
        from: Address,
        to: Address,
    };

    const TransferValue = struct {
        total_value: u256,
        tx_count: u32,
    };

    pub fn init(
        allocator: Allocator,
        epoch_size: u64,
        validator_count: usize,
    ) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.epoch_size = epoch_size;
        self.current_epoch = 0;
        self.blocks_in_epoch = .{};
        self.epoch_delta = try StateDelta.init(allocator);
        self.signature_aggregator = try sig_agg.SignatureAggregator.init(allocator, validator_count);
        self.transfers = std.AutoHashMap(TransferKey, TransferValue).init(allocator);
        self.tx_count = 0;
        self.gas_used = 0;
        self.on_epoch_complete = null;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.blocks_in_epoch.deinit(self.allocator);
        self.epoch_delta.deinit();
        self.signature_aggregator.deinit();
        self.transfers.deinit();
        self.allocator.destroy(self);
    }

    /// Set callback for when an epoch is complete
    pub fn setEpochCompleteCallback(
        self: *Self,
        callback: *const fn (*Self, *AggregatedEpoch) anyerror!void,
    ) void {
        self.on_epoch_complete = callback;
    }

    /// Process a block and add it to current epoch
    pub fn processBlock(
        self: *Self,
        block: anytype,
        state_diff: *const StateDelta,
    ) !?*AggregatedEpoch {
        const block_number = block.header.number;
        const epoch_for_block = block_number / self.epoch_size;

        // Check if we need to finalize current epoch
        if (epoch_for_block > self.current_epoch and self.blocks_in_epoch.items.len > 0) {
            const completed_epoch = try self.finalizeEpoch();

            // Reset for new epoch
            self.current_epoch = epoch_for_block;
            self.blocks_in_epoch.clearRetainingCapacity();
            self.epoch_delta.deinit();
            self.epoch_delta = try StateDelta.init(self.allocator);
            const validator_count = self.signature_aggregator.validator_count;
            self.signature_aggregator.deinit();
            self.signature_aggregator = try sig_agg.SignatureAggregator.init(
                self.allocator,
                validator_count,
            );
            self.transfers.clearRetainingCapacity();
            self.tx_count = 0;
            self.gas_used = 0;

            // Process current block into new epoch
            try self.addBlockToEpoch(block, state_diff);

            return completed_epoch;
        }

        // Add block to current epoch
        try self.addBlockToEpoch(block, state_diff);

        return null;
    }

    fn addBlockToEpoch(
        self: *Self,
        block: anytype,
        state_diff: *const StateDelta,
    ) !void {
        // Add block summary
        try self.blocks_in_epoch.append(self.allocator, BlockSummary.fromHeader(block.header));

        // Merge state delta
        try self.epoch_delta.merge(state_diff);

        // Track transactions - transactions is not optional
        for (block.transactions) |tx| {
            self.tx_count += 1;
            // Note: core.types.Transaction doesn't have gas_used, track count only
            // self.gas_used += tx.gas_used;

            // Track transfers
            if (tx.value > 0) {
                const key = TransferKey{
                    .from = tx.from.bytes,
                    .to = if (tx.to) |to_addr| to_addr.bytes else [_]u8{0} ** 20,
                };

                const gop = try self.transfers.getOrPut(key);
                if (gop.found_existing) {
                    gop.value_ptr.total_value +|= tx.value;
                    gop.value_ptr.tx_count += 1;
                } else {
                    gop.value_ptr.* = TransferValue{
                        .total_value = tx.value,
                        .tx_count = 1,
                    };
                }
            }
        }

        // Collect block signature
        if (block.header.extraData.len >= 96) {
            // Get proposer's public key and add signature
            // Note: In production, validator index should be derived from proposer address
            const validator_index = block.header.coinbase.bytes[0] % 100; // Simplified

            // For epoch aggregation, we sign the state root
            const msg = &block.header.verkleRoot.bytes;

            // Skip signature aggregation if we don't have pubkey
            // In production, lookup from validator registry
            _ = validator_index;
            _ = msg;
        }
    }

    /// Finalize current epoch into an aggregated form
    pub fn finalizeEpoch(self: *Self) !*AggregatedEpoch {
        if (self.blocks_in_epoch.items.len == 0) {
            return error.EmptyEpoch;
        }

        const first_block = &self.blocks_in_epoch.items[0];
        const last_block = &self.blocks_in_epoch.items[self.blocks_in_epoch.items.len - 1];

        // Compress state delta
        const compressed_delta = try self.epoch_delta.compress(self.allocator);
        errdefer self.allocator.free(compressed_delta);

        // Build net transfers array
        var net_transfers: std.ArrayListUnmanaged(AggregatedEpoch.NetTransfer) = .{};
        errdefer net_transfers.deinit(self.allocator);
        var transfer_iter = self.transfers.iterator();
        while (transfer_iter.next()) |entry| {
            try net_transfers.append(self.allocator, .{
                .from = entry.key_ptr.from,
                .to = entry.key_ptr.to,
                .total_value = entry.value_ptr.total_value,
                .tx_count = entry.value_ptr.tx_count,
            });
        }

        // Get aggregated signature (or placeholder if none)
        var agg_sig: [96]u8 = [_]u8{0} ** 96;
        var signers_bitmap: []u8 = &[_]u8{};

        if (self.signature_aggregator.signatures.items.len > 0) {
            const agg_result = try self.signature_aggregator.aggregate();
            agg_sig = agg_result.signature;
            signers_bitmap = agg_result.signers_bitmap;
        } else {
            signers_bitmap = try self.allocator.dupe(u8, &[_]u8{0});
        }
        errdefer self.allocator.free(signers_bitmap);

        // Get original size for metadata
        const serialized = try self.epoch_delta.serialize(self.allocator);
        const original_size = serialized.len;
        self.allocator.free(serialized);

        // Build epoch
        const epoch = try self.allocator.create(AggregatedEpoch);
        epoch.* = AggregatedEpoch{
            .metadata = EpochMetadata{
                .epoch_number = self.current_epoch,
                .start_block = first_block.number,
                .end_block = last_block.number,
                .start_timestamp = first_block.timestamp,
                .end_timestamp = last_block.timestamp,
                .pre_state_root = first_block.parent_hash, // Previous state
                .post_state_root = last_block.state_root,
                .account_count = @intCast(self.epoch_delta.getStats().accounts),
                .storage_count = @intCast(self.epoch_delta.getStats().storage),
                .tx_count = self.tx_count,
                .gas_used = self.gas_used,
                .aggregated_sig = agg_sig,
                .signers_bitmap = signers_bitmap,
                .compressed_size = @intCast(compressed_delta.len),
                .uncompressed_size = @intCast(original_size),
            },
            .compressed_delta = compressed_delta,
            .net_transfers = try net_transfers.toOwnedSlice(self.allocator),
        };

        // If validation or callback fails, free the entire epoch
        errdefer {
            epoch.deinit(self.allocator);
            self.allocator.destroy(epoch);
        }

        // Validate before returning
        try epoch.validate();

        // Invoke callback if set
        if (self.on_epoch_complete) |callback| {
            try callback(self, epoch);
        }

        return epoch;
    }

    /// Get current epoch progress
    pub fn getProgress(self: *const Self) struct {
        epoch: u64,
        blocks_processed: usize,
        epoch_size: u64,
        percent_complete: f32,
    } {
        return .{
            .epoch = self.current_epoch,
            .blocks_processed = self.blocks_in_epoch.items.len,
            .epoch_size = self.epoch_size,
            .percent_complete = @as(f32, @floatFromInt(self.blocks_in_epoch.items.len)) /
                @as(f32, @floatFromInt(self.epoch_size)) * 100.0,
        };
    }

    /// Persist aggregated epoch to storage
    pub fn persistEpoch(
        self: *Self,
        epoch: *AggregatedEpoch,
        db: anytype,
    ) !void {
        // Serialize metadata
        const meta_key = try std.fmt.allocPrint(
            self.allocator,
            "epoch-meta-{d}",
            .{epoch.metadata.epoch_number},
        );
        defer self.allocator.free(meta_key);

        const meta_data = try epoch.metadata.serialize(self.allocator);
        defer self.allocator.free(meta_data);

        try db.write(meta_key, meta_data);

        // Store compressed delta
        const delta_key = try std.fmt.allocPrint(
            self.allocator,
            "epoch-delta-{d}",
            .{epoch.metadata.epoch_number},
        );
        defer self.allocator.free(delta_key);

        try db.write(delta_key, epoch.compressed_delta);

        // Store net transfers
        const transfers_key = try std.fmt.allocPrint(
            self.allocator,
            "epoch-transfers-{d}",
            .{epoch.metadata.epoch_number},
        );
        defer self.allocator.free(transfers_key);

        var transfers_buf: std.ArrayListUnmanaged(u8) = .{};
        defer transfers_buf.deinit(self.allocator);

        // Simple serialization of transfers
        var count_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &count_bytes, @intCast(epoch.net_transfers.len), .big);
        try transfers_buf.appendSlice(self.allocator, &count_bytes);

        for (epoch.net_transfers) |*transfer| {
            try transfers_buf.appendSlice(self.allocator, &transfer.from);
            try transfers_buf.appendSlice(self.allocator, &transfer.to);
            var val_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &val_bytes, transfer.total_value, .big);
            try transfers_buf.appendSlice(self.allocator, &val_bytes);
            var tx_count_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &tx_count_bytes, transfer.tx_count, .big);
            try transfers_buf.appendSlice(self.allocator, &tx_count_bytes);
        }

        try db.write(transfers_key, transfers_buf.items);
    }

    /// Load an aggregated epoch from storage
    pub fn loadEpoch(allocator: Allocator, epoch_number: u64, db: anytype) !*AggregatedEpoch {
        // Load metadata
        const meta_key = try std.fmt.allocPrint(allocator, "epoch-meta-{d}", .{epoch_number});
        defer allocator.free(meta_key);

        const meta_data = db.read(meta_key) orelse return error.EpochNotFound;
        var metadata = try EpochMetadata.deserialize(allocator, meta_data);
        errdefer metadata.deinit(allocator);

        // Load delta
        const delta_key = try std.fmt.allocPrint(allocator, "epoch-delta-{d}", .{epoch_number});
        defer allocator.free(delta_key);

        const delta_data = db.read(delta_key) orelse return error.DeltaNotFound;
        const compressed_delta = try allocator.dupe(u8, delta_data);
        errdefer allocator.free(compressed_delta);

        // Load transfers
        const transfers_key = try std.fmt.allocPrint(allocator, "epoch-transfers-{d}", .{epoch_number});
        defer allocator.free(transfers_key);

        var net_transfers: []AggregatedEpoch.NetTransfer = &.{};
        if (db.read(transfers_key)) |transfers_data| {
            if (transfers_data.len >= 4) {
                const count = std.mem.readInt(u32, transfers_data[0..4], .big);
                net_transfers = try allocator.alloc(AggregatedEpoch.NetTransfer, count);
                errdefer allocator.free(net_transfers);

                var offset: usize = 4;
                for (net_transfers) |*transfer| {
                    if (offset + 78 > transfers_data.len) break;

                    @memcpy(&transfer.from, transfers_data[offset..][0..20]);
                    offset += 20;
                    @memcpy(&transfer.to, transfers_data[offset..][0..20]);
                    offset += 20;
                    transfer.total_value = std.mem.readInt(u256, transfers_data[offset..][0..32], .big);
                    offset += 32;
                    transfer.tx_count = std.mem.readInt(u32, transfers_data[offset..][0..4], .big);
                    offset += 4;
                }
            }
        }

        const epoch = try allocator.create(AggregatedEpoch);
        epoch.* = AggregatedEpoch{
            .metadata = metadata,
            .compressed_delta = compressed_delta,
            .net_transfers = net_transfers,
        };

        // If we fail here, the caller won't get the pointer, but deinit will free metadata
        // so we just need to ensure the epoch shell itself is freed if needed.
        // Actually, the current loadEpoch doesn't have more failing points after this,
        // but it's good practice.

        return epoch;
    }
};

// Tests
test "EpochAggregator basic flow" {
    const allocator = std.testing.allocator;

    var aggregator = try EpochAggregator.init(allocator, 10, 100); // Small epoch for testing
    defer aggregator.deinit();

    // The aggregator should start empty
    const progress = aggregator.getProgress();
    try std.testing.expectEqual(@as(usize, 0), progress.blocks_processed);
    try std.testing.expectEqual(@as(u64, 10), progress.epoch_size);
}

test "EpochAggregator reset logic" {
    const allocator = std.testing.allocator;

    var aggregator = try EpochAggregator.init(allocator, 2, 100); // Epoch size 2
    defer aggregator.deinit();

    // Mock block
    const MockBlock = struct {
        header: struct {
            number: u64,
            verkleRoot: @import("core").types.Hash = @import("core").types.Hash.zero(),
            coinbase: @import("core").types.Address = @import("core").types.Address.zero(),
            extraData: []const u8 = &[_]u8{},
        },
        transactions: []const @import("core").types.Transaction = &[_]@import("core").types.Transaction{},
    };

    const b0 = MockBlock{ .header = .{ .number = 0 } };
    const b1 = MockBlock{ .header = .{ .number = 1 } };
    const b2 = MockBlock{ .header = .{ .number = 2 } }; // This should trigger reset

    const delta = try @import("delta.zig").StateDelta.init(allocator);
    defer delta.deinit();

    // Block 0
    _ = try aggregator.processBlock(b0, delta);
    try std.testing.expectEqual(@as(usize, 1), aggregator.blocks_in_epoch.items.len);

    // Block 1
    _ = try aggregator.processBlock(b1, delta);
    try std.testing.expectEqual(@as(usize, 2), aggregator.blocks_in_epoch.items.len);

    // Block 2 - triggers transition
    const epoch = try aggregator.processBlock(b2, delta);
    try std.testing.expect(epoch != null);
    if (epoch) |e| e.deinit(allocator);

    // After reset, block 2 should be in the new epoch
    try std.testing.expectEqual(@as(usize, 1), aggregator.blocks_in_epoch.items.len);
    try std.testing.expectEqual(@as(u64, 1), aggregator.current_epoch);
}
