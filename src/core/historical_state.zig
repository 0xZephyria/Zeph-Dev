// ============================================================================
// Zephyria — Historical State
// ============================================================================
//
// Time-travel queries via epoch-based delta traversal.
// "What was account X balance at block N?"
//
// Uses epoch deltas stored in the storage layer to walk backwards
// from current state to any historical block.

const std = @import("std");
const types = @import("types.zig");
const storage = @import("storage");

const StateDelta = storage.epoch.StateDelta;
const EpochAggregator = storage.epoch.EpochAggregator;
const AggregatedEpoch = storage.epoch.AggregatedEpoch;
const EpochMetadata = storage.epoch.EpochMetadata;
const EPOCH_SIZE = storage.epoch.EPOCH_SIZE;

pub const HistoricalState = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    db: storage.DB,
    head_block: u64,
    head_epoch: u64,
    epoch_cache: std.AutoHashMap(u64, *AggregatedEpoch),
    cache_capacity: usize,
    cache_order: std.ArrayListUnmanaged(u64),
    current_state: *@import("state.zig").State,

    pub fn init(
        allocator: std.mem.Allocator,
        db: storage.DB,
        current_state: *@import("state.zig").State,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .db = db,
            .head_block = 0,
            .head_epoch = 0,
            .epoch_cache = std.AutoHashMap(u64, *AggregatedEpoch).init(allocator),
            .cache_capacity = 16,
            .cache_order = .{},
            .current_state = current_state,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        var it = self.epoch_cache.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.epoch_cache.deinit();
        self.cache_order.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn setHead(self: *Self, block_number: u64) void {
        self.head_block = block_number;
        self.head_epoch = block_number / EPOCH_SIZE;
    }

    pub fn getBalanceAt(self: *Self, address: types.Address, block: u64) !u256 {
        if (block >= self.head_block) {
            return self.current_state.getBalance(address);
        }

        const target_epoch = block / EPOCH_SIZE;
        var balance = self.current_state.getBalance(address);

        var epoch = self.head_epoch;
        while (epoch > target_epoch) {
            const epoch_data = try self.loadEpoch(epoch);
            const delta = try self.decompressEpochDelta(epoch_data);
            defer delta.deinit();

            if (delta.getAccountDelta(address.bytes)) |account_delta| {
                if (account_delta.balance_delta >= 0) {
                    balance -|= @intCast(account_delta.balance_delta);
                } else {
                    balance +|= @intCast(-account_delta.balance_delta);
                }
            }
            epoch -= 1;
        }
        return balance;
    }

    pub fn getNonceAt(self: *Self, address: types.Address, block: u64) !u64 {
        if (block >= self.head_block) {
            return self.current_state.getNonce(address);
        }

        const target_epoch = block / EPOCH_SIZE;
        var nonce = self.current_state.getNonce(address);

        var epoch = self.head_epoch;
        while (epoch > target_epoch) {
            const epoch_data = try self.loadEpoch(epoch);
            const delta = try self.decompressEpochDelta(epoch_data);
            defer delta.deinit();

            if (delta.getAccountDelta(address.bytes)) |account_delta| {
                if (account_delta.nonce_delta >= 0) {
                    nonce -|= @intCast(account_delta.nonce_delta);
                } else {
                    nonce +|= @intCast(-account_delta.nonce_delta);
                }
            }
            epoch -= 1;
        }
        return nonce;
    }

    pub const AccountSnapshot = struct {
        balance: u256,
        nonce: u64,
        block: u64,
    };

    pub fn getAccountAt(self: *Self, address: types.Address, block: u64) !AccountSnapshot {
        return AccountSnapshot{
            .balance = try self.getBalanceAt(address, block),
            .nonce = try self.getNonceAt(address, block),
            .block = block,
        };
    }

    fn loadEpoch(self: *Self, epoch_number: u64) !*AggregatedEpoch {
        if (self.epoch_cache.get(epoch_number)) |epoch| {
            self.touchCache(epoch_number);
            return epoch;
        }
        const epoch = try EpochAggregator.loadEpoch(self.allocator, epoch_number, self.db);
        try self.evictIfNeeded();
        try self.epoch_cache.put(epoch_number, epoch);
        try self.cache_order.append(self.allocator, epoch_number);
        return epoch;
    }

    fn touchCache(self: *Self, epoch_number: u64) void {
        for (self.cache_order.items, 0..) |e, i| {
            if (e == epoch_number) {
                _ = self.cache_order.orderedRemove(i);
                self.cache_order.append(self.allocator, epoch_number) catch {};
                break;
            }
        }
    }

    fn evictIfNeeded(self: *Self) !void {
        while (self.epoch_cache.count() >= self.cache_capacity) {
            if (self.cache_order.items.len > 0) {
                const oldest = self.cache_order.orderedRemove(0);
                if (self.epoch_cache.fetchRemove(oldest)) |removed| {
                    removed.value.deinit(self.allocator);
                    self.allocator.destroy(removed.value);
                }
            } else break;
        }
    }

    fn decompressEpochDelta(self: *Self, epoch: *AggregatedEpoch) !*StateDelta {
        const decompressed = try StateDelta.decompress(self.allocator, epoch.compressed_delta);
        defer self.allocator.free(decompressed);
        return try StateDelta.deserialize(self.allocator, decompressed);
    }

    pub fn getEpochForBlock(block: u64) u64 {
        return block / EPOCH_SIZE;
    }

    pub fn getEpochMetadata(self: *Self, epoch_number: u64) !EpochMetadata {
        const epoch = try self.loadEpoch(epoch_number);
        return epoch.metadata;
    }

    pub fn getStats(self: *const Self) struct {
        cached_epochs: usize,
        head_block: u64,
        head_epoch: u64,
    } {
        return .{
            .cached_epochs = self.epoch_cache.count(),
            .head_block = self.head_block,
            .head_epoch = self.head_epoch,
        };
    }
};

pub const HistoricalProof = struct {
    target_block: u64,
    epoch_number: u64,
    account: types.Address,
    epoch_end_balance: u256,
    epoch_end_nonce: u64,
    aggregated_sig: [96]u8,
    mmr_proof_siblings: std.ArrayListUnmanaged([32]u8),

    pub fn deinit(self: *HistoricalProof, allocator: std.mem.Allocator) void {
        self.mmr_proof_siblings.deinit(allocator);
    }
};

test "HistoricalState epoch calculation" {
    try std.testing.expectEqual(@as(u64, 0), HistoricalState.getEpochForBlock(0));
    try std.testing.expectEqual(@as(u64, 0), HistoricalState.getEpochForBlock(99999));
    try std.testing.expectEqual(@as(u64, 1), HistoricalState.getEpochForBlock(100000));
    try std.testing.expectEqual(@as(u64, 10), HistoricalState.getEpochForBlock(1000000));
}
