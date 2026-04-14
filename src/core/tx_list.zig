// ============================================================================
// Zephyria — Per-Account Transaction List
// ============================================================================
//
// Manages transactions for a single sender address.
// Two queues:
//   ready  — contiguous from expected nonce (executable now)
//   future — non-contiguous nonces (waiting for gap fill)
//
// Auto-promotes from future to ready when gaps are filled.

const std = @import("std");
const types = @import("types.zig");

pub const TxList = struct {
    allocator: std.mem.Allocator,
    ready_txs: std.ArrayListUnmanaged(*types.Transaction),
    queue_txs: std.ArrayListUnmanaged(*types.Transaction),
    nonce: u64,

    pub fn init(allocator: std.mem.Allocator, nonce: u64) TxList {
        return TxList{
            .allocator = allocator,
            .ready_txs = .{},
            .queue_txs = .{},
            .nonce = nonce,
        };
    }

    pub fn deinit(self: *TxList) void {
        self.ready_txs.deinit(self.allocator);
        self.queue_txs.deinit(self.allocator);
    }

    /// Add a transaction. Returns true if replaced an existing one.
    pub fn add(self: *TxList, tx: *types.Transaction) !bool {
        if (tx.nonce < self.nonce) return error.NonceTooLow;

        const next_ready_nonce = self.nonce + self.ready_txs.items.len;

        // Replace in ready list
        if (tx.nonce < next_ready_nonce) {
            const index = @as(usize, @intCast(tx.nonce - self.nonce));
            self.ready_txs.items[index] = tx;
            return true;
        }

        // Exact next nonce — append and promote
        if (tx.nonce == next_ready_nonce) {
            try self.ready_txs.append(self.allocator, tx);
            try self.promote();
            return false;
        }

        // Future transaction
        return try self.addToQueue(tx);
    }

    fn addToQueue(self: *TxList, tx: *types.Transaction) !bool {
        for (self.queue_txs.items, 0..) |existing, i| {
            if (existing.nonce == tx.nonce) {
                // Require 10% gas price bump for replacement
                const min_bump = existing.gas_price / 10;
                if (tx.gas_price < existing.gas_price + min_bump) {
                    return error.ReplacementGasTooLow;
                }
                self.queue_txs.items[i] = tx;
                return true;
            }
            if (existing.nonce > tx.nonce) {
                try self.queue_txs.insert(self.allocator, i, tx);
                return false;
            }
        }
        try self.queue_txs.append(self.allocator, tx);
        return false;
    }

    fn promote(self: *TxList) !void {
        while (self.queue_txs.items.len > 0) {
            const next_nonce = self.nonce + self.ready_txs.items.len;
            const head = self.queue_txs.items[0];
            if (head.nonce == next_nonce) {
                _ = self.queue_txs.orderedRemove(0);
                try self.ready_txs.append(self.allocator, head);
            } else if (head.nonce < next_nonce) {
                _ = self.queue_txs.orderedRemove(0);
            } else {
                break;
            }
        }
    }

    /// Advance expected nonce (after block inclusion).
    pub fn forward(self: *TxList, new_nonce: u64) void {
        if (new_nonce <= self.nonce) return;

        const diff = new_nonce - self.nonce;
        self.nonce = new_nonce;

        if (diff >= self.ready_txs.items.len) {
            self.ready_txs.clearRetainingCapacity();
        } else {
            const remove_count = @as(usize, @intCast(diff));
            _ = self.ready_txs.replaceRange(self.allocator, 0, remove_count, &[_]*types.Transaction{}) catch {};
        }

        // Prune stale queue entries
        while (self.queue_txs.items.len > 0) {
            if (self.queue_txs.items[0].nonce < self.nonce) {
                _ = self.queue_txs.orderedRemove(0);
            } else {
                break;
            }
        }

        self.promote() catch {};
    }

    pub fn ready(self: *TxList) []const *types.Transaction {
        return self.ready_txs.items;
    }

    pub fn len(self: *TxList) usize {
        return self.ready_txs.items.len + self.queue_txs.items.len;
    }

    pub fn empty(self: *TxList) bool {
        return self.len() == 0;
    }

    pub fn remove(self: *TxList, nonce: u64) bool {
        if (nonce >= self.nonce and nonce < self.nonce + self.ready_txs.items.len) {
            const index = @as(usize, @intCast(nonce - self.nonce));
            _ = self.ready_txs.orderedRemove(index);
            // Demote subsequent ready TXs to queue (gap created)
            while (self.ready_txs.items.len > index) {
                const tx = self.ready_txs.pop().?;
                _ = self.addToQueue(tx) catch {};
            }
            return true;
        }
        for (self.queue_txs.items, 0..) |tx, i| {
            if (tx.nonce == nonce) {
                _ = self.queue_txs.orderedRemove(i);
                return true;
            }
        }
        return false;
    }
};
