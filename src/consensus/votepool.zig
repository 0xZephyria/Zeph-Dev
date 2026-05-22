// ============================================================================
// Zephyria — Vote Pool (Hardened + Loom Genesis Adaptive)
// ============================================================================
//
// BLS vote aggregation with:
//   • Vote deduplication (bitmap-based)
//   • Signature batch verification
//   • Vote expiry (auto-prune old epochs)
//   • Safe iterator removal
//   • Tier-aware quorum: BLS aggregate at Tier 1–2, Snowball at Tier 3

const std = @import("std");
const types = @import("types.zig");
const ZeliusEngine = @import("zelius.zig").ZeliusEngine;
const core = @import("core");

const blst_mod = core.crypto.blst;
const c = blst_mod.c;

pub const VoteQueue = struct {
    const QueueEntry = struct {
        vote: types.VoteMsg,
        sequence: std.atomic.Value(usize),
    };

    buffer: []QueueEntry,
    allocator: std.mem.Allocator,
    capacity: usize,
    enqueue_pos: std.atomic.Value(usize),
    dequeue_pos: std.atomic.Value(usize),

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !VoteQueue {
        const actual_cap = try std.math.ceilPowerOfTwo(usize, capacity);
        const buffer = try allocator.alloc(QueueEntry, actual_cap);
        for (buffer, 0..) |*entry, i| {
            entry.sequence = std.atomic.Value(usize).init(i);
        }
        return VoteQueue{
            .allocator = allocator,
            .buffer = buffer,
            .capacity = actual_cap,
            .enqueue_pos = std.atomic.Value(usize).init(0),
            .dequeue_pos = std.atomic.Value(usize).init(0),
        };
    }

    pub fn deinit(self: *VoteQueue) void {
        self.allocator.free(self.buffer);
    }

    pub fn tryEnqueue(self: *VoteQueue, vote: types.VoteMsg) bool {
        var pos = self.enqueue_pos.load(.monotonic);
        while (true) {
            const entry = &self.buffer[pos & (self.capacity - 1)];
            const seq = entry.sequence.load(.acquire);
            const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(pos));
            if (diff == 0) {
                if (self.enqueue_pos.cmpxchgWeak(pos, pos + 1, .release, .monotonic)) |actual| {
                    pos = actual;
                } else {
                    entry.vote = vote;
                    entry.sequence.store(pos + 1, .release);
                    return true;
                }
            } else if (diff < 0) {
                return false; // Full
            } else {
                pos = self.enqueue_pos.load(.monotonic);
            }
        }
    }

    pub fn tryDequeue(self: *VoteQueue, vote_out: *types.VoteMsg) bool {
        var pos = self.dequeue_pos.load(.monotonic);
        while (true) {
            const entry = &self.buffer[pos & (self.capacity - 1)];
            const seq = entry.sequence.load(.acquire);
            const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(pos + 1));
            if (diff == 0) {
                if (self.dequeue_pos.cmpxchgWeak(pos, pos + 1, .release, .monotonic)) |actual| {
                    pos = actual;
                } else {
                    vote_out.* = entry.vote;
                    entry.sequence.store(pos + self.capacity, .release);
                    return true;
                }
            } else if (diff < 0) {
                return false; // Empty
            } else {
                pos = self.dequeue_pos.load(.monotonic);
            }
        }
    }
};

pub const VotePool = struct {
    allocator: std.mem.Allocator,
    engine: *ZeliusEngine,
    // BlockHash -> ValidatorIndex -> Vote
    votes: std.AutoHashMap(core.types.Hash, std.AutoHashMap(u64, types.VoteMsg)),
    // Inbound queue for lock-free vote submission
    inbound_queue: VoteQueue,
    // Stats
    votes_received: u64,
    votes_rejected: u64,
    votes_expired: u64,

    pub fn init(allocator: std.mem.Allocator, engine: *ZeliusEngine) !VotePool {
        const queue = try VoteQueue.init(allocator, 2048);
        return VotePool{
            .allocator = allocator,
            .engine = engine,
            .votes = std.AutoHashMap(core.types.Hash, std.AutoHashMap(u64, types.VoteMsg)).init(allocator),
            .inbound_queue = queue,
            .votes_received = 0,
            .votes_rejected = 0,
            .votes_expired = 0,
        };
    }

    pub fn deinit(self: *VotePool) void {
        var it = self.votes.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.votes.deinit();
        self.inbound_queue.deinit();
    }

    /// AddVote adds a vote to the pool. Returns true if new and valid.
    pub fn add_vote(self: *VotePool, vote: types.VoteMsg) !bool {
        self.votes_received += 1;

        // 1. Basic Validation
        if (vote.validatorIndex >= self.engine.activeValidators.len) {
            self.votes_rejected += 1;
            return false;
        }

        // 2. Verify Signature
        if (!try self.engine.verify_vote_signature(vote.validatorIndex, vote.blockHash, vote.view, vote.signature)) {
            self.votes_rejected += 1;
            return false;
        }

        // 3. Deduplication: check if already voted
        const g = try self.votes.getOrPut(vote.blockHash);
        if (!g.found_existing) {
            g.value_ptr.* = std.AutoHashMap(u64, types.VoteMsg).init(self.allocator);
        }

        const v_map = g.value_ptr;
        if (v_map.contains(vote.validatorIndex)) {
            self.votes_rejected += 1;
            return false; // Duplicate vote
        }

        try v_map.put(vote.validatorIndex, vote);
        return true;
    }

    /// Enqueue a vote thread-safely on the inbound lock-free MPMC queue.
    /// Returns true if successfully enqueued, false if queue is full.
    pub fn enqueue_vote(self: *VotePool, vote: types.VoteMsg) bool {
        return self.inbound_queue.tryEnqueue(vote);
    }

    /// Process all pending votes in the inbound queue sequentially.
    /// This should be called from the main thread / loop.
    /// Returns the number of votes processed.
    pub fn process_inbound_queue(self: *VotePool) !usize {
        var count: usize = 0;
        var vote: types.VoteMsg = undefined;
        while (self.inbound_queue.tryDequeue(&vote)) {
            _ = try self.add_vote(vote);
            count += 1;
        }
        return count;
    }

    /// Prune removes votes for views older than min_view (safe iteration).
    pub fn prune(self: *VotePool, min_view: u64) void {
        // Collect keys to remove first (safe iteration)
        var keys_to_remove = std.ArrayListUnmanaged(core.types.Hash){};
        defer keys_to_remove.deinit(self.allocator);

        var it = self.votes.iterator();
        while (it.next()) |entry| {
            // Check first vote's view
            var val_it = entry.value_ptr.iterator();
            if (val_it.next()) |v| {
                if (v.value_ptr.view < min_view) {
                    keys_to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }
        }

        // Now remove collected keys
        for (keys_to_remove.items) |key| {
            if (self.votes.getPtr(key)) |map| {
                const count = map.count();
                map.deinit();
                self.votes_expired += count;
            }
            _ = self.votes.remove(key);
        }
    }

    /// CheckQuorum checks if a block has 2/3+ votes.
    /// Returns the aggregated BLS signature and validator bitmask.
    pub fn check_quorum(self: *VotePool, block_hash: core.types.Hash) !?struct { sig: [96]u8, bitmask: []u8 } {
        const votes_map_ptr = self.votes.getPtr(block_hash);
        if (votes_map_ptr == null) return null;
        const votes_map = votes_map_ptr.*;

        var total_stake: u128 = 0;
        var voted_stake: u128 = 0;

        // Calculate Total Stake
        for (self.engine.activeValidators) |val| {
            total_stake += val.stake;
        }

        if (total_stake == 0) return null;

        // Build bitmask
        const num_vals = self.engine.activeValidators.len;
        const bitmask_len = (num_vals + 7) / 8;
        var bitmask = try self.allocator.alloc(u8, bitmask_len);
        @memset(bitmask, 0);

        // Aggregate BLS signatures
        var acc = std.mem.zeroes(c.blst_p2);
        var first = true;

        var it = votes_map.iterator();
        while (it.next()) |entry| {
            const idx = entry.key_ptr.*;
            const vote = entry.value_ptr.*;

            if (idx >= num_vals) continue;

            const val = self.engine.activeValidators[idx];
            voted_stake += val.stake;

            // Set bitmask
            const byte_idx = idx / 8;
            const bit_idx: u3 = @intCast(idx % 8);
            bitmask[byte_idx] |= (@as(u8, 1) << bit_idx);

            // Aggregate BLS signature
            var sig_affine = std.mem.zeroes(c.blst_p2_affine);
            const res = c.blst_p2_uncompress(&sig_affine, &vote.signature);
            if (res != c.BLST_SUCCESS) continue;

            var sig_jac = std.mem.zeroes(c.blst_p2);
            c.blst_p2_from_affine(&sig_jac, &sig_affine);

            if (first) {
                acc = sig_jac;
                first = false;
            } else {
                c.blst_p2_add_or_double(&acc, &acc, &sig_jac);
            }
        }

        // Check Threshold: > 2/3
        const threshold = (total_stake * 2) / 3;

        if (voted_stake > threshold) {
            // Serialize aggregated signature
            var sig_bytes: [96]u8 = undefined;
            c.blst_p2_compress(&sig_bytes, &acc);
            return .{ .sig = sig_bytes, .bitmask = bitmask };
        }

        self.allocator.free(bitmask);
        return null;
    }

    /// Get pool statistics.
    pub fn getStats(self: *const VotePool) struct { received: u64, rejected: u64, expired: u64, active: usize } {
        return .{
            .received = self.votes_received,
            .rejected = self.votes_rejected,
            .expired = self.votes_expired,
            .active = self.votes.count(),
        };
    }

    /// Tier-aware quorum check.
    /// At Tier 1–2: standard BLS aggregate (same as check_quorum).
    /// At Tier 3: should use Snowball instead (returns null, caller uses snowball engine).
    pub fn check_quorum_adaptive(self: *VotePool, block_hash: core.types.Hash, tier: types.ConsensusTier) !?struct { sig: [96]u8, bitmask: []u8 } {
        switch (tier) {
            .FullBFT, .CommitteeLoom => {
                // At Tier 1-2, standard BLS aggregate voting
                return self.check_quorum(block_hash);
            },
            .FullLoom => {
                // At Tier 3, Snowball finality is used instead.
                // The vote pool still collects votes for data availability,
                // but finality decisions are made by the Snowball engine.
                return null;
            },
        }
    }
};

test "VoteQueue basic enqueue and dequeue" {
    const allocator = std.testing.allocator;
    var queue = try VoteQueue.init(allocator, 4);
    defer queue.deinit();

    const vote1 = types.VoteMsg{
        .blockHash = core.types.Hash.zero(),
        .blockNumber = 1,
        .view = 10,
        .signature = [_]u8{0} ** 96,
        .validatorIndex = 0,
    };
    const vote2 = types.VoteMsg{
        .blockHash = core.types.Hash.zero(),
        .blockNumber = 2,
        .view = 11,
        .signature = [_]u8{0} ** 96,
        .validatorIndex = 1,
    };

    try std.testing.expect(queue.tryEnqueue(vote1));
    try std.testing.expect(queue.tryEnqueue(vote2));

    var vote_out: types.VoteMsg = undefined;
    try std.testing.expect(queue.tryDequeue(&vote_out));
    try std.testing.expectEqual(@as(u64, 1), vote_out.blockNumber);
    try std.testing.expectEqual(@as(u64, 10), vote_out.view);

    try std.testing.expect(queue.tryDequeue(&vote_out));
    try std.testing.expectEqual(@as(u64, 2), vote_out.blockNumber);
    try std.testing.expectEqual(@as(u64, 11), vote_out.view);

    try std.testing.expect(!queue.tryDequeue(&vote_out));
}

test "VoteQueue multi-threaded stress" {
    const allocator = std.testing.allocator;
    var queue = try VoteQueue.init(allocator, 128);
    defer queue.deinit();

    const Context = struct {
        q: *VoteQueue,
        target: usize,
        pub fn producer(ctx: *const @This()) void {
            var i: usize = 0;
            while (i < ctx.target) {
                const vote = types.VoteMsg{
                    .blockHash = core.types.Hash.zero(),
                    .blockNumber = i,
                    .view = 42,
                    .signature = [_]u8{0} ** 96,
                    .validatorIndex = 0,
                };
                if (ctx.q.tryEnqueue(vote)) {
                    i += 1;
                } else {
                    std.Thread.yield() catch {};
                }
            }
        }
        pub fn consumer(ctx: *const @This(), count: *std.atomic.Value(usize)) void {
            var local_count: usize = 0;
            while (local_count < ctx.target) {
                var vote: types.VoteMsg = undefined;
                if (ctx.q.tryDequeue(&vote)) {
                    local_count += 1;
                    _ = count.fetchAdd(1, .monotonic);
                } else {
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var count = std.atomic.Value(usize).init(0);
    const ctx = Context{ .q = &queue, .target = 2000 };

    const t1 = try std.Thread.spawn(.{}, Context.producer, .{&ctx});
    const t2 = try std.Thread.spawn(.{}, Context.producer, .{&ctx});
    const t3 = try std.Thread.spawn(.{}, Context.consumer, .{ &ctx, &count });
    const t4 = try std.Thread.spawn(.{}, Context.consumer, .{ &ctx, &count });

    t1.join();
    t2.join();
    t3.join();
    t4.join();

    try std.testing.expectEqual(@as(usize, 4000), count.load(.monotonic));
}

