const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const keys_mod = @import("keys.zig");

const blst_mod = core.crypto.blst;
const c = blst_mod.c;

pub const VoteQueue = struct {
    const QueueEntry = struct {
        entry: types.VoteMsg,
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

    pub fn tryEnqueue(self: *VoteQueue, data: types.VoteMsg) bool {
        var pos = self.enqueue_pos.load(.monotonic);
        while (true) {
            const entry = &self.buffer[pos & (self.capacity - 1)];
            const seq = entry.sequence.load(.acquire);
            const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(pos));
            if (diff == 0) {
                if (self.enqueue_pos.cmpxchgWeak(pos, pos + 1, .release, .monotonic)) |actual| {
                    pos = actual;
                } else {
                    entry.entry = data;
                    entry.sequence.store(pos + 1, .release);
                    return true;
                }
            } else if (diff < 0) {
                return false;
            } else {
                pos = self.enqueue_pos.load(.monotonic);
            }
        }
    }

    pub fn tryDequeue(self: *VoteQueue, data_out: *types.VoteMsg) bool {
        var pos = self.dequeue_pos.load(.monotonic);
        while (true) {
            const entry = &self.buffer[pos & (self.capacity - 1)];
            const seq = entry.sequence.load(.acquire);
            const diff = @as(isize, @intCast(seq)) - @as(isize, @intCast(pos + 1));
            if (diff == 0) {
                if (self.dequeue_pos.cmpxchgWeak(pos, pos + 1, .release, .monotonic)) |actual| {
                    pos = actual;
                } else {
                    data_out.* = entry.entry;
                    entry.sequence.store(pos + self.capacity, .release);
                    return true;
                }
            } else if (diff < 0) {
                return false;
            } else {
                pos = self.dequeue_pos.load(.monotonic);
            }
        }
    }
};

pub const AggregatedVotes = struct {
    slot: u64,
    blockHash: core.types.Hash,
    aggregateSignature: [96]u8,
    voterBitmap: []u8,
    totalAttestingStake: u256,
    totalStake: u256,
    voterCount: u32,
};

pub const VoteCollector = struct {
    allocator: std.mem.Allocator,
    inbound_queue: VoteQueue,

    votes: std.AutoHashMap(core.types.Hash, std.AutoHashMap(u32, types.VoteMsg)),
    block_stake: std.AutoHashMap(core.types.Hash, u256),

    votesReceived: u64,
    votesRejected: u64,
    votesExpired: u64,

    pub fn init(allocator: std.mem.Allocator, queue_capacity: usize) !VoteCollector {
        const queue = try VoteQueue.init(allocator, queue_capacity);
        return VoteCollector{
            .allocator = allocator,
            .inbound_queue = queue,
            .votes = std.AutoHashMap(core.types.Hash, std.AutoHashMap(u32, types.VoteMsg)).init(allocator),
            .block_stake = std.AutoHashMap(core.types.Hash, u256).init(allocator),
            .votesReceived = 0,
            .votesRejected = 0,
            .votesExpired = 0,
        };
    }

    pub fn deinit(self: *VoteCollector) void {
        var it = self.votes.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.votes.deinit();
        self.block_stake.deinit();
        self.inbound_queue.deinit();
    }

    pub fn addVote(self: *VoteCollector, vote: types.VoteMsg, validators: []const types.ValidatorInfo) !bool {
        self.votesReceived += 1;

        if (vote.validatorIndex >= validators.len) {
            self.votesRejected += 1;
            return false;
        }

        const pk = &validators[vote.validatorIndex].blsPubKey;
        if (!keys_mod.verifyVoteSignature(pk.*, vote.blockId, vote.view, vote.signature)) {
            self.votesRejected += 1;
            return false;
        }

        const g = try self.votes.getOrPut(vote.blockId);
        if (!g.found_existing) {
            g.value_ptr.* = std.AutoHashMap(u32, types.VoteMsg).init(self.allocator);
        }
        const v_map = g.value_ptr;
        if (v_map.contains(vote.validatorIndex)) {
            self.votesRejected += 1;
            return false;
        }
        try v_map.put(vote.validatorIndex, vote);

        const stake = validators[vote.validatorIndex].stake;
        const entry = try self.block_stake.getOrPut(vote.blockId);
        if (!entry.found_existing) {
            entry.value_ptr.* = 0;
        }
        entry.value_ptr.* += stake;

        const total = if (validators.len > 0) blk: {
            var sum: u256 = 0;
            for (validators) |v| sum += v.stake;
            break :blk sum;
        } else 0;

        if (total > 0 and entry.value_ptr.* * 3 > total * 2) {
            return true;
        }

        return false;
    }

    pub fn enqueueVote(self: *VoteCollector, vote: types.VoteMsg) bool {
        return self.inbound_queue.tryEnqueue(vote);
    }

    pub fn processInboundQueue(self: *VoteCollector, validators: []const types.ValidatorInfo) !usize {
        var count: usize = 0;
        var vote: types.VoteMsg = undefined;
        while (self.inbound_queue.tryDequeue(&vote)) {
            _ = try self.addVote(vote, validators);
            count += 1;
        }
        return count;
    }

    pub fn aggregateBlock(self: *VoteCollector, block_hash: core.types.Hash, slot: u64, validators: []const types.ValidatorInfo) !?AggregatedVotes {
        const v_map_ptr = self.votes.getPtr(block_hash) orelse return null;
        if (v_map_ptr.count() == 0) return null;

        var acc = std.mem.zeroes(c.blst_p2);
        var first = true;
        const bitmap_len = (validators.len + 7) / 8;
        var voter_bitmap = try self.allocator.alloc(u8, bitmap_len);
        @memset(voter_bitmap, 0);
        var voter_count: u32 = 0;
        var attesting_stake: u256 = 0;

        var it = v_map_ptr.iterator();
        while (it.next()) |entry| {
            const idx = entry.key_ptr.*;
            const vote = entry.value_ptr.*;

            if (idx >= validators.len) continue;
            attesting_stake += validators[idx].stake;

            const byte_idx = idx / 8;
            const bit_idx: u3 = @intCast(idx % 8);
            voter_bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
            voter_count += 1;

            var sig_affine = std.mem.zeroes(c.blst_p2_affine);
            const res = c.blst_p2_uncompress(&sig_affine, &vote.signature);
            if (res != c.BLST_SUCCESS) continue;
            if (!c.blst_p2_affine_in_g2(&sig_affine)) continue;

            var sig_jac = std.mem.zeroes(c.blst_p2);
            c.blst_p2_from_affine(&sig_jac, &sig_affine);

            if (first) {
                acc = sig_jac;
                first = false;
            } else {
                c.blst_p2_add_or_double(&acc, &acc, &sig_jac);
            }
        }

        if (voter_count == 0) return null;

        var agg_sig_bytes: [96]u8 = undefined;
        c.blst_p2_compress(&agg_sig_bytes, &acc);

        const total = if (validators.len > 0) blk: {
            var sum: u256 = 0;
            for (validators) |v| sum += v.stake;
            break :blk sum;
        } else 0;

        return AggregatedVotes{
            .slot = slot,
            .blockHash = block_hash,
            .aggregateSignature = agg_sig_bytes,
            .voterBitmap = voter_bitmap,
            .totalAttestingStake = attesting_stake,
            .totalStake = total,
            .voterCount = voter_count,
        };
    }

    pub fn checkQuorum(self: *VoteCollector, block_hash: core.types.Hash, validators: []const types.ValidatorInfo) !?struct { sig: [96]u8, bitmask: []u8 } {
        const v_map_ptr = self.votes.getPtr(block_hash) orelse return null;
        if (v_map_ptr.count() == 0) return null;

        const total_stake = if (validators.len > 0) blk: {
            var sum: u256 = 0;
            for (validators) |v| sum += v.stake;
            break :blk sum;
        } else 0;
        if (total_stake == 0) return null;

        var voted_stake: u256 = 0;
        const num_vals = validators.len;
        const bitmask_len = (num_vals + 7) / 8;
        var bitmask = try self.allocator.alloc(u8, bitmask_len);
        @memset(bitmask, 0);

        var acc = std.mem.zeroes(c.blst_p2);
        var first = true;

        var it = v_map_ptr.iterator();
        while (it.next()) |entry| {
            const idx = entry.key_ptr.*;
            const vote = entry.value_ptr.*;

            if (idx >= num_vals) continue;
            voted_stake += validators[idx].stake;

            const byte_idx = idx / 8;
            const bit_idx: u3 = @intCast(idx % 8);
            bitmask[byte_idx] |= (@as(u8, 1) << bit_idx);

            var sig_affine = std.mem.zeroes(c.blst_p2_affine);
            const res = c.blst_p2_uncompress(&sig_affine, &vote.signature);
            if (res != c.BLST_SUCCESS) continue;
            if (!c.blst_p2_affine_in_g2(&sig_affine)) continue;

            var sig_jac = std.mem.zeroes(c.blst_p2);
            c.blst_p2_from_affine(&sig_jac, &sig_affine);

            if (first) {
                acc = sig_jac;
                first = false;
            } else {
                c.blst_p2_add_or_double(&acc, &acc, &sig_jac);
            }
        }

        const threshold = (total_stake * 2) / 3;
        if (voted_stake > threshold) {
            var sig_bytes: [96]u8 = undefined;
            c.blst_p2_compress(&sig_bytes, &acc);
            return .{ .sig = sig_bytes, .bitmask = bitmask };
        }

        self.allocator.free(bitmask);
        return null;
    }

    pub fn checkQuorumAdaptive(self: *VoteCollector, block_hash: core.types.Hash, tier: types.ConsensusTier, validators: []const types.ValidatorInfo) !?struct { sig: [96]u8, bitmask: []u8 } {
        return switch (tier) {
            .FullBFT, .CommitteeLoom => self.checkQuorum(block_hash, validators),
            .FullLoom => null,
        };
    }

    pub fn prune(self: *VoteCollector, min_view: u64) void {
        var keys_to_remove = std.ArrayListUnmanaged(core.types.Hash){};
        defer keys_to_remove.deinit(self.allocator);

        var it = self.votes.iterator();
        while (it.next()) |entry| {
            var val_it = entry.value_ptr.iterator();
            if (val_it.next()) |v| {
                if (v.value_ptr.view < min_view) {
                    keys_to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }
        }

        for (keys_to_remove.items) |key| {
            if (self.votes.getPtr(key)) |map| {
                self.votesExpired += map.count();
                map.deinit();
            }
            _ = self.votes.remove(key);
            _ = self.block_stake.remove(key);
        }
    }

    pub fn getStats(self: *const VoteCollector) struct { received: u64, rejected: u64, expired: u64, active: usize } {
        return .{
            .received = self.votesReceived,
            .rejected = self.votesRejected,
            .expired = self.votesExpired,
            .active = self.votes.count(),
        };
    }
};
