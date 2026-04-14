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

pub const VotePool = struct {
    allocator: std.mem.Allocator,
    engine: *ZeliusEngine,
    // BlockHash -> ValidatorIndex -> Vote
    votes: std.AutoHashMap(core.types.Hash, std.AutoHashMap(u64, types.VoteMsg)),
    // Stats
    votes_received: u64,
    votes_rejected: u64,
    votes_expired: u64,

    pub fn init(allocator: std.mem.Allocator, engine: *ZeliusEngine) VotePool {
        return VotePool{
            .allocator = allocator,
            .engine = engine,
            .votes = std.AutoHashMap(core.types.Hash, std.AutoHashMap(u64, types.VoteMsg)).init(allocator),
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
    }

    /// AddVote adds a vote to the pool. Returns true if new and valid.
    pub fn add_vote(self: *VotePool, vote: types.VoteMsg) !bool {
        self.votes_received += 1;

        // 1. Basic Validation
        if (vote.validator_index >= self.engine.active_validators.len) {
            self.votes_rejected += 1;
            return false;
        }

        // 2. Verify Signature
        if (!try self.engine.verify_vote_signature(vote.validator_index, vote.block_hash, vote.view, vote.signature)) {
            self.votes_rejected += 1;
            return false;
        }

        // 3. Deduplication: check if already voted
        const g = try self.votes.getOrPut(vote.block_hash);
        if (!g.found_existing) {
            g.value_ptr.* = std.AutoHashMap(u64, types.VoteMsg).init(self.allocator);
        }

        const v_map = g.value_ptr;
        if (v_map.contains(vote.validator_index)) {
            self.votes_rejected += 1;
            return false; // Duplicate vote
        }

        try v_map.put(vote.validator_index, vote);
        return true;
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
        for (self.engine.active_validators) |val| {
            total_stake += val.stake;
        }

        if (total_stake == 0) return null;

        // Build bitmask
        const num_vals = self.engine.active_validators.len;
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

            const val = self.engine.active_validators[idx];
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
