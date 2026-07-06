// ============================================================================
// Zephyria — Snowball Voting Engine (Tier 3: Full Loom)
// ============================================================================
//
// Sub-sampled probabilistic finality for 2000+ validators.
// Instead of collecting BLS votes from all validators (O(N) messages),
// Snowball queries random subsets and converges on the preferred block.
//
// Parameters:
//   k (sample size) = 20 — peers queried per round
//   α (quorum) = 15 — threshold to update preference
//   β (confidence) = 3 — consecutive rounds needed to finalize
//
// At Tier 1-2, this module is never called. It activates at Tier 3 only.

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

/// Snowball preference state
pub const Preference = enum(u8) {
    None = 0,
    Accept = 1,
    Reject = 2,
};

/// Snowball configuration
pub const SnowballConfig = struct {
    /// Number of peers to sample per round
    k: u32 = types.SNOWBALL_K,
    /// Quorum threshold (must be > k/2)
    alpha: u32 = types.SNOWBALL_ALPHA,
    /// Consecutive rounds to finalize
    beta: u32 = types.SNOWBALL_BETA,
    /// Maximum rounds before timeout
    max_rounds: u32 = 20,
};

/// Per-block Snowball voting state
pub const SnowballInstance = struct {
    /// Block hash being voted on
    block_hash: core.types.Hash,
    /// Current preference (Accept or Reject)
    preference: Preference,
    /// Consecutive rounds with current preference
    consecutive_count: u32,
    /// Total rounds executed
    rounds_completed: u32,
    /// Whether finalization is achieved
    finalized: bool,
    /// Number of Accept responses in current round
    current_round_accept: u32,
    /// Number of Reject responses in current round
    current_round_reject: u32,
    /// Total responses in current round
    current_round_total: u32,
    /// Stake-weighted accept count
    current_round_accept_stake: u256,
    /// Stake-weighted reject count
    current_round_reject_stake: u256,
    /// Total stake of all respondents this round (for proportion check)
    current_round_total_stake: u256,
    /// Confidence counter for Accept
    accept_confidence: u32,
    /// Confidence counter for Reject
    reject_confidence: u32,
    /// Validator indices that already responded this round (dedup, max K)
    round_responders: [types.SNOWBALL_K]u32,
    /// How many unique responders we've seen this round
    round_responder_count: u8,

    /// Validator indices that were queried this round (set by setQueriedPeers)
    round_queried_peers: [types.SNOWBALL_K]u32,
    /// How many queried peers this round
    round_queried_count: u8,

    /// Snapshot of the final round's responders (set when finalized)
    final_round_responders: [types.SNOWBALL_K]u32,
    /// Count of valid final round responders
    final_round_responder_count: u8,
};

// ── Snowball Engine ─────────────────────────────────────────────────────

pub const Snowball = struct {
    allocator: std.mem.Allocator,
    config: SnowballConfig,

    /// Active Snowball instances (slot → instance)
    instances: std.AutoHashMap(u64, SnowballInstance),

    // Stats
    total_rounds: u64,
    total_finalizations: u64,
    total_timeouts: u64,

    /// Thread safety for concurrent P2P handler access.
    mutex: std.Thread.Mutex,

    pub const RecordResult = enum(u8) {
        None,           // Not enough responses yet
        Finalized,      // Block finalized (Accept or Reject)
        RoundComplete,  // Round complete, ready for next round
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: SnowballConfig) Self {
        // Snowball safety invariant: alpha > k/2 — without it no honest
        // majority can ever form and the protocol never converges.
        std.debug.assert(config.alpha * 2 > config.k);
        return Self{
            .allocator = allocator,
            .config = config,
            .instances = std.AutoHashMap(u64, SnowballInstance).init(allocator),
            .total_rounds = 0,
            .total_finalizations = 0,
            .total_timeouts = 0,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.instances.deinit();
    }

    /// Start a new Snowball instance for a slot.
    /// `preference` must be set by the caller based on block verification:
    /// - Accept if the block is valid, has valid parent, no equivocation
    /// - Reject if the block fails any verification step
    pub fn startInstance(self: *Self, slot: u64, block_hash: core.types.Hash, preference: Preference) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.instances.put(slot, SnowballInstance{
            .block_hash = block_hash,
            .preference = preference,
            .consecutive_count = 0,
            .rounds_completed = 0,
            .finalized = false,
            .current_round_accept = 0,
            .current_round_reject = 0,
            .current_round_total = 0,
            .current_round_accept_stake = 0,
            .current_round_reject_stake = 0,
            .current_round_total_stake = 0,
            .accept_confidence = 0,
            .reject_confidence = 0,
            .round_responders = undefined,
            .round_responder_count = 0,
            .round_queried_peers = undefined,
            .round_queried_count = 0,
            .final_round_responders = undefined,
            .final_round_responder_count = 0,
        });
    }

    /// Register the set of validators that were queried for the current round.
    /// Must be called before processing responses for this round.
    pub fn setQueriedPeers(self: *Self, slot: u64, peers: []const u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const instance = self.instances.getPtr(slot) orelse return;
        const count = @min(peers.len, types.SNOWBALL_K);
        for (peers[0..count], 0..) |p, i| {
            instance.round_queried_peers[i] = p;
        }
        instance.round_queried_count = @intCast(count);
    }

    /// Record a response from a queried peer.
    /// `responder_index` is the validator index — used for deduplication.
    /// `responder_stake` is that validator's voting stake.
    /// Returns RecordResult indicating what action the caller should take.
    pub fn recordResponse(
        self: *Self,
        slot: u64,
        responder_index: u32,
        accept: bool,
        responder_stake: u256,
    ) RecordResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        var instance = self.instances.getPtr(slot) orelse return .None;
        if (instance.finalized) return .Finalized;

        // Verify the responder was in the queried set for this round.
        const qc = instance.round_queried_count;
        if (qc > 0) {
            var found = false;
            for (0..qc) |i| {
                if (instance.round_queried_peers[i] == responder_index) {
                    found = true;
                    break;
                }
            }
            if (!found) return .None;
        }

        // Deduplicate: reject if this validator already responded this round
        const rc = instance.round_responder_count;
        for (0..rc) |i| {
            if (instance.round_responders[i] == responder_index) return .None;
        }
        if (rc < types.SNOWBALL_K) {
            instance.round_responders[rc] = responder_index;
            instance.round_responder_count = @intCast(rc + 1);
        }

        if (accept) {
            instance.current_round_accept += 1;
            instance.current_round_accept_stake += responder_stake;
        } else {
            instance.current_round_reject += 1;
            instance.current_round_reject_stake += responder_stake;
        }
        instance.current_round_total += 1;
        instance.current_round_total_stake += responder_stake;

        // Check if we have k responses (round complete)
        if (instance.current_round_total >= self.config.k) {
            return self.completeRound(instance);
        }

        return .None;
    }

    /// Complete a Snowball round and check for finalization.
    fn completeRound(self: *Self, instance: *SnowballInstance) RecordResult {
        self.total_rounds += 1;

        // Determine round winner using stake-weighted alpha.
        instance.rounds_completed += 1;
        self.total_rounds += 1;

        // Determine round winner using stake-weighted alpha.
        // For k sampled peers representing proportion of total stake,
        // require both count AND stake to pass the alpha threshold.
        // This prevents low-stake adversaries from biasing samples.
        const k = self.config.k;
        const alpha = self.config.alpha;
        const total_s = instance.current_round_total_stake;
        const accept_cnt = instance.current_round_accept >= alpha;
        const reject_cnt = instance.current_round_reject >= alpha;
        const accept_stake = total_s > 0 and
            instance.current_round_accept_stake * k >= total_s * alpha;
        const reject_stake = total_s > 0 and
            instance.current_round_reject_stake * k >= total_s * alpha;

        const round_pref: Preference = if (accept_cnt and accept_stake)
            .Accept
        else if (reject_cnt and reject_stake)
            .Reject
        else
            .None;

        // Update confidence counters
        if (round_pref == .Accept) {
            instance.accept_confidence += 1;
            instance.reject_confidence = 0;
        } else if (round_pref == .Reject) {
            instance.reject_confidence += 1;
            instance.accept_confidence = 0;
        } else {
            // No quorum this round — reset both
            instance.accept_confidence = 0;
            instance.reject_confidence = 0;
        }

        // Update preference based on confidence
        if (instance.accept_confidence > instance.reject_confidence) {
            instance.preference = .Accept;
            instance.consecutive_count = instance.accept_confidence;
        } else if (instance.reject_confidence > instance.accept_confidence) {
            instance.preference = .Reject;
            instance.consecutive_count = instance.reject_confidence;
        }

        // Check finalization: β consecutive rounds with same preference
        if (instance.consecutive_count >= self.config.beta) {
            instance.finalized = true;
            self.total_finalizations += 1;
            // Snapshot final round responders for QC formation
            const rc = instance.round_responder_count;
            for (0..rc) |i| {
                instance.final_round_responders[i] = instance.round_responders[i];
            }
            instance.final_round_responder_count = rc;
            return .Finalized;
        }

        // Check timeout — force Reject, never finalize an unconvincing block
        if (instance.rounds_completed >= self.config.max_rounds) {
            instance.preference = .Reject;
            instance.finalized = true;
            self.total_timeouts += 1;
            // Snapshot final round responders for QC formation
            const rc = instance.round_responder_count;
            for (0..rc) |i| {
                instance.final_round_responders[i] = instance.round_responders[i];
            }
            instance.final_round_responder_count = rc;
            return .Finalized;
        }

        // Round complete, caller should dispatch next round via nextRound()
        return .RoundComplete;
    }

    fn resetRound(self: *Self, instance: *SnowballInstance) void {
        _ = self;
        instance.current_round_accept = 0;
        instance.current_round_reject = 0;
        instance.current_round_total = 0;
        instance.current_round_accept_stake = 0;
        instance.current_round_reject_stake = 0;
        instance.current_round_total_stake = 0;
        instance.round_responder_count = 0;
        instance.round_queried_count = 0;
    }

    /// Check if a slot's instance has finalized.
    pub fn isFinalized(self: *Self, slot: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.instances.get(slot)) |instance| {
            return instance.finalized;
        }
        return false;
    }

    /// Get the preference for a slot's instance.
    pub fn getPreference(self: *Self, slot: u64) Preference {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.instances.get(slot)) |instance| {
            return instance.preference;
        }
        return .None;
    }

    /// Extract a SnowballQCProof from a finalized instance.
    /// Returns null if the instance is not finalized or doesn't exist.
    pub fn getFinalizationProof(self: *Self, slot: u64) ?types.SnowballQCProof {
        self.mutex.lock();
        defer self.mutex.unlock();
        const instance = self.instances.getPtr(slot) orelse return null;
        if (!instance.finalized) return null;
        return types.SnowballQCProof{
            .roundResponders = instance.final_round_responders,
            .responderCount = instance.final_round_responder_count,
            .roundsCompleted = instance.rounds_completed,
        };
    }

    /// Check if the block was accepted.
    pub fn isAccepted(self: *Self, slot: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.instances.get(slot)) |instance| {
            return instance.finalized and instance.preference == .Accept;
        }
        return false;
    }

    /// Check if a round is complete and the instance is ready for the next round.
    /// Returns true if the current round has collected enough responses for the
    /// next round to begin, regardless of whether finalization was achieved.
    pub fn isRoundComplete(self: *Self, slot: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const instance = self.instances.getPtr(slot) orelse return false;
        if (instance.finalized) return false;
        return instance.current_round_total >= self.config.k;
    }

    /// Reset the current round and return the peers for the next round.
    /// Advances `rounds_completed` and provides fresh peers for the caller
    /// to dispatch queries to.
    pub fn nextRound(
        self: *Self,
        slot: u64,
        seed: [32]u8,
        our_index: u32,
        validator_count: u32,
    ) ?[types.SNOWBALL_K]u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const instance = self.instances.getPtr(slot) orelse return null;
        if (instance.finalized) return null;

        instance.rounds_completed += 1;

        // Reset per-round state
        instance.current_round_accept = 0;
        instance.current_round_reject = 0;
        instance.current_round_total = 0;
        instance.current_round_accept_stake = 0;
        instance.current_round_reject_stake = 0;
        instance.current_round_total_stake = 0;
        instance.round_responder_count = 0;
        instance.round_queried_count = 0;

        const peers = self.selectPeers(
            seed,
            slot,
            instance.rounds_completed,
            validator_count,
            our_index,
        ) catch return null;

        for (peers, 0..) |p, i| {
            instance.round_queried_peers[i] = p;
        }
        instance.round_queried_count = types.SNOWBALL_K;

        return peers;
    }

    /// Remove an instance (cleanup after finalization).
    pub fn removeInstance(self: *Self, slot: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.instances.fetchRemove(slot);
    }

    /// Prune all instances older than a given slot.
    pub fn pruneOlderThan(self: *Self, slot: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var it = self.instances.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < slot) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |s| {
            _ = self.instances.fetchRemove(s);
        }
    }

    /// Select k random peers for querying (uses Blake3 PRNG).
    /// `our_index` is added to the PRNG seed so each validator queries
    /// a different (but deterministic and verifiable) set of peers.
    /// Returns indices into the validator array.
    pub fn selectPeers(
        self: *const Self,
        seed: [32]u8,
        slot: u64,
        round: u32,
        validator_count: u32,
        our_index: u32,
    ) ![types.SNOWBALL_K]u32 {
        _ = self;
        var peers: [types.SNOWBALL_K]u32 = undefined;
        if (validator_count <= types.SNOWBALL_K) {
            for (0..types.SNOWBALL_K) |i| {
                peers[i] = @intCast(i % validator_count);
            }
            return peers;
        }

        var state: [32]u8 = undefined;
        {
            var hasher = std.crypto.hash.Blake3.init(.{});
            hasher.update(&seed);
            var buf4: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf4, our_index, .big);
            hasher.update(&buf4);
            hasher.final(&state);
        }

        var selected: usize = 0;
        var attempts: usize = 0;
        const max_attempts = types.SNOWBALL_K * 4;
        while (selected < types.SNOWBALL_K and attempts < max_attempts) : (attempts += 1) {
            var hasher = std.crypto.hash.Blake3.init(.{});
            hasher.update(&state);
            var buf: [12]u8 = undefined;
            std.mem.writeInt(u64, buf[0..8], slot, .big);
            std.mem.writeInt(u32, buf[8..12], round + @as(u32, @intCast(attempts)), .big);
            hasher.update(&buf);
            hasher.final(&state);

            const val = std.mem.readInt(u32, state[0..4], .big);
            const idx = val % validator_count;

            const is_dup = blk: {
                for (0..selected) |j| {
                    if (peers[j] == idx) break :blk true;
                }
                break :blk false;
            };
            if (!is_dup) {
                peers[selected] = idx;
                selected += 1;
            }
        }
        var fallback_idx: u32 = @intCast(selected);
        while (selected < types.SNOWBALL_K) {
            const candidate = fallback_idx % validator_count;
            const is_dup = blk: {
                for (0..selected) |j| {
                    if (peers[j] == candidate) break :blk true;
                }
                break :blk false;
            };
            if (!is_dup) {
                peers[selected] = candidate;
                selected += 1;
            }
            fallback_idx += 1;
        }

        return peers;
    }

    /// Get statistics.
    pub const Stats = struct {
        active_instances: usize,
        total_rounds: u64,
        total_finalizations: u64,
        total_timeouts: u64,
    };

    pub fn getStats(self: *const Self) Stats {
        return .{
            .active_instances = self.instances.count(),
            .total_rounds = self.total_rounds,
            .total_finalizations = self.total_finalizations,
            .total_timeouts = self.total_timeouts,
        };
    }
};
