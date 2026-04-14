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
    current_round_accept_stake: u64,
    /// Stake-weighted reject count
    current_round_reject_stake: u64,
    /// Confidence counter for Accept
    accept_confidence: u32,
    /// Confidence counter for Reject
    reject_confidence: u32,
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

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: SnowballConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .instances = std.AutoHashMap(u64, SnowballInstance).init(allocator),
            .total_rounds = 0,
            .total_finalizations = 0,
            .total_timeouts = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.instances.deinit();
    }

    /// Start a new Snowball instance for a slot.
    pub fn startInstance(self: *Self, slot: u64, block_hash: core.types.Hash) !void {
        try self.instances.put(slot, SnowballInstance{
            .block_hash = block_hash,
            .preference = .None,
            .consecutive_count = 0,
            .rounds_completed = 0,
            .finalized = false,
            .current_round_accept = 0,
            .current_round_reject = 0,
            .current_round_total = 0,
            .current_round_accept_stake = 0,
            .current_round_reject_stake = 0,
            .accept_confidence = 0,
            .reject_confidence = 0,
        });
    }

    /// Record a response from a queried peer.
    /// Returns true if finalization is now achieved.
    pub fn recordResponse(
        self: *Self,
        slot: u64,
        accept: bool,
        responder_stake: u64,
    ) bool {
        var instance = self.instances.getPtr(slot) orelse return false;
        if (instance.finalized) return true;

        if (accept) {
            instance.current_round_accept += 1;
            instance.current_round_accept_stake += responder_stake;
        } else {
            instance.current_round_reject += 1;
            instance.current_round_reject_stake += responder_stake;
        }
        instance.current_round_total += 1;

        // Check if we have k responses (round complete)
        if (instance.current_round_total >= self.config.k) {
            return self.completeRound(instance);
        }

        return false;
    }

    /// Complete a Snowball round and check for finalization.
    fn completeRound(self: *Self, instance: *SnowballInstance) bool {
        instance.rounds_completed += 1;
        self.total_rounds += 1;

        // Determine round winner
        const round_pref: Preference = if (instance.current_round_accept >= self.config.alpha)
            .Accept
        else if (instance.current_round_reject >= self.config.alpha)
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
            // Reset for next round (round is done)
            self.resetRound(instance);
            return true;
        }

        // Check timeout
        if (instance.rounds_completed >= self.config.max_rounds) {
            // Force finalization with current preference
            instance.finalized = true;
            self.total_timeouts += 1;
            return true;
        }

        // Reset for next round
        self.resetRound(instance);
        return false;
    }

    fn resetRound(self: *Self, instance: *SnowballInstance) void {
        _ = self;
        instance.current_round_accept = 0;
        instance.current_round_reject = 0;
        instance.current_round_total = 0;
        instance.current_round_accept_stake = 0;
        instance.current_round_reject_stake = 0;
    }

    /// Check if a slot's instance has finalized.
    pub fn isFinalized(self: *const Self, slot: u64) bool {
        if (self.instances.get(slot)) |instance| {
            return instance.finalized;
        }
        return false;
    }

    /// Get the preference for a slot's instance.
    pub fn getPreference(self: *const Self, slot: u64) Preference {
        if (self.instances.get(slot)) |instance| {
            return instance.preference;
        }
        return .None;
    }

    /// Check if the block was accepted.
    pub fn isAccepted(self: *const Self, slot: u64) bool {
        if (self.instances.get(slot)) |instance| {
            return instance.finalized and instance.preference == .Accept;
        }
        return false;
    }

    /// Remove a completed instance (cleanup).
    pub fn removeInstance(self: *Self, slot: u64) void {
        _ = self.instances.fetchRemove(slot);
    }

    /// Prune all instances older than a given slot.
    pub fn pruneOlderThan(self: *Self, slot: u64) void {
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

    /// Select k random peers for querying (uses Keccak256 PRNG).
    /// Returns indices into the validator array.
    pub fn selectPeers(
        self: *const Self,
        seed: [32]u8,
        slot: u64,
        round: u32,
        validator_count: u32,
    ) ![types.SNOWBALL_K]u32 {
        _ = self;
        var peers: [types.SNOWBALL_K]u32 = undefined;
        if (validator_count <= types.SNOWBALL_K) {
            // If fewer validators than k, select all
            for (0..types.SNOWBALL_K) |i| {
                peers[i] = @intCast(i % validator_count);
            }
            return peers;
        }

        var state = seed;
        for (0..types.SNOWBALL_K) |i| {
            var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            hasher.update(&state);
            var buf: [12]u8 = undefined;
            std.mem.writeInt(u64, buf[0..8], slot, .big);
            std.mem.writeInt(u32, buf[8..12], round + @as(u32, @intCast(i)), .big);
            hasher.update(&buf);
            hasher.final(&state);

            const val = std.mem.readInt(u32, state[0..4], .big);
            peers[i] = val % validator_count;
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
