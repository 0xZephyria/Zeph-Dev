// ============================================================================
// Zephyria — Adaptive Consensus Coordinator (Loom Genesis)
// ============================================================================
//
// The heart of the adaptive three-tier consensus protocol.
// Manages tier detection, thread count adaptation, epoch transitions,
// proposer scheduling, woven root computation, and QC formation.
//
// Tier detection is automatic at epoch boundaries:
//   N ≤ 100  → FullBFT (all-to-all BLS voting)
//   100 < N ≤ 2000 → CommitteeLoom (epoch-shuffled committees)
//   N > 2000 → FullLoom (VRF sortition + Snowball)

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const vrf_mod = @import("vrf.zig");
const committees_mod = @import("committees.zig");

const blst_mod = core.crypto.blst;
const c = blst_mod.c;

const BLS_DST = "FORGEYRIA_BLS_DST_V01";

// ── Configuration ───────────────────────────────────────────────────────

pub const AdaptiveConfig = struct {
    /// Slots per epoch
    slots_per_epoch: u64 = types.SLOTS_PER_EPOCH,
    /// Slot duration in milliseconds
    slot_duration_ms: u64 = types.SLOT_DURATION_MS,
    /// View change timeout (ms)
    view_change_timeout_ms: u64 = types.VIEW_CHANGE_TIMEOUT_MS,
    /// Max consecutive missed slots before view change
    max_consecutive_misses: u32 = types.MAX_CONSECUTIVE_MISSES,
    /// Deferred execution depth (blocks behind consensus)
    execution_depth: u32 = 2,
};

// ── Adaptive Consensus Engine ───────────────────────────────────────────

pub const AdaptiveConsensus = struct {
    allocator: std.mem.Allocator,
    config: AdaptiveConfig,

    // ── Epoch State ─────────────────────────────────────────────────
    current_epoch: u64,
    current_tier: types.ConsensusTier,
    current_thread_count: u8,
    epoch_seed: [32]u8,
    validator_count: u32,

    // ── Slot State ──────────────────────────────────────────────────
    current_slot: u64,
    last_finalized_slot: u64,
    consecutive_misses: u32,

    // ── Proposer Schedule ───────────────────────────────────────────
    /// Pre-computed proposer schedule for the current epoch (slot → proposer index)
    proposer_schedule: std.AutoHashMap(u64, types.ProposerScheduleEntry),

    // ── Committee Manager (Tier 2) ──────────────────────────────────
    committee_manager: committees_mod.CommitteeManager,

    // ── QC Formation ────────────────────────────────────────────────
    /// Pending votes for the current slot: validator_index → BLS signature
    pending_votes: std.AutoHashMap(u32, [96]u8),
    pending_vote_stake: u64,
    total_voting_stake: u64,

    // ── Thread Certificates ─────────────────────────────────────────
    /// Thread certificates for the current slot
    thread_certs: [types.MAX_THREADS]?types.ThreadCertificate,
    thread_certs_received: u8,

    // ── Last QC ─────────────────────────────────────────────────────
    last_qc: ?types.WovenQuorumCertificate,

    // ── Stats ───────────────────────────────────────────────────────
    epochs_completed: u64,
    tier_transitions: u64,
    slots_finalized: u64,
    slots_missed: u64,
    qcs_formed: u64,

    lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: AdaptiveConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .current_epoch = 0,
            .current_tier = .FullBFT,
            .current_thread_count = 1,
            .epoch_seed = [_]u8{0} ** 32,
            .validator_count = 0,
            .current_slot = 0,
            .last_finalized_slot = 0,
            .consecutive_misses = 0,
            .proposer_schedule = std.AutoHashMap(u64, types.ProposerScheduleEntry).init(allocator),
            .committee_manager = committees_mod.CommitteeManager.init(allocator),
            .pending_votes = std.AutoHashMap(u32, [96]u8).init(allocator),
            .pending_vote_stake = 0,
            .total_voting_stake = 0,
            .thread_certs = [_]?types.ThreadCertificate{null} ** types.MAX_THREADS,
            .thread_certs_received = 0,
            .last_qc = null,
            .epochs_completed = 0,
            .tier_transitions = 0,
            .slots_finalized = 0,
            .slots_missed = 0,
            .qcs_formed = 0,
            .lock = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.proposer_schedule.deinit();
        self.pending_votes.deinit();
        self.committee_manager.deinit();
    }

    // ── Tier Detection ──────────────────────────────────────────────

    /// Compute the consensus tier for a given validator count.
    pub fn computeTier(validator_count: u32) types.ConsensusTier {
        if (validator_count <= types.TIER2_THRESHOLD) return .FullBFT;
        if (validator_count <= types.TIER3_THRESHOLD) return .CommitteeLoom;
        return .FullLoom;
    }

    /// Compute the adaptive thread count for a given validator count.
    pub fn computeThreadCount(validator_count: u32) u8 {
        if (validator_count <= 30) return 1;
        if (validator_count <= 100) return 2;
        if (validator_count <= 200) return 3;
        if (validator_count <= 500) return 5;
        if (validator_count <= 1000) return 8;
        if (validator_count <= 2000) return 10;
        // Beyond 2000: 1 thread per 200 validators, capped at MAX_THREADS
        const computed = validator_count / 200;
        return @intCast(@min(computed, types.MAX_THREADS));
    }

    // ── Epoch Transition ────────────────────────────────────────────

    /// Process an epoch transition. Called at the start of each epoch.
    /// Recomputes tier, thread count, committees, and proposer schedule.
    pub fn transitionEpoch(
        self: *Self,
        new_epoch: u64,
        validator_count: u32,
        new_seed: [32]u8,
        validator_stakes: []const u64,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const old_tier = self.current_tier;
        const new_tier = computeTier(validator_count);
        const new_thread_count = computeThreadCount(validator_count);

        self.current_epoch = new_epoch;
        self.current_tier = new_tier;
        self.current_thread_count = new_thread_count;
        self.epoch_seed = new_seed;
        self.validator_count = validator_count;

        // Track tier transitions
        if (old_tier != new_tier) {
            self.tier_transitions += 1;
        }

        // Recompute committees for Tier 2
        if (new_tier == .CommitteeLoom) {
            const committee_seed = vrf_mod.VRF.committee_seed(new_seed, new_epoch);
            self.committee_manager.recompute(
                committee_seed,
                validator_count,
                new_thread_count,
                validator_stakes,
            );
        }

        // Clear previous proposer schedule
        self.proposer_schedule.clearRetainingCapacity();

        self.epochs_completed += 1;
    }

    // ── Proposer Selection ──────────────────────────────────────────

    /// Compute the proposer schedule for the current epoch.
    /// For Tier 1: deterministic VRF-based rotation
    /// For Tier 2-3: VRF sortition (pre-compute by checking all validators)
    pub fn computeProposerForSlot(
        self: *Self,
        slot: u64,
        sk_bytes: [32]u8,
        my_stake: u64,
        total_stake: u64,
    ) !?struct { proposer_index: u32, proof: [48]u8, vrf_hash: [32]u8 } {
        const result = try vrf_mod.VRF.sortition_proposer(
            sk_bytes,
            self.epoch_seed,
            slot,
            my_stake,
            total_stake,
            types.EXPECTED_PROPOSERS,
        );

        if (result.eligible) {
            return .{
                .proposer_index = 0, // Caller fills in their actual index
                .proof = result.proof,
                .vrf_hash = result.vrf_hash,
            };
        }
        return null;
    }

    /// Determine the deterministic proposer for a slot at Tier 1 (small N).
    /// Uses epoch_seed + slot to deterministically select from validator set.
    pub fn deterministicProposer(self: *const Self, slot: u64) u32 {
        if (self.validator_count == 0) return 0;
        // Hash(epoch_seed ‖ slot) → deterministic index
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&self.epoch_seed);
        var buf8: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf8, slot, .big);
        hasher.update(&buf8);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        const val = std.mem.readInt(u32, hash[0..4], .big);
        return val % self.validator_count;
    }

    // ── Slot Advancement ────────────────────────────────────────────

    /// Advance to the next slot and reset per-slot state.
    pub fn advanceSlot(self: *Self, slot: u64) void {
        self.lock.lock();
        defer self.lock.unlock();

        self.current_slot = slot;
        self.pending_votes.clearRetainingCapacity();
        self.pending_vote_stake = 0;
        self.thread_certs = [_]?types.ThreadCertificate{null} ** types.MAX_THREADS;
        self.thread_certs_received = 0;
    }

    /// Check if the current slot is at an epoch boundary.
    pub fn isEpochBoundary(self: *const Self, slot: u64) bool {
        return (slot % self.config.slots_per_epoch) == 0;
    }

    /// Get the epoch number for a slot.
    pub fn epochForSlot(self: *const Self, slot: u64) u64 {
        return slot / self.config.slots_per_epoch;
    }

    // ── Vote Collection (Tier 1 & 2: BLS Aggregate) ────────────────

    /// Add a vote for the current slot's block.
    /// Returns true if quorum is now met.
    pub fn addVote(
        self: *Self,
        validator_index: u32,
        signature: [96]u8,
        stake: u64,
    ) !bool {
        self.lock.lock();
        defer self.lock.unlock();

        // Deduplicate
        if (self.pending_votes.contains(validator_index)) return false;

        try self.pending_votes.put(validator_index, signature);
        self.pending_vote_stake += stake;

        return self.hasVotingQuorum();
    }

    /// Check if voting quorum (≥67% stake) is met.
    pub fn hasVotingQuorum(self: *const Self) bool {
        if (self.total_voting_stake == 0) return false;
        return self.pending_vote_stake * 3 > self.total_voting_stake * 2;
    }

    /// Set the total voting stake for quorum calculations.
    pub fn setTotalVotingStake(self: *Self, total: u64) void {
        self.total_voting_stake = total;
    }

    // ── Thread Certificate Collection ───────────────────────────────

    /// Add a thread certificate for the current slot.
    pub fn addThreadCertificate(self: *Self, cert: types.ThreadCertificate) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (cert.thread_id >= types.MAX_THREADS) return;
        if (self.thread_certs[cert.thread_id] != null) return; // Already have it
        if (!cert.hasQuorum()) return; // Reject insufficient quorum

        self.thread_certs[cert.thread_id] = cert;
        self.thread_certs_received += 1;
    }

    /// Check if all thread certificates are received.
    pub fn hasAllThreadCerts(self: *const Self) bool {
        return self.thread_certs_received >= self.current_thread_count;
    }

    // ── QC Formation ────────────────────────────────────────────────

    /// Build a Quorum Certificate from collected votes and thread certificates.
    /// Returns null if quorum is not met.
    pub fn buildQC(
        self: *Self,
        woven_root: core.types.Hash,
    ) ?types.WovenQuorumCertificate {
        self.lock.lock();
        defer self.lock.unlock();

        if (!self.hasVotingQuorum()) return null;

        // Build thread cert bitmap
        var thread_cert_bitmap: u128 = 0;
        var i: u8 = 0;
        while (i < self.current_thread_count) : (i += 1) {
            if (self.thread_certs[i] != null) {
                thread_cert_bitmap |= @as(u128, 1) << @intCast(i);
            }
        }

        // At Tier 1, we don't require thread certs (all nodes verify everything)
        if (self.current_tier != .FullBFT) {
            const required_mask = (@as(u128, 1) << @intCast(self.current_thread_count)) - 1;
            if ((thread_cert_bitmap & required_mask) != required_mask) return null;
        } else {
            // At Tier 1, set all thread cert bits (trivially certified)
            thread_cert_bitmap = (@as(u128, 1) << @intCast(self.current_thread_count)) - 1;
        }

        // Aggregate BLS signatures
        var agg_sig = std.mem.zeroes(c.blst_p2);
        var first = true;
        var voter_bitmap: [32]u8 = [_]u8{0} ** 32;

        var vote_it = self.pending_votes.iterator();
        while (vote_it.next()) |entry| {
            const idx = entry.key_ptr.*;

            // Set voter bitmap
            if (idx < 256) {
                const byte_idx = idx / 8;
                const bit_idx: u3 = @intCast(idx % 8);
                voter_bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
            }

            // Aggregate BLS
            var sig_affine = std.mem.zeroes(c.blst_p2_affine);
            const res = c.blst_p2_uncompress(&sig_affine, &entry.value_ptr.*);
            if (res != c.BLST_SUCCESS) continue;

            var sig_jac = std.mem.zeroes(c.blst_p2);
            c.blst_p2_from_affine(&sig_jac, &sig_affine);

            if (first) {
                agg_sig = sig_jac;
                first = false;
            } else {
                c.blst_p2_add_or_double(&agg_sig, &agg_sig, &sig_jac);
            }
        }

        var agg_sig_bytes: [96]u8 = undefined;
        c.blst_p2_compress(&agg_sig_bytes, &agg_sig);

        // Compute next randomness seed
        var next_seed: [32]u8 = undefined;
        {
            var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            hasher.update(&self.epoch_seed);
            hasher.update(&agg_sig_bytes);
            var buf8: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf8, self.current_slot, .big);
            hasher.update(&buf8);
            hasher.final(&next_seed);
        }

        const qc = types.WovenQuorumCertificate{
            .slot = self.current_slot,
            .woven_root = woven_root,
            .thread_cert_bitmap = thread_cert_bitmap,
            .aggregate_signature = agg_sig_bytes,
            .voter_bitmap = voter_bitmap,
            .total_attesting_stake = self.pending_vote_stake,
            .randomness_seed = next_seed,
            .tier = self.current_tier,
        };

        self.last_qc = qc;
        self.qcs_formed += 1;
        self.slots_finalized += 1;
        self.last_finalized_slot = self.current_slot;
        self.consecutive_misses = 0;

        return qc;
    }

    // ── Missed Slot Handling ────────────────────────────────────────

    /// Record a missed slot (proposer timeout).
    pub fn recordMissedSlot(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.consecutive_misses += 1;
        self.slots_missed += 1;
    }

    /// Check if a view change should be triggered.
    pub fn shouldTriggerViewChange(self: *const Self) bool {
        return self.consecutive_misses >= self.config.max_consecutive_misses;
    }

    // ── Block Header Construction ───────────────────────────────────

    /// Build a new AdaptiveBlockHeader for the current slot.
    pub fn buildBlockHeader(
        self: *Self,
        parent_hash: core.types.Hash,
        proposer_index: u32,
        proposer_vrf_proof: [48]u8,
        thread_roots: []const core.types.Hash,
        thread_tx_counts: []const u32,
        state_root: core.types.Hash,
        total_tx_count: u32,
    ) types.AdaptiveBlockHeader {
        var header = types.AdaptiveBlockHeader{
            .slot = self.current_slot,
            .epoch = self.current_epoch,
            .parent_hash = parent_hash,
            .proposer_index = proposer_index,
            .proposer_vrf_proof = proposer_vrf_proof,
            .thread_count = self.current_thread_count,
            .thread_roots = [_]core.types.Hash{core.types.Hash.zero()} ** types.MAX_THREADS,
            .thread_tx_counts = [_]u32{0} ** types.MAX_THREADS,
            .woven_root = core.types.Hash.zero(),
            .state_root = state_root,
            .total_tx_count = total_tx_count,
            .randomness_seed = self.epoch_seed,
            .tier = self.current_tier,
        };

        // Copy thread data
        const count = @min(thread_roots.len, @as(usize, self.current_thread_count));
        for (0..count) |idx| {
            header.thread_roots[idx] = thread_roots[idx];
            if (idx < thread_tx_counts.len) {
                header.thread_tx_counts[idx] = thread_tx_counts[idx];
            }
        }

        // Compute woven root
        header.computeWovenRoot();

        return header;
    }

    // ── Block Header Verification ───────────────────────────────────

    /// Verify an AdaptiveBlockHeader received from a proposer.
    pub fn verifyBlockHeader(
        self: *const Self,
        header: *const types.AdaptiveBlockHeader,
        parent_hash: core.types.Hash,
    ) bool {
        // 1. Slot must be greater than last finalized
        if (header.slot <= self.last_finalized_slot) return false;

        // 2. Epoch must match current
        if (header.epoch != self.current_epoch) return false;

        // 3. Parent hash must match
        if (!std.mem.eql(u8, &header.parent_hash.bytes, &parent_hash.bytes)) return false;

        // 4. Thread count must match current configuration
        if (header.thread_count != self.current_thread_count) return false;

        // 5. Tier must match current
        if (header.tier != self.current_tier) return false;

        // 6. Woven root must be correctly computed
        if (!header.verifyWovenRoot()) return false;

        return true;
    }

    // ── BLS Vote Creation ───────────────────────────────────────────

    /// Create a BLS vote (signature) over a block header hash.
    pub fn createVote(bls_priv_key: [32]u8, header_hash: core.types.Hash) [96]u8 {
        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &header_hash.bytes, header_hash.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: c.blst_scalar = undefined;
        c.blst_scalar_from_bendian(&sk, &bls_priv_key);

        var sig: c.blst_p2 = undefined;
        c.blst_sign_pk_in_g1(&sig, &p2, &sk);

        var sig_bytes: [96]u8 = undefined;
        c.blst_p2_compress(&sig_bytes, &sig);

        return sig_bytes;
    }

    // ── Statistics ──────────────────────────────────────────────────

    pub const Stats = struct {
        epoch: u64,
        tier: types.ConsensusTier,
        thread_count: u8,
        validator_count: u32,
        slots_finalized: u64,
        slots_missed: u64,
        qcs_formed: u64,
        epochs_completed: u64,
        tier_transitions: u64,
        last_finalized_slot: u64,
    };

    pub fn getStats(self: *const Self) Stats {
        return .{
            .epoch = self.current_epoch,
            .tier = self.current_tier,
            .thread_count = self.current_thread_count,
            .validator_count = self.validator_count,
            .slots_finalized = self.slots_finalized,
            .slots_missed = self.slots_missed,
            .qcs_formed = self.qcs_formed,
            .epochs_completed = self.epochs_completed,
            .tier_transitions = self.tier_transitions,
            .last_finalized_slot = self.last_finalized_slot,
        };
    }
};
