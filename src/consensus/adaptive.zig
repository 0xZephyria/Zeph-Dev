const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const slot_mod = @import("slot.zig");
const epoch_mod = @import("epoch.zig");
const vote_mod = @import("vote.zig");
const quorum_mod = @import("quorum.zig");

const blst_mod = core.crypto.blst;
const secureZero = @import("utils").secureZero;
const c = blst_mod.c;

const BLS_DST = "ZEPHYRIA_BLS_DST_V01";

// ── Configuration ───────────────────────────────────────────────────────

pub const AdaptiveConfig = struct {
    slotsPerEpoch: u64 = types.SLOTS_PER_EPOCH,
    slotDurationMs: u64 = types.SLOT_DURATION_MS,
    viewChangeTimeoutMs: u64 = types.VIEW_CHANGE_TIMEOUT_MS,
    maxConsecutiveMisses: u32 = types.MAX_CONSECUTIVE_MISSES,
    executionDepth: u32 = 2,
};

// ── Adaptive Consensus Engine ───────────────────────────────────────────

pub const AdaptiveConsensus = struct {
    allocator: std.mem.Allocator,
    config: AdaptiveConfig,

    epochManager: epoch_mod.EpochManager,

    // ── Slot State ──────────────────────────────────────────────────
    currentSlot: u64,
    consecutiveMisses: u32,

    // ── Thread Certificates ─────────────────────────────────────────
    threadCerts: [types.MAX_THREADS]?types.ThreadCertificate,
    threadCertsReceived: u8,

    // ── Thread Timeout Proofs ───────────────────────────────────────
    threadTimeoutProofs: [types.MAX_THREADS]?types.ThreadTimeoutProof,
    threadTimeoutProofsReceived: u8,

    // ── Last QC ─────────────────────────────────────────────────────
    lastQC: ?types.WovenQuorumCertificate,

    // ── Stats ───────────────────────────────────────────────────────
    slotsFinalized: u64,
    slotsMissed: u64,
    qcsFormed: u64,

    lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: AdaptiveConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .epochManager = epoch_mod.EpochManager.init(allocator, .{
                .slotsPerEpoch = config.slotsPerEpoch,
                .slotDurationMs = config.slotDurationMs,
            }),
            .currentSlot = 0,
            .consecutiveMisses = 0,
            .threadCerts = [_]?types.ThreadCertificate{null} ** types.MAX_THREADS,
            .threadCertsReceived = 0,
            .threadTimeoutProofs = [_]?types.ThreadTimeoutProof{null} ** types.MAX_THREADS,
            .threadTimeoutProofsReceived = 0,
            .lastQC = null,
            .slotsFinalized = 0,
            .slotsMissed = 0,
            .qcsFormed = 0,
            .lock = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.lastQC) |*qc| qc.deinit(self.allocator);
        self.epochManager.deinit();
    }

    // ── Epoch Transition ────────────────────────────────────────────

    pub fn transitionEpoch(
        self: *Self,
        newEpoch: u64,
        validatorCount: u32,
        newSeed: [32]u8,
        validatorStakes: []const u256,
    ) !void {
        try self.epochManager.transition(newEpoch, validatorCount, newSeed, validatorStakes);
    }

    // ── Proposer Selection ──────────────────────────────────────────

    /// Compute VRF sortition for proposer eligibility (Tier 2-3).
    pub fn computeProposerForSlot(
        self: *Self,
        slot: u64,
        skBytes: [32]u8,
        myStake: u256,
        totalStake: u256,
    ) !?struct { proposer_index: u32, proof: [96]u8, vrf_hash: [32]u8 } {
        return self.epochManager.computeProposerVrf(slot, skBytes, myStake, totalStake);
    }

    /// Look up the deterministic proposer for a slot from the pre-computed schedule.
    pub fn deterministicProposer(self: *const Self, slot: u64) u32 {
        return self.epochManager.proposerForSlot(slot);
    }

    // ── Slot Advancement ────────────────────────────────────────────

    pub fn advanceSlot(self: *Self, slot: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.currentSlot = slot;
        self.threadCerts = [_]?types.ThreadCertificate{null} ** types.MAX_THREADS;
        self.threadCertsReceived = 0;
        self.threadTimeoutProofs = [_]?types.ThreadTimeoutProof{null} ** types.MAX_THREADS;
        self.threadTimeoutProofsReceived = 0;
    }

    pub fn isEpochBoundary(self: *const Self, slot: u64) bool {
        return slot_mod.isEpochBoundary(slot, self.config.slotsPerEpoch);
    }

    pub fn epochForSlot(self: *const Self, slot: u64) u64 {
        return slot_mod.epochForSlot(slot, self.config.slotsPerEpoch);
    }

    // ── Thread Certificate Collection (Tier 2) ──────────────────────

    pub fn addThreadCertificate(self: *Self, cert: types.ThreadCertificate) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (cert.threadId >= types.MAX_THREADS) return;
        if (self.threadCerts[cert.threadId] != null) return;

        const committee_stake = self.epochManager.committeeManager.getThreadStake(cert.threadId);
        if (committee_stake > 0) {
            if (@as(u512, cert.attestingStake) * 3 <= @as(u512, committee_stake) * 2) {
                return;
            }
        }

        self.threadCerts[cert.threadId] = cert;
        self.threadCertsReceived += 1;
    }

    pub fn hasAllThreadCerts(self: *const Self) bool {
        return self.threadCertsReceived >= self.epochManager.currentThreadCount;
    }

    // ── Thread Timeout Proofs ───────────────────────────────────────

    pub fn deterministicThreadProposer(
        self: *const Self,
        slot: u64,
        threadId: u8,
    ) ?u32 {
        const committee = self.epochManager.committeeManager.getThreadCommittee(threadId);
        if (committee.len == 0) return null;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(&self.epochManager.epochSeed);
        var buf8: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf8, slot, .big);
        hasher.update(&buf8);
        hasher.update(&[_]u8{threadId});
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        const idx = std.mem.readInt(u32, hash[0..4], .big) %
            @as(u32, @intCast(committee.len));
        return committee[idx];
    }

    pub fn addThreadTimeoutProof(self: *Self, proof: types.ThreadTimeoutProof) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (proof.threadId >= types.MAX_THREADS) return;
        if (proof.slot != self.currentSlot) return;
        if (self.threadCerts[proof.threadId] != null) return;
        if (self.threadTimeoutProofs[proof.threadId] != null) return;

        const expected_proposer = self.deterministicThreadProposer(proof.slot, proof.threadId) orelse return;
        if (proof.proposerIndex != expected_proposer) return;

        self.threadTimeoutProofs[proof.threadId] = proof;
        self.threadTimeoutProofsReceived += 1;
    }

    pub fn hasAllThreadsCertified(self: *const Self) bool {
        const combined = self.threadCertsReceived + self.threadTimeoutProofsReceived;
        return combined >= self.epochManager.currentThreadCount;
    }

    // ── QC Formation ────────────────────────────────────────────────

    /// Build a WovenQuorumCertificate from aggregated votes and thread certificates.
    /// Delegates to quorum.zig for the actual formation logic.
    /// Returns null if thread certification is incomplete.
    pub fn buildQC(
        self: *Self,
        woven_root: core.types.Hash,
        agg_votes: vote_mod.AggregatedVotes,
    ) !?types.WovenQuorumCertificate {
        self.lock.lock();
        defer self.lock.unlock();

        const qc_opt = try quorum_mod.buildQC(
            self.allocator,
            self.currentSlot,
            woven_root,
            agg_votes,
            self.epochManager.epochSeed,
            self.epochManager.currentTier,
            self.epochManager.currentThreadCount,
            &self.threadCerts,
            &self.threadTimeoutProofs,
        );
        const qc = qc_opt orelse return null;

        if (self.lastQC) |*old| old.deinit(self.allocator);
        self.lastQC = qc;
        self.qcsFormed += 1;
        self.slotsFinalized += 1;
        self.consecutiveMisses = 0;
        return qc;
    }

    // ── Missed Slot Handling ────────────────────────────────────────

    pub fn recordMissedSlot(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.consecutiveMisses += 1;
        self.slotsMissed += 1;
    }

    pub fn shouldTriggerViewChange(self: *const Self) bool {
        return self.consecutiveMisses >= self.config.maxConsecutiveMisses;
    }

    // ── Block Header Construction ───────────────────────────────────

    pub fn buildBlockHeader(
        self: *Self,
        parent_woven_root: core.types.Hash,
        proposer_index: u32,
        proposer_vrf_proof: [96]u8,
        thread_roots: []const core.types.Hash,
        thread_tx_counts: []const u32,
        state_root: core.types.Hash,
        total_tx_count: u32,
    ) types.AdaptiveBlockHeader {
        var header = types.AdaptiveBlockHeader{
            .slot = self.currentSlot,
            .epoch = self.epochManager.currentEpoch,
            .parentWovenRoot = parent_woven_root,
            .proposerIndex = proposer_index,
            .proposerVrfProof = proposer_vrf_proof,
            .threadCount = self.epochManager.currentThreadCount,
            .threadRoots = [_]core.types.Hash{core.types.Hash.zero()} ** types.MAX_THREADS,
            .threadTxCounts = [_]u32{0} ** types.MAX_THREADS,
            .wovenRoot = core.types.Hash.zero(),
            .stateRoot = state_root,
            .totalTxCount = total_tx_count,
            .randomnessSeed = self.epochManager.epochSeed,
            .tier = self.epochManager.currentTier,
        };

        const count = @min(thread_roots.len, @as(usize, self.epochManager.currentThreadCount));
        for (0..count) |idx| {
            header.threadRoots[idx] = thread_roots[idx];
            if (idx < thread_tx_counts.len) {
                header.threadTxCounts[idx] = thread_tx_counts[idx];
            }
        }

        header.computeWovenRoot();
        return header;
    }

    // ── Block Header Verification ───────────────────────────────────

    pub fn verifyBlockHeader(
        self: *const Self,
        header: *const types.AdaptiveBlockHeader,
        parent_woven_root: core.types.Hash,
        finalized_slot: u64,
    ) bool {
        if (header.slot <= finalized_slot) return false;
        if (header.epoch != self.epochManager.currentEpoch) return false;
        if (!std.mem.eql(u8, &header.parentWovenRoot.bytes, &parent_woven_root.bytes)) return false;
        if (header.threadCount != self.epochManager.currentThreadCount) return false;
        if (header.tier != self.epochManager.currentTier) return false;
        if (!header.verifyWovenRoot()) return false;
        return true;
    }

    // ── BLS Vote Creation ───────────────────────────────────────────

    pub fn createVote(bls_priv_key: [32]u8, header_hash: core.types.Hash) ![96]u8 {
        var mutable_key = bls_priv_key;
        defer secureZero(mutable_key[0..]);

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &header_hash.bytes, header_hash.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: c.blst_scalar = undefined;
        defer secureZero(std.mem.asBytes(&sk));
        c.blst_scalar_from_bendian(&sk, &mutable_key);
        if (!c.blst_sk_check(&sk)) return error.InvalidSecretKey;

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
        threadCount: u8,
        validatorCount: u32,
        slotsFinalized: u64,
        slotsMissed: u64,
        qcsFormed: u64,
        epochsCompleted: u64,
        tierTransitions: u64,
    };

    pub fn getStats(self: *const Self) Stats {
        const es = self.epochManager.getStats();
        return .{
            .epoch = es.epoch,
            .tier = es.tier,
            .threadCount = es.threadCount,
            .validatorCount = es.validatorCount,
            .slotsFinalized = self.slotsFinalized,
            .slotsMissed = self.slotsMissed,
            .qcsFormed = self.qcsFormed,
            .epochsCompleted = es.epochsCompleted,
            .tierTransitions = es.tierTransitions,
        };
    }
};
