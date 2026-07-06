// ============================================================================
// Zephyria — Zelius PoS Consensus Engine (Loom Genesis Adaptive)
// ============================================================================
//
// Production-hardened BLS-based Proof-of-Stake, adapted for the three-tier
// adaptive Loom Genesis protocol:
//
//   Tier 1 (Full BFT):       N ≤ 100 — all validators verify everything
//   Tier 2 (Committee Loom): 100 < N ≤ 2000 — epoch-shuffled committees
//   Tier 3 (Full Loom):      N > 2000 — VRF sortition + Snowball
//
// Hardened features:
//   • Full BLS signature verification
//   • Epoch-based validator rotation (1024-slot epochs)
//   • Double-signing detection + slashing
//   • View-change protocol for offline proposer failover
//   • VRF-based leader election (stake-weighted, domain-separated)
//   • Adaptive tier detection at epoch boundaries
//   • Thread-aware block construction and verification

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const vrf = @import("vrf.zig");
const staking_mod = @import("staking.zig");
const adaptive_mod = @import("adaptive.zig");
const keys_mod = @import("keys.zig");
const quorum_mod = @import("quorum.zig");
const proposer_mod = @import("proposer.zig");
const replay_mod = @import("replay.zig");
const validators_mod = @import("validators.zig");

const blst_mod = core.crypto.blst;
const c = blst_mod.c;
const secureZero = @import("utils").secureZero;

const BLS_DST = "ZEPHYRIA_BLS_DST_V01";

// ── Epoch Configuration ─────────────────────────────────────────────────

pub const EpochConfig = struct {
    /// Blocks/slots per epoch
    blocksPerEpoch: u64 = types.SLOTS_PER_EPOCH,
    /// Minimum stake to be eligible (10,000 ZEE)
    minStake: u256 = 10_000_000_000_000_000_000_000,
    /// Blocks missed before jailing
    jailThreshold: u32 = 100,
    /// Cooldown blocks after unjailing
    unjailCooldown: u64 = 10_000,
};

// ── Double-Sign Tracker ─────────────────────────────────────────────────

pub const SlashEvent = struct {
    validator: core.types.Address,
    blockNumber: u64,
    reason: SlashReason,
    evidenceHash1: core.types.Hash,
    evidenceHash2: core.types.Hash,
    timestamp: u64,
};

pub const SlashReason = enum {
    DoubleSigning,
    Downtime,
    FraudProof,
    InvalidBlock,
    InvalidThreadRoot,
};

const ProposalRecord = struct {
    blockHash: core.types.Hash,
    proposer: core.types.Address,
    timestamp: u64,
};

// ── View Change Protocol ────────────────────────────────────────────────

pub const ViewChangeState = enum {
    Normal,
    ViewChangePending,
    ViewChangeComplete,
};

pub const ViewChange = struct {
    view: u64,
    triggered_at: u64,
    timeout_ms: u64,
    new_proposer_index: u32,
    state: ViewChangeState,
    cumulativeStake: u256,
    requiredStake: u256,
};

// ── Main Engine ─────────────────────────────────────────────────────────

pub const ZeliusEngine = struct {
    allocator: std.mem.Allocator,
    validators: []const types.ValidatorInfo,

    /// Owns the active validator set lifecycle (init, epoch rotation, index, stake cache)
    validator_set: validators_mod.ValidatorSet,

    privKey: ?[32]u8,
    blsPrivKey: ?[32]u8,
    vrfPrivKey: ?[32]u8,

    // Epoch management
    epochConfig: EpochConfig,
    currentEpoch: u64,
    epochSeed: [32]u8,
    staking: ?*staking_mod.Staking,

    // Adaptive consensus (Loom Genesis)
    adaptive: adaptive_mod.AdaptiveConsensus,

    // Double-signing detection
    proposalsSeen: std.AutoHashMap(u64, ProposalRecord),
    slashEvents: std.ArrayListUnmanaged(SlashEvent),

    // View-change protocol
    viewChange: ?ViewChange,
    viewChangeTimeoutMs: u64,

    // Missed block tracking
    missedBlocks: std.AutoHashMap(core.types.Address, u32),

    // Thread-safety lock
    mutex: std.Thread.Mutex,

    // Finality tracker
    lastFinalizedBlock: u64,

    // Stats
    blocksVerified: u64,
    blocksSealed: u64,
    doubleSignsDetected: u64,
    viewChangesTriggered: u64,
    /// Consecutive view changes (for exponential backoff)
    consecutiveViewChanges: u32,
    /// Pending equivocation evidence broadcasts
    pendingEvidenceBroadcasts: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        validators: []const types.ValidatorInfo,
    ) !*ZeliusEngine {
        const self = try allocator.create(ZeliusEngine);
        self.* = ZeliusEngine{
            .allocator = allocator,
            .validators = validators,
            .validator_set = try validators_mod.ValidatorSet.init(allocator, validators),
            .privKey = null,
            .blsPrivKey = null,
            .vrfPrivKey = null,
            .epochConfig = .{},
            .currentEpoch = 0,
            .epochSeed = [_]u8{0} ** 32,
            .staking = null,
            .adaptive = adaptive_mod.AdaptiveConsensus.init(allocator, .{}),
            .proposalsSeen = std.AutoHashMap(u64, ProposalRecord).init(allocator),
            .slashEvents = .{},
            .viewChange = null,
            .viewChangeTimeoutMs = types.VIEW_CHANGE_TIMEOUT_MS,
            .missedBlocks = std.AutoHashMap(core.types.Address, u32).init(allocator),
            .mutex = .{},
            .lastFinalizedBlock = 0,
            .blocksVerified = 0,
            .blocksSealed = 0,
            .doubleSignsDetected = 0,
            .viewChangesTriggered = 0,
            .consecutiveViewChanges = 0,
            .pendingEvidenceBroadcasts = 0,
        };

        return self;
    }

    pub fn deinit(self: *ZeliusEngine) void {
        if (self.privKey) |*k| secureZero(k[0..]);
        if (self.blsPrivKey) |*k| secureZero(k[0..]);
        if (self.vrfPrivKey) |*k| secureZero(k[0..]);
        self.adaptive.deinit();
        self.proposalsSeen.deinit();
        self.slashEvents.deinit(self.allocator);
        self.missedBlocks.deinit();
        self.validator_set.deinit();
        self.allocator.destroy(self);
    }

    pub fn setPrivKey(self: *ZeliusEngine, key: [32]u8) void {
        self.privKey = key;
    }

    pub fn setBlsPrivKey(self: *ZeliusEngine, seed: []const u8) void {
        if (seed.len < 32) return;
        var key: [32]u8 = undefined;
        @memcpy(&key, seed[0..32]);
        defer secureZero(&key);

        self.blsPrivKey = keys_mod.deriveBlsPrivKey(key);
        self.vrfPrivKey = keys_mod.deriveVrfPrivKey(key);
    }

    // ── Adaptive Tier Access ────────────────────────────────────────

    /// Get the current consensus tier.
    pub fn getCurrentTier(self: *const ZeliusEngine) types.ConsensusTier {
        return self.adaptive.epochManager.currentTier;
    }

    /// Get the current thread count.
    pub fn getThreadCount(self: *const ZeliusEngine) u8 {
        return self.adaptive.epochManager.currentThreadCount;
    }

    /// Get the adaptive consensus engine reference.
    pub fn getAdaptive(self: *ZeliusEngine) *adaptive_mod.AdaptiveConsensus {
        return &self.adaptive;
    }

    // ── Epoch Management ────────────────────────────────────────────

    /// Get the epoch number for a given block/slot.
    pub fn epochForBlock(self: *const ZeliusEngine, blockNumber: u64) u64 {
        return blockNumber / self.epochConfig.blocksPerEpoch;
    }

    /// Check if block is at epoch boundary.
    pub fn isEpochBoundary(self: *const ZeliusEngine, blockNumber: u64) bool {
        return (blockNumber % self.epochConfig.blocksPerEpoch) == 0;
    }

    pub fn setStaking(self: *ZeliusEngine, staking: *staking_mod.Staking) void {
        self.staking = staking;
    }

    pub fn handleEpochRotationIfBoundary(self: *ZeliusEngine, blockNumber: u64, blockId: [32]u8) !void {
        if (self.isEpochBoundary(blockNumber)) {
            var stakesOwned: ?[]u256 = null;
            defer if (stakesOwned) |s| self.allocator.free(s);

            const stakes: []const u256 = if (self.staking) |stk| blk: {
                const s = stk.getValidatorStakes() catch break :blk &[_]u256{};
                stakesOwned = s;
                break :blk s;
            } else &[_]u256{};

            try self.rotateEpoch(blockNumber, blockId, stakes);
        }
    }

    /// Rotate validator set and update adaptive consensus at epoch boundary.
    /// If staking is wired, refreshes activeValidators from staking state.
    /// Jailed/tombstoned validators are naturally excluded by staking.getActiveSet().
    pub fn rotateEpoch(
        self: *ZeliusEngine,
        blockNumber: u64,
        newSeed: [32]u8,
        validatorStakes: []const u256,
    ) !void {
        self.currentEpoch = self.epochForBlock(blockNumber);
        self.epochSeed = newSeed;

        // Reset missed block counters
        self.missedBlocks.clearRetainingCapacity();

        // Rebuild active validator set from staking state if available
        if (self.staking) |stk| {
            try self.validator_set.rebuildFromStaking(stk);
        }

        // Update adaptive consensus with current validator count
        const validatorCount: u32 = @intCast(self.validator_set.active.len);
        try self.adaptive.transitionEpoch(
            self.currentEpoch,
            validatorCount,
            newSeed,
            validatorStakes,
        );
    }

    // ── Proposer Selection (Adaptive) ───────────────────────────────

    /// Check if this node is the proposer for the given slot.
    pub fn isProposerForSlot(self: *const ZeliusEngine, slot: u64, ourIndex: u32) bool {
        return proposer_mod.isProposerForSlot(
            slot,
            ourIndex,
            self.adaptive.epochManager.currentTier,
            &self.adaptive.epochManager.proposerSchedule,
            self.adaptive.epochManager.epochSeed,
            self.adaptive.epochManager.validatorCount,
        );
    }

    /// Get the expected proposer index for a slot.
    pub fn getExpectedProposer(self: *const ZeliusEngine, slot: u64) u32 {
        return proposer_mod.getExpectedProposer(
            slot,
            &self.adaptive.epochManager.proposerSchedule,
            self.adaptive.epochManager.epochSeed,
            self.adaptive.epochManager.validatorCount,
        );
    }

    /// Check if a given address is the eligible proposer for a slot.
    pub fn isEligibleProposer(self: *const ZeliusEngine, slot: u64, address: core.types.Address) bool {
        return proposer_mod.isEligibleProposer(
            slot,
            address,
            self.validator_set.active,
            &self.adaptive.epochManager.proposerSchedule,
            self.adaptive.epochManager.epochSeed,
        );
    }

    // ── Double-Signing Detection ────────────────────────────────────

    /// Record a block proposal. Detects and returns slash event if double-signing.
    /// blockId must be computed via block.id() — the canonical identifier.
    pub fn recordProposal(self: *ZeliusEngine, blockNumber: u64, blkId: core.types.Hash, proposer: core.types.Address) !?SlashEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = try self.proposalsSeen.getOrPut(blockNumber);
        if (gop.found_existing) {
            const existing = gop.value_ptr.*;
            if (!std.mem.eql(u8, &existing.blockHash.bytes, &blkId.bytes)) {
                // DOUBLE SIGNING DETECTED
                self.doubleSignsDetected += 1;

                const event = SlashEvent{
                    .validator = proposer,
                    .blockNumber = blockNumber,
                    .reason = .DoubleSigning,
                    .evidenceHash1 = existing.blockHash,
                    .evidenceHash2 = blkId,
                    .timestamp = @intCast(std.time.timestamp()),
                };

                try self.slashEvents.append(self.allocator, event);
                self.pendingEvidenceBroadcasts += 1;
                return event;
            }
        } else {
            gop.value_ptr.* = ProposalRecord{
                .blockHash = blkId,
                .proposer = proposer,
                .timestamp = @intCast(std.time.timestamp()),
            };
        }
        return null;
    }

    /// Check if a proposal at this block number already exists (cross-reference
    /// for Pipeline's equivocation check — covers ALL block numbers).
    pub fn proposalExists(self: *ZeliusEngine, blockNumber: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.proposalsSeen.contains(blockNumber);
    }

    // ── Missed Block Tracking ───────────────────────────────────────

    /// Record that a validator missed their slot.
    pub fn recordMissedBlock(self: *ZeliusEngine, validator: core.types.Address) !?SlashEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = try self.missedBlocks.getOrPut(validator);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;

        if (gop.value_ptr.* >= self.epochConfig.jailThreshold) {
            const event = SlashEvent{
                .validator = validator,
                .blockNumber = 0,
                .reason = .Downtime,
                .evidenceHash1 = core.types.Hash.zero(),
                .evidenceHash2 = core.types.Hash.zero(),
                .timestamp = @intCast(std.time.timestamp()),
            };
            try self.slashEvents.append(self.allocator, event);
            return event;
        }
        return null;
    }

    // ── View-Change Protocol ────────────────────────────────────────

    /// Trigger a view change when the proposer is offline.
    /// Uses exponential backoff on the timeout to prevent packet storms
    /// during network partitions (doubles each consecutive view change).
    pub fn triggerViewChange(self: *ZeliusEngine, current_block: u64, current_view: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.viewChange != null) return;

        const num_validators: u32 = @intCast(self.validator_set.active.len);
        const new_proposer = if (num_validators > 0)
            @as(u32, @intCast((current_view + 1) % num_validators))
        else
            0;

        // Exponential backoff: double timeout for each consecutive view change
        // Capped at 60 seconds to prevent indefinite waiting
        const base_timeout = self.viewChangeTimeoutMs;
        const backoff_factor = @min(self.consecutiveViewChanges, 6); // max 2^6 = 64x
        const timeout = base_timeout * (@as(u64, 1) << @intCast(backoff_factor));
        const capped_timeout = @min(timeout, 60_000); // Cap at 60s

        self.viewChange = ViewChange{
            .view = current_view + 1,
            .triggered_at = current_block,
            .timeout_ms = capped_timeout,
            .new_proposer_index = new_proposer,
            .state = .ViewChangePending,
            .cumulativeStake = 0,
            .requiredStake = if (self.validator_set.totalStake() > 0)
                (self.validator_set.totalStake() * 2 / 3) + 1
            else
                1,
        };

        self.viewChangesTriggered += 1;
        self.consecutiveViewChanges += 1;
    }

    /// Vote for a view change. Returns true if quorum reached.
    pub fn voteViewChange(self: *ZeliusEngine, voter_index: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.viewChange) |*vc| {
            const voter_stake = if (voter_index < @as(u32, @intCast(self.validator_set.active.len)))
                self.validator_set.active[@intCast(voter_index)].stake
            else
                0;
            vc.cumulativeStake += voter_stake;
            if (vc.cumulativeStake >= vc.requiredStake) {
                vc.state = .ViewChangeComplete;
                return true;
            }
        }
        return false;
    }

    /// Complete the view change.
    pub fn completeViewChange(self: *ZeliusEngine) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.viewChange = null;
    }

    /// Reset view change backoff counter (call on successful block production).
    pub fn resetViewChangeBackoff(self: *ZeliusEngine) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.consecutiveViewChanges = 0;
    }

    // ── Finality Tracking ───────────────────────────────────────────
    //
    // ZeliusEngine.lastFinalizedBlock is the single source of truth
    // for consensus finality. Set by updateFinality() when a QC is
    // formed (Tier 1-2) or Snowball finalizes (Tier 3).

    /// Update the finality tracker after a QC has been formed.
    /// Called by the P2P layer once buildQC() succeeds.
    /// The block/slot number must be monotonically increasing —
    /// stale finality updates are silently ignored to prevent
    /// finality regression attacks.
    pub fn updateFinality(self: *ZeliusEngine, finalized_block: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (finalized_block > self.lastFinalizedBlock) {
            self.lastFinalizedBlock = finalized_block;
        }
    }

    /// Get the last finalized block number.
    /// Returns 0 if no block has been finalized yet.
    pub fn getLastFinalizedBlock(self: *const ZeliusEngine) u64 {
        return self.lastFinalizedBlock;
    }

    /// Check whether a given block number has been finalized.
    /// Useful for RPC endpoints (eth_getBlockByNumber with "finalized" tag)
    /// and for the sync protocol to determine safe head.
    pub fn isFinalized(self: *const ZeliusEngine, blockNumber: u64) bool {
        return blockNumber <= self.lastFinalizedBlock;
    }

    /// Drain pending slash events for P2P broadcast.
    /// The P2P server polls this to broadcast equivocation/downtime evidence.
    /// Returns owned slice — caller must free.
    pub fn drainSlashEvents(self: *ZeliusEngine) ![]SlashEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.slashEvents.items.len == 0) return &[_]SlashEvent{};

        const events = try self.allocator.alloc(SlashEvent, self.slashEvents.items.len);
        @memcpy(events, self.slashEvents.items);
        self.slashEvents.clearRetainingCapacity();
        self.pendingEvidenceBroadcasts = 0;
        return events;
    }

    // ── BLS Voting ──────────────────────────────────────────────────

    pub fn verifyVoteSignature(self: *ZeliusEngine, validatorIndex: u64, blkId: core.types.Hash, view: u64, sig_bytes: [96]u8) !bool {
        if (validatorIndex >= self.validator_set.active.len) return false;
        const validator = self.validator_set.active[@intCast(validatorIndex)];
        return keys_mod.verifyVoteSignature(validator.blsPubKey, blkId, view, sig_bytes);
    }

    /// Verify a thread timeout proof BLS signature.
    /// Message: slot(8,BE) ‖ threadId(1) ‖ "TIMEOUT"
    pub fn verifyThreadTimeoutProof(
        self: *ZeliusEngine,
        proposerIndex: u32,
        slot: u64,
        threadId: u8,
        signature: [96]u8,
    ) !bool {
        if (proposerIndex >= self.validator_set.active.len) return false;

        const pk_bytes = self.validator_set.active[proposerIndex].blsPubKey;
        const zero_pk = [_]u8{0} ** 48;
        if (std.mem.eql(u8, &pk_bytes, &zero_pk)) return false;

        var msg: [9]u8 = undefined;
        std.mem.writeInt(u64, msg[0..8], slot, .big);
        msg[8] = threadId;
        const timeout_tag = "TIMEOUT";

        // Hash to G2: slot ‖ threadId ‖ "TIMEOUT"
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(&msg);
        hasher.update(timeout_tag);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        var msg_point: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&msg_point, &hash, hash.len, BLS_DST.ptr, BLS_DST.len, null, 0);
        var msg_affine: c.blst_p2_affine = undefined;
        c.blst_p2_to_affine(&msg_affine, &msg_point);

        var sig_affine: c.blst_p2_affine = undefined;
        const sig_rc = c.blst_p2_uncompress(&sig_affine, &signature);
        if (sig_rc != c.BLST_SUCCESS) return false;
        if (!c.blst_p2_affine_in_g2(&sig_affine)) return false;

        var pk_affine: c.blst_p1_affine = undefined;
        const pk_rc = c.blst_p1_uncompress(&pk_affine, &pk_bytes);
        if (pk_rc != c.BLST_SUCCESS) return false;
        if (!c.blst_p1_affine_in_g1(&pk_affine)) return false;

        const result = c.blst_core_verify_pk_in_g1(
            &pk_affine,
            &sig_affine,
            true,
            &hash,
            hash.len,
            BLS_DST.ptr,
            BLS_DST.len,
            null,
            0,
        );
        return result == c.BLST_SUCCESS;
    }

    pub fn createVote(self: *ZeliusEngine, blkId: core.types.Hash, view: u64) ![96]u8 {
        if (self.blsPrivKey == null) return error.NoBLSKey;

        // Vote message: blockId(32) || view(8,BE)
        var msg: [40]u8 = undefined;
        @memcpy(msg[0..32], &blkId.bytes);
        std.mem.writeInt(u64, msg[32..40], view, .big);

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &msg, msg.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: c.blst_scalar = undefined;
        defer secureZero(std.mem.asBytes(&sk));
        c.blst_scalar_from_bendian(&sk, &self.blsPrivKey.?);
        if (!c.blst_sk_check(&sk)) return error.InvalidSecretKey;

        var sig: c.blst_p2 = undefined;
        c.blst_sign_pk_in_g1(&sig, &p2, &sk);

        var sig_bytes: [96]u8 = undefined;
        c.blst_p2_compress(&sig_bytes, &sig);

        return sig_bytes;
    }

    /// Create a BLS vote for an adaptive block header.
    pub fn createAdaptiveVote(self: *ZeliusEngine, header_hash: core.types.Hash) ![96]u8 {
        if (self.blsPrivKey == null) return error.NoBLSKey;
        return adaptive_mod.AdaptiveConsensus.createVote(self.blsPrivKey.?, header_hash);
    }

    /// Verify a WovenQuorumCertificate's aggregate BLS signature and stake threshold.
    /// Delegates to quorum.zig for the actual verification.
    pub fn verifyQCAggregate(
        self: *const ZeliusEngine,
        wovenRoot: *const core.types.Hash,
        aggregateSignature: [96]u8,
        voterBitmap: []const u8,
    ) !void {
        try quorum_mod.verifyQCAggregate(
            self.validator_set.active,
            self.validator_set.totalStake(),
            wovenRoot,
            aggregateSignature,
            voterBitmap,
        );
    }

    // ── Block Sealing ───────────────────────────────────────────────

    pub fn seal(self: *ZeliusEngine, block: *core.types.Block) !void {
        if (self.blsPrivKey == null) return error.NoBLSKey;
        if (self.vrfPrivKey == null) return error.NoVRFKey;

        const header = &block.header;

        // Extra data layout (192 bytes total, fixed size):
        //   0 –  96: VRF proof (96 bytes, G2 compressed)
        //  96 – 192: BLS signature over block.id() (not part of id — avoids circularity)
        const VRF_OFFSET: usize = 0;
        const BLS_OFFSET: usize = 96;
        const TOTAL_SIZE: usize = 192;

        var preserved_data = try self.allocator.alloc(u8, TOTAL_SIZE);
        errdefer self.allocator.free(preserved_data);

        // VRF proof — domain-separated proposer sortition, bound to slot
        const vrf_input = vrf.VRF.buildSortitionInput(
            vrf.DOMAIN_PROPOSER,
            self.epochSeed,
            header.number,
            null,
        );
        const vrf_proof = try vrf.VRF.prove(&self.vrfPrivKey.?, &vrf_input);
        @memcpy(preserved_data[VRF_OFFSET..BLS_OFFSET], &vrf_proof);

        // Set extraData to the VRF proof region before computing block.id().
        // block.id() does NOT include extraData, so this is safe.
        header.extraData = preserved_data;

        // Use block.id() as the canonical signing message.
        // extraData is intentionally excluded from block.id() to avoid circularity.
        const blkId = block.id();

        // Sign block.id() with BLS key
        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &blkId.bytes, blkId.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: c.blst_scalar = undefined;
        defer secureZero(std.mem.asBytes(&sk));
        c.blst_scalar_from_bendian(&sk, &self.blsPrivKey.?);
        if (!c.blst_sk_check(&sk)) return error.InvalidSecretKey;

        var sig: c.blst_p2 = undefined;
        c.blst_sign_pk_in_g1(&sig, &p2, &sk);

        var sig_out: [96]u8 = undefined;
        c.blst_p2_compress(&sig_out, &sig);
        @memcpy(preserved_data[BLS_OFFSET..][0..96], &sig_out);

        header.extraData = preserved_data;
        header.quorumCertificate = null; // QC formed by vote aggregation after proposal
        self.blocksSealed += 1;
    }

    fn printHex(prefix_str: []const u8, bytes: []const u8) void {
        const hex_charset = "0123456789abcdef";
        var buf: [2048]u8 = undefined;
        const len = @min(bytes.len, buf.len / 2);
        for (bytes[0..len], 0..) |b, idx| {
            buf[idx * 2] = hex_charset[b >> 4];
            buf[idx * 2 + 1] = hex_charset[b & 15];
        }
        std.log.err("{s}: {s}", .{ prefix_str, buf[0..len * 2] });
    }

    // ── Block Verification ──────────────────────────────────────────

    pub fn verify(self: *ZeliusEngine, block: *core.types.Block, parent: *core.types.Header) !void {
        const ctx = replay_mod.VerifyContext{
            .epochSeed = self.epochSeed,
            .totalActiveStake = self.validator_set.totalStake(),
            .tier = self.adaptive.epochManager.currentTier,
            .proposerSchedule = &self.adaptive.epochManager.proposerSchedule,
            .activeValidators = self.validator_set.active,
            .validatorIndexByAddr = &self.validator_set.indexByAddr,
            .doubleSignChecker = &.{
                .ptr = self,
                .checkFn = struct {
                    fn check(ctx: *anyopaque, blockNumber: u64, blkId: core.types.Hash, proposer: core.types.Address) !bool {
                        const engine = @as(*ZeliusEngine, @alignCast(@ptrCast(ctx)));
                        return (try engine.recordProposal(blockNumber, blkId, proposer)) != null;
                    }
                }.check,
            },
        };
        try replay_mod.verify(block, parent, ctx);
        self.blocksVerified += 1;
    }

    // ── DAG Block Validation ────────────────────────────────────────

    /// Validate the DAG structure of a block's transactions.
    pub fn validateBlockDAG(self: *ZeliusEngine, block: *core.types.Block) !void {
        _ = self;
        const allocator = std.heap.page_allocator;

        if (block.transactions.len == 0) return;

        // 1. Group transactions by sender
        var sender_map = std.AutoHashMap(core.types.Address, std.ArrayListUnmanaged(core.types.Transaction)).init(allocator);
        defer {
            var map_it = sender_map.iterator();
            while (map_it.next()) |entry| {
                entry.value_ptr.deinit(allocator);
            }
            sender_map.deinit();
        }

        for (block.transactions) |tx| {
            const gop = try sender_map.getOrPut(tx.from);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{};
            }
            try gop.value_ptr.append(allocator, tx);
        }

        // 2. Verify nonce contiguity
        var it = sender_map.iterator();
        while (it.next()) |entry| {
            const txs = entry.value_ptr.items;
            if (txs.len <= 1) continue;

            std.mem.sortUnstable(core.types.Transaction, txs, {}, struct {
                pub fn lessThan(_: void, a: core.types.Transaction, b: core.types.Transaction) bool {
                    return a.sequence < b.sequence;
                }
            }.lessThan);

            for (1..txs.len) |idx| {
                if (txs[idx].sequence != txs[idx - 1].sequence + 1) {
                    return error.NonContiguousNonceInBlock;
                }
            }
        }

        // 3. Verify cross-sender write-set independence
        // O(S log S) via sorting — replaces O(S²) nested loop.
        // Collect all nonce and balance keys into one flat array,
        // sort it, and scan for adjacent duplicates.
        const state = @import("core").state.State;

        const num_senders = sender_map.count();
        if (num_senders <= 1) return; // Single sender — no conflicts possible

        // Each sender produces 2 keys (nonce + balance) tagged with their type
        const KeyTag = struct {
            key: [32]u8,
            is_balance: bool, // true = balance key, false = nonce key
        };

        var all_keys = try std.ArrayListUnmanaged(KeyTag).initCapacity(allocator, num_senders * 2);
        defer all_keys.deinit(allocator);

        var it2 = sender_map.iterator();
        while (it2.next()) |entry| {
            const addr = entry.key_ptr.*;
            all_keys.appendAssumeCapacity(.{ .key = state.nonceKey(addr), .is_balance = false });
            all_keys.appendAssumeCapacity(.{ .key = state.balanceKey(addr), .is_balance = true });
        }

        // Sort by key bytes (lexicographic)
        std.mem.sortUnstable(KeyTag, all_keys.items, {}, struct {
            pub fn lessThan(_: void, a: KeyTag, b: KeyTag) bool {
                return std.mem.order(u8, &a.key, &b.key) == .lt;
            }
        }.lessThan);

        // Linear scan for adjacent duplicates
        for (1..all_keys.items.len) |idx| {
            if (std.mem.eql(u8, &all_keys.items[idx].key, &all_keys.items[idx - 1].key)) {
                // Determine which type of collision
                if (all_keys.items[idx].is_balance) {
                    return error.BalanceKeyCollision;
                } else {
                    return error.NonceKeyCollision;
                }
            }
        }
    }

    // computeHeaderHash removed — use core.types.Block.blockId(header) instead.

    /// Get engine statistics.
    pub fn getStats(self: *const ZeliusEngine) struct {
        sealed: u64,
        verified: u64,
        double_signs: u64,
        viewChanges: u64,
        epoch: u64,
        slashEvents: usize,
        tier: types.ConsensusTier,
        thread_count: u8,
        validatorCount: u32,
        lastFinalizedBlock: u64,
        qcsFormed: u64,
    } {
        return .{
            .sealed = self.blocksSealed,
            .verified = self.blocksVerified,
            .double_signs = self.doubleSignsDetected,
            .viewChanges = self.viewChangesTriggered,
            .epoch = self.currentEpoch,
            .slashEvents = self.slashEvents.items.len,
            .tier = self.adaptive.epochManager.currentTier,
            .thread_count = self.adaptive.epochManager.currentThreadCount,
            .validatorCount = self.adaptive.epochManager.validatorCount,
            .lastFinalizedBlock = self.lastFinalizedBlock,
            .qcsFormed = self.adaptive.qcsFormed,
        };
    }
};



