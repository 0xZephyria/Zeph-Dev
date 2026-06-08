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

const blst_mod = core.crypto.blst;
const c = blst_mod.c;

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
    evidenceHash: core.types.Hash,
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
    votes: u32,
    required_votes: u32,
};

// ── Main Engine ─────────────────────────────────────────────────────────

pub const ZeliusEngine = struct {
    allocator: std.mem.Allocator,
    validators: []const types.ValidatorInfo,
    activeValidators: []const types.ValidatorInfo,
    privKey: ?[32]u8,
    blsPrivKey: ?[32]u8,
    vrfPrivKey: ?[32]u8,

    // Epoch management
    epochConfig: EpochConfig,
    currentEpoch: u64,
    epochSeed: [32]u8,

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

    // Fast O(1) validator lookup by address
    validatorIndexByAddr: std.AutoHashMap(core.types.Address, usize),

    // Cached total active stake for O(1) quorum checks
    totalActiveStake: u256,

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
            .activeValidators = validators,
            .privKey = null,
            .blsPrivKey = null,
            .vrfPrivKey = null,
            .epochConfig = .{},
            .currentEpoch = 0,
            .epochSeed = [_]u8{0} ** 32,
            .adaptive = adaptive_mod.AdaptiveConsensus.init(allocator, .{}),
            .proposalsSeen = std.AutoHashMap(u64, ProposalRecord).init(allocator),
            .slashEvents = .{},
            .viewChange = null,
            .viewChangeTimeoutMs = types.VIEW_CHANGE_TIMEOUT_MS,
            .missedBlocks = std.AutoHashMap(core.types.Address, u32).init(allocator),
            .validatorIndexByAddr = std.AutoHashMap(core.types.Address, usize).init(allocator),
            .totalActiveStake = 0,
            .lastFinalizedBlock = 0,
            .blocksVerified = 0,
            .blocksSealed = 0,
            .doubleSignsDetected = 0,
            .viewChangesTriggered = 0,
            .consecutiveViewChanges = 0,
            .pendingEvidenceBroadcasts = 0,
        };

        // Populate validator address index and compute total stake
        var total_stake: u256 = 0;
        for (validators, 0..) |v, i| {
            try self.validatorIndexByAddr.put(v.address, i);
            total_stake += v.stake;
        }
        self.totalActiveStake = total_stake;

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
        self.validatorIndexByAddr.deinit();
        self.allocator.destroy(self);
    }

    pub fn setPrivKey(self: *ZeliusEngine, key: [32]u8) void {
        self.privKey = key;
    }

    pub fn setBlsPrivKey(self: *ZeliusEngine, seed: []const u8) void {
        if (seed.len < 32) return;
        var key: [32]u8 = undefined;
        @memcpy(&key, seed[0..32]);
        defer secureZero(key[0..]);

        // Derive BLS signing key via blst_keygen (HKDF)
        var sk: c.blst_scalar = undefined;
        defer secureZero(std.mem.asBytes(&sk));
        c.blst_keygen(&sk, &key, key.len, null, 0);
        var sk_bytes: [32]u8 = undefined;
        defer secureZero(sk_bytes[0..]);
        c.blst_bendian_from_scalar(&sk_bytes, &sk);
        self.blsPrivKey = sk_bytes;

        // VRF uses the same key (domain-separated by DST in hash-to-curve).
        // A separate VRF public key would need on-chain registration.
        self.vrfPrivKey = self.blsPrivKey;
    }

    // ── Adaptive Tier Access ────────────────────────────────────────

    /// Get the current consensus tier.
    pub fn getCurrentTier(self: *const ZeliusEngine) types.ConsensusTier {
        return self.adaptive.currentTier;
    }

    /// Get the current thread count.
    pub fn getThreadCount(self: *const ZeliusEngine) u8 {
        return self.adaptive.currentThreadCount;
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

    /// Rotate validator set and update adaptive consensus at epoch boundary.
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

        // Update adaptive consensus
        const validatorCount: u32 = @intCast(self.activeValidators.len);
        try self.adaptive.transitionEpoch(
            self.currentEpoch,
            validatorCount,
            newSeed,
            validatorStakes,
        );
    }

    /// Rebuild the validator address index (call when activeValidators changes).
    pub fn rebuildValidatorIndex(self: *ZeliusEngine) void {
        self.validatorIndexByAddr.clearRetainingCapacity();
        var total_stake: u256 = 0;
        for (self.activeValidators, 0..) |v, i| {
            self.validatorIndexByAddr.put(v.address, i) catch {};
            total_stake += v.stake;
        }
        self.totalActiveStake = total_stake;
    }

    // ── Proposer Selection (Adaptive) ───────────────────────────────

    /// Check if this node is the proposer for the given slot.
    /// Tier 1: Deterministic VRF-based rotation
    /// Tier 2-3: VRF sortition
    pub fn isProposerForSlot(self: *const ZeliusEngine, slot: u64, ourIndex: u32) bool {
        switch (self.adaptive.currentTier) {
            .FullBFT => {
                // Deterministic proposer at Tier 1
                return self.adaptive.deterministicProposer(slot) == ourIndex;
            },
            .CommitteeLoom, .FullLoom => {
                // VRF-based — caller must check via sortition_proposer
                // Return true if schedule entry exists for this slot with our index
                if (self.adaptive.proposerSchedule.get(slot)) |entry| {
                    return entry.primaryProposer == ourIndex;
                }
                // Fallback: deterministic
                return self.adaptive.deterministicProposer(slot) == ourIndex;
            },
        }
    }

    /// Get the expected proposer index for a slot (for view change / Gulf Stream).
    pub fn getExpectedProposer(self: *const ZeliusEngine, slot: u64) u32 {
        return self.adaptive.deterministicProposer(slot);
    }

    // ── Double-Signing Detection ────────────────────────────────────

    /// Record a block proposal. Detects and returns slash event if double-signing.
    pub fn recordProposal(self: *ZeliusEngine, blockNumber: u64, blockHash: core.types.Hash, proposer: core.types.Address) !?SlashEvent {
        const gop = try self.proposalsSeen.getOrPut(blockNumber);
        if (gop.found_existing) {
            const existing = gop.value_ptr.*;
            if (!std.mem.eql(u8, &existing.blockHash.bytes, &blockHash.bytes)) {
                // DOUBLE SIGNING DETECTED
                self.doubleSignsDetected += 1;

                var evidence: [64]u8 = undefined;
                @memcpy(evidence[0..32], &existing.blockHash.bytes);
                @memcpy(evidence[32..64], &blockHash.bytes);
                var evidenceHash: core.types.Hash = undefined;
                std.crypto.hash.Blake3.hash(&evidence, &evidenceHash.bytes, .{});

                const event = SlashEvent{
                    .validator = proposer,
                    .blockNumber = blockNumber,
                    .reason = .DoubleSigning,
                    .evidenceHash = evidenceHash,
                    .timestamp = @intCast(std.time.timestamp()),
                };

                try self.slashEvents.append(self.allocator, event);

                // Broadcast equivocation evidence to the network for validator tombstoning
                self.pendingEvidenceBroadcasts += 1;

                return event;
            }
        } else {
            gop.value_ptr.* = ProposalRecord{
                .blockHash = blockHash,
                .proposer = proposer,
                .timestamp = @intCast(std.time.timestamp()),
            };
        }
        return null;
    }

    // ── Missed Block Tracking ───────────────────────────────────────

    /// Record that a validator missed their slot.
    pub fn recordMissedBlock(self: *ZeliusEngine, validator: core.types.Address) !?SlashEvent {
        const gop = try self.missedBlocks.getOrPut(validator);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;

        if (gop.value_ptr.* >= self.epochConfig.jailThreshold) {
            const event = SlashEvent{
                .validator = validator,
                .blockNumber = 0,
                .reason = .Downtime,
                .evidenceHash = core.types.Hash.zero(),
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
        if (self.viewChange != null) return;

        const num_validators: u32 = @intCast(self.activeValidators.len);
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
            .votes = 1, // Self-vote
            .required_votes = if (num_validators > 0) (num_validators * 2 / 3) + 1 else 1,
        };

        self.viewChangesTriggered += 1;
        self.consecutiveViewChanges += 1;
    }

    /// Vote for a view change. Returns true if quorum reached.
    pub fn voteViewChange(self: *ZeliusEngine) bool {
        if (self.viewChange) |*vc| {
            vc.votes += 1;
            if (vc.votes >= vc.required_votes) {
                vc.state = .ViewChangeComplete;
                return true;
            }
        }
        return false;
    }

    /// Complete the view change.
    pub fn completeViewChange(self: *ZeliusEngine) void {
        self.viewChange = null;
    }

    /// Reset view change backoff counter (call on successful block production).
    pub fn resetViewChangeBackoff(self: *ZeliusEngine) void {
        self.consecutiveViewChanges = 0;
    }

    // ── Finality Tracking ───────────────────────────────────────────
    //
    // The adaptive consensus layer (AdaptiveConsensus.buildQC) sets
    // lastFinalizedSlot when a Woven Quorum Certificate forms with
    // ≥67% attesting stake. These methods bridge that value into
    // ZeliusEngine so the P2P layer, RPC, and sync protocol can
    // query finality state through a single reference.

    /// Update the finality tracker after a QC has been formed.
    /// Called by the P2P layer once buildQC() succeeds.
    /// The block/slot number must be monotonically increasing —
    /// stale finality updates are silently ignored to prevent
    /// finality regression attacks.
    pub fn updateFinality(self: *ZeliusEngine, finalized_block: u64) void {
        if (finalized_block > self.lastFinalizedBlock) {
            self.lastFinalizedBlock = finalized_block;
        }
    }

    /// Synchronize finality state from the adaptive consensus layer.
    /// This is the primary mechanism: read adaptive.lastFinalizedSlot
    /// and propagate it. Safe to call on every slot tick.
    pub fn syncFinalityFromAdaptive(self: *ZeliusEngine) void {
        const adaptive_finalized = self.adaptive.lastFinalizedSlot;
        if (adaptive_finalized > self.lastFinalizedBlock) {
            self.lastFinalizedBlock = adaptive_finalized;
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
        if (self.slashEvents.items.len == 0) return &[_]SlashEvent{};

        const events = try self.allocator.alloc(SlashEvent, self.slashEvents.items.len);
        @memcpy(events, self.slashEvents.items);
        self.slashEvents.clearRetainingCapacity();
        self.pendingEvidenceBroadcasts = 0;
        return events;
    }

    // ── BLS Voting ──────────────────────────────────────────────────

    pub fn verifyVoteSignature(self: *ZeliusEngine, validatorIndex: u64, blockHash: core.types.Hash, view: u64, sig_bytes: [96]u8) !bool {
        // Validate index range
        if (validatorIndex >= self.activeValidators.len) return false;

        // Get the validator's BLS public key from registry
        const validator = self.activeValidators[@intCast(validatorIndex)];
        const pk_bytes = validator.blsPubKey;

        // Reject zero public keys — validator must have registered BLS key
        const zero_pk = [_]u8{0} ** 48;
        if (std.mem.eql(u8, &pk_bytes, &zero_pk)) return false;

        // Construct the vote message: blockHash (32 bytes) || view (8 bytes, big endian)
        var msg: [40]u8 = undefined;
        @memcpy(msg[0..32], &blockHash.bytes);
        std.mem.writeInt(u64, msg[32..40], view, .big);

        // Hash message to G2 (same as createVote)
        var msg_point: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&msg_point, &msg, msg.len, BLS_DST.ptr, BLS_DST.len, null, 0);
        var msg_affine: c.blst_p2_affine = undefined;
        c.blst_p2_to_affine(&msg_affine, &msg_point);

        // Decompress signature from bytes
        var sig_affine: c.blst_p2_affine = undefined;
        const sig_rc = c.blst_p2_uncompress(&sig_affine, &sig_bytes);
        if (sig_rc != c.BLST_SUCCESS) return false;
        if (!c.blst_p2_affine_in_g2(&sig_affine)) return false;

        // Decompress public key
        var pk_affine: c.blst_p1_affine = undefined;
        const pk_rc = c.blst_p1_uncompress(&pk_affine, &pk_bytes);
        if (pk_rc != c.BLST_SUCCESS) return false;
        if (!c.blst_p1_affine_in_g1(&pk_affine)) return false;

        // Core verification: e(pk, H(msg)) == e(G1, sig)
        const result = c.blst_core_verify_pk_in_g1(
            &pk_affine,
            &sig_affine,
            true, // hash
            &msg,
            msg.len,
            BLS_DST.ptr,
            BLS_DST.len,
            null,
            0,
        );

        return result == c.BLST_SUCCESS;
    }

    pub fn createVote(self: *ZeliusEngine, blockHash: core.types.Hash, view: u64) ![96]u8 {
        if (self.blsPrivKey == null) return error.NoBLSKey;

        var msg: [40]u8 = undefined;
        @memcpy(msg[0..32], &blockHash.bytes);
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

    // ── Block Sealing ───────────────────────────────────────────────

    pub fn seal(self: *ZeliusEngine, block: *core.types.Block) !void {
        if (self.blsPrivKey == null) return error.NoBLSKey;
        if (self.vrfPrivKey == null) return error.NoVRFKey;

        const header = &block.header;

        // Extra data layout (192 bytes total, fixed size):
        //   0 –  96: VRF proof (96 bytes, G2 compressed)
        //  96 – 192: BLS signature over block hash (96 bytes, not included in hash)
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

        // Hash includes VRF proof (96 bytes); BLS sig at [96..192] is excluded by EXTRA_DATA_HASH_LEN
        header.extraData = preserved_data;
        const h_bytes = block.hash();

        if (header.number == 1) {
            printHex("SEAL HASH", &h_bytes.bytes);
        }

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &h_bytes.bytes, h_bytes.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);

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
        header.quorumCertificate = null; // QC is formed by vote aggregation after proposal
        self.blocksSealed += 1;

        // Rotate epoch if at boundary
        if (self.isEpochBoundary(header.number)) {
            const stakes = try self.allocator.alloc(u256, self.activeValidators.len);
            defer self.allocator.free(stakes);
            for (self.activeValidators, 0..) |v, i| {
                stakes[i] = v.stake;
            }
            try self.rotateEpoch(header.number, h_bytes.bytes, stakes);
        }
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
        const VRF_OFFSET: usize = 0;
        const BLS_OFFSET: usize = 96;
        const MIN_EXTRA_SIZE: usize = 192;

        // 1. Check ExtraData length — enforce exact 192 bytes (VRF proof + BLS signature)
        if (block.header.extraData.len != MIN_EXTRA_SIZE) return error.InvalidExtraData;

        // 2. Verify BLS signature (Block.hash() strips BLS suffix via EXTRA_DATA_HASH_LEN)
        const sig_bytes = block.header.extraData[BLS_OFFSET..][0..96];

        const proposer_idx = self.validatorIndexByAddr.get(block.header.producer) orelse return error.ValidatorNotFound;
        const pk_bytes = self.activeValidators[proposer_idx].blsPubKey;

        const h_bytes = block.hash();

        if (block.header.number == 1) {
            printHex("VERIFY HASH", &h_bytes.bytes);
        }

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &h_bytes.bytes, h_bytes.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);
        var msg_affine: c.blst_p2_affine = undefined;
        c.blst_p2_to_affine(&msg_affine, &p2);

        var sig_affine: c.blst_p2_affine = undefined;
        const sig_rc = c.blst_p2_uncompress(&sig_affine, sig_bytes.ptr);
        if (sig_rc != c.BLST_SUCCESS) return error.InvalidSignature;
        if (!c.blst_p2_affine_in_g2(&sig_affine)) return error.InvalidSignature;

        var pk_affine: c.blst_p1_affine = undefined;
        const pk_rc = c.blst_p1_uncompress(&pk_affine, &pk_bytes);
        if (pk_rc != c.BLST_SUCCESS) return error.InvalidPublicKey;
        if (!c.blst_p1_affine_in_g1(&pk_affine)) return error.InvalidPublicKey;

        const result = c.blst_core_verify_pk_in_g1(
            &pk_affine,
            &sig_affine,
            true,
            &h_bytes.bytes,
            h_bytes.bytes.len,
            BLS_DST.ptr,
            BLS_DST.len,
            null,
            0,
        );
        if (result != c.BLST_SUCCESS) {
            const producer_hex = std.fmt.bytesToHex(block.header.producer.bytes, .lower);
            std.log.err("BLS signature verify failed: result={}, producer={s}", .{
                result,
                &producer_hex,
            });
            return error.InvalidSignature;
        }

        // 3. Verify VRF proof (proposer sortition — same input as sortition_proposer)
        const vrf_proof_bytes = block.header.extraData[VRF_OFFSET..][0..96];
        const vrf_input = vrf.VRF.buildSortitionInput(
            vrf.DOMAIN_PROPOSER,
            self.epochSeed,
            block.header.number,
            null,
        );
        if (!vrf.VRF.verify(pk_bytes, vrf_proof_bytes.*, &vrf_input)) {
            return error.InvalidVRF;
        }

        // 4. Proposer must be in active validator set and meet stake-weighted threshold.
        //    Zero-stake proposers are always rejected (cannot be eligible).
        const proposer_stake = self.activeValidators[proposer_idx].stake;
        if (proposer_stake == 0) return error.ZeroStakeProposer;
        if (!vrf.VRF.checkProposerEligibility(
            vrf_proof_bytes.*,
            proposer_stake,
            self.totalActiveStake,
            types.EXPECTED_PROPOSERS,
        )) return error.ProposerNotEligible;

        // 4b. Verify the block producer is the expected proposer for this slot.
        //     At Tier 1 the proposer is deterministic; at Tier 2-3 the VRF sortition
        //     (verified above) determines eligibility, and deterministicProposer
        //     serves as the fallback when the proposer schedule is unpopulated.
        const expected_proposer = self.adaptive.deterministicProposer(block.header.number);
        if (proposer_idx != expected_proposer) return error.WrongProposerForSlot;

        // 5. Double-signing check
        const blockHash = block.hash();
        if (try self.recordProposal(block.header.number, blockHash, block.header.producer)) |slash_event| {
            _ = slash_event;
            return error.DoubleSigningDetected;
        }

        // 6. Timestamp sanity
        if (block.header.time <= parent.time) return error.TimestampTooOld;

        // 7. Block number monotonicity
        if (block.header.number != parent.number + 1) return error.InvalidBlockNumber;

        // 8. Parent hash linkage
        const parentHash = computeHeaderHash(parent);
        if (!std.mem.eql(u8, &block.header.parentHash.bytes, &parentHash.bytes)) {
            return error.InvalidParentHash;
        }

        // 9. Validate QuorumCertificate if present.
        //     During sync, blocks carry a QC; during initial proposal it is null
        //     (formed after vote aggregation by the pipeline).
        if (block.header.quorumCertificate) |qc| {
            // Aggregate signer public keys from the bitmap
            var agg_pk: c.blst_p1 = undefined;
            var first = true;
            var computed_attesting_stake: u256 = 0;
            for (0..256) |i| {
                const byte_idx = i / 8;
                const bit_idx = @as(u3, @intCast(i % 8));
                if (byte_idx >= qc.voterBitmap.len) break;
                if ((qc.voterBitmap[byte_idx] >> @as(u3, @intCast(bit_idx))) & 1 == 1) {
                    if (i >= self.activeValidators.len) return error.InvalidQC;
                    const v_pk_bytes = self.activeValidators[i].blsPubKey;
                    var v_pk_affine: c.blst_p1_affine = undefined;
                    if (c.blst_p1_uncompress(&v_pk_affine, &v_pk_bytes) != c.BLST_SUCCESS) return error.InvalidQC;
                    if (!c.blst_p1_affine_in_g1(&v_pk_affine)) return error.InvalidQC;
                    var v_pk_jac: c.blst_p1 = undefined;
                    c.blst_p1_from_affine(&v_pk_jac, &v_pk_affine);
                    if (first) {
                        agg_pk = v_pk_jac;
                        first = false;
                    } else {
                        c.blst_p1_add_or_double(&agg_pk, &agg_pk, &v_pk_jac);
                    }
                    computed_attesting_stake += self.activeValidators[i].stake;
                }
            }
            if (first) return error.InvalidQC; // No signers in bitmap

            // Verify aggregate signature against the block hash (same hashed message as BLS sig)
            var agg_pk_affine: c.blst_p1_affine = undefined;
            c.blst_p1_to_affine(&agg_pk_affine, &agg_pk);

            var qc_sig_affine: c.blst_p2_affine = undefined;
            if (c.blst_p2_uncompress(&qc_sig_affine, &qc.aggregateSignature) != c.BLST_SUCCESS) return error.InvalidQC;
            if (!c.blst_p2_affine_in_g2(&qc_sig_affine)) return error.InvalidQC;

            const qc_result = c.blst_core_verify_pk_in_g1(
                &agg_pk_affine,
                &qc_sig_affine,
                true,
                &h_bytes.bytes,
                h_bytes.bytes.len,
                BLS_DST.ptr,
                BLS_DST.len,
                null,
                0,
            );
            if (qc_result != c.BLST_SUCCESS) return error.InvalidQC;

            // Check 2/3+ stake threshold using u512 to avoid overflow
            if (@as(u512, computed_attesting_stake) * 3 <= @as(u512, self.totalActiveStake) * 2) {
                return error.InsufficientQCMajority;
            }
        }

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

    /// Compute the Blake3 hash of a block header for parent-chain linking.
    pub fn computeHeaderHash(header: *core.types.Header) core.types.Hash {
        var h_res = core.types.Hash.zero();
        var hasher = std.crypto.hash.Blake3.init(.{});
        var buf8: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf8, header.number, .big);
        hasher.update(&buf8);
        hasher.update(&header.parentHash.bytes);
        std.mem.writeInt(u64, &buf8, header.time, .big);
        hasher.update(&buf8);
        hasher.update(&header.stateRoot.bytes);
        hasher.update(&header.txHash.bytes);
        hasher.update(&header.producer.bytes);
        std.mem.writeInt(u64, &buf8, header.executionBudget, .big);
        hasher.update(&buf8);
        std.mem.writeInt(u64, &buf8, header.gasUsed, .big);
        hasher.update(&buf8);
        hasher.update(header.extraData);
        hasher.final(&h_res.bytes);
        return h_res;
    }

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
            .tier = self.adaptive.currentTier,
            .thread_count = self.adaptive.currentThreadCount,
            .validatorCount = self.adaptive.validatorCount,
            .lastFinalizedBlock = self.lastFinalizedBlock,
            .qcsFormed = self.adaptive.qcsFormed,
        };
    }
};

pub fn deriveBlsPubKey(seed: [32]u8) [48]u8 {
    var mutable_seed = seed;
    defer secureZero(mutable_seed[0..]);
    var sk: c.blst_scalar = undefined;
    defer secureZero(std.mem.asBytes(&sk));
    c.blst_keygen(&sk, &mutable_seed, mutable_seed.len, null, 0);
    var pk: c.blst_p1 = undefined;
    c.blst_sk_to_pk_in_g1(&pk, &sk);
    var pk_compressed: [48]u8 = undefined;
    c.blst_p1_compress(&pk_compressed, &pk);
    return pk_compressed;
}

fn secureZero(buf: []u8) void {
    const ptr = @as([*]volatile u8, @ptrCast(buf.ptr));
    for (0..buf.len) |i| ptr[i] = 0;
}


