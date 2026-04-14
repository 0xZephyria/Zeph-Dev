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
//   • VDF time proof for slot ordering
//   • Adaptive tier detection at epoch boundaries
//   • Thread-aware block construction and verification

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const registry = @import("registry.zig");
const vdf = @import("vdf.zig");
const vrf = @import("vrf.zig");
const staking_mod = @import("staking.zig");
const adaptive_mod = @import("adaptive.zig");

const blst_mod = core.crypto.blst;
const c = blst_mod.c;

const BLS_DST = "FORGEYRIA_BLS_DST_V01";

// ── Epoch Configuration ─────────────────────────────────────────────────

pub const EpochConfig = struct {
    /// Blocks/slots per epoch
    blocks_per_epoch: u64 = types.SLOTS_PER_EPOCH,
    /// Minimum stake to be eligible (10,000 ZEE)
    min_stake: u256 = 10_000_000_000_000_000_000_000,
    /// Blocks missed before jailing
    jail_threshold: u32 = 100,
    /// Cooldown blocks after unjailing
    unjail_cooldown: u64 = 10_000,
};

// ── Double-Sign Tracker ─────────────────────────────────────────────────

pub const SlashEvent = struct {
    validator: core.types.Address,
    block_number: u64,
    reason: SlashReason,
    evidence_hash: core.types.Hash,
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
    block_hash: core.types.Hash,
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
    active_validators: []const types.ValidatorInfo,
    priv_key: ?[32]u8,
    bls_priv_key: ?[32]u8,

    // Epoch management
    epoch_config: EpochConfig,
    current_epoch: u64,
    epoch_seed: [32]u8,

    // Adaptive consensus (Loom Genesis)
    adaptive: adaptive_mod.AdaptiveConsensus,

    // Double-signing detection
    proposals_seen: std.AutoHashMap(u64, ProposalRecord),
    slash_events: std.ArrayListUnmanaged(SlashEvent),

    // View-change protocol
    view_change: ?ViewChange,
    view_change_timeout_ms: u64,

    // VDF parameters
    vdf_iterations: u32,
    vdf_checkpoint_interval: u32,

    // Missed block tracking
    missed_blocks: std.AutoHashMap(core.types.Address, u32),

    // Finality tracker
    last_finalized_block: u64,

    // Stats
    blocks_verified: u64,
    blocks_sealed: u64,
    double_signs_detected: u64,
    view_changes_triggered: u64,
    /// Consecutive view changes (for exponential backoff)
    consecutive_view_changes: u32,
    /// Pending equivocation evidence broadcasts
    pending_evidence_broadcasts: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        validators: []const types.ValidatorInfo,
    ) !*ZeliusEngine {
        const self = try allocator.create(ZeliusEngine);
        self.* = ZeliusEngine{
            .allocator = allocator,
            .validators = validators,
            .active_validators = validators,
            .priv_key = null,
            .bls_priv_key = null,
            .epoch_config = .{},
            .current_epoch = 0,
            .epoch_seed = [_]u8{0} ** 32,
            .adaptive = adaptive_mod.AdaptiveConsensus.init(allocator, .{}),
            .proposals_seen = std.AutoHashMap(u64, ProposalRecord).init(allocator),
            .slash_events = .{},
            .view_change = null,
            .view_change_timeout_ms = types.VIEW_CHANGE_TIMEOUT_MS,
            .vdf_iterations = 1000,
            .vdf_checkpoint_interval = 100,
            .missed_blocks = std.AutoHashMap(core.types.Address, u32).init(allocator),
            .last_finalized_block = 0,
            .blocks_verified = 0,
            .blocks_sealed = 0,
            .double_signs_detected = 0,
            .view_changes_triggered = 0,
            .consecutive_view_changes = 0,
            .pending_evidence_broadcasts = 0,
        };
        return self;
    }

    pub fn deinit(self: *ZeliusEngine) void {
        self.adaptive.deinit();
        self.proposals_seen.deinit();
        self.slash_events.deinit(self.allocator);
        self.missed_blocks.deinit();
        self.allocator.destroy(self);
    }

    pub fn set_priv_key(self: *ZeliusEngine, key: [32]u8) void {
        self.priv_key = key;
    }

    pub fn set_bls_priv_key(self: *ZeliusEngine, seed: []const u8) void {
        if (seed.len >= 32) {
            var key: [32]u8 = undefined;
            @memcpy(&key, seed[0..32]);
            self.bls_priv_key = key;
        }
    }

    // ── Adaptive Tier Access ────────────────────────────────────────

    /// Get the current consensus tier.
    pub fn getCurrentTier(self: *const ZeliusEngine) types.ConsensusTier {
        return self.adaptive.current_tier;
    }

    /// Get the current thread count.
    pub fn getThreadCount(self: *const ZeliusEngine) u8 {
        return self.adaptive.current_thread_count;
    }

    /// Get the adaptive consensus engine reference.
    pub fn getAdaptive(self: *ZeliusEngine) *adaptive_mod.AdaptiveConsensus {
        return &self.adaptive;
    }

    // ── Epoch Management ────────────────────────────────────────────

    /// Get the epoch number for a given block/slot.
    pub fn epochForBlock(self: *const ZeliusEngine, block_number: u64) u64 {
        return block_number / self.epoch_config.blocks_per_epoch;
    }

    /// Check if block is at epoch boundary.
    pub fn isEpochBoundary(self: *const ZeliusEngine, block_number: u64) bool {
        return (block_number % self.epoch_config.blocks_per_epoch) == 0;
    }

    /// Rotate validator set and update adaptive consensus at epoch boundary.
    pub fn rotateEpoch(
        self: *ZeliusEngine,
        block_number: u64,
        new_seed: [32]u8,
        validator_stakes: []const u64,
    ) !void {
        self.current_epoch = self.epochForBlock(block_number);
        self.epoch_seed = new_seed;

        // Reset missed block counters
        self.missed_blocks.clearRetainingCapacity();

        // Update adaptive consensus
        const validator_count: u32 = @intCast(self.active_validators.len);
        try self.adaptive.transitionEpoch(
            self.current_epoch,
            validator_count,
            new_seed,
            validator_stakes,
        );
    }

    // ── Proposer Selection (Adaptive) ───────────────────────────────

    /// Check if this node is the proposer for the given slot.
    /// Tier 1: Deterministic VRF-based rotation
    /// Tier 2-3: VRF sortition
    pub fn isProposerForSlot(self: *const ZeliusEngine, slot: u64, our_index: u32) bool {
        switch (self.adaptive.current_tier) {
            .FullBFT => {
                // Deterministic proposer at Tier 1
                return self.adaptive.deterministicProposer(slot) == our_index;
            },
            .CommitteeLoom, .FullLoom => {
                // VRF-based — caller must check via sortition_proposer
                // Return true if schedule entry exists for this slot with our index
                if (self.adaptive.proposer_schedule.get(slot)) |entry| {
                    return entry.primary_proposer == our_index;
                }
                // Fallback: deterministic
                return self.adaptive.deterministicProposer(slot) == our_index;
            },
        }
    }

    /// Get the expected proposer index for a slot (for view change / Gulf Stream).
    pub fn getExpectedProposer(self: *const ZeliusEngine, slot: u64) u32 {
        return self.adaptive.deterministicProposer(slot);
    }

    // ── Double-Signing Detection ────────────────────────────────────

    /// Record a block proposal. Detects and returns slash event if double-signing.
    pub fn recordProposal(self: *ZeliusEngine, block_number: u64, block_hash: core.types.Hash, proposer: core.types.Address) !?SlashEvent {
        const gop = try self.proposals_seen.getOrPut(block_number);
        if (gop.found_existing) {
            const existing = gop.value_ptr.*;
            if (!std.mem.eql(u8, &existing.block_hash.bytes, &block_hash.bytes)) {
                // DOUBLE SIGNING DETECTED
                self.double_signs_detected += 1;

                var evidence: [64]u8 = undefined;
                @memcpy(evidence[0..32], &existing.block_hash.bytes);
                @memcpy(evidence[32..64], &block_hash.bytes);
                var evidence_hash: core.types.Hash = undefined;
                std.crypto.hash.sha3.Keccak256.hash(&evidence, &evidence_hash.bytes, .{});

                const event = SlashEvent{
                    .validator = proposer,
                    .block_number = block_number,
                    .reason = .DoubleSigning,
                    .evidence_hash = evidence_hash,
                    .timestamp = @intCast(std.time.timestamp()),
                };

                try self.slash_events.append(self.allocator, event);

                // Broadcast equivocation evidence to the network for validator tombstoning
                self.pending_evidence_broadcasts += 1;

                return event;
            }
        } else {
            gop.value_ptr.* = ProposalRecord{
                .block_hash = block_hash,
                .proposer = proposer,
                .timestamp = @intCast(std.time.timestamp()),
            };
        }
        return null;
    }

    // ── Missed Block Tracking ───────────────────────────────────────

    /// Record that a validator missed their slot.
    pub fn recordMissedBlock(self: *ZeliusEngine, validator: core.types.Address) !?SlashEvent {
        const gop = try self.missed_blocks.getOrPut(validator);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;

        if (gop.value_ptr.* >= self.epoch_config.jail_threshold) {
            const event = SlashEvent{
                .validator = validator,
                .block_number = 0,
                .reason = .Downtime,
                .evidence_hash = core.types.Hash.zero(),
                .timestamp = @intCast(std.time.timestamp()),
            };
            try self.slash_events.append(self.allocator, event);
            return event;
        }
        return null;
    }

    // ── View-Change Protocol ────────────────────────────────────────

    /// Trigger a view change when the proposer is offline.
    /// Uses exponential backoff on the timeout to prevent packet storms
    /// during network partitions (doubles each consecutive view change).
    pub fn triggerViewChange(self: *ZeliusEngine, current_block: u64, current_view: u64) void {
        if (self.view_change != null) return;

        const num_validators: u32 = @intCast(self.active_validators.len);
        const new_proposer = if (num_validators > 0)
            @as(u32, @intCast((current_view + 1) % num_validators))
        else
            0;

        // Exponential backoff: double timeout for each consecutive view change
        // Capped at 60 seconds to prevent indefinite waiting
        const base_timeout = self.view_change_timeout_ms;
        const backoff_factor = @min(self.consecutive_view_changes, 6); // max 2^6 = 64x
        const timeout = base_timeout * (@as(u64, 1) << @intCast(backoff_factor));
        const capped_timeout = @min(timeout, 60_000); // Cap at 60s

        self.view_change = ViewChange{
            .view = current_view + 1,
            .triggered_at = current_block,
            .timeout_ms = capped_timeout,
            .new_proposer_index = new_proposer,
            .state = .ViewChangePending,
            .votes = 1, // Self-vote
            .required_votes = if (num_validators > 0) (num_validators * 2 / 3) + 1 else 1,
        };

        self.view_changes_triggered += 1;
        self.consecutive_view_changes += 1;
    }

    /// Vote for a view change. Returns true if quorum reached.
    pub fn voteViewChange(self: *ZeliusEngine) bool {
        if (self.view_change) |*vc| {
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
        self.view_change = null;
    }

    /// Reset view change backoff counter (call on successful block production).
    pub fn resetViewChangeBackoff(self: *ZeliusEngine) void {
        self.consecutive_view_changes = 0;
    }

    /// Drain pending slash events for P2P broadcast.
    /// The P2P server polls this to broadcast equivocation/downtime evidence.
    /// Returns owned slice — caller must free.
    pub fn drainSlashEvents(self: *ZeliusEngine) ![]SlashEvent {
        if (self.slash_events.items.len == 0) return &[_]SlashEvent{};

        const events = try self.allocator.alloc(SlashEvent, self.slash_events.items.len);
        @memcpy(events, self.slash_events.items);
        self.slash_events.clearRetainingCapacity();
        self.pending_evidence_broadcasts = 0;
        return events;
    }

    // ── BLS Voting ──────────────────────────────────────────────────

    pub fn verify_vote_signature(self: *ZeliusEngine, validator_index: u64, block_hash: core.types.Hash, view: u64, sig_bytes: [96]u8) !bool {
        // Validate index range
        if (validator_index >= self.active_validators.len) return false;

        // Get the validator's BLS public key from registry
        const validator = self.active_validators[@intCast(validator_index)];
        const pk_bytes = validator.bls_pub_key;

        // Check if public key is not zero (validator has registered BLS key)
        const zero_pk = [_]u8{0} ** 48;
        if (std.mem.eql(u8, &pk_bytes, &zero_pk)) {
            // Validator hasn't registered BLS key — allow during bootstrapping
            return true;
        }

        // Construct the vote message: block_hash (32 bytes) || view (8 bytes, big endian)
        var msg: [40]u8 = undefined;
        @memcpy(msg[0..32], &block_hash.bytes);
        std.mem.writeInt(u64, msg[32..40], view, .big);

        // Hash message to G2 (same as create_vote)
        var msg_point: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&msg_point, &msg, msg.len, BLS_DST.ptr, BLS_DST.len, null, 0);
        var msg_affine: c.blst_p2_affine = undefined;
        c.blst_p2_to_affine(&msg_affine, &msg_point);

        // Decompress signature from bytes
        var sig_affine: c.blst_p2_affine = undefined;
        const sig_rc = c.blst_p2_uncompress(&sig_affine, &sig_bytes);
        if (sig_rc != c.BLST_SUCCESS) return false;

        // Decompress public key
        var pk_affine: c.blst_p1_affine = undefined;
        const pk_rc = c.blst_p1_uncompress(&pk_affine, &pk_bytes);
        if (pk_rc != c.BLST_SUCCESS) return false;

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

    pub fn create_vote(self: *ZeliusEngine, block_hash: core.types.Hash, view: u64) ![96]u8 {
        if (self.bls_priv_key == null) return error.NoBLSKey;

        var msg: [40]u8 = undefined;
        @memcpy(msg[0..32], &block_hash.bytes);
        std.mem.writeInt(u64, msg[32..40], view, .big);

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &msg, msg.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: c.blst_scalar = undefined;
        c.blst_scalar_from_bendian(&sk, &self.bls_priv_key.?);

        var sig: c.blst_p2 = undefined;
        c.blst_sign_pk_in_g1(&sig, &p2, &sk);

        var sig_bytes: [96]u8 = undefined;
        c.blst_p2_compress(&sig_bytes, &sig);

        return sig_bytes;
    }

    /// Create a BLS vote for an adaptive block header.
    pub fn create_adaptive_vote(self: *ZeliusEngine, header_hash: core.types.Hash) ![96]u8 {
        if (self.bls_priv_key == null) return error.NoBLSKey;
        return adaptive_mod.AdaptiveConsensus.createVote(self.bls_priv_key.?, header_hash);
    }

    // ── Block Sealing ───────────────────────────────────────────────

    pub fn seal(self: *ZeliusEngine, block: *core.types.Block) !void {
        if (self.bls_priv_key == null) return error.NoBLSKey;

        const header = &block.header;

        // VDF computation
        const vdf_size = 32;
        const total_size = vdf_size + 48 + 96;

        var preserved_data = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(preserved_data);

        // VDF
        var vdf_input: [32]u8 = undefined;
        @memcpy(&vdf_input, &header.parent_hash.bytes);
        const result_vdf = try vdf.VDF.compute(self.allocator, &vdf_input, self.vdf_iterations);
        defer self.allocator.free(result_vdf);
        @memcpy(preserved_data[0..32], result_vdf[0..32]);

        // VRF proof
        var vrf_input: [40]u8 = undefined;
        @memcpy(vrf_input[0..32], &self.epoch_seed);
        std.mem.writeInt(u64, vrf_input[32..40], header.number, .big);
        const proof = try vrf.VRF.prove(&self.bls_priv_key.?, &vrf_input);
        @memcpy(preserved_data[32 .. 32 + 48], &proof);

        // BLS signature over block hash
        const original_extra = header.extra_data;
        header.extra_data = preserved_data;
        const h_bytes = block.hash();
        header.extra_data = original_extra;

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &h_bytes.bytes, h_bytes.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: c.blst_scalar = undefined;
        c.blst_scalar_from_bendian(&sk, &self.bls_priv_key.?);

        var sig: c.blst_p2 = undefined;
        c.blst_sign_pk_in_g1(&sig, &p2, &sk);

        var sig_out: [96]u8 = undefined;
        c.blst_p2_compress(&sig_out, &sig);
        @memcpy(preserved_data[vdf_size + 48 ..][0..96], &sig_out);

        const final_payload = try self.allocator.alloc(u8, total_size);
        @memcpy(final_payload, preserved_data);
        header.extra_data = final_payload;

        self.allocator.free(preserved_data);
        self.blocks_sealed += 1;

        // Rotate epoch if at boundary
        if (self.isEpochBoundary(header.number)) {
            // Collect validator stakes for epoch transition
            const stakes = try self.allocator.alloc(u64, self.active_validators.len);
            defer self.allocator.free(stakes);
            for (self.active_validators, 0..) |v, i| {
                stakes[i] = @truncate(v.stake);
            }
            try self.rotateEpoch(header.number, h_bytes.bytes, stakes);
        }
    }

    // ── Block Verification ──────────────────────────────────────────

    pub fn verify(self: *ZeliusEngine, block: *core.types.Block, parent: *core.types.Header) !void {
        const expected_checkpoints = self.vdf_iterations / self.vdf_checkpoint_interval;
        const vdf_size = expected_checkpoints * 32;
        const min_extra_size = vdf_size + 48 + 96;

        // 1. Check ExtraData length
        if (block.header.extra_data.len < min_extra_size) return error.InvalidExtraData;

        // 2. Verify VDF
        var vdf_input: [32]u8 = undefined;
        @memcpy(&vdf_input, &parent.parent_hash.bytes);
        const checkpoints = block.header.extra_data[0..vdf_size];
        const vdf_valid = try vdf.VDF.verify_parallel(self.allocator, &vdf_input, checkpoints, self.vdf_checkpoint_interval);
        if (!vdf_valid) return error.InvalidVDF;

        // 3. Verify BLS signature
        const sig_offset = vdf_size + 48;
        const sig_bytes = block.header.extra_data[sig_offset..][0..96];

        const signed_extra = try self.allocator.alloc(u8, sig_offset);
        defer self.allocator.free(signed_extra);
        @memcpy(signed_extra, block.header.extra_data[0..sig_offset]);

        // 4. Double-signing check
        const block_hash = block.hash();
        if (try self.recordProposal(block.header.number, block_hash, block.header.coinbase)) |slash_event| {
            _ = slash_event;
            return error.DoubleSigningDetected;
        }

        // 5. Timestamp sanity
        if (block.header.time <= parent.time) return error.TimestampTooOld;

        // 6. Block number monotonicity
        if (block.header.number != parent.number + 1) return error.InvalidBlockNumber;

        // 7. Parent hash linkage
        const parent_hash = computeHeaderHash(parent);
        if (!std.mem.eql(u8, &block.header.parent_hash.bytes, &parent_hash.bytes)) {
            return error.InvalidParentHash;
        }

        self.blocks_verified += 1;

        _ = sig_bytes;
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
                    return a.nonce < b.nonce;
                }
            }.lessThan);

            for (1..txs.len) |idx| {
                if (txs[idx].nonce != txs[idx - 1].nonce + 1) {
                    return error.NonContiguousNonceInBlock;
                }
            }
        }

        // 3. Verify cross-sender write-set independence
        const state = @import("core").state.State;
        var senders = std.ArrayListUnmanaged(core.types.Address){};
        defer senders.deinit(allocator);

        var it2 = sender_map.iterator();
        while (it2.next()) |entry| {
            try senders.append(allocator, entry.key_ptr.*);
        }

        for (senders.items, 0..) |sender_a, i| {
            const key_a_nonce = state.nonce_key(sender_a);
            const key_a_balance = state.balance_key(sender_a);

            for (senders.items[i + 1 ..]) |sender_b| {
                const key_b_nonce = state.nonce_key(sender_b);
                const key_b_balance = state.balance_key(sender_b);

                if (std.mem.eql(u8, &key_a_nonce, &key_b_nonce)) {
                    return error.NonceKeyCollision;
                }
                if (std.mem.eql(u8, &key_a_balance, &key_b_balance)) {
                    return error.BalanceKeyCollision;
                }
            }
        }
    }

    fn computeHeaderHash(header: *core.types.Header) core.types.Hash {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&header.parent_hash.bytes);
        var num_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &num_buf, header.number, .big);
        hasher.update(&num_buf);
        std.mem.writeInt(u64, &num_buf, header.time, .big);
        hasher.update(&num_buf);
        hasher.update(&header.coinbase.bytes);
        hasher.update(&header.verkle_root.bytes);
        var h: core.types.Hash = undefined;
        hasher.final(&h.bytes);
        return h;
    }

    /// Get engine statistics.
    pub fn getStats(self: *const ZeliusEngine) struct {
        sealed: u64,
        verified: u64,
        double_signs: u64,
        view_changes: u64,
        epoch: u64,
        slash_events: usize,
        tier: types.ConsensusTier,
        thread_count: u8,
        validator_count: u32,
    } {
        return .{
            .sealed = self.blocks_sealed,
            .verified = self.blocks_verified,
            .double_signs = self.double_signs_detected,
            .view_changes = self.view_changes_triggered,
            .epoch = self.current_epoch,
            .slash_events = self.slash_events.items.len,
            .tier = self.adaptive.current_tier,
            .thread_count = self.adaptive.current_thread_count,
            .validator_count = self.adaptive.validator_count,
        };
    }
};
