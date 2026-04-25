// ============================================================================
// Zephyria — Thread Attestation Pool (Loom Genesis)
// ============================================================================
//
// Per-thread attestation collection and certificate generation.
// Used by Tier 2 (committee members attest to their assigned thread)
// and Tier 3 (VRF-selected weavers attest to threads).
//
// At Tier 1, this module is unused — all validators verify everything
// and vote on the entire block directly.
//
// Lifecycle per slot:
//   1. Proposer distributes block with thread data via Turbine
//   2. Weavers/committee members verify their thread's transactions
//   3. Weavers submit ThreadAttestations via P2P
//   4. Aggregator collects attestations → produces ThreadCertificate
//   5. All validators receive block header + T thread certificates
//   6. Validators vote on the woven block (BLS all-to-all or Snowball)

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

const blst_mod = core.crypto.blst;
const blst_c = blst_mod.c;

const BLS_DST = "FORGEYRIA_BLS_DST_V01";

// ── Thread Attestation Pool ─────────────────────────────────────────────

pub const ThreadAttestationPool = struct {
    allocator: std.mem.Allocator,

    /// Current slot being processed
    current_slot: u64,

    /// Thread ID → list of attestations received
    attestations: [types.MAX_THREADS]std.ArrayListUnmanaged(types.ThreadAttestation),
    /// Thread ID → set of validator indices that have attested (dedup)
    attested_validators: [types.MAX_THREADS]std.AutoHashMap(u32, void),
    /// Thread ID → accumulated attesting stake
    attested_stake: [types.MAX_THREADS]u64,
    /// Thread ID → total eligible stake (set externally)
    eligible_stake: [types.MAX_THREADS]u64,

    /// Produced certificates
    certificates: [types.MAX_THREADS]?types.ThreadCertificate,
    certs_produced: u8,

    // Stats
    total_attestations_received: u64,
    total_attestations_rejected: u64,
    total_certs_produced: u64,

    lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        var pool: Self = undefined;
        pool.allocator = allocator;
        pool.current_slot = 0;
        pool.certs_produced = 0;
        pool.total_attestations_received = 0;
        pool.total_attestations_rejected = 0;
        pool.total_certs_produced = 0;
        pool.lock = .{};
        pool.certificates = [_]?types.ThreadCertificate{null} ** types.MAX_THREADS;

        for (0..types.MAX_THREADS) |i| {
            pool.attestations[i] = .{};
            pool.attested_validators[i] = std.AutoHashMap(u32, void).init(allocator);
            pool.attested_stake[i] = 0;
            pool.eligible_stake[i] = 0;
        }

        return pool;
    }

    pub fn deinit(self: *Self) void {
        for (0..types.MAX_THREADS) |i| {
            self.attestations[i].deinit(self.allocator);
            self.attested_validators[i].deinit();
        }
    }

    /// Reset the pool for a new slot.
    pub fn resetForSlot(self: *Self, slot: u64) void {
        self.lock.lock();
        defer self.lock.unlock();

        self.current_slot = slot;
        self.certs_produced = 0;
        self.certificates = [_]?types.ThreadCertificate{null} ** types.MAX_THREADS;

        for (0..types.MAX_THREADS) |i| {
            self.attestations[i].clearRetainingCapacity();
            self.attested_validators[i].clearRetainingCapacity();
            self.attested_stake[i] = 0;
            self.eligible_stake[i] = 0;
        }
    }

    /// Set the total eligible stake for a thread (needed for quorum check).
    pub fn setEligibleStake(self: *Self, thread_id: u8, stake: u64) void {
        if (thread_id >= types.MAX_THREADS) return;
        self.eligible_stake[thread_id] = stake;
    }

    /// Add a thread attestation. Returns true if a new certificate was produced.
    pub fn addAttestation(self: *Self, attestation: types.ThreadAttestation) !bool {
        self.lock.lock();
        defer self.lock.unlock();

        const tid = attestation.threadId;
        if (tid >= types.MAX_THREADS) {
            self.total_attestations_rejected += 1;
            return false;
        }

        // Validate slot
        if (attestation.slot != self.current_slot) {
            self.total_attestations_rejected += 1;
            return false;
        }

        // Deduplicate
        if (self.attested_validators[tid].contains(attestation.validatorIndex)) {
            return false;
        }

        // Store attestation
        try self.attestations[tid].append(self.allocator, attestation);
        try self.attested_validators[tid].put(attestation.validatorIndex, {});
        self.attested_stake[tid] += attestation.attestingStake;
        self.total_attestations_received += 1;

        // Check if we've reached quorum for this thread
        if (self.certificates[tid] == null and self.hasThreadQuorum(tid)) {
            self.certificates[tid] = try self.buildCertificate(tid);
            self.certs_produced += 1;
            self.total_certs_produced += 1;
            return true;
        }

        return false;
    }

    /// Check if a thread has sufficient quorum (≥67% of eligible stake).
    fn hasThreadQuorum(self: *const Self, thread_id: u8) bool {
        const tid: usize = thread_id;
        if (self.eligible_stake[tid] == 0) return false;
        return self.attested_stake[tid] * 3 > self.eligible_stake[tid] * 2;
    }

    /// Build a ThreadCertificate from collected attestations.
    fn buildCertificate(self: *Self, thread_id: u8) !types.ThreadCertificate {
        const tid: usize = thread_id;
        const atts = self.attestations[tid].items;
        if (atts.len == 0) return error.NoAttestations;

        // All attestations must agree on the thread root
        const thread_root = atts[0].thread_root;

        // Build weaver bitmap
        var weaver_bitmap: [32]u8 = [_]u8{0} ** 32;
        for (atts) |att| {
            if (att.validatorIndex < 256) {
                const byte_idx = att.validatorIndex / 8;
                const bit_idx: u3 = @intCast(att.validatorIndex % 8);
                weaver_bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
            }
        }

        // Aggregate BLS signatures
        var agg_sig = std.mem.zeroes(blst_c.blst_p2);
        var first = true;

        for (atts) |att| {
            var sig_affine = std.mem.zeroes(blst_c.blst_p2_affine);
            const res = blst_c.blst_p2_uncompress(&sig_affine, &att.blsSignature);
            if (res != blst_c.BLST_SUCCESS) continue;

            var sig_jac = std.mem.zeroes(blst_c.blst_p2);
            blst_c.blst_p2_from_affine(&sig_jac, &sig_affine);

            if (first) {
                agg_sig = sig_jac;
                first = false;
            } else {
                blst_c.blst_p2_add_or_double(&agg_sig, &agg_sig, &sig_jac);
            }
        }

        var agg_sig_bytes: [96]u8 = undefined;
        blst_c.blst_p2_compress(&agg_sig_bytes, &agg_sig);

        return types.ThreadCertificate{
            .slot = self.current_slot,
            .threadId = thread_id,
            .thread_root = thread_root,
            .aggregateSignature = agg_sig_bytes,
            .weaverBitmap = weaver_bitmap,
            .attestingStake = self.attested_stake[tid],
            .totalEligibleStake = self.eligible_stake[tid],
        };
    }

    /// Get a produced certificate for a thread.
    pub fn getCertificate(self: *const Self, thread_id: u8) ?types.ThreadCertificate {
        if (thread_id >= types.MAX_THREADS) return null;
        return self.certificates[thread_id];
    }

    /// Check if all required thread certificates are produced.
    pub fn hasAllCertificates(self: *const Self, thread_count: u8) bool {
        return self.certs_produced >= thread_count;
    }

    /// Get attestation count for a thread.
    pub fn getAttestationCount(self: *const Self, thread_id: u8) u32 {
        if (thread_id >= types.MAX_THREADS) return 0;
        return @intCast(self.attestations[thread_id].items.len);
    }

    /// Create a BLS signature for a thread attestation.
    pub fn createAttestationSignature(
        bls_priv_key: [32]u8,
        slot: u64,
        thread_id: u8,
        thread_root: core.types.Hash,
    ) [96]u8 {
        const msg = types.threadAttestationMessage(slot, thread_id, thread_root);

        var p2: blst_c.blst_p2 = undefined;
        blst_c.blst_hash_to_g2(&p2, &msg, msg.len, BLS_DST.ptr, BLS_DST.len, null, 0);

        var sk: blst_c.blst_scalar = undefined;
        blst_c.blst_scalar_from_bendian(&sk, &bls_priv_key);

        var sig: blst_c.blst_p2 = undefined;
        blst_c.blst_sign_pk_in_g1(&sig, &p2, &sk);

        var sig_bytes: [96]u8 = undefined;
        blst_c.blst_p2_compress(&sig_bytes, &sig);

        return sig_bytes;
    }

    /// Get statistics.
    pub const Stats = struct {
        current_slot: u64,
        certs_produced: u8,
        total_attestations_received: u64,
        total_attestations_rejected: u64,
        total_certs_produced: u64,
    };

    pub fn getStats(self: *const Self) Stats {
        return .{
            .current_slot = self.current_slot,
            .certs_produced = self.certs_produced,
            .total_attestations_received = self.total_attestations_received,
            .total_attestations_rejected = self.total_attestations_rejected,
            .total_certs_produced = self.total_certs_produced,
        };
    }
};
