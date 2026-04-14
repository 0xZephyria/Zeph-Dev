// ============================================================================
// Zephyria — VRF Sortition (Loom Genesis)
// ============================================================================
//
// BLS-based Verifiable Random Function for consensus role selection:
//   • Proposer sortition (all tiers)
//   • Weaver sortition (Tier 3 — per-thread)
//   • Attestor sortition (Tier 3)
//   • Committee seed (Tier 2 — epoch-level)
//
// Domain separation ensures the same validator key produces independent
// random outputs for each role, preventing correlation attacks.

const std = @import("std");
const core = @import("core");
const blst_mod = core.crypto.blst;
const c = blst_mod.c;

const VRF_DST = "FORGEYRIA_VRF_DST_V01";

// Domain separators for role-specific sortition
const DOMAIN_PROPOSER = "FORGEYRIA_SORTITION_PROPOSER_V01";
const DOMAIN_WEAVER = "FORGEYRIA_SORTITION_WEAVER_V01";
const DOMAIN_ATTESTOR = "FORGEYRIA_SORTITION_ATTESTOR_V01";
const DOMAIN_COMMITTEE = "FORGEYRIA_SORTITION_COMMITTEE_V01";

pub const VRF = struct {
    /// Generate a VRF proof: output = sk * H(input)
    /// Returns 48-byte compressed G1 point.
    pub fn prove(sk_bytes: []const u8, input: []const u8) ![48]u8 {
        if (sk_bytes.len != 32) return error.InvalidSecretKeyLength;

        // 1. Hash to G1
        var p1: c.blst_p1 = undefined;
        c.blst_hash_to_g1(&p1, input.ptr, @as(usize, input.len), VRF_DST.ptr, @as(usize, VRF_DST.len), null, 0);

        // 2. Deserialize scalar (SK)
        var sk: c.blst_scalar = undefined;
        c.blst_scalar_from_bendian(&sk, sk_bytes.ptr);

        // 3. Scalar multiplication: res = p1 * sk
        var res: c.blst_p1 = undefined;
        c.blst_p1_mult(&res, &p1, @ptrCast(&sk), 256);

        // 4. Compress to 48 bytes
        var out_bytes: [48]u8 = undefined;
        c.blst_p1_compress(&out_bytes, &res);

        return out_bytes;
    }

    /// Check eligibility for a role based on VRF output and stake proportion.
    /// Returns (is_eligible, vrf_proof).
    pub fn check_eligibility(sk_bytes: []const u8, seed: []const u8, slot: u64, stake: u256, total_stake: u256) !struct { bool, [48]u8 } {
        var input_buf: [40]u8 = undefined;
        if (seed.len != 32) return error.InvalidSeedLength;

        @memcpy(input_buf[0..32], seed);
        std.mem.writeInt(u64, input_buf[32..40], slot, .big);

        const proof = try prove(sk_bytes, &input_buf);

        // Hash proof to scalar for threshold comparison
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&proof, &hash_buf, .{});
        const val_u256 = std.mem.readInt(u256, &hash_buf, .big);

        // limit = (2^256 - 1) * stake / total_stake
        const max = ~@as(u256, 0);
        const stake_ext = @as(u512, stake);
        const max_ext = @as(u512, max);
        const num = max_ext * stake_ext;
        const limit = @as(u256, @truncate(num / @as(u512, total_stake)));

        return .{ val_u256 < limit, proof };
    }

    // ── Domain-Separated Sortition Functions ─────────────────────────

    /// Build a domain-separated VRF input: Keccak256(domain ‖ seed ‖ slot [‖ extra])
    fn buildSortitionInput(domain: []const u8, seed: [32]u8, slot: u64, extra: ?[]const u8) [32]u8 {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(domain);
        hasher.update(&seed);
        var buf8: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf8, slot, .big);
        hasher.update(&buf8);
        if (extra) |e| {
            hasher.update(e);
        }
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Hash a VRF proof to a u256 for threshold comparison.
    fn proofToScalar(proof: [48]u8) u256 {
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&proof, &hash_buf, .{});
        return std.mem.readInt(u256, &hash_buf, .big);
    }

    /// Check if a VRF proof value falls below a stake-weighted threshold.
    /// expected_count: how many validators we expect to be selected (Poisson parameter)
    fn isEligible(proof_scalar: u256, stake: u64, total_stake: u64, expected_count: u32) bool {
        if (total_stake == 0) return false;
        // threshold = (2^256 - 1) * (stake / total_stake) * expected_count
        // Using u512 to avoid overflow
        const max = ~@as(u256, 0);
        const num = @as(u512, max) * @as(u512, stake) * @as(u512, expected_count);
        const limit = @as(u256, @truncate(num / @as(u512, total_stake)));
        return proof_scalar < limit;
    }

    // ── Proposer Sortition ──────────────────────────────────────────

    /// Check if this validator is eligible to propose for the given slot.
    /// Used across all tiers. Expected ~3 candidates, lowest VRF hash wins.
    pub fn sortition_proposer(
        sk_bytes: [32]u8,
        seed: [32]u8,
        slot: u64,
        stake: u64,
        total_stake: u64,
        expected_proposers: u32,
    ) !struct { eligible: bool, proof: [48]u8, vrf_hash: [32]u8 } {
        const input = buildSortitionInput(DOMAIN_PROPOSER, seed, slot, null);
        const proof = try prove(&sk_bytes, &input);
        var vrf_hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&proof, &vrf_hash, .{});
        const scalar = std.mem.readInt(u256, &vrf_hash, .big);
        const eligible = isEligible(scalar, stake, total_stake, expected_proposers);
        return .{ .eligible = eligible, .proof = proof, .vrf_hash = vrf_hash };
    }

    // ── Weaver Sortition (Tier 3) ───────────────────────────────────

    /// Check if this validator is selected as a weaver for a specific thread.
    /// Each thread has ~100 expected weavers selected independently.
    pub fn sortition_weaver(
        sk_bytes: [32]u8,
        seed: [32]u8,
        slot: u64,
        thread_id: u8,
        stake: u64,
        total_stake: u64,
        expected_weavers: u32,
    ) !struct { eligible: bool, proof: [48]u8 } {
        const extra = [_]u8{thread_id};
        const input = buildSortitionInput(DOMAIN_WEAVER, seed, slot, &extra);
        const proof = try prove(&sk_bytes, &input);
        const scalar = proofToScalar(proof);
        const eligible = isEligible(scalar, stake, total_stake, expected_weavers);
        return .{ .eligible = eligible, .proof = proof };
    }

    // ── Attestor Sortition (Tier 3) ─────────────────────────────────

    /// Check if this validator is selected as an attestor for Snowball voting.
    /// ~1000 expected attestors per slot.
    pub fn sortition_attestor(
        sk_bytes: [32]u8,
        seed: [32]u8,
        slot: u64,
        stake: u64,
        total_stake: u64,
        expected_attestors: u32,
    ) !struct { eligible: bool, proof: [48]u8 } {
        const input = buildSortitionInput(DOMAIN_ATTESTOR, seed, slot, null);
        const proof = try prove(&sk_bytes, &input);
        const scalar = proofToScalar(proof);
        const eligible = isEligible(scalar, stake, total_stake, expected_attestors);
        return .{ .eligible = eligible, .proof = proof };
    }

    // ── Committee Seed (Tier 2) ─────────────────────────────────────

    /// Compute the deterministic committee shuffle seed for an epoch.
    /// All validators compute this independently and get the same result.
    pub fn committee_seed(epoch_seed: [32]u8, epoch: u64) [32]u8 {
        const input = buildSortitionInput(DOMAIN_COMMITTEE, epoch_seed, epoch, null);
        return input;
    }
};
