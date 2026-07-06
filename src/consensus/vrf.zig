const std = @import("std");
const core = @import("core");
const blst_mod = core.crypto.blst;
const c = blst_mod.c;
const secureZero = @import("utils").secureZero;

const VRF_DST = "ZEPHYRIA_VRF_DST_V01";

pub const DOMAIN_PROPOSER = "ZEPHYRIA_SORTITION_PROPOSER_V01";
pub const DOMAIN_WEAVER = "ZEPHYRIA_SORTITION_WEAVER_V01";
const DOMAIN_ATTESTOR = "ZEPHYRIA_SORTITION_ATTESTOR_V01";
const DOMAIN_COMMITTEE = "ZEPHYRIA_SORTITION_COMMITTEE_V01";

pub const VRF = struct {
    /// Generate a BLS-based VRF proof: proof = sk * H_G2(input).
    /// Returns 96-byte compressed G2 point (verifiable with blst_core_verify_pk_in_g1).
    pub fn prove(sk_bytes: []const u8, input: []const u8) ![96]u8 {
        if (sk_bytes.len != 32) return error.InvalidSecretKeyLength;

        var sk: c.blst_scalar = undefined;
        defer secureZero(std.mem.asBytes(&sk));
        c.blst_scalar_from_bendian(&sk, sk_bytes.ptr);
        if (!c.blst_sk_check(&sk)) return error.InvalidSecretKey;

        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, input.ptr, @as(usize, input.len), VRF_DST.ptr, @as(usize, VRF_DST.len), null, 0);

        var res: c.blst_p2 = undefined;
        c.blst_sign_pk_in_g1(&res, &p2, &sk);

        var out_bytes: [96]u8 = undefined;
        c.blst_p2_compress(&out_bytes, &res);
        return out_bytes;
    }

    /// Verify a VRF proof: e(pk, H_G2(input)) == e(G1, proof).
    /// pk_bytes: 48-byte compressed G1 public key.
    /// proof: 96-byte compressed G2 VRF proof.
    /// input: the raw input to the VRF (caller handles domain separation).
    pub fn verify(pk_bytes: [48]u8, proof: [96]u8, input: []const u8) bool {
        var pk_affine: c.blst_p1_affine = undefined;
        if (c.blst_p1_uncompress(&pk_affine, &pk_bytes) != c.BLST_SUCCESS) return false;
        if (!c.blst_p1_affine_in_g1(&pk_affine)) return false;

        var sig_affine: c.blst_p2_affine = undefined;
        if (c.blst_p2_uncompress(&sig_affine, &proof) != c.BLST_SUCCESS) return false;
        if (!c.blst_p2_affine_in_g2(&sig_affine)) return false;

        return c.blst_core_verify_pk_in_g1(
            &pk_affine,
            &sig_affine,
            true,
            input.ptr,
            input.len,
            VRF_DST.ptr,
            VRF_DST.len,
            null,
            0,
        ) == c.BLST_SUCCESS;
    }

    /// Build a domain-separated VRF input: Blake3(domain ‖ seed ‖ slot [‖ extra]).
    pub fn buildSortitionInput(domain: []const u8, seed: [32]u8, slot: u64, extra: ?[]const u8) [32]u8 {
        var hasher = std.crypto.hash.Blake3.init(.{});
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

    fn hashProofToScalar(proof: [96]u8) u256 {
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&proof, &hash_buf, .{});
        return std.mem.readInt(u256, &hash_buf, .big);
    }

    fn isEligible(proof_scalar: u256, stake: u256, total_stake: u256, expected_count: u32) bool {
        if (total_stake == 0) return false;
        // When stake * expected_count >= total_stake, the proposer has a
        // guaranteed slot (limit >= max_u256, so every VRF hash qualifies).
        if (@as(u512, stake) * expected_count >= @as(u512, total_stake)) return true;

        const max = ~@as(u256, 0);
        // Avoid expensive u512 division. Instead, cross-multiply:
        //   proof < max * stake * expected / total  ⟺  proof * total < max * stake * expected
        // With the guard above, stake * expected < total, so:
        //   max * (stake * expected) < max * total ≤ nextU256(total) → fits in u512
        // And proof * total < max * total < 2^512, also fits in u512.
        // Use u640 to be safe and avoid ordering sensitivity of intermediate products.
        const left = @as(u640, proof_scalar) * @as(u640, total_stake);
        const right = @as(u640, max) * @as(u640, stake) * @as(u640, expected_count);
        return left < right;
    }

    pub fn sortition_proposer(
        sk_bytes: [32]u8,
        seed: [32]u8,
        slot: u64,
        stake: u256,
        total_stake: u256,
        expected_proposers: u32,
    ) !struct { eligible: bool, proof: [96]u8, vrf_hash: [32]u8 } {
        const input = buildSortitionInput(DOMAIN_PROPOSER, seed, slot, null);
        const proof = try prove(&sk_bytes, &input);
        var vrf_hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&proof, &vrf_hash, .{});
        const scalar = std.mem.readInt(u256, &vrf_hash, .big);
        const eligible = isEligible(scalar, stake, total_stake, expected_proposers);
        return .{ .eligible = eligible, .proof = proof, .vrf_hash = vrf_hash };
    }

    pub fn sortition_weaver(
        sk_bytes: [32]u8,
        seed: [32]u8,
        slot: u64,
        thread_id: u8,
        stake: u256,
        total_stake: u256,
        expected_weavers: u32,
    ) !struct { eligible: bool, proof: [96]u8 } {
        const extra = [_]u8{thread_id};
        const input = buildSortitionInput(DOMAIN_WEAVER, seed, slot, &extra);
        const proof = try prove(&sk_bytes, &input);
        const scalar = hashProofToScalar(proof);
        const eligible = isEligible(scalar, stake, total_stake, expected_weavers);
        return .{ .eligible = eligible, .proof = proof };
    }

    pub fn sortition_attestor(
        sk_bytes: [32]u8,
        seed: [32]u8,
        slot: u64,
        stake: u256,
        total_stake: u256,
        expected_attestors: u32,
    ) !struct { eligible: bool, proof: [96]u8 } {
        const input = buildSortitionInput(DOMAIN_ATTESTOR, seed, slot, null);
        const proof = try prove(&sk_bytes, &input);
        const scalar = hashProofToScalar(proof);
        const eligible = isEligible(scalar, stake, total_stake, expected_attestors);
        return .{ .eligible = eligible, .proof = proof };
    }

    /// Check if a VRF proof meets the stake-weighted proposer threshold.
    /// Called during verify() to confirm the proposer was eligible for the slot.
    pub fn checkProposerEligibility(
        proof: [96]u8,
        stake: u256,
        total_stake: u256,
        expected_proposers: u32,
    ) bool {
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&proof, &hash_buf, .{});
        const scalar = std.mem.readInt(u256, &hash_buf, .big);
        return isEligible(scalar, stake, total_stake, expected_proposers);
    }

    pub fn committee_seed(epoch_seed: [32]u8, epoch: u64) [32]u8 {
        return buildSortitionInput(DOMAIN_COMMITTEE, epoch_seed, epoch, null);
    }
};


