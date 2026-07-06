const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const quorum_mod = @import("quorum.zig");
const vrf_mod = @import("vrf.zig");
const proposer_mod = @import("proposer.zig");

const blst_mod = core.crypto.blst;
const c = blst_mod.c;

const BLS_DST = "ZEPHYRIA_BLS_DST_V01";
const VRF_OFFSET: usize = 0;
const BLS_OFFSET: usize = 96;
const MIN_EXTRA_SIZE: usize = 192;

/// Context needed for block verification.
pub const VerifyContext = struct {
    epochSeed: [32]u8,
    totalActiveStake: u256,
    tier: types.ConsensusTier,
    proposerSchedule: *const std.AutoHashMap(u64, types.ProposerScheduleEntry),
    activeValidators: []const types.ValidatorInfo,
    validatorIndexByAddr: *const std.AutoHashMap(core.types.Address, usize),
    doubleSignChecker: *const DoubleSignChecker,
};

/// Callback for double-sign detection during verification.
/// Returns `true` if double-signing was detected (block should be rejected).
pub const DoubleSignChecker = struct {
    ptr: *anyopaque,
    checkFn: *const fn (ctx: *anyopaque, blockNumber: u64, blkId: core.types.Hash, proposer: core.types.Address) anyerror!bool,

    pub fn check(self: *const DoubleSignChecker, blockNumber: u64, blkId: core.types.Hash, proposer: core.types.Address) !bool {
        return self.checkFn(self.ptr, blockNumber, blkId, proposer);
    }
};

/// 9-step block verification. Returns `void` on success, or an error on any failure.
///
/// Steps:
///   1. ExtraData length check
///   2. BLS signature verification (producer signed block.id())
///   3. VRF proof verification (proposer sortition)
///   4. Proposer eligibility (stake-weighted threshold)
///   5. Double-signing detection
///   6. Timestamp monotonicity
///   7. Block number monotonicity
///   8. Parent hash linkage
///   9. QC verification (if present)
pub fn verify(block: *core.types.Block, parent: *core.types.Header, ctx: VerifyContext) !void {
    // 1. ExtraData length — enforce exact 192 bytes (VRF proof + BLS signature)
    if (block.header.extraData.len != MIN_EXTRA_SIZE) return error.InvalidExtraData;

    // 2. Verify BLS signature (producer signed block.id() — extraData excluded)
    const sigBytes = block.header.extraData[BLS_OFFSET..][0..96];
    const proposerIdx = ctx.validatorIndexByAddr.get(block.header.producer) orelse return error.ValidatorNotFound;
    const pkBytes = ctx.activeValidators[proposerIdx].blsPubKey;

    const blkId = block.id();

    {
        var p2: c.blst_p2 = undefined;
        c.blst_hash_to_g2(&p2, &blkId.bytes, blkId.bytes.len, BLS_DST.ptr, BLS_DST.len, null, 0);
        var msgAffine: c.blst_p2_affine = undefined;
        c.blst_p2_to_affine(&msgAffine, &p2);

        var sigAffine: c.blst_p2_affine = undefined;
        if (c.blst_p2_uncompress(&sigAffine, sigBytes.ptr) != c.BLST_SUCCESS) return error.InvalidSignature;
        if (!c.blst_p2_affine_in_g2(&sigAffine)) return error.InvalidSignature;

        var pkAffine: c.blst_p1_affine = undefined;
        if (c.blst_p1_uncompress(&pkAffine, &pkBytes) != c.BLST_SUCCESS) return error.InvalidPublicKey;
        if (!c.blst_p1_affine_in_g1(&pkAffine)) return error.InvalidPublicKey;

        if (c.blst_core_verify_pk_in_g1(
            &pkAffine,
            &sigAffine,
            true,
            &blkId.bytes,
            blkId.bytes.len,
            BLS_DST.ptr,
            BLS_DST.len,
            null,
            0,
        ) != c.BLST_SUCCESS) {
            return error.InvalidSignature;
        }
    }

    // 3. Verify VRF proof (proposer sortition)
    const vrfProofBytes = block.header.extraData[VRF_OFFSET..][0..96];
    {
        const vrfInput = vrf_mod.VRF.buildSortitionInput(
            vrf_mod.DOMAIN_PROPOSER,
            ctx.epochSeed,
            block.header.number,
            null,
        );
        if (!vrf_mod.VRF.verify(pkBytes, vrfProofBytes.*, &vrfInput)) {
            return error.InvalidVRF;
        }
    }

    // 4. Proposer eligibility — stake-weighted threshold
    const proposerStake = ctx.activeValidators[proposerIdx].stake;
    if (proposerStake == 0) return error.ZeroStakeProposer;

    if (ctx.tier == .FullBFT) {
        const expectedProposerIdx = proposer_mod.deterministicProposer(
            ctx.epochSeed,
            block.header.number,
            @intCast(ctx.activeValidators.len),
        );
        if (proposerIdx != expectedProposerIdx) return error.ProposerNotEligible;
    } else {
        if (!vrf_mod.VRF.checkProposerEligibility(
            vrfProofBytes.*,
            proposerStake,
            ctx.totalActiveStake,
            types.EXPECTED_PROPOSERS,
        )) return error.ProposerNotEligible;
    }

    // 5. Double-signing check
    if (try ctx.doubleSignChecker.check(block.header.number, blkId, block.header.producer)) {
        return error.DoubleSigningDetected;
    }

    // 6. Timestamp sanity
    if (block.header.time <= parent.time) return error.TimestampTooOld;

    // 7. Block number monotonicity
    if (block.header.number != parent.number + 1) return error.InvalidBlockNumber;

    // 8. Parent hash linkage
    const parentId = core.types.Block.blockId(parent);
    if (!std.mem.eql(u8, &block.header.parentId.bytes, &parentId.bytes)) {
        return error.InvalidParentHash;
    }

    // 9. Validate QuorumCertificate if present
    if (block.header.quorumCertificate) |qc| {
        try quorum_mod.verifyQCAggregate(
            ctx.activeValidators,
            ctx.totalActiveStake,
            &blkId,
            qc.aggregateSignature,
            &qc.voterBitmap,
        );
    }
}
