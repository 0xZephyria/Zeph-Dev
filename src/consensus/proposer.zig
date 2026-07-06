const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const slot_mod = @import("slot.zig");
const vrf_mod = @import("vrf.zig");

/// Stateless proposer selection at all tiers.
/// Tier 1: deterministic Blake3(seed ‖ slot) % validatorCount
/// Tier 2-3: VRF sortition with schedule lookup fallback

/// Deterministic proposer index for a slot (pure function).
/// Used at Tier 1, and as fallback at Tier 2-3 when schedule is empty.
pub fn deterministicProposer(epochSeed: [32]u8, slot: u64, validatorCount: u32) u32 {
    return slot_mod.deterministicProposer(epochSeed, slot, validatorCount);
}

/// Check if the given validator index is the proposer for a slot.
/// Tier 1: uses deterministic proposer directly.
/// Tier 2-3: checks the pre-computed proposer schedule first, falls back to deterministic.
pub fn isProposerForSlot(
    slot: u64,
    ourIndex: u32,
    tier: types.ConsensusTier,
    proposerSchedule: *const std.AutoHashMap(u64, types.ProposerScheduleEntry),
    epochSeed: [32]u8,
    validatorCount: u32,
) bool {
    switch (tier) {
        .FullBFT => {
            return deterministicProposer(epochSeed, slot, validatorCount) == ourIndex;
        },
        .CommitteeLoom, .FullLoom => {
            if (proposerSchedule.get(slot)) |entry| {
                return entry.primaryProposer == ourIndex;
            }
            return deterministicProposer(epochSeed, slot, validatorCount) == ourIndex;
        },
    }
}

/// Get the expected proposer index for a slot.
pub fn getExpectedProposer(
    slot: u64,
    proposerSchedule: *const std.AutoHashMap(u64, types.ProposerScheduleEntry),
    epochSeed: [32]u8,
    validatorCount: u32,
) u32 {
    if (proposerSchedule.get(slot)) |entry| {
        return entry.primaryProposer;
    }
    return deterministicProposer(epochSeed, slot, validatorCount);
}

/// Check if a given address is the eligible proposer for a slot.
/// Used by Gulf Stream as Firewall 1 before forwarding TXs.
pub fn isEligibleProposer(
    slot: u64,
    address: core.types.Address,
    validators: []const types.ValidatorInfo,
    proposerSchedule: *const std.AutoHashMap(u64, types.ProposerScheduleEntry),
    epochSeed: [32]u8,
) bool {
    const proposerIdx = getExpectedProposer(slot, proposerSchedule, epochSeed, @intCast(validators.len));
    if (proposerIdx >= validators.len) return false;
    return std.mem.eql(u8, &validators[proposerIdx].address.bytes, &address.bytes);
}

/// Compute VRF sortition for proposer eligibility (Tier 2-3).
pub fn computeProposerVrf(
    epochSeed: [32]u8,
    slot: u64,
    skBytes: [32]u8,
    myStake: u256,
    totalStake: u256,
) !?struct { proposer_index: u32, proof: [96]u8, vrf_hash: [32]u8 } {
    const result = try vrf_mod.VRF.sortition_proposer(
        skBytes,
        epochSeed,
        slot,
        myStake,
        totalStake,
        types.EXPECTED_PROPOSERS,
    );
    if (result.eligible) {
        return .{
            .proposer_index = 0,
            .proof = result.proof,
            .vrf_hash = result.vrf_hash,
        };
    }
    return null;
}
