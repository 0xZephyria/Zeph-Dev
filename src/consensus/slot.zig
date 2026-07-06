const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

/// Compute the consensus tier for a given validator count.
pub fn computeTier(validatorCount: u32) types.ConsensusTier {
    if (validatorCount <= types.TIER2_THRESHOLD) return .FullBFT;
    if (validatorCount <= types.TIER3_THRESHOLD) return .CommitteeLoom;
    return .FullLoom;
}

/// Compute the adaptive thread count for a given validator count.
pub fn computeThreadCount(validatorCount: u32) u8 {
    if (validatorCount <= 30) return 1;
    if (validatorCount <= 100) return 2;
    if (validatorCount <= 200) return 3;
    if (validatorCount <= 500) return 5;
    if (validatorCount <= 1000) return 8;
    if (validatorCount <= 2000) return 10;
    const computed = validatorCount / 200;
    return @intCast(@min(computed, types.MAX_THREADS));
}

/// Deterministic proposer index for a slot (pure function).
pub fn deterministicProposer(epochSeed: [32]u8, slot: u64, validatorCount: u32) u32 {
    if (validatorCount == 0) return 0;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(&epochSeed);
    var buf8: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf8, slot, .big);
    hasher.update(&buf8);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    const val = std.mem.readInt(u32, hash[0..4], .big);
    return val % validatorCount;
}

/// Get the epoch number for a slot.
pub fn epochForSlot(slot: u64, slotsPerEpoch: u64) u64 {
    return slot / slotsPerEpoch;
}

/// Check if a slot is at an epoch boundary.
pub fn isEpochBoundary(slot: u64, slotsPerEpoch: u64) bool {
    if (slotsPerEpoch == 0) return false;
    return (slot % slotsPerEpoch) == 0;
}
