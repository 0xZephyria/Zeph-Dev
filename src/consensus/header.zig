const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

/// Compute the woven root (Merkle root of thread roots).
pub fn computeWovenRoot(threadRoots: []const core.types.Hash) core.types.Hash {
    if (threadRoots.len == 0) return core.types.Hash.zero();
    if (threadRoots.len == 1) return threadRoots[0];
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("ZEPH_WOVEN_ROOT_V1");
    for (threadRoots) |root| {
        hasher.update(&root.bytes);
    }
    var result: core.types.Hash = undefined;
    hasher.final(&result.bytes);
    return result;
}

/// Verify a woven root against an array of thread roots.
pub fn verifyWovenRoot(wovenRoot: core.types.Hash, threadRoots: []const core.types.Hash) bool {
    const computed = computeWovenRoot(threadRoots);
    return std.mem.eql(u8, &computed.bytes, &wovenRoot.bytes);
}

/// Compute the deterministic thread root for a thread at a given slot/state.
pub fn computeThreadRoot(stateRoot: core.types.Hash, threadId: u8, txCount: u32) core.types.Hash {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("ZEPH_THREAD_ROOT_V1");
    hasher.update(&stateRoot.bytes);
    hasher.update(&[_]u8{threadId});
    var count_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_buf, txCount, .big);
    hasher.update(&count_buf);
    var result: core.types.Hash = undefined;
    hasher.final(&result.bytes);
    return result;
}

/// Build an AdaptiveBlockHeader for the current slot.
pub fn buildBlockHeader(
    slot: u64,
    epoch: u64,
    parentWovenRoot: core.types.Hash,
    proposerIndex: u32,
    proposerVrfProof: [96]u8,
    threadCount: u8,
    threadRoots: []const core.types.Hash,
    threadTxCounts: []const u32,
    stateRoot: core.types.Hash,
    totalTxCount: u32,
    randomnessSeed: [32]u8,
    tier: types.ConsensusTier,
) types.AdaptiveBlockHeader {
    var header = types.AdaptiveBlockHeader{
        .slot = slot,
        .epoch = epoch,
        .parentWovenRoot = parentWovenRoot,
        .proposerIndex = proposerIndex,
        .proposerVrfProof = proposerVrfProof,
        .threadCount = threadCount,
        .threadRoots = [_]core.types.Hash{core.types.Hash.zero()} ** types.MAX_THREADS,
        .threadTxCounts = [_]u32{0} ** types.MAX_THREADS,
        .wovenRoot = core.types.Hash.zero(),
        .stateRoot = stateRoot,
        .totalTxCount = totalTxCount,
        .randomnessSeed = randomnessSeed,
        .tier = tier,
    };
    const count = @min(threadRoots.len, @as(usize, threadCount));
    for (0..count) |i| {
        header.threadRoots[i] = threadRoots[i];
        if (i < threadTxCounts.len) {
            header.threadTxCounts[i] = threadTxCounts[i];
        }
    }
    header.wovenRoot = computeWovenRoot(threadRoots[0..count]);
    return header;
}

/// Verify an AdaptiveBlockHeader against expected values.
pub fn verifyBlockHeader(
    header: *const types.AdaptiveBlockHeader,
    parentWovenRoot: core.types.Hash,
    lastFinalizedSlot: u64,
    currentEpoch: u64,
    expectedThreadCount: u8,
    expectedTier: types.ConsensusTier,
) bool {
    if (header.slot <= lastFinalizedSlot) return false;
    if (header.epoch != currentEpoch) return false;
    if (!std.mem.eql(u8, &header.parentWovenRoot.bytes, &parentWovenRoot.bytes)) return false;
    if (header.threadCount != expectedThreadCount) return false;
    if (header.tier != expectedTier) return false;
    if (!verifyWovenRoot(header.wovenRoot, header.threadRoots[0..header.threadCount])) return false;
    return true;
}

/// Verify an attestation message format.
pub fn buildAttestationMessage(slot: u64, threadId: u8, threadRoot: core.types.Hash) [41]u8 {
    var msg: [41]u8 = undefined;
    @memcpy(msg[0..8], "ZEPH_ATST");
    std.mem.writeInt(u64, msg[8..16], slot, .big);
    msg[16] = threadId;
    @memcpy(msg[17..49], &threadRoot.bytes);
    return msg;
}
