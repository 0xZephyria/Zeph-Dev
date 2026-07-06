const log = @import("core").logger;
const std = @import("std");
pub const types = @import("types.zig");
pub const vrf = @import("vrf.zig");
pub const zelius = @import("zelius.zig");
pub const vote = @import("vote.zig");
pub const staking = @import("staking.zig");
pub const pipeline = @import("pipeline.zig");

// Loom Genesis Adaptive Consensus modules
pub const adaptive = @import("adaptive.zig");
pub const committees = @import("committees.zig");
pub const snowball = @import("snowball.zig");
pub const thread_pool = @import("thread_pool.zig");

// Extracted shared modules (single interface)
pub const keys = @import("keys.zig");
pub const validators = @import("validators.zig");
pub const header = @import("header.zig");
pub const slashing = @import("slashing.zig");
pub const slot = @import("slot.zig");
pub const epoch = @import("epoch.zig");
pub const proposer = @import("proposer.zig");
pub const quorum = @import("quorum.zig");
pub const replay = @import("replay.zig");

// Re-export specific structs for easier access
pub const ValidatorInfo = types.ValidatorInfo;
pub const VRF = vrf.VRF;
pub const ZeliusEngine = zelius.ZeliusEngine;
pub const VoteCollector = vote.VoteCollector;
pub const Pipeline = pipeline.Pipeline;
pub const Staking = staking.Staking;

// Loom Genesis re-exports
pub const AdaptiveConsensus = adaptive.AdaptiveConsensus;
pub const CommitteeManager = committees.CommitteeManager;
pub const Snowball = snowball.Snowball;
pub const ThreadAttestationPool = thread_pool.ThreadAttestationPool;
pub const ConsensusTier = types.ConsensusTier;
pub const AdaptiveBlockHeader = types.AdaptiveBlockHeader;
pub const ThreadCertificate = types.ThreadCertificate;
pub const ThreadAttestation = types.ThreadAttestation;
pub const WovenQuorumCertificate = types.WovenQuorumCertificate;
pub const EpochState = types.EpochState;
pub const ThreadTimeoutProof = types.ThreadTimeoutProof;
pub const SnowballQCProof = types.SnowballQCProof;
pub const SnowballQuorumCertificate = types.SnowballQuorumCertificate;
pub const QuorumCertificate = types.QuorumCertificate;

// Extracted re-exports
pub const deriveBlsPubKey = keys.deriveBlsPubKey;
pub const verifyBlsSignature = keys.verifyBlsSignature;
pub const aggregateBlsSignatures = keys.aggregateBlsSignatures;
pub const SlashEvent = slashing.SlashEvent;
pub const SlashReason = slashing.SlashReason;
pub const SlashingDetector = slashing.SlashingDetector;

// Security types re-exported (legacy — use slashing.SlashEvent going forward)
pub const SlashEventLegacy = zelius.SlashEvent;
pub const SlashReasonLegacy = zelius.SlashReason;
pub const EpochConfig = zelius.EpochConfig;

pub fn init() void {
    log.debug("Consensus module initialized with VRF/Zelius (Loom Genesis Adaptive)\n", .{});
}
