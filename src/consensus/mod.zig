const log = @import("core").logger;
const std = @import("std");
pub const types = @import("types.zig");
pub const registry = @import("registry.zig");
pub const vdf = @import("vdf.zig");
pub const vrf = @import("vrf.zig");
pub const zelius = @import("zelius.zig");
pub const votepool = @import("votepool.zig");
pub const staking = @import("staking.zig");
pub const pipeline = @import("pipeline.zig");
pub const fraud_proof = @import("fraud_proof.zig");
pub const deferred_executor = @import("deferred_executor.zig");

// Loom Genesis Adaptive Consensus modules
pub const adaptive = @import("adaptive.zig");
pub const committees = @import("committees.zig");
pub const snowball = @import("snowball.zig");
pub const thread_pool = @import("thread_pool.zig");

// Re-export specific structs for easier access
pub const ValidatorInfo = types.ValidatorInfo;
pub const ValidatorRegistry = registry.ValidatorRegistry;
pub const VDF = vdf.VDF;
pub const VRF = vrf.VRF;
pub const ZeliusEngine = zelius.ZeliusEngine;
pub const VotePool = votepool.VotePool;
pub const Pipeline = pipeline.Pipeline;
pub const Staking = staking.Staking;
pub const FraudProofManager = fraud_proof.FraudProofManager;
pub const DeferredExecutor = deferred_executor.DeferredExecutor;

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

// Security types re-exported
pub const SlashEvent = zelius.SlashEvent;
pub const SlashReason = zelius.SlashReason;
pub const EpochConfig = zelius.EpochConfig;

pub fn init() void {
    log.debug("Consensus module initialized with VDF/VRF/Zelius (Loom Genesis Adaptive)\n", .{});
}
