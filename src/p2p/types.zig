// ============================================================================
// Zephyria — P2P Network Message Types & Protocol Constants
// ============================================================================
//
// Production-grade message definitions for committee-based consensus,
// Turbine block propagation, subnet-based gossip, and Gulf Stream
// transaction forwarding.

const std = @import("std");
const core = @import("core");

// ── Protocol Version ────────────────────────────────────────────────────

pub const PROTOCOL_VERSION: u32 = 2;
pub const CHAIN_NAME = "zephyria";

// ── Message Codes ───────────────────────────────────────────────────────

pub const MsgStatus: u64 = 0x00;
pub const MsgNewBlock: u64 = 0x01;
pub const MsgGetBlocks: u64 = 0x02;
pub const MsgBlocks: u64 = 0x03;
pub const MsgTxBatch: u64 = 0x04;
pub const MsgVote: u64 = 0x05;
pub const MsgGetHeaders: u64 = 0x06;
pub const MsgHeaders: u64 = 0x07;
pub const MsgGetBodies: u64 = 0x08;
pub const MsgBodies: u64 = 0x09;
pub const MsgAuth: u64 = 0x0A;
pub const MsgSlashEvidence: u64 = 0x0B;
pub const MsgGetPeers: u64 = 0x0C;
pub const MsgPeers: u64 = 0x0D;
pub const MsgGetNodeData: u64 = 0x0E;
pub const MsgNodeData: u64 = 0x0F;

// Committee & Consensus Messages
pub const MsgShred: u64 = 0x10;
pub const MsgAttestation: u64 = 0x11;
pub const MsgAggregateAttestation: u64 = 0x12;
pub const MsgQuorumCertificate: u64 = 0x13;
pub const MsgViewChange: u64 = 0x14;
pub const MsgViewChangeQC: u64 = 0x15;
pub const MsgCommitteeHandshake: u64 = 0x16;
pub const MsgSubnetSubscribe: u64 = 0x17;
pub const MsgSubnetUnsubscribe: u64 = 0x18;
pub const MsgPing: u64 = 0x19;
pub const MsgPong: u64 = 0x1A;
pub const MsgShredRepairRequest: u64 = 0x1B;

// Loom Genesis Adaptive Consensus Messages
pub const MsgThreadAttestation: u64 = 0x20;
pub const MsgThreadCertificate: u64 = 0x21;
pub const MsgAdaptiveQC: u64 = 0x22;
pub const MsgSnowballQuery: u64 = 0x23;
pub const MsgSnowballResponse: u64 = 0x24;
pub const MsgEpochTransition: u64 = 0x25;
pub const MsgThreadTimeoutProof: u64 = 0x26;

// ── Network Constants ───────────────────────────────────────────────────

pub const MAX_CONNECTIONS: u32 = 512;
pub const COMMITTEE_SIZE: u32 = 256;
pub const GOSSIP_SUBNETS: u32 = 128; // One subnet per thread (matches consensus.MAX_THREADS)
pub const SUBNETS_PER_VALIDATOR: u32 = 1; // Each validator subscribes to their thread's subnet
pub const PEERS_PER_SUBNET: u32 = 8;
pub const TURBINE_FANOUT: u32 = 32;
pub const MAX_SHRED_SIZE: u32 = 262144; // IPv4 Max UDP payload - headers
pub const EPOCH_BLOCKS: u64 = 2048;
pub const SLOT_DURATION_MS: u64 = 1000;
pub const VIEW_CHANGE_TIMEOUT_MS: u64 = 4000;
pub const VIEW_CHANGE_MAX_TIMEOUT_MS: u64 = 60000;
pub const PEER_SCORE_DISCONNECT_THRESHOLD: i32 = -100;
pub const PEER_SCORE_MAX: i32 = 200;
pub const PEER_SCORE_DECAY_INTERVAL_MS: u64 = 60_000;
pub const PEER_SCORE_DECAY_AMOUNT: i32 = 1;
pub const STALE_PEER_TIMEOUT_S: i64 = 300;
pub const MAX_BATCH_SIZE: u32 = 4096;

// ── Subnet & Committee Types ────────────────────────────────────────────

pub const SubnetID = u8; // 0..127 for thread-topology subnets

pub const PeerRole = enum(u8) {
    Validator = 0,
    RPCRelay = 1,
    LightNode = 2,
    FullNode = 3,
};

pub const CommitteeRole = enum(u8) {
    None = 0,
    BlockProducer = 1,
    Attestor = 2,
    Aggregator = 3,
};

pub const CommitteeAssignment = struct {
    epoch: u64,
    slotStart: u64,
    slotEnd: u64,
    committeeIndex: u32,
    role: CommitteeRole,
    threadId: u8,
};

// ── Rate Limiting ───────────────────────────────────────────────────────

pub const RateLimitConfig = struct {
    /// Base burst capacity for unstaked peers
    baseCapacity: f64 = 20.0,
    /// Base refill rate (tokens per second) for unstaked peers
    baseRefill: f64 = 10.0,
    /// Multiplier for committee members during their active slot
    committeeBurstMultiplier: f64 = 10.0,
    /// Stake scaling: refill_rate = base_refill * sqrt(stake / min_stake)
    /// Capped at 100x base_refill
    maxStakeMultiplier: f64 = 100.0,
};

// ── Message Structures ──────────────────────────────────────────────────

pub const StatusMsg = struct {
    protocolVersion: u32,
    chainId: u64,
    genesisHash: core.types.Hash,
    headHash: core.types.Hash,
    headNumber: u64,
    challenge: [32]u8,
    peerRole: PeerRole,
    stakeAmount: u64,
    subscribedSubnets: [16]u8, // Bitmap: 128 subnets packed into 16 bytes
};

pub const NewBlockMsg = struct {
    block: core.types.Block,
    totalDifficulty: u256,
    hopCount: u32,
};

pub const GetBlocksMsg = struct {
    startHash: core.types.Hash,
    limit: u64,
    direction: u8,
};

pub const BlocksMsg = struct {
    blocks: []core.types.Block,
};

pub const TxBatchMsg = struct {
    txHashes: []core.types.Hash,
    txData: [][]const u8,
    compressed: bool,
    batchId: u64,
    senderSubnet: SubnetID,
};

pub const VoteMsg = struct {
    blockId: core.types.Hash,
    blockNumber: u64,
    view: u64,
    signature: [96]u8,
    validatorIndex: u32,
};

pub const AuthMsg = struct {
    signature: [64]u8,
    publicKey: [32]u8,   // Ed25519 public key (32 bytes)
    validatorAddress: core.types.Address,
    stakeProof: [32]u8,
};

pub const SlashEvidenceMsg = struct {
    validator: core.types.Address,
    blockNumber: u64,
    reason: SlashReason,
    evidenceHash1: core.types.Hash,
    evidenceHash2: core.types.Hash,
    reporterSignature: [96]u8,
};

pub const SlashReason = enum(u8) {
    DoubleSigning = 0,
    DoubleAttestation = 1,
    InvalidBlock = 2,
};

pub const PeersMsg = struct {
    nodes: []NodeInfo,
};

pub const GetPeersMsg = struct {
    version: u32,
};

pub const NodeInfo = struct {
    id: [64]u8,
    ip: [16]u8,
    ipLen: u8,
    port: u16,
    peerRole: PeerRole,
    subnets: [16]u8,
};

pub const GetNodeDataMsg = struct {
    requestId: u64,
    hashes: []core.types.Hash,
};

pub const NodeDataMsg = struct {
    requestId: u64,
    data: [][]const u8,
};

pub const PingMsg = struct {
    sequence: u64,
    timestamp: i64,
};

pub const PongMsg = struct {
    sequence: u64,
    timestamp: i64,
};

// ── Shred Types (Turbine) ───────────────────────────────────────────────

pub const ShredType = enum(u8) {
    Data = 0,
    Parity = 1,
};

pub const ShredMsg = struct {
    /// Canonical block id — allows receiver to authenticate which block this shred belongs to
    blockId: core.types.Hash,
    blockNumber: u64,
    shredIndex: u32,
    totalDataShreds: u32,
    totalParityShreds: u32,
    shredType: ShredType,
    payload: []const u8,
    /// Block-level BLS signature — same on every shred for a given block.
    /// Verified after block reconstruction by consensus verify().
    producerSignature: [96]u8,
    /// Thread ID (Loom Genesis: which thread this shred belongs to)
    threadId: u8,
};

pub const ShredRepairRequestMsg = struct {
    blockNumber: u64,
    shredIndices: []const u32,
    requesterAddress: core.types.Address,
};

// ── Attestation Types ───────────────────────────────────────────────────

pub const AttestationMsg = struct {
    blockHash: core.types.Hash,
    blockNumber: u64,
    slot: u64,
    validatorIndex: u32,
    committeeIndex: u32,
    signature: [96]u8,
    subnetId: SubnetID,
};

pub const AggregateAttestationMsg = struct {
    blockHash: core.types.Hash,
    blockNumber: u64,
    slot: u64,
    subnetId: SubnetID,
    participationBitmap: [32]u8,
    aggregateSignature: [96]u8,
    aggregatorIndex: u32,
    aggregatorProof: [96]u8,
};

pub const QuorumCertificate = struct {
    blockHash: core.types.Hash,
    blockNumber: u64,
    slot: u64,
    epoch: u64,
    aggregateSignature: [96]u8,
    participationBitmap: [32]u8,
    proposerVrfProof: [96]u8,
};

pub const ViewChangeMsg = struct {
    slot: u64,
    view: u64,
    highestQc: ?QuorumCertificate,
    validatorIndex: u32,
    signature: [96]u8,
};

pub const ViewChangeQCMsg = struct {
    slot: u64,
    newView: u64,
    participationBitmap: [32]u8,
    aggregateSignature: [96]u8,
    bestQc: QuorumCertificate,
};

pub const CommitteeHandshakeMsg = struct {
    epoch: u64,
    committeeIndex: u32,
    validatorIndex: u32,
    validatorAddress: core.types.Address,
    role: CommitteeRole,
    blsPubkey: [48]u8,
    signature: [96]u8,
};

pub const SubnetSubscribeMsg = struct {
    subnetId: SubnetID,
    validatorAddress: core.types.Address,
    epoch: u64,
    signature: [96]u8,
};

// ── Utility Functions ───────────────────────────────────────────────────

/// Check if a subnet bit is set in a 128-subnet bitmap (16 bytes)
pub fn isSubnetSubscribed(bitmap: [16]u8, subnet: SubnetID) bool {
    if (subnet >= 128) return false;
    const byte_idx = subnet / 8;
    const bit_idx: u3 = @intCast(subnet % 8);
    return (bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
}

/// Set a subnet bit in a 128-subnet bitmap
pub fn setSubnetBit(bitmap: *[16]u8, subnet: SubnetID) void {
    if (subnet >= 128) return;
    const byte_idx = subnet / 8;
    const bit_idx: u3 = @intCast(subnet % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

/// Clear a subnet bit in a 128-subnet bitmap
pub fn clearSubnetBit(bitmap: *[16]u8, subnet: SubnetID) void {
    if (subnet >= 128) return;
    const byte_idx = subnet / 8;
    const bit_idx: u3 = @intCast(subnet % 8);
    bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
}

/// Count set bits in participation bitmap (256-bit, 32 bytes)
pub fn countParticipation(bitmap: [32]u8) u32 {
    var count: u32 = 0;
    for (bitmap) |byte| {
        count += @popCount(byte);
    }
    return count;
}

/// Check if participation meets quorum (2/3 + 1 of committee_size)
pub fn hasQuorum(bitmap: [32]u8, committee_size: u32) bool {
    const required = (committee_size * 2 / 3) + 1;
    return countParticipation(bitmap) >= required;
}

/// Set a validator bit in a 256-bit participation bitmap (32 bytes)
pub fn setParticipationBit(bitmap: *[32]u8, index: u32) void {
    if (index >= 256) return;
    const byte_idx = index / 8;
    const bit_idx: u3 = @intCast(index % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

/// Check if a validator bit is set in participation bitmap
pub fn isParticipating(bitmap: [32]u8, index: u32) bool {
    if (index >= 256) return false;
    const byte_idx = index / 8;
    const bit_idx: u3 = @intCast(index % 8);
    return (bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
}

// ── Loom Genesis Adaptive Message Structures ────────────────────────────

/// Thread attestation message (sent by weavers/committee members)
pub const ThreadAttestationMsg = struct {
    slot: u64,
    threadId: u8,
    threadRoot: core.types.Hash,
    validatorIndex: u32,
    roleProof: [96]u8,
    blsSignature: [96]u8,
    attestingStake: u256,
};

/// Thread certificate message (aggregated from attestations)
pub const ThreadCertificateMsg = struct {
    slot: u64,
    threadId: u8,
    threadRoot: core.types.Hash,
    aggregateSignature: [96]u8,
    weaverBitmap: [32]u8,
    attestingStake: u256,
    totalEligibleStake: u256,
};

/// Adaptive Quorum Certificate message
pub const AdaptiveQCMsg = struct {
    slot: u64,
    wovenRoot: core.types.Hash,
    threadCertBitmap: u128,
    aggregateSignature: [96]u8,
    voterBitmap: []u8,
    totalAttestingStake: u256,
    randomnessSeed: [32]u8,
    tier: u8, // ConsensusTier as u8
};

/// Thread timeout proof message (substitute for missing committee cert)
pub const ThreadTimeoutProofMsg = struct {
    slot: u64,
    threadId: u8,
    proposerIndex: u32,
    signature: [96]u8,
};

/// Snowball query message (Tier 3: request a peer's preference)
pub const SnowballQueryMsg = struct {
    slot: u64,
    blockHash: core.types.Hash,
    round: u32,
    querierIndex: u32,
};

/// Snowball response message
pub const SnowballResponseMsg = struct {
    slot: u64,
    blockHash: core.types.Hash,
    accept: bool,
    round: u32,
    responderIndex: u32,
    responderStake: u256,
};

/// Epoch transition notification
pub const EpochTransitionMsg = struct {
    newEpoch: u64,
    tier: u8, // ConsensusTier as u8
    threadCount: u8,
    validatorCount: u32,
    epochSeed: [32]u8,
};
