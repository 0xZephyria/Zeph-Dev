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
pub const CHAIN_NAME = "forgeyria";

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

// Loom Genesis Adaptive Consensus Messages
pub const MsgThreadAttestation: u64 = 0x20;
pub const MsgThreadCertificate: u64 = 0x21;
pub const MsgAdaptiveQC: u64 = 0x22;
pub const MsgSnowballQuery: u64 = 0x23;
pub const MsgSnowballResponse: u64 = 0x24;
pub const MsgEpochTransition: u64 = 0x25;

// ── Network Constants ───────────────────────────────────────────────────

pub const MAX_CONNECTIONS: u32 = 512;
pub const COMMITTEE_SIZE: u32 = 256;
pub const AGGREGATION_SUBNETS: u32 = 16;
pub const GOSSIP_SUBNETS: u32 = 64;
pub const SUBNETS_PER_VALIDATOR: u32 = 2;
pub const PEERS_PER_SUBNET: u32 = 8;
pub const TURBINE_FANOUT: u32 = 32;
pub const MAX_SHRED_SIZE: u32 = 1232; // IPv6 MTU - headers
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

pub const SubnetID = u8; // 0..63 for gossip subnets, 0..15 for aggregation subnets

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
    slot_start: u64,
    slot_end: u64,
    committee_index: u32,
    role: CommitteeRole,
    aggregation_subnet: SubnetID,
};

// ── Rate Limiting ───────────────────────────────────────────────────────

pub const RateLimitConfig = struct {
    /// Base burst capacity for unstaked peers
    base_capacity: f64 = 20.0,
    /// Base refill rate (tokens per second) for unstaked peers
    base_refill: f64 = 10.0,
    /// Multiplier for committee members during their active slot
    committee_burst_multiplier: f64 = 10.0,
    /// Stake scaling: refill_rate = base_refill * sqrt(stake / min_stake)
    /// Capped at 100x base_refill
    max_stake_multiplier: f64 = 100.0,
};

// ── Message Structures ──────────────────────────────────────────────────

pub const StatusMsg = struct {
    protocol_version: u32,
    chain_id: u64,
    genesis_hash: core.types.Hash,
    head_hash: core.types.Hash,
    head_number: u64,
    challenge: [32]u8,
    peer_role: PeerRole,
    stake_amount: u64,
    subscribed_subnets: [8]u8, // Bitmap: 64 subnets packed into 8 bytes
};

pub const NewBlockMsg = struct {
    block: core.types.Block,
    total_difficulty: u256,
    hop_count: u32,
};

pub const GetBlocksMsg = struct {
    start_hash: core.types.Hash,
    limit: u64,
    direction: u8,
};

pub const BlocksMsg = struct {
    blocks: []core.types.Block,
};

pub const TxBatchMsg = struct {
    tx_hashes: []core.types.Hash,
    tx_data: [][]const u8,
    compressed: bool,
    batch_id: u64,
    sender_subnet: SubnetID,
};

pub const VoteMsg = struct {
    block_hash: core.types.Hash,
    block_number: u64,
    view: u64,
    signature: [96]u8,
    validator_index: u32,
};

pub const AuthMsg = struct {
    signature: [64]u8,
    public_key: [65]u8,
    validator_address: core.types.Address,
    stake_proof: [32]u8,
};

pub const SlashEvidenceMsg = struct {
    validator: core.types.Address,
    block_number: u64,
    reason: SlashReason,
    evidence_hash_1: core.types.Hash,
    evidence_hash_2: core.types.Hash,
    reporter_signature: [96]u8,
};

pub const SlashReason = enum(u8) {
    DoubleSigning = 0,
    DoubleAttestation = 1,
    InvalidBlock = 2,
};

pub const PeersMsg = struct {
    nodes: []NodeInfo,
};

pub const NodeInfo = struct {
    id: [64]u8,
    ip: [16]u8,
    ip_len: u8,
    port: u16,
    peer_role: PeerRole,
    subnets: [8]u8,
};

pub const GetNodeDataMsg = struct {
    request_id: u64,
    hashes: []core.types.Hash,
};

pub const NodeDataMsg = struct {
    request_id: u64,
    data: [][]const u8,
};

pub const PingMsg = struct {
    nonce: u64,
    timestamp: i64,
};

pub const PongMsg = struct {
    nonce: u64,
    timestamp: i64,
};

// ── Shred Types (Turbine) ───────────────────────────────────────────────

pub const ShredType = enum(u8) {
    Data = 0,
    Parity = 1,
};

pub const ShredMsg = struct {
    block_number: u64,
    shred_index: u32,
    total_data_shreds: u32,
    total_parity_shreds: u32,
    shred_type: ShredType,
    payload: []const u8,
    producer_signature: [64]u8,
    tree_layer: u8,
    tree_index: u16,
    /// Thread ID (Loom Genesis: which thread this shred belongs to)
    thread_id: u8,
};

// ── Attestation Types ───────────────────────────────────────────────────

pub const AttestationMsg = struct {
    block_hash: core.types.Hash,
    block_number: u64,
    slot: u64,
    validator_index: u32,
    committee_index: u32,
    signature: [96]u8,
    subnet_id: SubnetID,
};

pub const AggregateAttestationMsg = struct {
    block_hash: core.types.Hash,
    block_number: u64,
    slot: u64,
    subnet_id: SubnetID,
    participation_bitmap: [32]u8,
    aggregate_signature: [96]u8,
    aggregator_index: u32,
    aggregator_proof: [96]u8,
};

pub const QuorumCertificate = struct {
    block_hash: core.types.Hash,
    block_number: u64,
    slot: u64,
    epoch: u64,
    aggregate_signature: [96]u8,
    participation_bitmap: [32]u8,
    proposer_vrf_proof: [48]u8,
};

pub const ViewChangeMsg = struct {
    slot: u64,
    view: u64,
    highest_qc: ?QuorumCertificate,
    validator_index: u32,
    signature: [96]u8,
};

pub const ViewChangeQCMsg = struct {
    slot: u64,
    new_view: u64,
    participation_bitmap: [32]u8,
    aggregate_signature: [96]u8,
    best_qc: QuorumCertificate,
};

pub const CommitteeHandshakeMsg = struct {
    epoch: u64,
    committee_index: u32,
    validator_index: u32,
    validator_address: core.types.Address,
    role: CommitteeRole,
    bls_pubkey: [48]u8,
    signature: [96]u8,
};

pub const SubnetSubscribeMsg = struct {
    subnet_id: SubnetID,
    validator_address: core.types.Address,
    epoch: u64,
    signature: [96]u8,
};

// ── Utility Functions ───────────────────────────────────────────────────

/// Check if a subnet bit is set in a 64-subnet bitmap (8 bytes)
pub fn isSubnetSubscribed(bitmap: [8]u8, subnet: SubnetID) bool {
    if (subnet >= 64) return false;
    const byte_idx = subnet / 8;
    const bit_idx: u3 = @intCast(subnet % 8);
    return (bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
}

/// Set a subnet bit in a 64-subnet bitmap
pub fn setSubnetBit(bitmap: *[8]u8, subnet: SubnetID) void {
    if (subnet >= 64) return;
    const byte_idx = subnet / 8;
    const bit_idx: u3 = @intCast(subnet % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

/// Clear a subnet bit in a 64-subnet bitmap
pub fn clearSubnetBit(bitmap: *[8]u8, subnet: SubnetID) void {
    if (subnet >= 64) return;
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
    thread_id: u8,
    thread_root: core.types.Hash,
    validator_index: u32,
    role_proof: [48]u8,
    bls_signature: [96]u8,
    attesting_stake: u64,
};

/// Thread certificate message (aggregated from attestations)
pub const ThreadCertificateMsg = struct {
    slot: u64,
    thread_id: u8,
    thread_root: core.types.Hash,
    aggregate_signature: [96]u8,
    weaver_bitmap: [32]u8,
    attesting_stake: u64,
    total_eligible_stake: u64,
};

/// Adaptive Quorum Certificate message
pub const AdaptiveQCMsg = struct {
    slot: u64,
    woven_root: core.types.Hash,
    thread_cert_bitmap: u128,
    aggregate_signature: [96]u8,
    voter_bitmap: [32]u8,
    total_attesting_stake: u64,
    randomness_seed: [32]u8,
    tier: u8, // ConsensusTier as u8
};

/// Snowball query message (Tier 3: request a peer's preference)
pub const SnowballQueryMsg = struct {
    slot: u64,
    block_hash: core.types.Hash,
    round: u32,
    querier_index: u32,
};

/// Snowball response message
pub const SnowballResponseMsg = struct {
    slot: u64,
    block_hash: core.types.Hash,
    accept: bool,
    round: u32,
    responder_index: u32,
    responder_stake: u64,
};

/// Epoch transition notification
pub const EpochTransitionMsg = struct {
    new_epoch: u64,
    tier: u8, // ConsensusTier as u8
    thread_count: u8,
    validator_count: u32,
    epoch_seed: [32]u8,
};
