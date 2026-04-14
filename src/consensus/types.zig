// ============================================================================
// Zephyria — Consensus Types (Loom Genesis Adaptive Protocol)
// ============================================================================
//
// Core type definitions for the three-tier adaptive consensus:
//   Tier 1 (Full BFT): N ≤ 100 — all validators verify everything
//   Tier 2 (Committee Loom): 100 < N ≤ 2000 — epoch-shuffled committees
//   Tier 3 (Full Loom): N > 2000 — VRF sortition + Snowball finality
//
// Types are shared across tiers. The block format is identical regardless
// of operating tier — only the verification path differs.

const std = @import("std");
const core = @import("core");

// ── Constants ───────────────────────────────────────────────────────────

/// Maximum threads supported by the protocol (hardware ceiling)
pub const MAX_THREADS: u8 = 128;

/// Default threads for mid-tier consumer hardware (1 Gbps NIC)
pub const DEFAULT_THREADS: u8 = 10;

/// Minimum committee size for statistical safety (Tier 2)
pub const MIN_COMMITTEE_SIZE: u32 = 20;

/// Slots per epoch (≈7 minutes at 400ms slots)
pub const SLOTS_PER_EPOCH: u64 = 1024;

/// Slot duration in milliseconds
pub const SLOT_DURATION_MS: u64 = 400;

/// Tier 1 → Tier 2 transition threshold
pub const TIER2_THRESHOLD: u32 = 100;

/// Tier 2 → Tier 3 transition threshold
pub const TIER3_THRESHOLD: u32 = 2000;

/// Expected proposer candidates per slot (Poisson parameter)
pub const EXPECTED_PROPOSERS: u32 = 3;

/// Expected weavers per thread per slot (Tier 3)
pub const EXPECTED_WEAVERS_PER_THREAD: u32 = 100;

/// Expected attestors per slot (Tier 3)
pub const EXPECTED_ATTESTORS: u32 = 1000;

/// DAS sample count per attestor
pub const DAS_SAMPLE_COUNT: u32 = 20;

/// Snowball parameters (Tier 3)
pub const SNOWBALL_K: u32 = 20;
pub const SNOWBALL_ALPHA: u32 = 15;
pub const SNOWBALL_BETA: u32 = 3;

/// View change timeout (2× slot time)
pub const VIEW_CHANGE_TIMEOUT_MS: u64 = SLOT_DURATION_MS * 2;

/// Maximum consecutive misses before view change
pub const MAX_CONSECUTIVE_MISSES: u32 = 3;

// ── Consensus Tier ──────────────────────────────────────────────────────

/// Operating tier of the adaptive consensus protocol.
/// Determined automatically at each epoch boundary based on active validator count.
pub const ConsensusTier = enum(u8) {
    /// N ≤ 100: All validators verify everything. Classical BFT safety.
    FullBFT = 1,
    /// 100 < N ≤ 2000: Epoch-shuffled committees per thread. BLS voting.
    CommitteeLoom = 2,
    /// N > 2000: Full VRF sortition + Snowball finality + DAS.
    FullLoom = 3,
};

// ── Existing Types (unchanged) ──────────────────────────────────────────

pub const ValidatorStatus = enum(u8) {
    Active = 0,
    Unbonding = 1,
    Slashed = 2,
    Exited = 3,
};

pub const ValidatorInfo = struct {
    address: core.types.Address,
    stake: u256,
    status: ValidatorStatus,
    bls_pub_key: [48]u8,
    commission: u16,
    activation_block: u64,
    slash_count: u64,
    total_rewards: u256,
    name: []const u8,
    website: []const u8,
};

pub const UnbondingRequest = struct {
    amount: u256,
    unlock_block: u64,
    request_block: u64,
};

pub const SlashingType = enum(u8) {
    DoubleSign = 0,
    SurroundVote = 1,
    Unavailability = 2,
    InvalidThreadRoot = 3,
};

pub const SlashingRecord = struct {
    validator_addr: core.types.Address,
    slash_type: SlashingType,
    evidence: []const u8,
    slash_amount: u256,
    block_number: u64,
    reporter: core.types.Address,
};

pub const Vote = struct {
    sender: core.types.Address,
    block_hash: core.types.Hash,
    view: u64,
    signature: [96]u8, // BLS G2 signature
};

// ── VoteMsg (used by VotePool and P2P) ──────────────────────────────────

pub const VoteMsg = struct {
    block_hash: core.types.Hash,
    block_number: u64,
    view: u64,
    signature: [96]u8,
    validator_index: u32,
};

// ── Adaptive Block Header ───────────────────────────────────────────────

/// The woven block header — identical format across all tiers.
/// At Tier 1 (1 thread), thread_roots[0] == woven_root.
/// At Tier 3 (10+ threads), woven_root = Merkle(thread_roots[0..thread_count]).
pub const AdaptiveBlockHeader = struct {
    /// Slot number (monotonically increasing, one per 400ms)
    slot: u64,
    /// Epoch number
    epoch: u64,
    /// Parent block's woven_root hash
    parent_hash: core.types.Hash,
    /// Proposer's validator index in the active set
    proposer_index: u32,
    /// Proposer's VRF proof (proves legitimate selection)
    proposer_vrf_proof: [48]u8,

    // ── Thread structure (the Loom) ─────────────────────────────────
    /// Number of active threads in this block (1 at Tier 1, up to MAX_THREADS)
    thread_count: u8,
    /// Merkle root of each thread's transactions (only [0..thread_count] valid)
    thread_roots: [MAX_THREADS]core.types.Hash,
    /// Transaction count per thread
    thread_tx_counts: [MAX_THREADS]u32,
    /// THE block hash: Merkle(thread_roots[0..thread_count])
    woven_root: core.types.Hash,

    // ── State ───────────────────────────────────────────────────────
    /// State root committed with deferred execution (2 slots behind)
    state_root: core.types.Hash,
    /// Total transaction count across all threads
    total_tx_count: u32,
    /// Randomness seed for next slot's VRF sortition
    randomness_seed: [32]u8,

    // ── Tier metadata ───────────────────────────────────────────────
    /// Which consensus tier produced this block
    tier: ConsensusTier,

    /// Compute the woven root from thread roots.
    /// Uses iterative Keccak256 Merkle: H(H(r0 ‖ r1) ‖ H(r2 ‖ r3) ‖ ...)
    pub fn computeWovenRoot(self: *AdaptiveBlockHeader) void {
        if (self.thread_count == 0) {
            self.woven_root = core.types.Hash.zero();
            return;
        }
        if (self.thread_count == 1) {
            self.woven_root = self.thread_roots[0];
            return;
        }

        // Binary Merkle tree over thread_roots[0..thread_count]
        var level: [MAX_THREADS]core.types.Hash = undefined;
        var count: usize = self.thread_count;
        @memcpy(level[0..count], self.thread_roots[0..count]);

        while (count > 1) {
            var next_count: usize = 0;
            var i: usize = 0;
            while (i + 1 < count) : (i += 2) {
                var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                hasher.update(&level[i].bytes);
                hasher.update(&level[i + 1].bytes);
                hasher.final(&level[next_count].bytes);
                next_count += 1;
            }
            // Odd element: promote directly
            if (i < count) {
                level[next_count] = level[i];
                next_count += 1;
            }
            count = next_count;
        }
        self.woven_root = level[0];
    }

    /// Verify that the woven_root matches the thread_roots.
    pub fn verifyWovenRoot(self: *const AdaptiveBlockHeader) bool {
        var copy = self.*;
        copy.computeWovenRoot();
        return std.mem.eql(u8, &copy.woven_root.bytes, &self.woven_root.bytes);
    }

    /// Hash the entire header for signing/QC purposes.
    pub fn hash(self: *const AdaptiveBlockHeader) core.types.Hash {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        // Slot + epoch + parent
        var buf8: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf8, self.slot, .big);
        hasher.update(&buf8);
        std.mem.writeInt(u64, &buf8, self.epoch, .big);
        hasher.update(&buf8);
        hasher.update(&self.parent_hash.bytes);
        // Proposer
        var buf4: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf4, self.proposer_index, .big);
        hasher.update(&buf4);
        hasher.update(&self.proposer_vrf_proof);
        // Woven root (THE block identity)
        hasher.update(&self.woven_root.bytes);
        // State
        hasher.update(&self.state_root.bytes);
        std.mem.writeInt(u32, &buf4, self.total_tx_count, .big);
        hasher.update(&buf4);
        hasher.update(&self.randomness_seed);
        // Tier + thread count
        hasher.update(&[_]u8{ @intFromEnum(self.tier), self.thread_count });
        var result: core.types.Hash = undefined;
        hasher.final(&result.bytes);
        return result;
    }
};

// ── Thread Attestation ──────────────────────────────────────────────────

/// Signed attestation from a weaver/committee member for a specific thread.
/// Used in Tier 2 (committee member) and Tier 3 (VRF-selected weaver).
pub const ThreadAttestation = struct {
    /// Slot being attested
    slot: u64,
    /// Which thread this attestation covers
    thread_id: u8,
    /// Verified Merkle root for this thread's transactions
    thread_root: core.types.Hash,
    /// Validator index of the weaver
    validator_index: u32,
    /// Weaver's VRF proof (Tier 3) or committee membership proof (Tier 2)
    role_proof: [48]u8,
    /// BLS signature over (slot, thread_id, thread_root)
    bls_signature: [96]u8,
    /// Stake of the attesting validator
    attesting_stake: u64,
};

/// Signing message for thread attestation: Keccak256(slot ‖ thread_id ‖ thread_root)
pub fn threadAttestationMessage(slot: u64, thread_id: u8, thread_root: core.types.Hash) [32]u8 {
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    var buf8: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf8, slot, .big);
    hasher.update(&buf8);
    hasher.update(&[_]u8{thread_id});
    hasher.update(&thread_root.bytes);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

// ── Thread Certificate ──────────────────────────────────────────────────

/// Aggregated thread certificate — produced when ≥67% of thread's
/// committee/weavers have attested to the same thread root.
pub const ThreadCertificate = struct {
    /// Slot this certificate covers
    slot: u64,
    /// Thread ID
    thread_id: u8,
    /// Verified thread root (all weavers agreed on this)
    thread_root: core.types.Hash,
    /// BLS aggregate signature of all attesting weavers
    aggregate_signature: [96]u8,
    /// Bitmap of which weavers/committee members signed (up to 256)
    weaver_bitmap: [32]u8,
    /// Total stake of attesting weavers
    attesting_stake: u64,
    /// Total stake of all eligible weavers for this thread
    total_eligible_stake: u64,

    /// Check if the certificate has sufficient quorum (≥67% of eligible stake).
    pub fn hasQuorum(self: *const ThreadCertificate) bool {
        if (self.total_eligible_stake == 0) return false;
        return self.attesting_stake * 3 > self.total_eligible_stake * 2;
    }
};

// ── Woven Quorum Certificate ────────────────────────────────────────────

/// The final Quorum Certificate for a block — identical format across all tiers.
/// At Tier 1: thread_cert_bitmap has 1-2 bits set, voter_bitmap covers all validators.
/// At Tier 3: thread_cert_bitmap has 10+ bits set, voter_bitmap covers attestors.
pub const WovenQuorumCertificate = struct {
    /// Slot this QC certifies
    slot: u64,
    /// THE block hash (woven_root from AdaptiveBlockHeader)
    woven_root: core.types.Hash,
    /// Which threads are certified (bitmask, up to MAX_THREADS)
    thread_cert_bitmap: u128,
    /// BLS aggregate signature of all voters (attestors at Tier 1-2, Snowball at Tier 3)
    aggregate_signature: [96]u8,
    /// Bitmap of which validators signed (up to 256 validators for Tier 1-2)
    voter_bitmap: [32]u8,
    /// Total attesting stake
    total_attesting_stake: u64,
    /// Randomness seed for next slot
    randomness_seed: [32]u8,
    /// Which tier produced this QC
    tier: ConsensusTier,

    /// Check if all required threads are certified.
    pub fn allThreadsCertified(self: *const WovenQuorumCertificate, thread_count: u8) bool {
        const required_mask = (@as(u128, 1) << @intCast(thread_count)) - 1;
        return (self.thread_cert_bitmap & required_mask) == required_mask;
    }

    /// Check if voting quorum is met (≥67% of total voting stake).
    pub fn hasVotingQuorum(self: *const WovenQuorumCertificate, total_stake: u64) bool {
        if (total_stake == 0) return false;
        return self.total_attesting_stake * 3 > total_stake * 2;
    }

    /// Compute the randomness seed for the next slot.
    pub fn computeNextSeed(self: *const WovenQuorumCertificate) [32]u8 {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&self.randomness_seed);
        hasher.update(&self.aggregate_signature);
        var buf8: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf8, self.slot, .big);
        hasher.update(&buf8);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

// ── Committee Assignment (Tier 2) ───────────────────────────────────────

/// Assignment of a validator to a thread committee for an epoch.
pub const ThreadCommitteeAssignment = struct {
    /// Epoch this assignment is valid for
    epoch: u64,
    /// Thread ID assigned to
    thread_id: u8,
    /// Validator index in the active set
    validator_index: u32,
    /// Validator's stake weight
    stake: u64,
};

// ── Proposer Schedule Entry ─────────────────────────────────────────────

/// Pre-computed proposer for a specific slot in the epoch.
pub const ProposerScheduleEntry = struct {
    /// Slot number
    slot: u64,
    /// Primary proposer's validator index
    primary_proposer: u32,
    /// Backup proposer (for view change)
    backup_proposer: u32,
    /// VRF hash (for comparison / lowest-hash-wins)
    vrf_hash: [32]u8,
};

// ── Epoch State ─────────────────────────────────────────────────────────

/// Snapshot of consensus state at an epoch boundary.
pub const EpochState = struct {
    /// Epoch number
    epoch: u64,
    /// Active consensus tier
    tier: ConsensusTier,
    /// Number of active threads
    thread_count: u8,
    /// Number of active validators
    validator_count: u32,
    /// Epoch randomness seed
    seed: [32]u8,
    /// Last finalized slot of previous epoch
    last_finalized_slot: u64,
};
