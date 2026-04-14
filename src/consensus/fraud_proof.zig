// Fraud Proof — State root challenge/response system
//
// With deferred execution, validators agree on tx ordering first.
// State roots are computed later and verified retroactively.
// If a validator commits an invalid state root, challengers can submit
// a fraud proof to slash the malicious validator.
//
// Mechanism:
//   1. Validator V commits state root R for block B
//   2. Challenger C re-executes block B, gets root R'
//   3. If R ≠ R', C submits fraud proof with the Merkle proof of divergence
//   4. Network re-executes block B, slashes V if fraud confirmed

const std = @import("std");
const core = @import("core");
const types = core.types;

/// Fraud proof status
pub const ProofStatus = enum {
    Pending,
    Verified,
    Rejected,
    Expired,
};

/// A fraud proof submission
pub const FraudProof = struct {
    /// Block number being challenged
    block_number: u64,
    /// The committed (potentially incorrect) state root
    committed_root: types.Hash,
    /// The challenger's computed state root
    challenged_root: types.Hash,
    /// The validator who committed the root
    accused: types.Address,
    /// The challenger
    challenger: types.Address,
    /// Timestamp of submission
    timestamp: u64,
    /// Status of the proof
    status: ProofStatus,
    /// Merkle proof of divergent state (serialized)
    proof_data: []const u8,
    /// Block number at which this proof expires
    expiry_block: u64,
};

/// Fraud proof manager configuration
pub const FraudConfig = struct {
    /// Number of blocks during which a fraud proof can be submitted
    challenge_window: u64 = 1000,
    /// Reward for successful fraud proof (in ZEE wei)
    challenge_reward: u256 = 100 * 1_000_000_000_000_000_000, // 100 ZEE
    /// Maximum pending proofs
    max_pending: u32 = 100,
};

/// Fraud proof statistics
pub const FraudStats = struct {
    proofs_submitted: u64,
    proofs_verified: u64,
    proofs_rejected: u64,
    proofs_expired: u64,
    total_slashed: u256,
};

/// Fraud proof manager
pub const FraudProofManager = struct {
    allocator: std.mem.Allocator,
    config: FraudConfig,
    /// Pending fraud proofs
    pending: std.ArrayList(FraudProof),
    /// Committed state roots per block for verification
    committed_roots: std.AutoHashMap(u64, CommittedRoot),
    /// Stats
    proofs_submitted: u64,
    proofs_verified: u64,
    proofs_rejected: u64,
    proofs_expired: u64,
    total_slashed: u256,

    const CommittedRoot = struct {
        root: types.Hash,
        validator: types.Address,
        block_number: u64,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: FraudConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .pending = .{},
            .committed_roots = std.AutoHashMap(u64, CommittedRoot).init(allocator),
            .proofs_submitted = 0,
            .proofs_verified = 0,
            .proofs_rejected = 0,
            .proofs_expired = 0,
            .total_slashed = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.pending.items) |*p| {
            self.allocator.free(p.proof_data);
        }
        self.pending.deinit(self.allocator);
        self.committed_roots.deinit();
    }

    /// Record a committed state root from a validator
    pub fn commitRoot(
        self: *Self,
        block_number: u64,
        root: types.Hash,
        validator: types.Address,
    ) !void {
        try self.committed_roots.put(block_number, CommittedRoot{
            .root = root,
            .validator = validator,
            .block_number = block_number,
        });
    }

    /// Submit a fraud proof challenging a state root
    pub fn submitProof(
        self: *Self,
        block_number: u64,
        challenged_root: types.Hash,
        challenger: types.Address,
        proof_data: []const u8,
        current_block: u64,
    ) !bool {
        // Check challenge window
        const committed = self.committed_roots.get(block_number) orelse return error.BlockNotFound;
        if (current_block > block_number + self.config.challenge_window) {
            return error.ChallengeWindowExpired;
        }

        // Check if roots actually differ
        if (std.mem.eql(u8, &committed.root.bytes, &challenged_root.bytes)) {
            return false; // Not a fraud — roots match
        }

        // Copy proof data
        const data = try self.allocator.alloc(u8, proof_data.len);
        @memcpy(data, proof_data);

        try self.pending.append(self.allocator, FraudProof{
            .block_number = block_number,
            .committed_root = committed.root,
            .challenged_root = challenged_root,
            .accused = committed.validator,
            .challenger = challenger,
            .timestamp = @intCast(std.time.timestamp()),
            .status = .Pending,
            .proof_data = data,
            .expiry_block = block_number + self.config.challenge_window,
        });

        self.proofs_submitted += 1;
        return true;
    }

    /// Verify a pending fraud proof by re-executing the block
    /// Returns the slash amount if fraud is confirmed
    pub fn verifyProof(
        self: *Self,
        proof_index: usize,
        recomputed_root: types.Hash,
    ) !?u256 {
        if (proof_index >= self.pending.items.len) return null;

        var proof = &self.pending.items[proof_index];
        if (proof.status != .Pending) return null;

        // Compare recomputed root with challenged root
        if (std.mem.eql(u8, &recomputed_root.bytes, &proof.challenged_root.bytes)) {
            // Fraud confirmed — the challenger was right
            proof.status = .Verified;
            self.proofs_verified += 1;
            return self.config.challenge_reward;
        } else if (std.mem.eql(u8, &recomputed_root.bytes, &proof.committed_root.bytes)) {
            // Original was correct — reject the challenge
            proof.status = .Rejected;
            self.proofs_rejected += 1;
            return null;
        }

        // Neither matches — something else is wrong
        proof.status = .Rejected;
        self.proofs_rejected += 1;
        return null;
    }

    /// Expire old fraud proofs
    pub fn expireProofs(self: *Self, current_block: u64) void {
        for (self.pending.items) |*proof| {
            if (proof.status == .Pending and current_block > proof.expiry_block) {
                proof.status = .Expired;
                self.proofs_expired += 1;
            }
        }
    }

    /// Get fraud proof statistics
    pub fn getStats(self: *const Self) FraudStats {
        return .{
            .proofs_submitted = self.proofs_submitted,
            .proofs_verified = self.proofs_verified,
            .proofs_rejected = self.proofs_rejected,
            .proofs_expired = self.proofs_expired,
            .total_slashed = self.total_slashed,
        };
    }
};
