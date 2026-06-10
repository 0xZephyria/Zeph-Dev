// ============================================================================
// Zephyria — Core Types
// ============================================================================
//
// Single canonical hash identity rule:
//   Every block has exactly ONE 32-byte identifier: Block.id()
//   Every transaction has exactly ONE 32-byte identifier: Transaction.id()
//   Every address is exactly 32 bytes: Blake3(Ed25519_pubkey)
//
// Hash functions used:
//   - Addresses:    Blake3(pubkey_bytes)          [domain: ADDR_DERIVE_V1]
//   - TX ids:       Blake3(domain ‖ wire_bytes)   [domain: ZEPH_TX_V1]
//   - Block ids:    Blake3(domain ‖ header_fields ‖ txMerkleRoot)
//                                                 [domain: ZEPH_BLK_V1]
//
// Seal window: BLS aggregate sig is stored in extraData[0..96].
// Block.id() hashes extraData[0..EXTRA_DATA_HASH_LEN] where
// EXTRA_DATA_HASH_LEN = 0 (pre-seal region is empty; seal goes in [0..96]).
// The QC / aggregate BLS sig lives in extraData[0..96] and is NOT part of
// the id (QC signs the id — circular otherwise).

const std = @import("std");

// ── Domain Separation Tags ──────────────────────────────────────────────
// Blake3 is collision-resistant, but domain tags prevent cross-context
// hash reuse (e.g. a crafted TX that collides with a Block id).

/// Domain tag for address derivation: Blake3(ADDR_TAG ‖ pubkey)
pub const ADDR_DERIVE_TAG: []const u8 = "ZEPH_ADDR_V1";
/// Domain tag for transaction id: Blake3(TX_TAG ‖ wire_bytes)
pub const TX_ID_TAG: []const u8 = "ZEPH_TX_V1";
/// Domain tag for block id: Blake3(BLK_TAG ‖ canonical_header_bytes)
pub const BLK_ID_TAG: []const u8 = "ZEPH_BLK_V1";
/// Domain tag for state-root derivation
pub const STATE_ROOT_TAG: []const u8 = "ZEPH_STATE_V1";

// ── Address ─────────────────────────────────────────────────────────────

pub const Address = extern struct {
    bytes: [32]u8,

    pub fn zero() Address {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn eql(self: Address, other: Address) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn isZero(self: Address) bool {
        for (self.bytes) |b| if (b != 0) return false;
        return true;
    }

    /// Derive a Zephyria address from an Ed25519 public key.
    /// address = Blake3(ADDR_DERIVE_TAG ‖ pubkey_bytes)
    pub fn fromPubKey(pubkey: *const [32]u8) Address {
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(ADDR_DERIVE_TAG);
        hasher.update(pubkey);
        var addr = Address.zero();
        hasher.final(&addr.bytes);
        return addr;
    }
};

// ── Hash ─────────────────────────────────────────────────────────────────

pub const Hash = extern struct {
    bytes: [32]u8,

    pub fn zero() Hash {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn eql(self: Hash, other: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn isZero(self: Hash) bool {
        for (self.bytes) |b| if (b != 0) return false;
        return true;
    }
};

// ── Block Header ─────────────────────────────────────────────────────────
//
// Fields included in Block.id() (canonical block identifier):
//   parentId(32) ‖ number(8,BE) ‖ timestamp(8,BE) ‖
//   stateRoot(32) ‖ txMerkleRoot(32) ‖ producer(32) ‖
//   executionBudget(8,BE) ‖ budgetUsed(8,BE)
//
// Fields NOT included in Block.id() (post-seal / attestation):
//   extraData — carries BLS aggregate signature (not hashed to avoid circularity)
//   quorumCertificate — QC signs the id, so it cannot be part of it

pub const Header = struct {
    /// Hash/id of the parent block (zero for genesis)
    parentId: Hash,
    /// Block number (0 = genesis)
    number: u64,
    /// Unix timestamp in seconds
    time: u64,
    /// Merkle root of the post-execution world state
    stateRoot: Hash,
    /// Merkle root of all transaction ids in this block (Blake3 of tx id list)
    txMerkleRoot: Hash,
    /// Ed25519-derived address of the block producer
    producer: Address,
    /// Extra data (BLS sig in [0..96], not hashed in block id)
    extraData: []const u8,
    /// Block-wide budget/execution budget
    executionBudget: u64,
    /// Actual budget consumed by all transactions
    budgetUsed: u64,
    /// Optional quorum certificate (NOT part of block id)
    quorumCertificate: ?QuorumCertificate = null,

    pub fn deinit(self: Header, allocator: std.mem.Allocator) void {
        allocator.free(self.extraData);
    }
};

/// BLS aggregate signature from 2/3+ validators attesting to a block.
/// Stored in extraData[0..96] and separately in this struct for convenience.
/// NEVER included in Block.id() — QC signs the id, circular otherwise.
pub const QuorumCertificate = struct {
    /// Aggregate BLS signature from voting validators (96 bytes, G2 compressed)
    aggregateSignature: [96]u8,
    /// Bitmap of which validator indices signed (up to 256 validators)
    voterBitmap: [32]u8,
};

// ── Transaction ───────────────────────────────────────────────────────────

pub const Transaction = struct {
    /// Ed25519 public key of the sender (32 bytes)
    pub_key: [32]u8 = [_]u8{0} ** 32,
    /// Derived sender address: Blake3(ADDR_TAG ‖ pub_key)
    from: Address = Address.zero(),
    /// Recipient address (null = contract deployment)
    to: ?Address = null,
    /// Value in attoZEE (1 ZEE = 1e18 attoZEE)
    value: u256 = 0,
    /// Execution budget for this transaction
    executionBudget: u64 = 0,
    /// Compute price in attoZEE per budget unit
    computePrice: u64 = 0,
    /// Sender's sequence number (monotonically increasing, anti-replay)
    sequence: u64 = 0,
    /// Ed25519 signature over the signing message (64 bytes)
    signature: [64]u8 = [_]u8{0} ** 64,
    /// Calldata (ABI-encoded function call or contract init code)
    data: []const u8 = &[_]u8{},

    // ── Wire Format Offsets ──────────────────────────────────────────
    // Layout: pub_key(32) + to(32) + value(32,BE) + budget(8,LE) +
    //         computePrice(8,LE) + sequence(8,LE) + sig(64) + calldataLen(4,LE)
    // Total fixed: 188 bytes, followed by calldata.

    const BF_PUB_KEY = 0;
    const BF_TARGET = 32;
    const BF_VALUE = 64;
    const BF_BUDGET = 96;
    const BF_COMPUTE_PRICE = 104;
    const BF_SEQUENCE = 112;
    const BF_SIG = 120;
    const BF_CALEN = 184;
    pub const BF_SIZE = 188;

    /// Maximum allowed calldata size (1 MB per transaction)
    pub const MAX_CALLDATA_SIZE: u32 = 1024 * 1024;
    /// Maximum allowed total wire size (1 MB + fixed header)
    pub const MAX_WIRE_SIZE: usize = BF_SIZE + MAX_CALLDATA_SIZE;

    /// Canonical transaction identifier.
    /// id = Blake3(TX_ID_TAG ‖ full_wire_bytes_with_signature)
    /// The signature IS included — a TX is uniquely identified by its full
    /// signed content. Signing-message hashing uses zeros for the sig field.
    pub fn id(self: *const Transaction) Hash {
        var h_res = Hash.zero();
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(TX_ID_TAG);
        var buf: [BF_SIZE]u8 = undefined;
        @memcpy(buf[BF_PUB_KEY..BF_TARGET], &self.pub_key);
        if (self.to) |t| {
            @memcpy(buf[BF_TARGET..BF_VALUE], &t.bytes);
        } else {
            @memset(buf[BF_TARGET..BF_VALUE], 0);
        }
        std.mem.writeInt(u256, buf[BF_VALUE..BF_BUDGET], self.value, .big);
        std.mem.writeInt(u64, buf[BF_BUDGET..BF_COMPUTE_PRICE], self.executionBudget, .little);
        std.mem.writeInt(u64, buf[BF_COMPUTE_PRICE..BF_SEQUENCE], self.computePrice, .little);
        std.mem.writeInt(u64, buf[BF_SEQUENCE..BF_SIG], self.sequence, .little);
        @memcpy(buf[BF_SIG..BF_CALEN], &self.signature);
        std.mem.writeInt(u32, buf[BF_CALEN..BF_SIZE], @intCast(self.data.len), .little);
        hasher.update(buf[0..]);
        hasher.update(self.data);
        hasher.final(&h_res.bytes);
        return h_res;
    }

    /// Build the signing message: same wire format but with signature zeroed.
    /// Caller must free the returned slice.
    pub fn getSigningMessage(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        var buf: [BF_SIZE]u8 = undefined;
        @memcpy(buf[BF_PUB_KEY..BF_TARGET], &self.pub_key);
        if (self.to) |t| {
            @memcpy(buf[BF_TARGET..BF_VALUE], &t.bytes);
        } else {
            @memset(buf[BF_TARGET..BF_VALUE], 0);
        }
        std.mem.writeInt(u256, buf[BF_VALUE..BF_BUDGET], self.value, .big);
        std.mem.writeInt(u64, buf[BF_BUDGET..BF_COMPUTE_PRICE], self.executionBudget, .little);
        std.mem.writeInt(u64, buf[BF_COMPUTE_PRICE..BF_SEQUENCE], self.computePrice, .little);
        std.mem.writeInt(u64, buf[BF_SEQUENCE..BF_SIG], self.sequence, .little);
        // Signature field zeroed for signing
        @memset(buf[BF_SIG..BF_CALEN], 0);
        std.mem.writeInt(u32, buf[BF_CALEN..BF_SIZE], @intCast(self.data.len), .little);

        const msg = try allocator.alloc(u8, BF_SIZE + self.data.len);
        @memcpy(msg[0..BF_SIZE], &buf);
        @memcpy(msg[BF_SIZE..], self.data);
        return msg;
    }

    /// Encode the transaction to binary wire format.
    pub fn encodeBinary(self: Transaction, writer: anytype) !void {
        var buf: [BF_SIZE]u8 = undefined;
        @memcpy(buf[BF_PUB_KEY..BF_TARGET], &self.pub_key);
        if (self.to) |t| {
            @memcpy(buf[BF_TARGET..BF_VALUE], &t.bytes);
        } else {
            @memset(buf[BF_TARGET..BF_VALUE], 0);
        }
        std.mem.writeInt(u256, buf[BF_VALUE..BF_BUDGET], self.value, .big);
        std.mem.writeInt(u64, buf[BF_BUDGET..BF_COMPUTE_PRICE], self.executionBudget, .little);
        std.mem.writeInt(u64, buf[BF_COMPUTE_PRICE..BF_SEQUENCE], self.computePrice, .little);
        std.mem.writeInt(u64, buf[BF_SEQUENCE..BF_SIG], self.sequence, .little);
        @memcpy(buf[BF_SIG..BF_CALEN], &self.signature);
        std.mem.writeInt(u32, buf[BF_CALEN..BF_SIZE], @intCast(self.data.len), .little);
        try writer.writeAll(buf[0..]);
        try writer.writeAll(self.data);
    }

    /// Decode a transaction from binary wire format, allocating calldata.
    pub fn decodeBinary(self: *Transaction, allocator: std.mem.Allocator, bytes: []const u8) !void {
        if (bytes.len < BF_SIZE) return error.InvalidLength;
        const caldata_len = std.mem.readInt(u32, bytes[BF_CALEN..BF_SIZE], .little);
        if (caldata_len > MAX_CALLDATA_SIZE) return error.CalldataTooLarge;
        const calldata = bytes[BF_SIZE..];
        if (calldata.len < caldata_len) return error.InvalidLength;

        self.pub_key = bytes[BF_PUB_KEY..BF_TARGET].*;
        // Derive sender address with domain tag
        self.from = Address.fromPubKey(&self.pub_key);

        var all_zeros = true;
        for (bytes[BF_TARGET..BF_VALUE]) |b| {
            if (b != 0) { all_zeros = false; break; }
        }
        if (all_zeros) {
            self.to = null;
        } else {
            self.to = Address{ .bytes = bytes[BF_TARGET..BF_VALUE].* };
        }
        self.value = std.mem.readInt(u256, bytes[BF_VALUE..BF_BUDGET], .big);
        self.executionBudget = std.mem.readInt(u64, bytes[BF_BUDGET..BF_COMPUTE_PRICE], .little);
        self.computePrice = std.mem.readInt(u64, bytes[BF_COMPUTE_PRICE..BF_SEQUENCE], .little);
        self.sequence = std.mem.readInt(u64, bytes[BF_SEQUENCE..BF_SIG], .little);
        self.signature = bytes[BF_SIG..BF_CALEN].*;
        self.data = try allocator.dupe(u8, calldata[0..caldata_len]);
    }

    /// Decode without allocating (zero-copy — calldata slice points into `bytes`).
    pub fn decodeBinaryZeroCopy(self: *Transaction, bytes: []const u8) !void {
        if (bytes.len < BF_SIZE) return error.InvalidLength;
        const caldata_len = std.mem.readInt(u32, bytes[BF_CALEN..BF_SIZE], .little);
        if (caldata_len > MAX_CALLDATA_SIZE) return error.CalldataTooLarge;
        const calldata = bytes[BF_SIZE..];
        if (calldata.len < caldata_len) return error.InvalidLength;

        self.pub_key = bytes[BF_PUB_KEY..BF_TARGET].*;
        self.from = Address.fromPubKey(&self.pub_key);

        var all_zeros = true;
        for (bytes[BF_TARGET..BF_VALUE]) |b| {
            if (b != 0) { all_zeros = false; break; }
        }
        if (all_zeros) {
            self.to = null;
        } else {
            self.to = Address{ .bytes = bytes[BF_TARGET..BF_VALUE].* };
        }
        self.value = std.mem.readInt(u256, bytes[BF_VALUE..BF_BUDGET], .big);
        self.executionBudget = std.mem.readInt(u64, bytes[BF_BUDGET..BF_COMPUTE_PRICE], .little);
        self.computePrice = std.mem.readInt(u64, bytes[BF_COMPUTE_PRICE..BF_SEQUENCE], .little);
        self.sequence = std.mem.readInt(u64, bytes[BF_SEQUENCE..BF_SIG], .little);
        self.signature = bytes[BF_SIG..BF_CALEN].*;
        self.data = calldata[0..caldata_len];
    }

    /// Derive contract deployment address from sender + sequence.
    pub fn deriveContractAddress(self: *const Transaction) Address {
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(ADDR_DERIVE_TAG);
        hasher.update("contract:");
        hasher.update(&self.from.bytes);
        var sequenceBuf: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequenceBuf, self.sequence, .big);
        hasher.update(&sequenceBuf);
        var addr: Address = undefined;
        hasher.final(&addr.bytes);
        return addr;
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

// ── Block ─────────────────────────────────────────────────────────────────

pub const Block = struct {
    header: Header,
    transactions: []Transaction,

    /// THE canonical block identifier.
    ///
    /// id = Blake3(BLK_ID_TAG ‖
    ///             parentId(32) ‖ number(8,BE) ‖ time(8,BE) ‖
    ///             stateRoot(32) ‖ txMerkleRoot(32) ‖ producer(32) ‖
    ///             executionBudget(8,BE) ‖ budgetUsed(8,BE))
    ///
    /// NOT included: extraData (carries post-id BLS sig), quorumCertificate
    /// (QC signs this id — circular if included).
    ///
    /// This is the single function used for:
    ///   - DB storage key
    ///   - parent linkage (header.parentId)
    ///   - P2P StatusMsg.headId / genesisId
    ///   - Consensus vote target
    ///   - Transaction lookup (tx → blockId)
    pub fn id(self: *const Block) Hash {
        return Block.blockId(&self.header);
    }

    /// Compute block id directly from header fields (used during construction
    /// before the Block struct is fully assembled).
    pub fn blockId(header: *const Header) Hash {
        var h_res = Hash.zero();
        var hasher = std.crypto.hash.Blake3.init(.{});
        var buf8: [8]u8 = undefined;

        hasher.update(BLK_ID_TAG);
        hasher.update(&header.parentId.bytes);
        std.mem.writeInt(u64, &buf8, header.number, .big);
        hasher.update(&buf8);
        std.mem.writeInt(u64, &buf8, header.time, .big);
        hasher.update(&buf8);
        hasher.update(&header.stateRoot.bytes);
        hasher.update(&header.txMerkleRoot.bytes);
        hasher.update(&header.producer.bytes);
        std.mem.writeInt(u64, &buf8, header.executionBudget, .big);
        hasher.update(&buf8);
        std.mem.writeInt(u64, &buf8, header.budgetUsed, .big);
        hasher.update(&buf8);

        hasher.final(&h_res.bytes);
        return h_res;
    }

    /// Compute the transaction merkle root from a slice of transactions.
    /// txMerkleRoot = Blake3(TX_ID_TAG_MERKLE ‖ tx0.id() ‖ tx1.id() ‖ ...)
    /// For an empty transaction list, returns Hash.zero() (genesis convention).
    pub fn computeTxMerkleRoot(txs: []const Transaction) Hash {
        if (txs.len == 0) return Hash.zero();
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update("ZEPH_TXROOT_V1");
        for (txs) |*tx| {
            const tx_id = tx.id();
            hasher.update(&tx_id.bytes);
        }
        var root: Hash = undefined;
        hasher.final(&root.bytes);
        return root;
    }

    pub fn deinit(self: Block, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        for (self.transactions) |tx| {
            tx.deinit(allocator);
        }
        allocator.free(self.transactions);
    }
};

// Use Block.blockId(header) for computing block ids from header structs.

// ── Account Types ─────────────────────────────────────────────────────────

pub const AccountType = enum(u8) {
    EOA = 0,
    ContractRoot = 1,
    Code = 2,
    Config = 3,
    StorageCell = 4,
    DerivedState = 5,
    Vault = 6,
    System = 7,
};

pub const SlotClassification = enum {
    PerUser,
    Global,
    Immutable,
};

// ── Receipt Types ─────────────────────────────────────────────────────────

pub const CreditReceipt = struct {
    recipient: Address,
    contract: Address,
    slot: [32]u8,
    deltaValue: [32]u8,
    isAddition: bool,
    txIndex: u32,
};

pub const AccumulatorDelta = struct {
    contract: Address,
    slot: [32]u8,
    deltaValue: [32]u8,
    isAddition: bool,
    txIndex: u32,
};

pub const ParallelTxResult = struct {
    success: bool,
    budgetUsed: u64,
    fee: u256,
    errorMessage: ?[]const u8,
    receipts: []CreditReceipt,
    deltas: []AccumulatorDelta,
};
