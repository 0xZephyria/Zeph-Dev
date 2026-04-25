// Epoch Types - Core data structures for constant-size blockchain
// Designed for 1M+ TPS with zero-copy operations and cache-friendly layouts

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Configuration constants
pub const EPOCH_SIZE: u64 = 100_000; // Blocks per epoch
pub const MAX_ACCOUNTS_PER_EPOCH: usize = 10_000_000; // 10M accounts max
pub const MAX_DELTA_SIZE: usize = 256 * 1024 * 1024; // 256 MB max compressed delta
pub const COMPRESSION_LEVEL: i32 = 3; // Zstd compression level (fast)

/// 20-byte Ethereum address
pub const Address = [20]u8;

/// 32-byte hash
pub const Hash = [32]u8;

/// Account state delta entry - tracks changes to a single account
/// Packed struct for cache efficiency (64 bytes aligned)
pub const AccountDelta = extern struct {
    address: Address, // 20 bytes
    balance_delta: i128, // 16 bytes (signed for debits)
    nonce_delta: i64, // 8 bytes (usually +1)
    code_hash: Hash, // 32 bytes (zero if unchanged)
    // Total: 76 bytes, padded to 80

    pub fn isEmpty(self: *const AccountDelta) bool {
        return self.balance_delta == 0 and
            self.nonce_delta == 0 and
            std.mem.eql(u8, &self.code_hash, &[_]u8{0} ** 32);
    }

    pub fn merge(self: *AccountDelta, other: *const AccountDelta) void {
        self.balance_delta +|= other.balance_delta; // Saturating add
        self.nonce_delta +|= other.nonce_delta;
        // Code hash: take latest non-zero
        if (!std.mem.eql(u8, &other.code_hash, &[_]u8{0} ** 32)) {
            self.code_hash = other.code_hash;
        }
    }
};

/// Storage slot delta - tracks changes to contract storage
pub const StorageDelta = struct {
    address: Address,
    slot: Hash, // Storage slot key
    old_value: Hash, // For reverse application
    new_value: Hash,

    pub fn isZeroToNonZero(self: *const StorageDelta) bool {
        return std.mem.eql(u8, &self.old_value, &[_]u8{0} ** 32) and
            !std.mem.eql(u8, &self.new_value, &[_]u8{0} ** 32);
    }

    pub fn isNonZeroToZero(self: *const StorageDelta) bool {
        return !std.mem.eql(u8, &self.old_value, &[_]u8{0} ** 32) and
            std.mem.eql(u8, &self.new_value, &[_]u8{0} ** 32);
    }
};

/// Epoch metadata - header information for an aggregated epoch
pub const EpochMetadata = struct {
    epoch_number: u64,
    start_block: u64,
    end_block: u64,
    start_timestamp: u64,
    end_timestamp: u64,

    // State roots
    pre_state_root: Hash, // State root before epoch
    post_state_root: Hash, // State root after epoch

    // Delta statistics
    account_count: u32, // Number of accounts modified
    storage_count: u32, // Number of storage slots modified
    tx_count: u64, // Total transactions in epoch
    gas_used: u128, // Total gas used

    // Aggregated signature
    aggregated_sig: [96]u8, // BLS aggregated signature
    signers_bitmap: []u8, // Bitmap of validators who signed

    // Compression info
    compressed_size: u32, // Size of compressed delta
    uncompressed_size: u32, // Original size for validation

    pub fn serialize(self: *const EpochMetadata, allocator: Allocator) ![]u8 {
        // Fixed-size header + variable signers bitmap
        const header_size = 8 + 8 + 8 + 8 + 8 + 32 + 32 + 4 + 4 + 8 + 16 + 96 + 4 + 4 + 4;
        const total_size = header_size + self.signers_bitmap.len;

        const buffer = try allocator.alloc(u8, total_size);
        var offset: usize = 0;

        // Write fields in order
        std.mem.writeInt(u64, buffer[offset..][0..8], self.epoch_number, .big);
        offset += 8;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.start_block, .big);
        offset += 8;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.end_block, .big);
        offset += 8;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.start_timestamp, .big);
        offset += 8;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.end_timestamp, .big);
        offset += 8;

        @memcpy(buffer[offset..][0..32], &self.pre_state_root);
        offset += 32;
        @memcpy(buffer[offset..][0..32], &self.post_state_root);
        offset += 32;

        std.mem.writeInt(u32, buffer[offset..][0..4], self.account_count, .big);
        offset += 4;
        std.mem.writeInt(u32, buffer[offset..][0..4], self.storage_count, .big);
        offset += 4;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.tx_count, .big);
        offset += 8;
        std.mem.writeInt(u128, buffer[offset..][0..16], self.gas_used, .big);
        offset += 16;

        @memcpy(buffer[offset..][0..96], &self.aggregated_sig);
        offset += 96;

        std.mem.writeInt(u32, buffer[offset..][0..4], self.compressed_size, .big);
        offset += 4;
        std.mem.writeInt(u32, buffer[offset..][0..4], self.uncompressed_size, .big);
        offset += 4;

        // Variable-length signers bitmap
        std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(self.signers_bitmap.len), .big);
        offset += 4;
        @memcpy(buffer[offset..], self.signers_bitmap);

        return buffer;
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !EpochMetadata {
        if (data.len < 216) return error.InvalidData;

        var offset: usize = 0;
        var meta: EpochMetadata = undefined;

        meta.epoch_number = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        meta.start_block = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        meta.end_block = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        meta.start_timestamp = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        meta.end_timestamp = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;

        @memcpy(&meta.pre_state_root, data[offset..][0..32]);
        offset += 32;
        @memcpy(&meta.post_state_root, data[offset..][0..32]);
        offset += 32;

        meta.account_count = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;
        meta.storage_count = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;
        meta.tx_count = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        meta.gas_used = std.mem.readInt(u128, data[offset..][0..16], .big);
        offset += 16;

        @memcpy(&meta.aggregated_sig, data[offset..][0..96]);
        offset += 96;

        meta.compressed_size = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;
        meta.uncompressed_size = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;

        const bitmap_len = std.mem.readInt(u32, data[offset..][0..4], .big);
        offset += 4;

        if (offset + bitmap_len > data.len) return error.InvalidData;
        meta.signers_bitmap = try allocator.dupe(u8, data[offset..][0..bitmap_len]);

        return meta;
    }

    pub fn deinit(self: *EpochMetadata, allocator: Allocator) void {
        if (self.signers_bitmap.len > 0) {
            allocator.free(self.signers_bitmap);
        }
    }
};

/// Aggregated epoch - the complete compressed epoch data
pub const AggregatedEpoch = struct {
    metadata: EpochMetadata,
    compressed_delta: []u8, // Zstd compressed state delta

    // Transaction summary (not individual txs)
    net_transfers: []NetTransfer, // Aggregated transfers

    pub const NetTransfer = struct {
        from: Address,
        to: Address,
        total_value: u256, // Sum of all transfers from→to in epoch
        tx_count: u32, // Number of transactions
    };

    pub fn deinit(self: *AggregatedEpoch, allocator: Allocator) void {
        self.metadata.deinit(allocator);
        if (self.compressed_delta.len > 0) {
            allocator.free(self.compressed_delta);
        }
        if (self.net_transfers.len > 0) {
            allocator.free(self.net_transfers);
        }
    }

    /// Validate epoch integrity
    pub fn validate(self: *const AggregatedEpoch) !void {
        // Check metadata consistency
        if (self.metadata.end_block < self.metadata.start_block) {
            return error.InvalidBlockRange;
        }
        if (self.metadata.end_block - self.metadata.start_block + 1 > EPOCH_SIZE) {
            return error.EpochTooLarge;
        }
        if (self.metadata.compressed_size > MAX_DELTA_SIZE) {
            return error.DeltaTooLarge;
        }
        if (self.compressed_delta.len != self.metadata.compressed_size) {
            return error.SizeMismatch;
        }
    }
};

/// Block summary - minimal data retained per block within epoch
pub const BlockSummary = struct {
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    state_root: Hash,
    tx_root: Hash,
    receipts_root: Hash,
    timestamp: u64,
    gas_used: u64,
    gas_limit: u64,
    base_fee: u64,

    // Signature data
    proposer: Address,
    signature: [96]u8, // Individual BLS signature

    pub fn fromHeader(header: anytype) BlockSummary {
        // Compute header hash from verkleRoot (approximation without full RLP encoding)
        var header_hash: Hash = [_]u8{0} ** 32;
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{}); // wait, used Sha256 earlier, wait, let's see
        hasher.update(&header.verkleRoot.bytes);
        hasher.update(std.mem.asBytes(&header.number));
        hasher.update(std.mem.asBytes(&header.time));
        var hash_res: [32]u8 = undefined;
        hasher.final(&hash_res);
        header_hash = hash_res;

        return BlockSummary{
            .number = header.number,
            .hash = header_hash,
            .parent_hash = header.parentHash.bytes,
            .state_root = header.verkleRoot.bytes, // Use verkleRoot as state root
            .tx_root = header.txHash.bytes,
            .receipts_root = [_]u8{0} ** 32, // Not available in header
            .timestamp = header.time, // time field maps to timestamp
            .gas_used = header.gasUsed,
            .gas_limit = header.gasLimit,
            .base_fee = @truncate(header.baseFee), // Truncate u256 to u64
            .proposer = header.coinbase.bytes, // coinbase maps to proposer
            .signature = [_]u8{0} ** 96, // Signature not available in basic header
        };
    }
};

// Tests
test "AccountDelta merge" {
    var d1 = AccountDelta{
        .address = [_]u8{1} ** 20,
        .balance_delta = 100,
        .nonce_delta = 1,
        .code_hash = [_]u8{0} ** 32,
    };

    const d2 = AccountDelta{
        .address = [_]u8{1} ** 20,
        .balance_delta = -50,
        .nonce_delta = 1,
        .code_hash = [_]u8{0xAB} ** 32,
    };

    d1.merge(&d2);

    try std.testing.expectEqual(@as(i128, 50), d1.balance_delta);
    try std.testing.expectEqual(@as(i64, 2), d1.nonce_delta);
    try std.testing.expectEqual([_]u8{0xAB} ** 32, d1.code_hash);
}

test "EpochMetadata serialization" {
    const allocator = std.testing.allocator;

    var meta = EpochMetadata{
        .epoch_number = 42,
        .start_block = 4200000,
        .end_block = 4299999,
        .start_timestamp = 1700000000,
        .end_timestamp = 1700100000,
        .pre_state_root = [_]u8{0xAA} ** 32,
        .post_state_root = [_]u8{0xBB} ** 32,
        .account_count = 50000,
        .storage_count = 100000,
        .tx_count = 1000000,
        .gas_used = 30000000000000,
        .aggregated_sig = [_]u8{0xCC} ** 96,
        .signers_bitmap = try allocator.dupe(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }),
        .compressed_size = 1024,
        .uncompressed_size = 4096,
    };
    defer meta.deinit(allocator);

    const serialized = try meta.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try EpochMetadata.deserialize(allocator, serialized);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(meta.epoch_number, deserialized.epoch_number);
    try std.testing.expectEqual(meta.start_block, deserialized.start_block);
    try std.testing.expectEqual(meta.tx_count, deserialized.tx_count);
}
