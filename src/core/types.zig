// ============================================================================
// Zephyria — Core Types
// ============================================================================
//
// Foundational data structures for the Zephyria blockchain.
// Zephyria is a native L1 — NOT EVM-based. Key differences:
//   • RISC-V VM execution (not EVM)
//   • DAG-based mempool for tx ordering (no access lists)
//   • Per-slot isolated accounts for zero-conflict parallelism
//   • Native parallel execution — no sequential fallback ever

const std = @import("std");
const rlp = @import("encoding").rlp;

// ── Primitives ──────────────────────────────────────────────────────────

/// Represents a 20-byte account address.
pub const Address = extern struct {
    bytes: [20]u8,

    pub fn zero() Address {
        return .{ .bytes = [_]u8{0} ** 20 };
    }

    pub fn format(self: Address, writer: anytype) !void {
        var buf: [42]u8 = undefined;
        _ = @import("utils").hex.encodeBuffer(&buf, &self.bytes) catch unreachable;
        try writer.writeAll(&buf);
    }

    pub fn eql(self: Address, other: Address) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn decodeFromRLP(self: *Address, allocator: std.mem.Allocator, serialized: []const u8) !usize {
        return try rlp.deserialize([20]u8, allocator, serialized, &self.bytes);
    }

    pub fn encodeToRLP(self: Address, allocator: std.mem.Allocator, listData: *std.ArrayListUnmanaged(u8)) !void {
        try rlp.serialize([20]u8, allocator, self.bytes, listData);
    }
};

/// Represents a 32-byte cryptographic hash (Keccak-256).
pub const Hash = extern struct {
    bytes: [32]u8,

    pub fn zero() Hash {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn format(self: Hash, writer: anytype) !void {
        var buf: [66]u8 = undefined;
        _ = @import("utils").hex.encodeBuffer(&buf, &self.bytes) catch unreachable;
        try writer.writeAll(&buf);
    }

    pub fn eql(self: Hash, other: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn decodeFromRLP(self: *Hash, allocator: std.mem.Allocator, serialized: []const u8) !usize {
        return try rlp.deserialize([32]u8, allocator, serialized, &self.bytes);
    }

    pub fn encodeToRLP(self: Hash, allocator: std.mem.Allocator, listData: *std.ArrayListUnmanaged(u8)) !void {
        try rlp.serialize([32]u8, allocator, self.bytes, listData);
    }
};

// ── Block Header ────────────────────────────────────────────────────────

/// Represents a block header containing metadata and commitments.
pub const Header = struct {
    parentHash: Hash,
    number: u64,
    time: u64,
    verkleRoot: Hash,
    txHash: Hash,
    coinbase: Address,
    extraData: []const u8,
    gasLimit: u64,
    gasUsed: u64,
    baseFee: u256,

    pub fn rlpEncode(self: Header, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayListUnmanaged(u8){};
        defer list.deinit(allocator);
        try self.encodeToRLP(allocator, &list);
        return list.toOwnedSlice(allocator);
    }

    pub fn rlpDecode(allocator: std.mem.Allocator, data: []const u8) !Header {
        var header: Header = undefined;
        _ = try header.decodeFromRLP(allocator, data);
        return header;
    }

    pub fn encodeToRLP(self: Header, allocator: std.mem.Allocator, listData: *std.ArrayListUnmanaged(u8)) !void {
        var inner = std.ArrayListUnmanaged(u8){};
        defer inner.deinit(allocator);
        try self.parentHash.encodeToRLP(allocator, &inner);
        try rlp.serialize(u64, allocator, self.number, &inner);
        try rlp.serialize(u64, allocator, self.time, &inner);
        try self.verkleRoot.encodeToRLP(allocator, &inner);
        try self.txHash.encodeToRLP(allocator, &inner);
        try self.coinbase.encodeToRLP(allocator, &inner);
        try rlp.serialize([]const u8, allocator, self.extraData, &inner);
        try rlp.serialize(u64, allocator, self.gasLimit, &inner);
        try rlp.serialize(u64, allocator, self.gasUsed, &inner);
        try rlp.serialize(u256, allocator, self.baseFee, &inner);
        try rlp.encodeListHeader(allocator, inner.items.len, listData);
        try listData.appendSlice(allocator, inner.items);
    }

    pub fn decodeFromRLP(self: *Header, allocator: std.mem.Allocator, serialized: []const u8) !usize {
        var offset: usize = 0;
        if (serialized.len == 0) return error.Truncated;
        const prefix = serialized[offset];

        var list_len: usize = 0;
        if (prefix >= 0xc0 and prefix <= 0xf7) {
            list_len = @as(usize, prefix - 0xc0);
            offset += 1;
        } else if (prefix >= 0xf8) {
            const ll = @as(usize, prefix - 0xf7);
            if (offset + 1 + ll > serialized.len) return error.Truncated;
            for (serialized[offset + 1 .. offset + 1 + ll]) |b| list_len = (list_len << 8) | b;
            offset += 1 + ll;
        } else {
            return error.ExpectedList;
        }

        if (offset + list_len > serialized.len) return error.Truncated;
        const listData = serialized[offset .. offset + list_len];
        var itemOffset: usize = 0;

        itemOffset += try self.parentHash.decodeFromRLP(allocator, listData[itemOffset..]);
        itemOffset += try rlp.deserialize(u64, allocator, listData[itemOffset..], &self.number);
        itemOffset += try rlp.deserialize(u64, allocator, listData[itemOffset..], &self.time);
        itemOffset += try self.verkleRoot.decodeFromRLP(allocator, listData[itemOffset..]);
        itemOffset += try self.txHash.decodeFromRLP(allocator, listData[itemOffset..]);
        itemOffset += try self.coinbase.decodeFromRLP(allocator, listData[itemOffset..]);
        itemOffset += try rlp.deserialize([]const u8, allocator, listData[itemOffset..], &self.extraData);
        itemOffset += try rlp.deserialize(u64, allocator, listData[itemOffset..], &self.gasLimit);
        itemOffset += try rlp.deserialize(u64, allocator, listData[itemOffset..], &self.gasUsed);
        itemOffset += try rlp.deserialize(u256, allocator, listData[itemOffset..], &self.baseFee);

        return offset + list_len;
    }

    pub fn deinit(self: Header, allocator: std.mem.Allocator) void {
        allocator.free(self.extraData);
    }
};

// ── Transaction ─────────────────────────────────────────────────────────
//
// Zephyria native transaction format. No EVM access lists.
// The DAG-based mempool analyzes account dependencies from tx.from, tx.to,
// and contract storage touch patterns (via static analysis at submission)
// to construct the dependency graph for parallel execution ordering.

/// Represents a Zephyria native transaction.
/// Note: This format does not include EVM-style access lists; dependencies
/// are determined by the DAG mempool.
pub const Transaction = struct {
    nonce: u64,
    gasPrice: u256,
    gasLimit: u64,
    from: Address,
    to: ?Address,
    value: u256,
    data: []const u8,
    v: u256,
    r: u256,
    s: u256,

    /// Serialization format excludes `from` (derived from signature)
    const WireFormat = struct {
        nonce: u64,
        gasPrice: u256,
        gasLimit: u64,
        to: ?Address,
        value: u256,
        data: []const u8,
        v: u256,
        r: u256,
        s: u256,
    };

    pub fn encodeToRLP(self: Transaction, allocator: std.mem.Allocator, listData: *std.ArrayListUnmanaged(u8)) !void {
        const wire = WireFormat{
            .nonce = self.nonce,
            .gasPrice = self.gasPrice,
            .gasLimit = self.gasLimit,
            .to = self.to,
            .value = self.value,
            .data = self.data,
            .v = self.v,
            .r = self.r,
            .s = self.s,
        };
        try rlp.serialize(WireFormat, allocator, wire, listData);
    }

    pub fn decodeFromRLP(self: *Transaction, allocator: std.mem.Allocator, serialized: []const u8) !usize {
        var wire: WireFormat = undefined;
        const consumed = try rlp.deserialize(WireFormat, allocator, serialized, &wire);
        self.* = Transaction{
            .nonce = wire.nonce,
            .gasPrice = wire.gasPrice,
            .gasLimit = wire.gasLimit,
            .from = Address.zero(), // Recovered from signature by caller
            .to = wire.to,
            .value = wire.value,
            .data = wire.data,
            .v = wire.v,
            .r = wire.r,
            .s = wire.s,
        };
        return consumed;
    }

    pub fn hash(self: *const Transaction) Hash {
        var h_res = Hash.zero();
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        const ally = std.heap.page_allocator;
        const encoded = rlp.encode(ally, self.*) catch return h_res;
        defer ally.free(encoded);
        hasher.update(encoded);
        hasher.final(&h_res.bytes);
        return h_res;
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn deriveContractAddress(self: *const Transaction) Address {
        const ally = std.heap.page_allocator;
        const Derivation = struct { from: Address, nonce: u64 };
        const d = Derivation{ .from = self.from, .nonce = self.nonce };
        const encoded = rlp.encode(ally, d) catch return Address.zero();
        defer ally.free(encoded);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(encoded, &h, .{});
        var addr: Address = undefined;
        @memcpy(&addr.bytes, h[12..32]);
        return addr;
    }
};

// ── Block ───────────────────────────────────────────────────────────────

/// Represents a complete block consisting of a header and a list of transactions.
pub const Block = struct {
    header: Header,
    transactions: []Transaction,

    pub fn rlpEncode(self: Block, allocator: std.mem.Allocator) ![]u8 {
        return try rlp.encode(allocator, self);
    }

    pub fn rlpDecode(allocator: std.mem.Allocator, data: []const u8) !Block {
        return try rlp.decode(allocator, Block, data);
    }

    pub fn hash(self: *const Block) Hash {
        var h_res = Hash.zero();
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        const ally = std.heap.page_allocator;
        const encoded = self.header.rlpEncode(ally) catch return h_res;
        defer ally.free(encoded);
        hasher.update(encoded);
        hasher.final(&h_res.bytes);
        return h_res;
    }

    pub fn encodeToRLP(self: Block, allocator: std.mem.Allocator, listData: *std.ArrayListUnmanaged(u8)) !void {
        var inner = std.ArrayListUnmanaged(u8){};
        defer inner.deinit(allocator);

        // 1. Header
        try self.header.encodeToRLP(allocator, &inner);

        // 2. Transactions (List of items)
        var txList = std.ArrayListUnmanaged(u8){};
        defer txList.deinit(allocator);
        for (self.transactions) |tx| {
            try tx.encodeToRLP(allocator, &txList);
        }
        try rlp.encodeListHeader(allocator, txList.items.len, &inner);
        try inner.appendSlice(allocator, txList.items);

        try rlp.encodeListHeader(allocator, inner.items.len, listData);
        try listData.appendSlice(allocator, inner.items);
    }

    pub fn decodeFromRLP(self: *Block, allocator: std.mem.Allocator, serialized: []const u8) !usize {
        var offset: usize = 0;
        if (serialized.len == 0) return error.Truncated;
        const prefix = serialized[offset];

        var list_len: usize = 0;
        if (prefix >= 0xc0 and prefix <= 0xf7) {
            list_len = @as(usize, prefix - 0xc0);
            offset += 1;
        } else if (prefix >= 0xf8) {
            const ll = @as(usize, prefix - 0xf7);
            if (offset + 1 + ll > serialized.len) return error.Truncated;
            for (serialized[offset + 1 .. offset + 1 + ll]) |b| list_len = (list_len << 8) | b;
            offset += 1 + ll;
        } else {
            return error.ExpectedList;
        }

        if (offset + list_len > serialized.len) return error.Truncated;
        const listData = serialized[offset .. offset + list_len];
        var itemOffset: usize = 0;

        // 1. Header
        itemOffset += try self.header.decodeFromRLP(allocator, listData[itemOffset..]);

        // 2. Transactions
        const txPrefix = listData[itemOffset];
        var txList_len: usize = 0;
        var txOffsetStart: usize = 0;
        if (txPrefix >= 0xc0 and txPrefix <= 0xf7) {
            txList_len = @as(usize, txPrefix - 0xc0);
            txOffsetStart = 1;
        } else if (txPrefix >= 0xf8) {
            const tx_ll = @as(usize, txPrefix - 0xf7);
            for (listData[itemOffset + 1 .. itemOffset + 1 + tx_ll]) |b| txList_len = (txList_len << 8) | b;
            txOffsetStart = 1 + tx_ll;
        } else {
            return error.ExpectedList;
        }

        const txData = listData[itemOffset + txOffsetStart .. itemOffset + txOffsetStart + txList_len];
        var tx_itemOffset: usize = 0;
        var txs = std.ArrayListUnmanaged(Transaction){};
        defer txs.deinit(allocator);

        while (tx_itemOffset < txData.len) {
            var tx: Transaction = undefined;
            const consumed = try tx.decodeFromRLP(allocator, txData[tx_itemOffset..]);
            try txs.append(allocator, tx);
            tx_itemOffset += consumed;
        }

        itemOffset += txOffsetStart + txList_len;

        self.transactions = try txs.toOwnedSlice(allocator);
        return offset + list_len;
    }

    pub fn deinit(self: Block, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        for (self.transactions) |tx| {
            tx.deinit(allocator);
        }
        allocator.free(self.transactions);
    }
};

// ── Account Type Classification ─────────────────────────────────────────

/// Classification of account types in the Verkle trie.
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

// ── Slot Classification ─────────────────────────────────────────────────

/// Classification of storage slots for parallel execution analysis.
pub const SlotClassification = enum {
    PerUser,
    Global,
    Immutable,
};

// ── Parallel Execution Types ────────────────────────────────────────────

/// Credit receipt for cross-user state changes during parallel execution.
/// Phase 1 (parallel): each TX produces receipts for effects on OTHER users.
/// Phase 2 (sequential): receipts applied in TX-index order.
pub const CreditReceipt = struct {
    recipient: Address,
    contract: Address,
    slot: [32]u8,
    deltaValue: [32]u8,
    isAddition: bool,
    txIndex: u32,
};

/// Accumulator delta for commutative global state (totalSupply, reserves).
/// These merge order-independently — final result is the same regardless
/// of which thread produced them first.
pub const AccumulatorDelta = struct {
    contract: Address,
    slot: [32]u8,
    deltaValue: [32]u8,
    isAddition: bool,
    txIndex: u32,
};

/// Result of parallel transaction execution
/// Result of parallel transaction execution, including gas usage and state deltas.
pub const ParallelTxResult = struct {
    success: bool,
    gasUsed: u64,
    fee: u256,
    errorMessage: ?[]const u8,
    receipts: []CreditReceipt,
    deltas: []AccumulatorDelta,
};
