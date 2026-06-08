const std = @import("std");

pub const Address = extern struct {
    bytes: [32]u8,

    pub fn zero() Address {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn format(self: Address, writer: anytype) !void {
        var buf: [66]u8 = undefined;
        _ = @import("utils").hex.encodeBuffer(&buf, &self.bytes) catch unreachable;
        try writer.writeAll(&buf);
    }

    pub fn eql(self: Address, other: Address) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

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
};

pub const Header = struct {
    parentHash: Hash,
    number: u64,
    time: u64,
    stateRoot: Hash,
    txHash: Hash,
    producer: Address,
    extraData: []const u8,
    executionBudget: u64,
    gasUsed: u64,
    quorumCertificate: ?QuorumCertificate = null,

    pub fn deinit(self: Header, allocator: std.mem.Allocator) void {
        allocator.free(self.extraData);
    }
};

/// BLS aggregate signature from 2/3+ validators, attesting to a block.
/// Never included in Block.hash() (QC signs the hash, so it cannot be part of it).
/// Block.hash() includes only this many bytes of extraData.
/// The remaining bytes (if any) carry the BLS block signature
/// and would create a circular dependency if included in the hash.
pub const EXTRA_DATA_HASH_LEN: usize = 96;

pub const QuorumCertificate = struct {
    /// Aggregate BLS signature from voting validators (96 bytes, G2 compressed)
    aggregateSignature: [96]u8,
    /// Bitmap of which validator indices signed (up to 256 validators)
    voterBitmap: [32]u8,
};

pub const Transaction = struct {
    pub_key: [32]u8 = [_]u8{0} ** 32,
    from: Address = Address.zero(),
    to: ?Address = null,
    value: u256 = 0,
    executionBudget: u64 = 0,
    gasPrice: u64 = 0,
    sequence: u64 = 0,
    signature: [64]u8 = [_]u8{0} ** 64,
    data: []const u8 = &[_]u8{},

    pub const BinaryFormat = extern struct {
        pub_key: [32]u8,
        target: [32]u8,
        value: [32]u8,
        executionBudget: u64,
        gasPrice: u64,
        sequence: u64,
        signature: [64]u8,
        calldata_len: u32,
    };

    pub fn encodeBinary(self: Transaction, writer: anytype) !void {
        var bf: BinaryFormat = undefined;
        @memcpy(&bf.pub_key, &self.pub_key);
        if (self.to) |t| {
            @memcpy(&bf.target, &t.bytes);
        } else {
            @memset(&bf.target, 0);
        }
        std.mem.writeInt(u256, &bf.value, self.value, .big);
        bf.executionBudget = self.executionBudget;
        bf.gasPrice = self.gasPrice;
        bf.sequence = self.sequence;
        @memcpy(&bf.signature, &self.signature);
        bf.calldata_len = @intCast(self.data.len);

        try writer.writeAll(std.mem.asBytes(&bf));
        try writer.writeAll(self.data);
    }

    pub fn decodeBinary(self: *Transaction, allocator: std.mem.Allocator, bytes: []const u8) !void {
        if (bytes.len < @sizeOf(BinaryFormat)) return error.InvalidLength;
        const bf = std.mem.bytesAsValue(BinaryFormat, bytes[0..@sizeOf(BinaryFormat)]);
        const calldata = bytes[@sizeOf(BinaryFormat)..];
        if (calldata.len != bf.calldata_len) return error.InvalidLength;

        self.pub_key = bf.pub_key;
        std.crypto.hash.Blake3.hash(&bf.pub_key, &self.from.bytes, .{});

        var all_zeros = true;
        for (bf.target) |b| {
            if (b != 0) {
                all_zeros = false;
                break;
            }
        }
        if (all_zeros) {
            self.to = null;
        } else {
            self.to = Address{ .bytes = bf.target };
        }
        self.value = std.mem.readInt(u256, &bf.value, .big);
        self.executionBudget = bf.executionBudget;
        self.gasPrice = bf.gasPrice;
        self.sequence = bf.sequence;
        self.signature = bf.signature;
        self.data = try allocator.dupe(u8, calldata);
    }

    pub fn decodeBinaryZeroCopy(self: *Transaction, bytes: []const u8) !void {
        if (bytes.len < @sizeOf(BinaryFormat)) return error.InvalidLength;
        const bf = std.mem.bytesAsValue(BinaryFormat, bytes[0..@sizeOf(BinaryFormat)]);
        const calldata = bytes[@sizeOf(BinaryFormat)..];
        if (calldata.len != bf.calldata_len) return error.InvalidLength;

        self.pub_key = bf.pub_key;
        std.crypto.hash.Blake3.hash(&bf.pub_key, &self.from.bytes, .{});

        var all_zeros = true;
        for (bf.target) |b| {
            if (b != 0) {
                all_zeros = false;
                break;
            }
        }
        if (all_zeros) {
            self.to = null;
        } else {
            self.to = Address{ .bytes = bf.target };
        }
        self.value = std.mem.readInt(u256, &bf.value, .big);
        self.executionBudget = bf.executionBudget;
        self.gasPrice = bf.gasPrice;
        self.sequence = bf.sequence;
        self.signature = bf.signature;
        self.data = calldata;
    }

    pub fn getSigningMessage(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        var bf: BinaryFormat = undefined;
        @memcpy(&bf.pub_key, &self.pub_key);
        if (self.to) |t| {
            @memcpy(&bf.target, &t.bytes);
        } else {
            @memset(&bf.target, 0);
        }
        std.mem.writeInt(u256, &bf.value, self.value, .big);
        bf.executionBudget = self.executionBudget;
        bf.gasPrice = self.gasPrice;
        bf.sequence = self.sequence;
        @memset(&bf.signature, 0);
        bf.calldata_len = @intCast(self.data.len);

        const msg = try allocator.alloc(u8, @sizeOf(BinaryFormat) + self.data.len);
        @memcpy(msg[0..@sizeOf(BinaryFormat)], std.mem.asBytes(&bf));
        @memcpy(msg[@sizeOf(BinaryFormat)..], self.data);
        return msg;
    }

    pub fn hash(self: *const Transaction) Hash {
        var h_res = Hash.zero();
        var hasher = std.crypto.hash.Blake3.init(.{});
        var bf: BinaryFormat = undefined;
        @memcpy(&bf.pub_key, &self.pub_key);
        if (self.to) |t| {
            @memcpy(&bf.target, &t.bytes);
        } else {
            @memset(&bf.target, 0);
        }
        std.mem.writeInt(u256, &bf.value, self.value, .big);
        bf.executionBudget = self.executionBudget;
        bf.gasPrice = self.gasPrice;
        bf.sequence = self.sequence;
        @memcpy(&bf.signature, &self.signature);
        bf.calldata_len = @intCast(self.data.len);

        hasher.update(std.mem.asBytes(&bf));
        hasher.update(self.data);
        hasher.final(&h_res.bytes);
        return h_res;
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn deriveContractAddress(self: *const Transaction) Address {
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(&self.from.bytes);
        var sequenceBuf: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequenceBuf, self.sequence, .big);
        hasher.update(&sequenceBuf);
        var addr: Address = undefined;
        hasher.final(&addr.bytes);
        return addr;
    }
};

pub const Block = struct {
    header: Header,
    transactions: []Transaction,

    pub fn hash(self: *const Block) Hash {
        var h_res = Hash.zero();
        var hasher = std.crypto.hash.Blake3.init(.{});
        var buf8: [8]u8 = undefined;
        hasher.update(&self.header.parentHash.bytes);
        std.mem.writeInt(u64, &buf8, self.header.number, .big);
        hasher.update(&buf8);
        hasher.update(&self.header.stateRoot.bytes);
        hasher.update(&self.header.txHash.bytes);
        std.mem.writeInt(u64, &buf8, self.header.time, .big);
        hasher.update(&buf8);
        hasher.update(&self.header.producer.bytes);
        std.mem.writeInt(u64, &buf8, self.header.executionBudget, .big);
        hasher.update(&buf8);
        std.mem.writeInt(u64, &buf8, self.header.gasUsed, .big);
        hasher.update(&buf8);
        if (self.header.extraData.len > 0) {
            const hash_len = @min(self.header.extraData.len, EXTRA_DATA_HASH_LEN);
            hasher.update(self.header.extraData[0..hash_len]);
        }
        // NOTE: quorumCertificate is deliberately excluded — QC signs this hash,
        // so it cannot be part of the hash itself (circular dependency).
        for (self.transactions) |*tx| {
            const tx_hash = tx.hash();
            hasher.update(&tx_hash.bytes);
        }
        hasher.final(&h_res.bytes);
        return h_res;
    }

    pub fn deinit(self: Block, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        for (self.transactions) |tx| {
            tx.deinit(allocator);
        }
        allocator.free(self.transactions);
    }
};

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
    gasUsed: u64,
    fee: u256,
    errorMessage: ?[]const u8,
    receipts: []CreditReceipt,
    deltas: []AccumulatorDelta,
};
