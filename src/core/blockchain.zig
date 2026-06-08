// ============================================================================
// Zephyria — Blockchain
// ============================================================================
//
// Chain management: block storage, retrieval, fork choice, head tracking.
// Thread-safe with RwLock for concurrent read access.

const std = @import("std");
const types = @import("types.zig");
const storage = @import("storage");
const DB = storage.DB;
const log = @import("logger.zig");

/// Manages the blockchain state, including block storage, retrieval, and head tracking.
/// Provides thread-safe access to the chain data using a read-write lock.
pub const Blockchain = struct {
    allocator: std.mem.Allocator,
    db: DB,
    currentBlock: ?*types.Block,
    cachedHeadHash: types.Hash,
    chainId: u64,
    genesisHash: types.Hash,
    lock: std.Thread.RwLock,

    /// Initializes a new Blockchain instance, loading the persisted head from the database.
    pub fn init(allocator: std.mem.Allocator, db: DB, chainId: u64) !*Blockchain {
        const self = try allocator.create(Blockchain);
        self.* = Blockchain{
            .allocator = allocator,
            .db = db,
            .currentBlock = null,
            .cachedHeadHash = types.Hash.zero(),
            .chainId = chainId,
            .genesisHash = types.Hash.zero(),
            .lock = .{},
        };

        // Load persisted head
        if (db.read("head")) |hashBytes| {
            if (hashBytes.len == 32) {
                var hash: types.Hash = undefined;
                @memcpy(&hash.bytes, hashBytes[0..32]);
                if (try self.getBlockByHash(hash)) |block| {
                    self.currentBlock = block;
                    self.cachedHeadHash = block.hash();
                }
            }
        }

        // Load genesis hash
        var genKey: [10]u8 = undefined;
        @memcpy(genKey[0..2], "H-");
        std.mem.writeInt(u64, genKey[2..10], 0, .big);
        if (db.read(&genKey)) |hashBytes| {
            if (hashBytes.len == 32) {
                @memcpy(&self.genesisHash.bytes, hashBytes[0..32]);
            }
        }

        return self;
    }

    /// Deinitializes the Blockchain instance and frees the current head block.
    pub fn deinit(self: *Blockchain) void {
        if (self.currentBlock) |block| {
            self.freeBlock(block);
        }
        self.allocator.destroy(self);
    }

    pub fn setGenesisHash(self: *Blockchain, hash: types.Hash) void {
        self.genesisHash = hash;
    }

    /// Returns the current head block of the chain.
    pub fn getHead(self: *Blockchain) ?*types.Block {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.currentBlock;
    }

    /// Returns the hash of the current head block.
    pub fn getHeadHash(self: *Blockchain) types.Hash {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.cachedHeadHash;
    }

    /// Returns the block number of the current head block.
    pub fn getHeadNumber(self: *Blockchain) u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.currentBlock) |block| {
            return block.header.number;
        }
        return 0;
    }

    /// Internal: update the head pointer. Must be called under exclusive lock.
    /// Frees the previous head block if it differs from the new one.
    fn setHeadLocked(self: *Blockchain, block: *types.Block, blockHash: types.Hash) void {
        if (self.currentBlock) |old| {
            if (old != block) self.freeBlock(old);
        }
        self.currentBlock = block;
        self.cachedHeadHash = blockHash;
        self.db.write("head", &blockHash.bytes) catch {};
    }

    /// Frees the memory associated with a block.
    pub fn freeBlock(self: *Blockchain, block: *types.Block) void {
        block.deinit(self.allocator);
        self.allocator.destroy(block);
    }

    /// Add a block to the chain (validates and stores)
    /// Adds a new block to the chain, updates the transaction index, and performs fork choice.
    pub fn addBlock(self: *Blockchain, block: *types.Block) !void {
        // Cache the block hash once before taking the lock — avoids repeated
        // hashing (which allocates internally) while holding the write lock.
        const blkHash = block.hash();

        self.lock.lock();
        defer self.lock.unlock();

        try self.storeBlock(block);

        // TX lookup index
        for (block.transactions, 0..) |*tx, i| {
            const txHash = tx.hash();
            var hexBuf: [128]u8 = undefined;
            const hexStr = try @import("utils").hex.encodeBuffer(&hexBuf, &txHash.bytes);
            const key = try std.fmt.allocPrint(self.allocator, "tx_lookup_{s}", .{hexStr});
            defer self.allocator.free(key);
            var value: [40]u8 = undefined;
            @memcpy(value[0..32], &blkHash.bytes);
            std.mem.writeInt(u64, value[32..40], i, .big);
            try self.db.write(key, &value);
        }

        // Fork choice: longest chain with reorg guard
        var updateHead = false;
        const MAX_REORG_DEPTH = 128;

        if (self.currentBlock == null) {
            updateHead = true;
        } else {
            const currentNumber = self.currentBlock.?.header.number;
            const newNumber = block.header.number;

            if (newNumber > currentNumber) {
                updateHead = true;
            } else if (newNumber == currentNumber) {
                if (std.mem.order(u8, &blkHash.bytes, &self.cachedHeadHash.bytes) == .gt) {
                    updateHead = true;
                }
            }

            if (updateHead and self.currentBlock != null) {
                const diff = if (newNumber > currentNumber) newNumber - currentNumber else currentNumber - newNumber;
                if (diff > MAX_REORG_DEPTH) {
                    log.warn("Deep reorg or sync jump detected (diff={d})", .{diff});
                }
            }
        }

        if (updateHead) {
            self.setHeadLocked(block, blkHash);
            var key: [10]u8 = undefined;
            @memcpy(key[0..2], "H-");
            std.mem.writeInt(u64, key[2..10], block.header.number, .big);
            try self.db.write(&key, &blkHash.bytes);
        }

        try self.db.sync();
    }

    fn storeBlock(self: *Blockchain, block: *types.Block) !void {
        const h = block.hash();
        var key: [34]u8 = undefined;
        @memcpy(key[0..2], "b-");
        @memcpy(key[2..34], &h.bytes);
        const encoded = try encodeBlockBinary(self.allocator, block.*);
        defer self.allocator.free(encoded);
        try self.db.write(&key, encoded);
    }

    /// Retrieves a block from the database by its cryptographic hash.
    pub fn getBlockByHash(self: *Blockchain, hash: types.Hash) !?*types.Block {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var key: [34]u8 = undefined;
        @memcpy(key[0..2], "b-");
        @memcpy(key[2..34], &hash.bytes);

        const data = self.db.read(&key) orelse return null;
        const block = try self.allocator.create(types.Block);
        block.* = try decodeBlockBinary(self.allocator, data);

        // Recover sender addresses
        const tx_decode = @import("tx_decode.zig");
        for (block.transactions) |*tx| {
            tx.from = tx_decode.recoverFromTx(self.allocator, tx.*) catch |e| return e;
        }

        return block;
    }

    /// Retrieves a block from the database by its block number.
    pub fn getBlockByNumber(self: *Blockchain, number: u64) ?*types.Block {
        var hash: types.Hash = undefined;
        {
            self.lock.lockShared();
            defer self.lock.unlockShared();
            var key: [10]u8 = undefined;
            @memcpy(key[0..2], "H-");
            std.mem.writeInt(u64, key[2..10], number, .big);
            const hash_bytes = self.db.read(&key) orelse return null;
            @memcpy(&hash.bytes, hash_bytes[0..32]);
        }
        return self.getBlockByHash(hash) catch null;
    }

    pub const TxLocation = struct {
        blockHash: types.Hash,
        txIndex: u64,
    };

    /// Finds the location of a transaction (block hash and index) given its hash.
    pub fn getTransactionLocation(self: *Blockchain, txHash: types.Hash) !?TxLocation {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var hexBuf: [128]u8 = undefined;
        const hexStr = try @import("utils").hex.encodeBuffer(&hexBuf, &txHash.bytes);
        const key = try std.fmt.allocPrint(self.allocator, "tx_lookup_{s}", .{hexStr});
        defer self.allocator.free(key);

        if (self.db.read(key)) |value| {
            if (value.len != 40) return null;
            var loc: TxLocation = undefined;
            @memcpy(&loc.blockHash.bytes, value[0..32]);
            loc.txIndex = std.mem.readInt(u64, value[32..40], .big);
            return loc;
        }
        return null;
    }
};

fn encodeBlockBinary(allocator: std.mem.Allocator, block: types.Block) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);

    const h = block.header;
    try buf.appendSlice(allocator, &h.parentHash.bytes);
    var numBuf: [8]u8 = undefined;
    std.mem.writeInt(u64, &numBuf, h.number, .big);
    try buf.appendSlice(allocator, &numBuf);
    std.mem.writeInt(u64, &numBuf, h.time, .big);
    try buf.appendSlice(allocator, &numBuf);
    try buf.appendSlice(allocator, &h.stateRoot.bytes);
    try buf.appendSlice(allocator, &h.txHash.bytes);
    try buf.appendSlice(allocator, &h.producer.bytes);
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, @intCast(h.extraData.len), .big);
    try buf.appendSlice(allocator, &lenBuf);
    if (h.extraData.len > 0) try buf.appendSlice(allocator, h.extraData);
    std.mem.writeInt(u64, &numBuf, h.executionBudget, .big);
    try buf.appendSlice(allocator, &numBuf);
    std.mem.writeInt(u64, &numBuf, h.gasUsed, .big);
    try buf.appendSlice(allocator, &numBuf);

    std.mem.writeInt(u32, &lenBuf, @intCast(block.transactions.len), .big);
    try buf.appendSlice(allocator, &lenBuf);
    for (block.transactions) |tx| {
        var txBuf = std.ArrayListUnmanaged(u8){};
        defer txBuf.deinit(allocator);
        try tx.encodeBinary(txBuf.writer(allocator));
        try buf.appendSlice(allocator, txBuf.items);
    }

    return buf.toOwnedSlice(allocator);
}

fn decodeBlockBinary(allocator: std.mem.Allocator, data: []const u8) !types.Block {
    var pos: usize = 0;

    var header: types.Header = undefined;
    @memcpy(&header.parentHash.bytes, data[pos..][0..32]);
    pos += 32;
    header.number = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    header.time = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    @memcpy(&header.stateRoot.bytes, data[pos..][0..32]);
    pos += 32;
    @memcpy(&header.txHash.bytes, data[pos..][0..32]);
    pos += 32;
    @memcpy(&header.producer.bytes, data[pos..][0..32]);
    pos += 32;
    const extraLen = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;
    header.extraData = try allocator.dupe(u8, data[pos..][0..extraLen]);
    pos += extraLen;
    header.executionBudget = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    header.gasUsed = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;

    const txCount = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;
    const transactions = try allocator.alloc(types.Transaction, txCount);
    for (0..txCount) |i| {
        try transactions[i].decodeBinary(allocator, data[pos..]);
        pos += @sizeOf(types.Transaction.BinaryFormat) + transactions[i].data.len;
    }

    return .{ .header = header, .transactions = transactions };
}

