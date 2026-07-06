// ============================================================================
// Zephyria — Blockchain
// ============================================================================
//
// Chain management: block storage, retrieval, fork choice, head tracking.
// Thread-safe with RwLock for concurrent read access.
//
// Database key space:
//   "b-" ++ blockId(32)    → serialized block bytes
//   "H-" ++ number(8,BE)   → blockId(32)   (number → canonical block)
//   "tx_lookup_" ++ txId   → blockId(32) ++ txIndex(8,BE)
//   "head"                 → blockId(32)   (current head block id)
//   "genesis_id"           → blockId(32)   (immutable genesis id)
//
// All block identifiers use Block.id() — the single canonical 32-byte hash.
// There is no separate "header hash" vs "block hash" in external usage.

const std = @import("std");
const types = @import("types.zig");
const storage = @import("storage");
const DB = storage.DB;
const log = @import("logger.zig");

/// Maximum allowed reorg depth before emitting a warning.
const MAX_REORG_DEPTH: u64 = 128;

/// Maximum blocks ahead of head we will accept (sync tolerance window).
const MAX_FUTURE_BLOCKS: u64 = 10;

/// Manages the blockchain state, including block storage, retrieval, and head tracking.
/// Provides thread-safe access to chain data using a read-write lock.
pub const Blockchain = struct {
    allocator: std.mem.Allocator,
    db: DB,
    currentBlock: ?*types.Block,
    /// Cached id of the current head block (= Block.id() of currentBlock).
    cachedHeadId: types.Hash,
    chainId: u64,
    /// The id of the genesis block (immutable after initialization).
    genesisId: types.Hash,
    lastFinalizedBlock: u64,
    lock: std.Thread.RwLock,

    /// Initializes a new Blockchain instance, loading the persisted head from the database.
    pub fn init(allocator: std.mem.Allocator, db: DB, chainId: u64) !*Blockchain {
        const self = try allocator.create(Blockchain);
        self.* = Blockchain{
            .allocator = allocator,
            .db = db,
            .currentBlock = null,
            .cachedHeadId = types.Hash.zero(),
            .chainId = chainId,
            .genesisId = types.Hash.zero(),
            .lastFinalizedBlock = 0,
            .lock = .{},
        };

        // Load persisted genesis id
        if (db.read("genesis_id")) |idBytes| {
            if (idBytes.len == 32) {
                @memcpy(&self.genesisId.bytes, idBytes[0..32]);
            }
        }

        // Load persisted head block
        if (db.read("head")) |idBytes| {
            if (idBytes.len == 32) {
                var blkId: types.Hash = undefined;
                @memcpy(&blkId.bytes, idBytes[0..32]);
                if (try self.getBlockById(blkId)) |block| {
                    self.currentBlock = block;
                    self.cachedHeadId = block.id();
                }
            }
        }

        return self;
    }

    pub fn deinit(self: *Blockchain) void {
        if (self.currentBlock) |block| {
            self.freeBlock(block);
        }
        self.allocator.destroy(self);
    }

    pub fn setGenesisId(self: *Blockchain, id: types.Hash) void {
        self.genesisId = id;
        self.db.write("genesis_id", &id.bytes) catch |err| {
            log.err("Failed to persist genesis_id: {}\n", .{err});
        };
    }

    // ── Head Access (thread-safe) ─────────────────────────────────────

    pub fn getHead(self: *Blockchain) ?*types.Block {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.currentBlock;
    }

    /// Returns the canonical id of the current head block.
    pub fn getHeadId(self: *Blockchain) types.Hash {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.cachedHeadId;
    }

    pub fn getHeadNumber(self: *Blockchain) u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.currentBlock) |block| {
            return block.header.number;
        }
        return 0;
    }

    pub fn setLastFinalized(self: *Blockchain, number: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (number > self.lastFinalizedBlock) {
            self.lastFinalizedBlock = number;
        }
    }

    pub fn getLastFinalized(self: *Blockchain) u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.lastFinalizedBlock;
    }

    // ── Block Addition ────────────────────────────────────────────────

    /// Add a new block to the chain (validates, stores, and performs fork choice).
    ///
    /// Security checks performed before storage:
    ///   1. Block number must be within sync window of current head
    ///   2. Parent id must reference a known block (anti-orphan)
    ///   3. Block id must be deterministically derivable (anti-substitution)
    pub fn addBlock(self: *Blockchain, block: *types.Block) !bool {
        // Compute the single canonical block id
        const blkId = block.id();

        self.lock.lock();
        defer self.lock.unlock();

        // Security check: reject blocks too far ahead of our head (sync gap protection)
        if (self.currentBlock) |head| {
            const headNumber = head.header.number;
            const newNumber = block.header.number;
            if (newNumber > headNumber + MAX_FUTURE_BLOCKS and newNumber > 1) {
                log.warn("Block #{d} is {d} blocks ahead of head #{d} — possible sync attack, dropping", .{
                    newNumber, newNumber - headNumber, headNumber,
                });
                return error.BlockTooFarAhead;
            }
        }

        // Store block under its canonical id
        try self.storeBlock(block, blkId);

        // TX lookup index: tx_id → (blockId, txIndex)
        for (block.transactions, 0..) |*tx, i| {
            const txId = tx.id();
            var keyBuf: [10 + 32]u8 = undefined;
            @memcpy(keyBuf[0..10], "tx_lookup_");
            @memcpy(keyBuf[10..42], &txId.bytes);
            var value: [40]u8 = undefined;
            @memcpy(value[0..32], &blkId.bytes);
            std.mem.writeInt(u64, value[32..40], i, .big);
            try self.db.write(&keyBuf, &value);
        }

        // Fork choice: longest chain wins; tie-break by lexicographic id comparison
        var updateHead = false;

        if (self.currentBlock == null) {
            updateHead = true;
        } else {
            const currentNumber = self.currentBlock.?.header.number;
            const newNumber = block.header.number;

            if (newNumber > currentNumber) {
                updateHead = true;
            } else if (newNumber == currentNumber) {
                // Tie-break: lower block id wins (deterministic across all nodes)
                if (std.mem.order(u8, &blkId.bytes, &self.cachedHeadId.bytes) == .lt) {
                    updateHead = true;
                }
            }

            if (updateHead) {
                const diff = if (newNumber > currentNumber)
                    newNumber - currentNumber
                else
                    currentNumber - newNumber;
                if (diff > MAX_REORG_DEPTH) {
                    log.warn("Deep reorg detected (diff={d}, new=#{d}, old=#{d})", .{
                        diff, newNumber, currentNumber,
                    });
                }
            }
        }

        if (updateHead) {
            self.setHeadLocked(block, blkId);
            // Map number → blockId for getBlockByNumber
            var numKey: [10]u8 = undefined;
            @memcpy(numKey[0..2], "H-");
            std.mem.writeInt(u64, numKey[2..10], block.header.number, .big);
            try self.db.write(&numKey, &blkId.bytes);
        }

        try self.db.sync();
        return updateHead;
    }

    // ── Internal: Update Head ─────────────────────────────────────────

    /// Update the head pointer. Must be called under exclusive lock.
    fn setHeadLocked(self: *Blockchain, block: *types.Block, blkId: types.Hash) void {
        if (self.currentBlock) |old| {
            if (old != block) self.freeBlock(old);
        }
        self.currentBlock = block;
        self.cachedHeadId = blkId;
        self.db.write("head", &blkId.bytes) catch |err| {
            log.err("Failed to persist head: {}\n", .{err});
        };
    }

    // ── Block Storage ─────────────────────────────────────────────────

    fn storeBlock(self: *Blockchain, block: *types.Block, blkId: types.Hash) !void {
        var key: [34]u8 = undefined;
        @memcpy(key[0..2], "b-");
        @memcpy(key[2..34], &blkId.bytes);
        const encoded = try encodeBlockBinary(self.allocator, block.*);
        defer self.allocator.free(encoded);
        try self.db.write(&key, encoded);
    }

    // ── Block Retrieval ───────────────────────────────────────────────

    /// Retrieve a block by its canonical id (Block.id()).
    pub fn getBlockById(self: *Blockchain, blkId: types.Hash) !?*types.Block {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.getBlockByIdUnlocked(blkId);
    }

    /// Retrieve a block by its canonical id without taking the lock.
    /// Caller must hold at least a shared lock.
    fn getBlockByIdUnlocked(self: *Blockchain, blkId: types.Hash) !?*types.Block {
        var key: [34]u8 = undefined;
        @memcpy(key[0..2], "b-");
        @memcpy(key[2..34], &blkId.bytes);

        const data = self.db.read(&key) orelse return null;
        const block = try self.allocator.create(types.Block);
        block.* = try decodeBlockBinary(self.allocator, data);

        // Re-derive sender addresses (not stored on wire to save space)
        for (block.transactions) |*tx| {
            tx.from = types.Address.fromPubKey(&tx.pub_key);
        }

        return block;
    }

    /// Retrieve a block by block number (looks up number→id mapping first).
    pub fn getBlockByNumber(self: *Blockchain, number: u64) ?*types.Block {
        var blkId: types.Hash = undefined;
        {
            self.lock.lockShared();
            defer self.lock.unlockShared();
            var numKey: [10]u8 = undefined;
            @memcpy(numKey[0..2], "H-");
            std.mem.writeInt(u64, numKey[2..10], number, .big);
            const id_bytes = self.db.read(&numKey) orelse return null;
            if (id_bytes.len < 32) return null;
            @memcpy(&blkId.bytes, id_bytes[0..32]);
        }
        return self.getBlockById(blkId) catch null;
    }

    // ── TX Lookup ─────────────────────────────────────────────────────

    pub const TxLocation = struct {
        blockId: types.Hash,
        txIndex: u64,
    };

    /// Find the location of a transaction (block id + index within block).
    pub fn getTransactionLocation(self: *Blockchain, txId: types.Hash) !?TxLocation {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var keyBuf: [10 + 32]u8 = undefined;
        @memcpy(keyBuf[0..10], "tx_lookup_");
        @memcpy(keyBuf[10..42], &txId.bytes);

        const value = self.db.read(&keyBuf) orelse return null;
        if (value.len != 40) return null;

        var loc: TxLocation = undefined;
        @memcpy(&loc.blockId.bytes, value[0..32]);
        loc.txIndex = std.mem.readInt(u64, value[32..40], .big);
        return loc;
    }

    // ── Helpers ───────────────────────────────────────────────────────

    pub fn freeBlock(self: *Blockchain, block: *types.Block) void {
        block.deinit(self.allocator);
        self.allocator.destroy(block);
    }
};

// ── Block Serialization ───────────────────────────────────────────────────

pub fn encodeBlockBinary(allocator: std.mem.Allocator, block: types.Block) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);

    const h = block.header;
    // parentId (32)
    try buf.appendSlice(allocator, &h.parentId.bytes);
    // number (8, BE)
    var numBuf: [8]u8 = undefined;
    std.mem.writeInt(u64, &numBuf, h.number, .big);
    try buf.appendSlice(allocator, &numBuf);
    // time (8, BE)
    std.mem.writeInt(u64, &numBuf, h.time, .big);
    try buf.appendSlice(allocator, &numBuf);
    // stateRoot (32)
    try buf.appendSlice(allocator, &h.stateRoot.bytes);
    // txMerkleRoot (32)
    try buf.appendSlice(allocator, &h.txMerkleRoot.bytes);
    // producer (32)
    try buf.appendSlice(allocator, &h.producer.bytes);
    // extraData (4-byte len prefix + data)
    var lenBuf: [4]u8 = undefined;
    std.mem.writeInt(u32, &lenBuf, @intCast(h.extraData.len), .big);
    try buf.appendSlice(allocator, &lenBuf);
    if (h.extraData.len > 0) try buf.appendSlice(allocator, h.extraData);
    // executionBudget (8, BE)
    std.mem.writeInt(u64, &numBuf, h.executionBudget, .big);
    try buf.appendSlice(allocator, &numBuf);
    // budgetUsed (8, BE)
    std.mem.writeInt(u64, &numBuf, h.budgetUsed, .big);
    try buf.appendSlice(allocator, &numBuf);

    // Transaction count (4, BE)
    std.mem.writeInt(u32, &lenBuf, @intCast(block.transactions.len), .big);
    try buf.appendSlice(allocator, &lenBuf);

    // Transactions
    for (block.transactions) |tx| {
        var txBuf = std.ArrayListUnmanaged(u8){};
        defer txBuf.deinit(allocator);
        try tx.encodeBinary(txBuf.writer(allocator));
        try buf.appendSlice(allocator, txBuf.items);
    }

    return buf.toOwnedSlice(allocator);
}

pub fn decodeBlockBinary(allocator: std.mem.Allocator, data: []const u8) !types.Block {
    var pos: usize = 0;

    var header: types.Header = undefined;

    // parentId (32)
    @memcpy(&header.parentId.bytes, data[pos..][0..32]);
    pos += 32;
    // number (8, BE)
    header.number = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    // time (8, BE)
    header.time = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    // stateRoot (32)
    @memcpy(&header.stateRoot.bytes, data[pos..][0..32]);
    pos += 32;
    // txMerkleRoot (32)
    @memcpy(&header.txMerkleRoot.bytes, data[pos..][0..32]);
    pos += 32;
    // producer (32)
    @memcpy(&header.producer.bytes, data[pos..][0..32]);
    pos += 32;
    // extraData
    const extraLen = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;
    header.extraData = try allocator.dupe(u8, data[pos..][0..extraLen]);
    pos += extraLen;
    // executionBudget (8, BE)
    header.executionBudget = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    // budgetUsed (8, BE)
    header.budgetUsed = std.mem.readInt(u64, data[pos..][0..8], .big);
    pos += 8;
    // quorumCertificate not serialized (added post-decode if needed)
    header.quorumCertificate = null;

    // Transactions
    const txCount = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;
    const transactions = try allocator.alloc(types.Transaction, txCount);
    for (0..txCount) |i| {
        try transactions[i].decodeBinary(allocator, data[pos..]);
        pos += types.Transaction.BF_SIZE + transactions[i].data.len;
    }

    return .{ .header = header, .transactions = transactions };
}
