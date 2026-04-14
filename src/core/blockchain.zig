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

pub const Blockchain = struct {
    allocator: std.mem.Allocator,
    db: DB,
    current_block: ?*types.Block,
    cached_head_hash: types.Hash,
    chain_id: u64,
    genesis_hash: types.Hash,
    lock: std.Thread.RwLock,

    pub fn init(allocator: std.mem.Allocator, db: DB, chain_id: u64) !*Blockchain {
        const self = try allocator.create(Blockchain);
        self.* = Blockchain{
            .allocator = allocator,
            .db = db,
            .current_block = null,
            .cached_head_hash = types.Hash.zero(),
            .chain_id = chain_id,
            .genesis_hash = types.Hash.zero(),
            .lock = .{},
        };

        // Load persisted head
        if (db.read("head")) |hash_bytes| {
            if (hash_bytes.len == 32) {
                var hash: types.Hash = undefined;
                @memcpy(&hash.bytes, hash_bytes[0..32]);
                if (try self.get_block_by_hash(hash)) |block| {
                    self.current_block = block;
                    self.cached_head_hash = block.hash();
                }
            }
        }

        // Load genesis hash
        var gen_key: [10]u8 = undefined;
        @memcpy(gen_key[0..2], "H-");
        std.mem.writeInt(u64, gen_key[2..10], 0, .big);
        if (db.read(&gen_key)) |hash_bytes| {
            if (hash_bytes.len == 32) {
                @memcpy(&self.genesis_hash.bytes, hash_bytes[0..32]);
            }
        }

        return self;
    }

    pub fn deinit(self: *Blockchain) void {
        if (self.current_block) |block| {
            self.free_block(block);
        }
        self.allocator.destroy(self);
    }

    pub fn set_genesis_hash(self: *Blockchain, hash: types.Hash) void {
        self.genesis_hash = hash;
    }

    pub fn get_head(self: *Blockchain) ?*types.Block {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.current_block;
    }

    pub fn get_head_hash(self: *Blockchain) types.Hash {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.cached_head_hash;
    }

    pub fn get_head_number(self: *Blockchain) u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.current_block) |block| {
            return block.header.number;
        }
        return 0;
    }

    /// Internal: update the head pointer. Must be called under exclusive lock.
    /// Frees the previous head block if it differs from the new one.
    fn set_head_locked(self: *Blockchain, block: *types.Block, block_hash: types.Hash) void {
        if (self.current_block) |old| {
            if (old != block) self.free_block(old);
        }
        self.current_block = block;
        self.cached_head_hash = block_hash;
        self.db.write("head", &block_hash.bytes) catch {};
    }

    pub fn free_block(self: *Blockchain, block: *types.Block) void {
        block.deinit(self.allocator);
        self.allocator.destroy(block);
    }

    /// Add a block to the chain (validates and stores)
    pub fn add_block(self: *Blockchain, block: *types.Block) !void {
        // Cache the block hash once before taking the lock — avoids repeated
        // hashing (which allocates internally) while holding the write lock.
        const blk_hash = block.hash();

        self.lock.lock();
        defer self.lock.unlock();

        try self.store_block(block);

        // TX lookup index
        for (block.transactions, 0..) |*tx, i| {
            const tx_hash = tx.hash();
            var hex_buf: [128]u8 = undefined;
            const hex_str = try @import("utils").hex.encodeBuffer(&hex_buf, &tx_hash.bytes);
            const key = try std.fmt.allocPrint(self.allocator, "tx_lookup_{s}", .{hex_str});
            defer self.allocator.free(key);
            var value: [40]u8 = undefined;
            @memcpy(value[0..32], &blk_hash.bytes);
            std.mem.writeInt(u64, value[32..40], i, .big);
            try self.db.write(key, &value);
        }

        // Fork choice: longest chain with reorg guard
        var update_head = false;
        const MAX_REORG_DEPTH = 128;

        if (self.current_block == null) {
            update_head = true;
        } else {
            const current_number = self.current_block.?.header.number;
            const new_number = block.header.number;

            if (new_number > current_number) {
                update_head = true;
            } else if (new_number == current_number) {
                if (std.mem.order(u8, &blk_hash.bytes, &self.cached_head_hash.bytes) == .gt) {
                    update_head = true;
                }
            }

            if (update_head and self.current_block != null) {
                const diff = if (new_number > current_number) new_number - current_number else current_number - new_number;
                if (diff > MAX_REORG_DEPTH) {
                    log.warn("Deep reorg or sync jump detected (diff={d})", .{diff});
                }
            }
        }

        if (update_head) {
            self.set_head_locked(block, blk_hash);
            var key: [10]u8 = undefined;
            @memcpy(key[0..2], "H-");
            std.mem.writeInt(u64, key[2..10], block.header.number, .big);
            try self.db.write(&key, &blk_hash.bytes);
        }
    }

    fn store_block(self: *Blockchain, block: *types.Block) !void {
        const h = block.hash();
        var key: [34]u8 = undefined;
        @memcpy(key[0..2], "b-");
        @memcpy(key[2..34], &h.bytes);
        const encoded = try @import("encoding").rlp.encode(self.allocator, block.*);
        defer self.allocator.free(encoded);
        try self.db.write(&key, encoded);
    }

    pub fn get_block_by_hash(self: *Blockchain, hash: types.Hash) !?*types.Block {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var key: [34]u8 = undefined;
        @memcpy(key[0..2], "b-");
        @memcpy(key[2..34], &hash.bytes);

        const data = self.db.read(&key) orelse return null;
        const block = try self.allocator.create(types.Block);
        block.* = @import("encoding").rlp.decode(self.allocator, types.Block, data) catch |err| {
            log.err("RLP decode failed for block: {}", .{err});
            self.allocator.destroy(block);
            return null;
        };

        // Recover sender addresses
        const tx_decode = @import("tx_decode.zig");
        for (block.transactions) |*tx| {
            tx.from = tx_decode.recoverFromTx(self.allocator, tx.*) catch |e| return e;
        }

        return block;
    }

    pub fn get_block_by_number(self: *Blockchain, number: u64) ?*types.Block {
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
        return self.get_block_by_hash(hash) catch null;
    }

    /// EIP-1559 base fee calculation
    pub fn calc_base_fee(parent: *const types.Header) u256 {
        const elasticity_multiplier = @as(u64, 2);
        const base_fee_change_denominator = @as(u64, 8);
        const initial_base_fee = @as(u256, 1_000_000_000);

        if (parent.number == 0) return initial_base_fee;
        const parent_gas_target = parent.gas_limit / elasticity_multiplier;

        if (parent.gas_used == parent_gas_target) return parent.base_fee;

        if (parent.gas_used > parent_gas_target) {
            const gas_used_delta = parent.gas_used - parent_gas_target;
            const num = parent.base_fee * @as(u256, gas_used_delta);
            const den = @as(u256, parent_gas_target) * @as(u256, base_fee_change_denominator);
            var delta = num / den;
            if (delta < 1) delta = 1;
            return parent.base_fee + delta;
        } else {
            const gas_unused_delta = parent_gas_target - parent.gas_used;
            const num = parent.base_fee * @as(u256, gas_unused_delta);
            const den = @as(u256, parent_gas_target) * @as(u256, base_fee_change_denominator);
            const delta = num / den;
            const floor = @as(u256, 7);
            if (parent.base_fee > delta + floor) return parent.base_fee - delta;
            return floor;
        }
    }

    pub const TxLocation = struct {
        block_hash: types.Hash,
        tx_index: u64,
    };

    pub fn get_transaction_location(self: *Blockchain, tx_hash: types.Hash) !?TxLocation {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var hex_buf: [128]u8 = undefined;
        const hex_str = try @import("utils").hex.encodeBuffer(&hex_buf, &tx_hash.bytes);
        const key = try std.fmt.allocPrint(self.allocator, "tx_lookup_{s}", .{hex_str});
        defer self.allocator.free(key);

        if (self.db.read(key)) |value| {
            if (value.len != 40) return null;
            var loc: TxLocation = undefined;
            @memcpy(&loc.block_hash.bytes, value[0..32]);
            loc.tx_index = std.mem.readInt(u64, value[32..40], .big);
            return loc;
        }
        return null;
    }
};
