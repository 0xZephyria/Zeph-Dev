// ============================================================================
// Zephyria — World State
// ============================================================================
//
// The State wraps the Verkle trie and provides account-level abstractions.
// All key derivation follows the zero-conflict isolation model:
//   • Each account type gets deterministic, non-overlapping trie keys
//   • Per-user derived keys ensure parallelism for token/DEX operations
//   • Global accumulator keys handle commutative state
//
// The Overlay provides per-transaction journaled state with snapshot/revert
// for atomic execution within a single TX.

const std = @import("std");
const types = @import("types.zig");
const accounts = @import("accounts/mod.zig");
const storage = @import("storage");
const VerkleTrie = storage.verkle.trie.VerkleTrie;

// ── World State ─────────────────────────────────────────────────────────

/// Represents the world state, wrapping the Verkle trie and providing account abstractions.
pub const State = struct {
    allocator: std.mem.Allocator,
    trie: *VerkleTrie,

    /// Initializes a new State instance.
    pub fn init(allocator: std.mem.Allocator, trie: *VerkleTrie) State {
        return State{ .allocator = allocator, .trie = trie };
    }

    /// Deinitializes the State instance.
    pub fn deinit(self: *State) void {
        _ = self;
    }

    // ── Key Derivation (Verkle standard) ────────────────────────────────

    /// Derives the Verkle stem for an address (Keccak256 hash, first 31 bytes).
    pub fn accountStem(addr: types.Address) [31]u8 {
        var h: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&addr.bytes, &h, .{});
        var stem: [31]u8 = undefined;
        @memcpy(&stem, h[0..31]);
        return stem;
    }

    /// Derives the Verkle key for an account's nonce.
    pub fn nonceKey(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &accountStem(addr));
        key[31] = 0x00;
        return key;
    }

    /// Derives the Verkle key for an account's balance.
    pub fn balanceKey(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &accountStem(addr));
        key[31] = 0x01;
        return key;
    }

    pub fn codeHashKey(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &accountStem(addr));
        key[31] = 0x02;
        return key;
    }

    pub fn codeKey(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &accountStem(addr));
        key[31] = 0x03;
        return key;
    }

    /// Legacy storage key: keccak256(address || slot)
    pub fn storageKey(addr: types.Address, slot: [32]u8) [32]u8 {
        return accounts.storage_cell.storageKey(addr, slot);
    }

    /// Per-user derived storage key: keccak256(user || contract || slot)
    pub fn derivedStorageKey(user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
        return accounts.derived.derivedStorageKey(user, contract, slot);
    }

    /// Global accumulator key: keccak256(contract || "global" || slot)
    pub fn globalStorageKey(contract: types.Address, slot: [32]u8) [32]u8 {
        return accounts.derived.globalStorageKey(contract, slot);
    }

    // ── Account API ────────────────────────────────────────────────────

    pub fn getBalance(self: *State, addr: types.Address) u256 {
        const key = balanceKey(addr);
        const data = self.trie.get(key) catch return 0;
        if (data) |d| {
            defer self.allocator.free(d);
            if (d.len < 32) return 0;
            return std.mem.readInt(u256, d[0..32], .big);
        }
        return 0;
    }

    pub fn setBalance(self: *State, addr: types.Address, balance: u256) !void {
        const key = balanceKey(addr);
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u256, &buf, balance, .big);
        try self.trie.put(key, &buf);
    }

    pub fn getNonce(self: *State, addr: types.Address) u64 {
        const key = nonceKey(addr);
        const data = self.trie.get(key) catch return 0;
        if (data) |d| {
            defer self.allocator.free(d);
            if (d.len < 8) return 0;
            return std.mem.readInt(u64, d[0..8], .big);
        }
        return 0;
    }

    pub fn setNonce(self: *State, addr: types.Address, nonce: u64) !void {
        const key = nonceKey(addr);
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, nonce, .big);
        try self.trie.put(key, &buf);
    }

    pub fn getCode(self: *State, addr: types.Address) ![]const u8 {
        const key = codeKey(addr);
        const data = try self.trie.get(key);
        return data orelse &[_]u8{};
    }

    pub fn setCode(self: *State, addr: types.Address, code: []const u8) !void {
        const key = codeKey(addr);
        try self.trie.put(key, code);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(code, &hash, .{});
        try self.trie.put(codeHashKey(addr), &hash);
    }

    /// Adds or subtracts an amount from an account's balance.
    pub fn addBalance(self: *State, addr: types.Address, amount: i256) !void {
        const current = self.getBalance(addr);
        const new_bal = if (amount >= 0) current +% @as(u256, @intCast(amount)) else current -% @as(u256, @intCast(-amount));
        try self.setBalance(addr, new_bal);
    }

    pub fn getStorage(self: *State, addr: types.Address, slot: [32]u8) [32]u8 {
        const key = storageKey(addr, slot);
        const data = self.trie.get(key) catch return [_]u8{0} ** 32;
        if (data) |d| {
            defer self.allocator.free(d);
            if (d.len >= 32) {
                var result: [32]u8 = undefined;
                @memcpy(&result, d[0..32]);
                return result;
            }
        }
        return [_]u8{0} ** 32;
    }

    pub fn setStorage(self: *State, addr: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = storageKey(addr, slot);
        try self.trie.put(key, &value);
    }

    pub fn getVerkleValue(self: *State, key: [32]u8) ?[]const u8 {
        const data = self.trie.get(key) catch return null;
        return data;
    }

    pub fn setVerkleValue(self: *State, key: [32]u8, value: []const u8) !void {
        try self.trie.put(key, value);
    }

    /// Checks if an account contains contract code.
    pub fn isProgramAccount(self: *State, addr: types.Address) bool {
        const key = codeHashKey(addr);
        const data = self.trie.get(key) catch return false;
        if (data) |hash| {
            return accounts.code.CodeAccount.hasCode(types.Hash{ .bytes = hash[0..32].* });
        }
        return false;
    }

    /// Creates a new per-transaction state overlay.
    pub fn newOverlay(self: *State) !Overlay {
        return Overlay.init(self.allocator, self);
    }
};

// ── Overlay (Per-Transaction State) ─────────────────────────────────────
//
// Handles per-transaction state changes with journaled rollback.
// Each TX runs in its own Overlay, which is committed to the base State
// after successful execution. On revert, all changes are unwound.

/// Handles per-transaction state changes with journaled rollback support.
/// Changes are buffered in the overlay and only committed to the base state
/// upon successful transaction completion.
pub const Overlay = struct {
    allocator: std.mem.Allocator,
    base: *State,
    dirty: std.AutoHashMap([32]u8, []const u8),
    journal: std.ArrayListUnmanaged(JournalEntry),
    selfDestructs: std.AutoHashMap(types.Address, void),
    createdAccounts: std.AutoHashMap(types.Address, void),
    transientStorage: std.AutoHashMap(StorageKey, []const u8),
    logs: std.ArrayListUnmanaged(Log),
    refund: u64,

    /// Represents a log entry emitted during transaction execution.
    pub const Log = struct {
        address: types.Address,
        topics: std.ArrayListUnmanaged(types.Hash),
        data: []const u8,

        /// Frees the memory associated with the log entry.
        pub fn deinit(self: *Log, alloc: std.mem.Allocator) void {
            self.topics.deinit(alloc);
            alloc.free(self.data);
        }
    };

    pub const StorageKey = struct { addr: types.Address, key: [32]u8 };

    /// Represents a snapshot identifier for journaling and rollback.
    pub const SnapshotId = struct {
        journalLen: usize,
        logsLen: usize,
    };

    /// Initializes a new Overlay with the given base state.
    pub fn init(allocator: std.mem.Allocator, base: *State) Overlay {
        return Overlay{
            .allocator = allocator,
            .base = base,
            .dirty = std.AutoHashMap([32]u8, []const u8).init(allocator),
            .journal = .{},
            .selfDestructs = std.AutoHashMap(types.Address, void).init(allocator),
            .createdAccounts = std.AutoHashMap(types.Address, void).init(allocator),
            .transientStorage = std.AutoHashMap(StorageKey, []const u8).init(allocator),
            .logs = .{},
            .refund = 0,
        };
    }

    /// Deinitializes the Overlay and frees all buffered changes and journal entries.
    pub fn deinit(self: *Overlay) void {
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.dirty.deinit();

        var tIt = self.transientStorage.iterator();
        while (tIt.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.transientStorage.deinit();

        for (self.logs.items) |*log| {
            log.deinit(self.allocator);
        }
        self.logs.deinit(self.allocator);

        for (self.journal.items) |entry| {
            switch (entry) {
                .storage => |s| if (s.prev) |v| self.allocator.free(v),
                .transientStorage => |s| if (s.prev) |v| self.allocator.free(v),
                .suicide, .refund, .createdAccount => {},
            }
        }
        self.journal.deinit(self.allocator);
        self.selfDestructs.deinit();
        self.createdAccounts.deinit();
    }

    const JournalEntry = union(enum) {
        storage: struct { key: [32]u8, prev: ?[]const u8 },
        transientStorage: struct { key: StorageKey, prev: ?[]const u8 },
        suicide: types.Address,
        refund: u64,
        createdAccount: types.Address,
    };

    pub fn markCreated(self: *Overlay, addr: types.Address) !void {
        if (self.createdAccounts.contains(addr)) return;
        try self.journal.append(self.allocator, .{ .createdAccount = addr });
        try self.createdAccounts.put(addr, {});
    }

    /// Creates a state snapshot that can be reverted to later.
    pub fn snapshot(self: *Overlay) SnapshotId {
        return SnapshotId{
            .journalLen = self.journal.items.len,
            .logsLen = self.logs.items.len,
        };
    }

    /// Reverts all state changes made since the specified snapshot was taken.
    pub fn revertToSnapshot(self: *Overlay, id: SnapshotId) void {
        while (self.journal.items.len > id.journalLen) {
            const entry = self.journal.pop() orelse unreachable;
            switch (entry) {
                .storage => |s| {
                    if (s.prev) |val| {
                        if (self.dirty.get(s.key)) |current| {
                            self.allocator.free(current);
                        }
                        self.dirty.put(s.key, val) catch unreachable;
                    } else {
                        if (self.dirty.fetchRemove(s.key)) |kv| {
                            self.allocator.free(kv.value);
                        }
                    }
                },
                .transientStorage => |s| {
                    if (s.prev) |val| {
                        if (self.transientStorage.get(s.key)) |current| {
                            self.allocator.free(current);
                        }
                        self.transientStorage.put(s.key, val) catch unreachable;
                    } else {
                        if (self.transientStorage.fetchRemove(s.key)) |kv| {
                            self.allocator.free(kv.value);
                        }
                    }
                },
                .suicide => |addr| {
                    _ = self.selfDestructs.remove(addr);
                },
                .refund => |prev| {
                    self.refund = prev;
                },
                .createdAccount => |addr| {
                    _ = self.createdAccounts.remove(addr);
                },
            }
        }

        while (self.logs.items.len > id.logsLen) {
            var logEntry = self.logs.pop();
            logEntry.?.topics.deinit(self.allocator);
            self.allocator.free(logEntry.?.data);
        }
    }

    pub fn estimateSize(self: *Overlay) usize {
        var size: usize = @sizeOf(Overlay);
        size += self.dirty.count() * (@sizeOf([32]u8) + @sizeOf([]const u8));
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            size += entry.value_ptr.len;
        }
        size += self.journal.items.len * @sizeOf(JournalEntry);
        size += self.createdAccounts.count() * @sizeOf(types.Address);
        size += self.transientStorage.count() * (@sizeOf(StorageKey) + @sizeOf([]const u8));
        for (self.logs.items) |log| {
            size += @sizeOf(Log);
            size += log.topics.items.len * @sizeOf(types.Hash);
            size += log.data.len;
        }
        size += self.selfDestructs.count() * @sizeOf(types.Address);
        return size;
    }

    pub fn addRefund(self: *Overlay, amount: u64) !void {
        try self.journal.append(self.allocator, .{ .refund = self.refund });
        self.refund += amount;
    }

    pub fn subRefund(self: *Overlay, amount: u64) !void {
        try self.journal.append(self.allocator, .{ .refund = self.refund });
        self.refund = if (self.refund < amount) 0 else self.refund - amount;
    }

    pub fn suicide(self: *Overlay, addr: types.Address) !void {
        if (self.createdAccounts.contains(addr)) {
            if (self.selfDestructs.contains(addr)) return;
            try self.journal.append(self.allocator, .{ .suicide = addr });
            try self.selfDestructs.put(addr, {});
        }
        try self.setBalance(addr, 0);
    }

    pub fn isSuicided(self: *Overlay, addr: types.Address) bool {
        return self.selfDestructs.contains(addr);
    }

    pub fn getTransientStorage(self: *Overlay, addr: types.Address, key: [32]u8) [32]u8 {
        if (self.transientStorage.get(.{ .addr = addr, .key = key })) |val| {
            var ret: [32]u8 = [_]u8{0} ** 32;
            const len = @min(val.len, 32);
            @memcpy(ret[32 - len ..], val);
            return ret;
        }
        return [_]u8{0} ** 32;
    }

    pub fn setTransientStorage(self: *Overlay, addr: types.Address, key: [32]u8, value: []const u8) !void {
        const sKey = StorageKey{ .addr = addr, .key = key };
        const g = try self.transientStorage.getOrPut(sKey);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .transientStorage = .{ .key = sKey, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, value);
    }

    pub fn addLog(self: *Overlay, log: Log) !void {
        try self.logs.append(self.allocator, log);
    }

    // ── Account Operations ──────────────────────────────────────────────

    pub fn getBalance(self: *Overlay, addr: types.Address) u256 {
        const key = State.balanceKey(addr);
        if (self.dirty.get(key)) |d| {
            return std.mem.readInt(u256, d[0..32], .big);
        }
        return self.base.getBalance(addr);
    }

    pub fn setBalance(self: *Overlay, addr: types.Address, balance: u256) !void {
        const key = State.balanceKey(addr);
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u256, &buf, balance, .big);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, &buf);
    }

    pub fn isProgramAccount(self: *Overlay, addr: types.Address) bool {
        const hash_key = State.codeHashKey(addr);
        if (self.dirty.get(hash_key)) |h| {
            return accounts.code.CodeAccount.hasCode(types.Hash{ .bytes = h[0..32].* });
        }
        return self.base.isProgramAccount(addr);
    }

    pub fn getNonce(self: *Overlay, addr: types.Address) u64 {
        const key = State.nonceKey(addr);
        if (self.dirty.get(key)) |d| {
            return std.mem.readInt(u64, d[0..8], .big);
        }
        return self.base.getNonce(addr);
    }

    pub fn setNonce(self: *Overlay, addr: types.Address, nonce: u64) !void {
        const key = State.nonceKey(addr);
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, nonce, .big);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, &buf);
    }

    pub fn getCode(self: *Overlay, addr: types.Address) ![]const u8 {
        const key = State.codeKey(addr);
        if (self.dirty.get(key)) |d| {
            return try self.allocator.dupe(u8, d);
        }
        return self.base.getCode(addr);
    }

    pub fn setCode(self: *Overlay, addr: types.Address, codeBytes: []const u8) !void {
        const key = State.codeKey(addr);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, codeBytes);

        // Update code hash
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(codeBytes, &hash, .{});
        const hKey = State.codeHashKey(addr);
        const hG = try self.dirty.getOrPut(hKey);
        var hPrev: ?[]const u8 = null;
        if (hG.found_existing) {
            hPrev = hG.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = hKey, .prev = hPrev } });
        hG.value_ptr.* = try self.allocator.dupe(u8, &hash);
    }

    pub fn addBalance(self: *Overlay, addr: types.Address, amount: i256) !void {
        const current = self.getBalance(addr);
        const newBal = if (amount >= 0) current +% @as(u256, @intCast(amount)) else current -% @as(u256, @intCast(-amount));
        try self.setBalance(addr, newBal);
    }

    pub fn getStorage(self: *Overlay, addr: types.Address, slot: [32]u8) [32]u8 {
        const key = State.storageKey(addr, slot);
        if (self.dirty.get(key)) |d| {
            var result: [32]u8 = undefined;
            @memcpy(&result, d[0..32]);
            return result;
        }
        return self.base.getStorage(addr, slot);
    }

    pub fn setStorage(self: *Overlay, addr: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = State.storageKey(addr, slot);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, &value);
    }

    // ── Zero-Conflict Per-User Derived Storage ──────────────────────────

    pub fn getDerivedStorage(self: *Overlay, user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
        const key = State.derivedStorageKey(user, contract, slot);
        if (self.dirty.get(key)) |d| {
            var result: [32]u8 = undefined;
            @memcpy(&result, d[0..32]);
            return result;
        }
        const data = self.base.trie.get(key) catch return [_]u8{0} ** 32;
        if (data) |d| {
            defer self.allocator.free(d);
            if (d.len >= 32) {
                var result: [32]u8 = undefined;
                @memcpy(&result, d[0..32]);
                return result;
            }
        }
        return [_]u8{0} ** 32;
    }

    pub fn setDerivedStorage(self: *Overlay, user: types.Address, contract: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = State.derivedStorageKey(user, contract, slot);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, &value);
    }

    // ── Commit ──────────────────────────────────────────────────────────

    /// Commits all buffered dirty changes to the underlying base State's Verkle trie.
    pub fn commit(self: *Overlay) !void {
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            try self.base.trie.put(entry.key_ptr.*, entry.value_ptr.*);
        }
    }
};
