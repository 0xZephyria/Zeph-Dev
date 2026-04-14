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

pub const State = struct {
    allocator: std.mem.Allocator,
    trie: *VerkleTrie,

    pub fn init(allocator: std.mem.Allocator, trie: *VerkleTrie) State {
        return State{ .allocator = allocator, .trie = trie };
    }

    pub fn deinit(self: *State) void {
        _ = self;
    }

    // ── Key Derivation (Verkle standard) ────────────────────────────────

    pub fn account_stem(addr: types.Address) [31]u8 {
        var h: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&addr.bytes, &h, .{});
        var stem: [31]u8 = undefined;
        @memcpy(&stem, h[0..31]);
        return stem;
    }

    pub fn nonce_key(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &account_stem(addr));
        key[31] = 0x00;
        return key;
    }

    pub fn balance_key(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &account_stem(addr));
        key[31] = 0x01;
        return key;
    }

    pub fn code_hash_key(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &account_stem(addr));
        key[31] = 0x02;
        return key;
    }

    pub fn code_key(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &account_stem(addr));
        key[31] = 0x03;
        return key;
    }

    /// Legacy storage key: keccak256(address || slot)
    pub fn storage_key(addr: types.Address, slot: [32]u8) [32]u8 {
        return accounts.storage_cell.storageKey(addr, slot);
    }

    /// Per-user derived storage key: keccak256(user || contract || slot)
    pub fn derived_storage_key(user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
        return accounts.derived.derivedStorageKey(user, contract, slot);
    }

    /// Global accumulator key: keccak256(contract || "global" || slot)
    pub fn global_storage_key_fn(contract: types.Address, slot: [32]u8) [32]u8 {
        return accounts.derived.globalStorageKey(contract, slot);
    }

    // ── Account API ────────────────────────────────────────────────────

    pub fn get_balance(self: *State, addr: types.Address) u256 {
        const key = balance_key(addr);
        const data = self.trie.get(key) catch return 0;
        if (data) |d| {
            defer self.allocator.free(d);
            if (d.len < 32) return 0;
            return std.mem.readInt(u256, d[32 - @min(d.len, 32) .. 32][0..32], .big);
        }
        return 0;
    }

    pub fn set_balance(self: *State, addr: types.Address, balance: u256) !void {
        const key = balance_key(addr);
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u256, &buf, balance, .big);
        try self.trie.put(key, &buf);
    }

    pub fn get_nonce(self: *State, addr: types.Address) u64 {
        const key = nonce_key(addr);
        const data = self.trie.get(key) catch return 0;
        if (data) |d| {
            defer self.allocator.free(d);
            if (d.len < 8) return 0;
            return std.mem.readInt(u64, d[8 - @min(d.len, 8) .. 8][0..8], .big);
        }
        return 0;
    }

    pub fn set_nonce(self: *State, addr: types.Address, nonce: u64) !void {
        const key = nonce_key(addr);
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, nonce, .big);
        try self.trie.put(key, &buf);
    }

    pub fn get_code(self: *State, addr: types.Address) ![]const u8 {
        const key = code_key(addr);
        const data = try self.trie.get(key);
        return data orelse &[_]u8{};
    }

    pub fn set_code(self: *State, addr: types.Address, code: []const u8) !void {
        const key = code_key(addr);
        try self.trie.put(key, code);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(code, &hash, .{});
        try self.trie.put(code_hash_key(addr), &hash);
    }

    pub fn add_balance(self: *State, addr: types.Address, amount: i256) !void {
        const current = self.get_balance(addr);
        const new_bal = if (amount >= 0) current +% @as(u256, @intCast(amount)) else current -% @as(u256, @intCast(-amount));
        try self.set_balance(addr, new_bal);
    }

    pub fn get_storage(self: *State, addr: types.Address, slot: [32]u8) [32]u8 {
        const key = storage_key(addr, slot);
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

    pub fn set_storage(self: *State, addr: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = storage_key(addr, slot);
        try self.trie.put(key, &value);
    }

    pub fn get_verkle_value(self: *State, key: [32]u8) ?[]const u8 {
        const data = self.trie.get(key) catch return null;
        return data;
    }

    pub fn set_verkle_value(self: *State, key: [32]u8, value: []const u8) !void {
        try self.trie.put(key, value);
    }

    pub fn is_program_account(self: *State, addr: types.Address) bool {
        const key = code_hash_key(addr);
        const data = self.trie.get(key) catch return false;
        if (data) |hash| {
            return accounts.code.CodeAccount.hasCode(types.Hash{ .bytes = hash[0..32].* });
        }
        return false;
    }

    pub fn new_overlay(self: *State) !Overlay {
        return Overlay.init(self.allocator, self);
    }
};

// ── Overlay (Per-Transaction State) ─────────────────────────────────────
//
// Handles per-transaction state changes with journaled rollback.
// Each TX runs in its own Overlay, which is committed to the base State
// after successful execution. On revert, all changes are unwound.

pub const Overlay = struct {
    allocator: std.mem.Allocator,
    base: *State,
    dirty: std.AutoHashMap([32]u8, []const u8),
    journal: std.ArrayListUnmanaged(JournalEntry),
    self_destructs: std.AutoHashMap(types.Address, void),
    created_accounts: std.AutoHashMap(types.Address, void),
    transient_storage: std.AutoHashMap(StorageKey, []const u8),
    logs: std.ArrayListUnmanaged(Log),
    refund: u64,

    pub const Log = struct {
        address: types.Address,
        topics: std.ArrayListUnmanaged(types.Hash),
        data: []const u8,

        pub fn deinit(self: *Log, alloc: std.mem.Allocator) void {
            self.topics.deinit(alloc);
            alloc.free(self.data);
        }
    };

    pub const StorageKey = struct { addr: types.Address, key: [32]u8 };

    pub const SnapshotId = struct {
        journal_len: usize,
        logs_len: usize,
    };

    pub fn init(allocator: std.mem.Allocator, base: *State) Overlay {
        return Overlay{
            .allocator = allocator,
            .base = base,
            .dirty = std.AutoHashMap([32]u8, []const u8).init(allocator),
            .journal = .{},
            .self_destructs = std.AutoHashMap(types.Address, void).init(allocator),
            .created_accounts = std.AutoHashMap(types.Address, void).init(allocator),
            .transient_storage = std.AutoHashMap(StorageKey, []const u8).init(allocator),
            .logs = .{},
            .refund = 0,
        };
    }

    pub fn deinit(self: *Overlay) void {
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.dirty.deinit();

        var t_it = self.transient_storage.iterator();
        while (t_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.transient_storage.deinit();

        for (self.logs.items) |*log| {
            log.deinit(self.allocator);
        }
        self.logs.deinit(self.allocator);

        for (self.journal.items) |entry| {
            switch (entry) {
                .storage => |s| if (s.prev) |v| self.allocator.free(v),
                .transient_storage => |s| if (s.prev) |v| self.allocator.free(v),
                .suicide, .refund, .created_account => {},
            }
        }
        self.journal.deinit(self.allocator);
        self.self_destructs.deinit();
        self.created_accounts.deinit();
    }

    const JournalEntry = union(enum) {
        storage: struct { key: [32]u8, prev: ?[]const u8 },
        transient_storage: struct { key: StorageKey, prev: ?[]const u8 },
        suicide: types.Address,
        refund: u64,
        created_account: types.Address,
    };

    pub fn mark_created(self: *Overlay, addr: types.Address) !void {
        if (self.created_accounts.contains(addr)) return;
        try self.journal.append(self.allocator, .{ .created_account = addr });
        try self.created_accounts.put(addr, {});
    }

    pub fn snapshot(self: *Overlay) SnapshotId {
        return SnapshotId{
            .journal_len = self.journal.items.len,
            .logs_len = self.logs.items.len,
        };
    }

    pub fn revert_to_snapshot(self: *Overlay, id: SnapshotId) void {
        while (self.journal.items.len > id.journal_len) {
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
                .transient_storage => |s| {
                    if (s.prev) |val| {
                        if (self.transient_storage.get(s.key)) |current| {
                            self.allocator.free(current);
                        }
                        self.transient_storage.put(s.key, val) catch unreachable;
                    } else {
                        if (self.transient_storage.fetchRemove(s.key)) |kv| {
                            self.allocator.free(kv.value);
                        }
                    }
                },
                .suicide => |addr| {
                    _ = self.self_destructs.remove(addr);
                },
                .refund => |prev| {
                    self.refund = prev;
                },
                .created_account => |addr| {
                    _ = self.created_accounts.remove(addr);
                },
            }
        }

        while (self.logs.items.len > id.logs_len) {
            var log_entry = self.logs.pop();
            log_entry.?.topics.deinit(self.allocator);
            self.allocator.free(log_entry.?.data);
        }
    }

    pub fn estimate_size(self: *Overlay) usize {
        var size: usize = @sizeOf(Overlay);
        size += self.dirty.count() * (@sizeOf([32]u8) + @sizeOf([]const u8));
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            size += entry.value_ptr.len;
        }
        size += self.journal.items.len * @sizeOf(JournalEntry);
        size += self.created_accounts.count() * @sizeOf(types.Address);
        size += self.transient_storage.count() * (@sizeOf(StorageKey) + @sizeOf([]const u8));
        for (self.logs.items) |log| {
            size += @sizeOf(Log);
            size += log.topics.items.len * @sizeOf(types.Hash);
            size += log.data.len;
        }
        size += self.self_destructs.count() * @sizeOf(types.Address);
        return size;
    }

    pub fn add_refund(self: *Overlay, amount: u64) !void {
        try self.journal.append(self.allocator, .{ .refund = self.refund });
        self.refund += amount;
    }

    pub fn sub_refund(self: *Overlay, amount: u64) !void {
        try self.journal.append(self.allocator, .{ .refund = self.refund });
        self.refund = if (self.refund < amount) 0 else self.refund - amount;
    }

    pub fn suicide(self: *Overlay, addr: types.Address) !void {
        if (self.created_accounts.contains(addr)) {
            if (self.self_destructs.contains(addr)) return;
            try self.journal.append(self.allocator, .{ .suicide = addr });
            try self.self_destructs.put(addr, {});
        }
        try self.set_balance(addr, 0);
    }

    pub fn is_suicided(self: *Overlay, addr: types.Address) bool {
        return self.self_destructs.contains(addr);
    }

    pub fn get_transient_storage(self: *Overlay, addr: types.Address, key: [32]u8) [32]u8 {
        if (self.transient_storage.get(.{ .addr = addr, .key = key })) |val| {
            var ret: [32]u8 = [_]u8{0} ** 32;
            const len = @min(val.len, 32);
            @memcpy(ret[32 - len ..], val);
            return ret;
        }
        return [_]u8{0} ** 32;
    }

    pub fn set_transient_storage(self: *Overlay, addr: types.Address, key: [32]u8, value: []const u8) !void {
        const s_key = StorageKey{ .addr = addr, .key = key };
        const g = try self.transient_storage.getOrPut(s_key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .transient_storage = .{ .key = s_key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, value);
    }

    pub fn add_log(self: *Overlay, log: Log) !void {
        try self.logs.append(self.allocator, log);
    }

    // ── Account Operations ──────────────────────────────────────────────

    pub fn get_balance(self: *Overlay, addr: types.Address) u256 {
        const key = State.balance_key(addr);
        if (self.dirty.get(key)) |d| {
            return std.mem.readInt(u256, d[0..32], .big);
        }
        return self.base.get_balance(addr);
    }

    pub fn set_balance(self: *Overlay, addr: types.Address, balance: u256) !void {
        const key = State.balance_key(addr);
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

    pub fn is_program_account(self: *Overlay, addr: types.Address) bool {
        const hash_key = State.code_hash_key(addr);
        if (self.dirty.get(hash_key)) |h| {
            return accounts.code.CodeAccount.hasCode(types.Hash{ .bytes = h[0..32].* });
        }
        return self.base.is_program_account(addr);
    }

    pub fn get_nonce(self: *Overlay, addr: types.Address) u64 {
        const key = State.nonce_key(addr);
        if (self.dirty.get(key)) |d| {
            return std.mem.readInt(u64, d[0..8], .big);
        }
        return self.base.get_nonce(addr);
    }

    pub fn set_nonce(self: *Overlay, addr: types.Address, nonce: u64) !void {
        const key = State.nonce_key(addr);
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

    pub fn get_code(self: *Overlay, addr: types.Address) ![]const u8 {
        const key = State.code_key(addr);
        if (self.dirty.get(key)) |d| {
            return try self.allocator.dupe(u8, d);
        }
        return self.base.get_code(addr);
    }

    pub fn set_code(self: *Overlay, addr: types.Address, code_bytes: []const u8) !void {
        const key = State.code_key(addr);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, code_bytes);

        // Update code hash
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(code_bytes, &hash, .{});
        const h_key = State.code_hash_key(addr);
        const h_g = try self.dirty.getOrPut(h_key);
        var h_prev: ?[]const u8 = null;
        if (h_g.found_existing) {
            h_prev = h_g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = h_key, .prev = h_prev } });
        h_g.value_ptr.* = try self.allocator.dupe(u8, &hash);
    }

    pub fn add_balance(self: *Overlay, addr: types.Address, amount: i256) !void {
        const current = self.get_balance(addr);
        const new_bal = if (amount >= 0) current +% @as(u256, @intCast(amount)) else current -% @as(u256, @intCast(-amount));
        try self.set_balance(addr, new_bal);
    }

    pub fn get_storage(self: *Overlay, addr: types.Address, slot: [32]u8) [32]u8 {
        const key = State.storage_key(addr, slot);
        if (self.dirty.get(key)) |d| {
            var result: [32]u8 = undefined;
            @memcpy(&result, d[0..32]);
            return result;
        }
        return self.base.get_storage(addr, slot);
    }

    pub fn set_storage(self: *Overlay, addr: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = State.storage_key(addr, slot);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, &value);
    }

    // ── Zero-Conflict Per-User Derived Storage ──────────────────────────

    pub fn get_derived_storage(self: *Overlay, user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
        const key = State.derived_storage_key(user, contract, slot);
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

    pub fn set_derived_storage(self: *Overlay, user: types.Address, contract: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = State.derived_storage_key(user, contract, slot);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.allocator.dupe(u8, &value);
    }

    // ── Commit ──────────────────────────────────────────────────────────

    pub fn commit(self: *Overlay) !void {
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            try self.base.trie.put(entry.key_ptr.*, entry.value_ptr.*);
        }
    }
};
