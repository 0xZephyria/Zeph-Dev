const std = @import("std");
const types = @import("types.zig");
const accounts = @import("accounts/mod.zig");
const storage = @import("storage");

pub const State = struct {
    allocator: std.mem.Allocator,
    db: storage.DB,

    pub fn init(allocator: std.mem.Allocator, db: storage.DB) State {
        return State{ .allocator = allocator, .db = db };
    }

    pub fn deinit(self: *State) void {
        _ = self;
    }

    // ── Key Derivation ──────────────────────────────────────────

    threadlocal var last_addr_bytes: ?[32]u8 = null;
    threadlocal var last_stem: [31]u8 = undefined;

    pub fn accountStem(addr: types.Address) [31]u8 {
        if (last_addr_bytes) |lab| {
            if (std.mem.eql(u8, &lab, &addr.bytes)) {
                return last_stem;
            }
        }
        var h: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&addr.bytes, &h, .{});
        var stem: [31]u8 = undefined;
        @memcpy(&stem, h[0..31]);
        last_addr_bytes = addr.bytes;
        last_stem = stem;
        return stem;
    }

    pub fn nonceKey(addr: types.Address) [32]u8 {
        var key: [32]u8 = undefined;
        @memcpy(key[0..31], &accountStem(addr));
        key[31] = 0x00;
        return key;
    }

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

    pub fn storageKey(addr: types.Address, slot: [32]u8) [32]u8 {
        return accounts.storage_cell.storageKey(addr, slot);
    }

    pub fn derivedStorageKey(user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
        return accounts.derived.derivedStorageKey(user, contract, slot);
    }

    pub fn globalStorageKey(contract: types.Address, slot: [32]u8) [32]u8 {
        return accounts.derived.globalStorageKey(contract, slot);
    }

    // ── Account API ─────────────────────────────────────────────

    pub fn getBalance(self: *State, addr: types.Address) u256 {
        const key = balanceKey(addr);
        const data = self.db.read(&key);
        if (data) |d| {
            if (d.len < 32) return 0;
            return std.mem.readInt(u256, d[0..32], .big);
        }
        return 0;
    }

    pub fn setBalance(self: *State, addr: types.Address, balance: u256) !void {
        const key = balanceKey(addr);
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u256, &buf, balance, .big);
        try self.db.write(&key, &buf);
    }

    pub fn getNonce(self: *State, addr: types.Address) u64 {
        const key = nonceKey(addr);
        const data = self.db.read(&key);
        if (data) |d| {
            if (d.len < 8) return 0;
            return std.mem.readInt(u64, d[0..8], .big);
        }
        return 0;
    }

    pub fn setNonce(self: *State, addr: types.Address, nonce: u64) !void {
        const key = nonceKey(addr);
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, nonce, .big);
        try self.db.write(&key, &buf);
    }

    pub fn getCode(self: *State, addr: types.Address) ![]const u8 {
        const key = codeKey(addr);
        const data = self.db.read(&key);
        std.debug.print("GETCODE: addr={x}, key={x}, found_len={d}\n", .{ addr.bytes, key, if (data) |d| d.len else 0 });
        return if (data) |d| try self.allocator.dupe(u8, d) else &[_]u8{};
    }

    pub fn setCode(self: *State, addr: types.Address, code: []const u8) !void {
        const key = codeKey(addr);
        try self.db.write(&key, code);
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(code, &hash, .{});
        try self.db.write(&codeHashKey(addr), &hash);
    }

    pub fn addBalance(self: *State, addr: types.Address, amount: i256) !void {
        const current = self.getBalance(addr);
        const new_bal = if (amount >= 0) current +% @as(u256, @intCast(amount)) else current -% @as(u256, @intCast(-amount));
        try self.setBalance(addr, new_bal);
    }

    pub fn getStorage(self: *State, addr: types.Address, slot: [32]u8) [32]u8 {
        const key = storageKey(addr, slot);
        const data = self.db.read(&key);
        if (data) |d| {
            var result: [32]u8 = undefined;
            const len = @min(d.len, 32);
            @memcpy(result[0..len], d[0..len]);
            if (len < 32) @memset(result[len..], 0);
            return result;
        }
        return [_]u8{0} ** 32;
    }

    pub fn setStorage(self: *State, addr: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = storageKey(addr, slot);
        try self.db.write(&key, &value);
    }

    pub fn isProgramAccount(self: *State, addr: types.Address) bool {
        const key = codeHashKey(addr);
        const data = self.db.read(&key);
        if (data) |hash| {
            return accounts.code.CodeAccount.hasCode(types.Hash{ .bytes = hash[0..32].* });
        }
        return false;
    }

    pub fn newOverlay(self: *State, overlay: *Overlay) void {
        overlay.* = Overlay.init(self.allocator, self);
        overlay.finalizeInit();
    }
};

const ChunkHeader = struct {
    next: ?*ChunkHeader,
    size: usize,
};

const OVERLAY_ARENA_SIZE = 16 * 1024; // 16 KB

const OverlayArena = struct {
    buf: [OVERLAY_ARENA_SIZE]u8 align(16) = undefined,
    offset: usize = 0,
    backing_allocator: std.mem.Allocator,
    first_chunk: ?*ChunkHeader = null,
    current_chunk: ?*ChunkHeader = null,
    chunk_offset: usize = 0,

    pub fn init(backing_allocator: std.mem.Allocator) OverlayArena {
        return .{
            .backing_allocator = backing_allocator,
            .first_chunk = null,
            .current_chunk = null,
            .chunk_offset = 0,
        };
    }

    pub fn deinit(self: *OverlayArena) void {
        var current = self.first_chunk;
        while (current) |chunk| {
            const next = chunk.next;
            self.backing_allocator.rawFree(
                @as([*]u8, @ptrCast(chunk))[0..chunk.size],
                std.mem.Alignment.fromByteUnits(16),
                @returnAddress(),
            );
            current = next;
        }
        self.first_chunk = null;
        self.current_chunk = null;
        self.chunk_offset = 0;
        self.offset = 0;
    }

    pub fn allocator(self: *OverlayArena) std.mem.Allocator {
        const S = struct {
            fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
                const arena: *OverlayArena = @ptrCast(@alignCast(ctx));
                const align_bits = alignment.toByteUnits();
                
                // Try allocating from inline buffer first
                const aligned = std.mem.alignForward(usize, arena.offset, align_bits);
                const new_end = aligned + len;
                if (new_end <= OVERLAY_ARENA_SIZE) {
                    arena.offset = new_end;
                    return @ptrCast(&arena.buf[aligned]);
                }
                
                // Try allocating from current chunk if it exists
                if (arena.current_chunk) |chunk| {
                    const chunk_start = @intFromPtr(chunk) + @sizeOf(ChunkHeader);
                    const current_ptr = chunk_start + arena.chunk_offset;
                    const aligned_ptr = std.mem.alignForward(usize, current_ptr, align_bits);
                    const new_end_ptr = aligned_ptr + len;
                    const chunk_end = @intFromPtr(chunk) + chunk.size;
                    if (new_end_ptr <= chunk_end) {
                        arena.chunk_offset = new_end_ptr - chunk_start;
                        return @ptrFromInt(aligned_ptr);
                    }
                }
                
                // Allocate a new chunk.
                // We want to allocate a chunk size that is at least 16KB to avoid frequent allocations.
                // It should also accommodate the requested length plus some extra space for alignment padding.
                const min_needed = @sizeOf(ChunkHeader) + align_bits - 1 + len;
                const chunk_size = @max(min_needed, 16 * 1024);
                
                const raw = arena.backing_allocator.rawAlloc(chunk_size, std.mem.Alignment.fromByteUnits(16), ret_addr) orelse return null;
                const new_chunk: *ChunkHeader = @ptrCast(@alignCast(raw));
                new_chunk.next = null;
                new_chunk.size = chunk_size;
                
                if (arena.current_chunk) |chunk| {
                    chunk.next = new_chunk;
                } else {
                    arena.first_chunk = new_chunk;
                }
                arena.current_chunk = new_chunk;
                
                const chunk_start = @intFromPtr(new_chunk) + @sizeOf(ChunkHeader);
                const aligned_ptr = std.mem.alignForward(usize, chunk_start, align_bits);
                arena.chunk_offset = (aligned_ptr + len) - chunk_start;
                return @ptrFromInt(aligned_ptr);
            }

            fn freeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
                _ = ctx;
                _ = buf;
                _ = alignment;
                _ = ret_addr;
            }

            fn resizeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
                _ = ctx;
                _ = alignment;
                _ = ret_addr;
                return new_len <= buf.len;
            }

            fn remapFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
                _ = ctx;
                _ = buf;
                _ = alignment;
                _ = new_len;
                _ = ret_addr;
                return null;
            }
        };
        return .{
            .ptr = @ptrCast(self),
            .vtable = &.{
                .alloc = S.allocFn,
                .free = S.freeFn,
                .resize = S.resizeFn,
                .remap = S.remapFn,
            },
        };
    }
};

pub const Overlay = struct {
    /// General allocator for journal/logs (supports realloc).
    general_allocator: std.mem.Allocator,
    /// Arena allocator for hash maps and value dupes (bump, bulk free).
    arena_allocator: std.mem.Allocator,
    arena: OverlayArena,
    base: *State,
    dirty: std.AutoHashMap([32]u8, []const u8),
    journal: std.ArrayListUnmanaged(JournalEntry),
    selfDestructs: std.AutoHashMap(types.Address, void),
    createdAccounts: std.AutoHashMap(types.Address, void),
    transientStorage: std.AutoHashMap(StorageKey, []const u8),
    logs: std.ArrayListUnmanaged(Log),
    refund: u64,

    pub const Log = struct {
        address: types.Address,
        topics: std.ArrayListUnmanaged(types.Hash),
        data: []const u8,
    };

    pub const StorageKey = struct { addr: types.Address, key: [32]u8 };

    pub const SnapshotId = struct {
        journalLen: usize,
        logsLen: usize,
    };

    pub fn init(allocator: std.mem.Allocator, base: *State) Overlay {
        return Overlay{
            .general_allocator = allocator,
            .arena_allocator = undefined,
            .arena = OverlayArena.init(allocator),
            .base = base,
            .dirty = undefined,
            .journal = .{},
            .selfDestructs = undefined,
            .createdAccounts = undefined,
            .transientStorage = undefined,
            .logs = .{},
            .refund = 0,
        };
    }

    /// Must be called after the Overlay is in its final memory location
    /// (e.g. after init + copy into an array slot). Initializes hash maps
    /// with a stable pointer into this overlay's arena.
    pub fn finalizeInit(self: *Overlay) void {
        const a = self.arena.allocator();
        self.arena_allocator = a;
        self.dirty = std.AutoHashMap([32]u8, []const u8).init(a);
        self.selfDestructs = std.AutoHashMap(types.Address, void).init(a);
        self.createdAccounts = std.AutoHashMap(types.Address, void).init(a);
        self.transientStorage = std.AutoHashMap(StorageKey, []const u8).init(a);
    }

    pub fn deinit(self: *Overlay) void {
        for (self.logs.items) |*log| {
            log.topics.deinit(self.general_allocator);
            self.general_allocator.free(log.data);
        }
        self.logs.deinit(self.general_allocator);
        self.journal.deinit(self.general_allocator);
        self.arena.deinit();
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
        try self.journal.append(self.general_allocator, .{ .createdAccount = addr });
        try self.createdAccounts.put(addr, {});
    }

    pub fn snapshot(self: *Overlay) SnapshotId {
        return SnapshotId{
            .journalLen = self.journal.items.len,
            .logsLen = self.logs.items.len,
        };
    }

    pub fn revertToSnapshot(self: *Overlay, id: SnapshotId) void {
        while (self.journal.items.len > id.journalLen) {
            const entry = self.journal.pop() orelse unreachable;
            switch (entry) {
                .storage => |s| {
                    if (s.prev) |val| {
                        self.dirty.put(s.key, val) catch unreachable;
                    } else {
                        _ = self.dirty.fetchRemove(s.key);
                    }
                },
                .transientStorage => |s| {
                    if (s.prev) |val| {
                        self.transientStorage.put(s.key, val) catch unreachable;
                    } else {
                        _ = self.transientStorage.fetchRemove(s.key);
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
            _ = self.logs.pop();
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
        try self.journal.append(self.general_allocator, .{ .refund = self.refund });
        self.refund += amount;
    }

    pub fn subRefund(self: *Overlay, amount: u64) !void {
        try self.journal.append(self.general_allocator, .{ .refund = self.refund });
        self.refund = if (self.refund < amount) 0 else self.refund - amount;
    }

    pub fn suicide(self: *Overlay, addr: types.Address) !void {
        if (self.createdAccounts.contains(addr)) {
            if (self.selfDestructs.contains(addr)) return;
            try self.journal.append(self.general_allocator, .{ .suicide = addr });
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
        try self.journal.append(self.general_allocator, .{ .transientStorage = .{ .key = sKey, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, value);
    }

    pub fn addLog(self: *Overlay, log: Log) !void {
        try self.logs.append(self.general_allocator, log);
    }

    // ── Account Operations ──────────────────────────────────────

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
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, &buf);
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
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, &buf);
    }

    pub fn getCode(self: *Overlay, addr: types.Address) ![]const u8 {
        const key = State.codeKey(addr);
        if (self.dirty.get(key)) |d| {
            return try self.general_allocator.dupe(u8, d);
        }
        const code = try self.base.getCode(addr);
        if (code.len > 0) {
            const result = try self.general_allocator.dupe(u8, code);
            self.base.allocator.free(code);
            return result;
        }
        return &[_]u8{};
    }

    pub fn setCode(self: *Overlay, addr: types.Address, codeBytes: []const u8) !void {
        const key = State.codeKey(addr);
        std.debug.print("SETCODE: addr={x}, key={x}, len={d}\n", .{ addr.bytes, key, codeBytes.len });
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, codeBytes);

        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(codeBytes, &hash, .{});
        const hKey = State.codeHashKey(addr);
        const hG = try self.dirty.getOrPut(hKey);
        var hPrev: ?[]const u8 = null;
        if (hG.found_existing) {
            hPrev = hG.value_ptr.*;
        }
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = hKey, .prev = hPrev } });
        hG.value_ptr.* = try self.arena_allocator.dupe(u8, &hash);
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
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, &value);
    }

    // ── Zero-Conflict Derived Storage ───────────────────────────

    pub fn getDerivedStorage(self: *Overlay, user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
        const key = State.derivedStorageKey(user, contract, slot);
        if (self.dirty.get(key)) |d| {
            var result: [32]u8 = undefined;
            @memcpy(&result, d[0..32]);
            return result;
        }
        const data = self.base.db.read(&key);
        if (data) |d| {
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
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, &value);
    }

    // ── Zero-Conflict Global Storage ───────────────────────────

    pub fn getGlobalStorage(self: *Overlay, contract: types.Address, slot: [32]u8) [32]u8 {
        const key = State.globalStorageKey(contract, slot);
        if (self.dirty.get(key)) |d| {
            var result: [32]u8 = undefined;
            @memcpy(&result, d[0..32]);
            return result;
        }
        const data = self.base.db.read(&key);
        if (data) |d| {
            if (d.len >= 32) {
                var result: [32]u8 = undefined;
                @memcpy(&result, d[0..32]);
                return result;
            }
        }
        return [_]u8{0} ** 32;
    }

    pub fn setGlobalStorage(self: *Overlay, contract: types.Address, slot: [32]u8, value: [32]u8) !void {
        const key = State.globalStorageKey(contract, slot);
        const g = try self.dirty.getOrPut(key);
        var prev: ?[]const u8 = null;
        if (g.found_existing) {
            prev = g.value_ptr.*;
        }
        try self.journal.append(self.general_allocator, .{ .storage = .{ .key = key, .prev = prev } });
        g.value_ptr.* = try self.arena_allocator.dupe(u8, &value);
    }

    // ── Commit ──────────────────────────────────────────────────

    pub fn commit(self: *Overlay) !void {
        var it = self.dirty.iterator();
        while (it.next()) |entry| {
            try self.base.db.write(entry.key_ptr.*[0..], entry.value_ptr.*);
        }
    }
};
