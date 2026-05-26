// ZephyrDB FlatTable — Arena-backed generic KV store for 32-byte keys
//
// Open-addressing Robin Hood hash table with variable-length values
// stored directly in the Arena. Designed for the Flat KV state model
// (Solana approach): no Merkle trie, just key → value.
//
// Key benefits over std.AutoHashMap:
//   • Backed by Arena mmap — zero fragmentation, O(1) alloc
//   • Robin Hood probing — worst-case O(log n) probe distance
//   • Cache-line aligned entries — 64 bytes per entry (hot data)
//   • Variable-length values stored in Arena, referenced by offset+len
//
// Integration: plugs into ZephyrDB and the storage.DB abstract interface.

const std = @import("std");
const Atomic = std.atomic.Value;
const Arena = @import("arena.zig").Arena;
const WalRing = @import("wal_ring.zig").WalRing;

/// A single hash table entry — exactly 64 bytes (one cache line).
pub const Entry = extern struct {
    key: [32]u8,
    value_offset: u32,
    value_len: u32,
    flags: u32,
    _padding: [20]u8,

    const FLAG_OCCUPIED: u32 = 0x01;
    const FLAG_DIRTY: u32 = 0x02;
    const EMPTY_FLAGS: u32 = 0;

    pub fn isEmpty(self: *const Entry) bool {
        return self.flags & FLAG_OCCUPIED == 0;
    }

    pub fn isOccupied(self: *const Entry) bool {
        return self.flags & FLAG_OCCUPIED != 0;
    }

    pub fn probeDistance(self: *const Entry) u32 {
        return self.flags >> 16;
    }

    pub fn setProbeDistance(self: *Entry, dist: u32) void {
        self.flags = (self.flags & 0x0000FFFF) | (dist << 16);
    }
};

/// FlatTable — generic KV table using Arena memory + Robin Hood hashing.
pub const FlatTable = struct {
    const Self = @This();
    pub const INITIAL_CAPACITY: u32 = 256 * 1024;
    const MAX_LOAD_NUM: u32 = 7;
    const MAX_LOAD_DEN: u32 = 10;
    const STRIPE_COUNT: usize = 64;

    arena: *Arena,
    entries: []Entry,
    capacity: u32,
    mask: u32,
    count: Atomic(u32),
    wal: ?*WalRing,
    stripe_locks: [STRIPE_COUNT]std.Thread.Mutex,

    pub fn init(arena: *Arena, wal: ?*WalRing) !Self {
        return initWithCapacity(arena, wal, INITIAL_CAPACITY);
    }

    pub fn initWithCapacity(arena: *Arena, wal: ?*WalRing, capacity: u32) !Self {
        const actual_cap = nextPowerOfTwo(capacity);
        const byte_size = @as(usize, actual_cap) * @sizeOf(Entry);
        const mem = arena.allocRaw(byte_size) orelse return error.ArenaOutOfMemory;
        @memset(mem, 0);

        var stripe_locks: [STRIPE_COUNT]std.Thread.Mutex = undefined;
        for (&stripe_locks) |*lock| lock.* = .{};

        return Self{
            .arena = arena,
            .entries = @as([*]Entry, @ptrCast(@alignCast(mem.ptr)))[0..actual_cap],
            .capacity = actual_cap,
            .mask = actual_cap - 1,
            .count = Atomic(u32).init(0),
            .wal = wal,
            .stripe_locks = stripe_locks,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
        // Arena owns the memory; no per-entry cleanup needed.
    }

    /// Get a value by 32-byte key. Returns null if not found.
    /// Returned slice points into Arena memory — valid until Arena reset.
    pub fn get(self: *Self, key: [32]u8) ?[]const u8 {
        const stripe = hashKey(key) % STRIPE_COUNT;
        self.stripe_locks[stripe].lock();
        defer self.stripe_locks[stripe].unlock();

        var idx = hashKey(key) & self.mask;
        var probes: u32 = 0;

        while (probes < self.capacity) : (probes += 1) {
            const entry = &self.entries[idx];
            if (entry.isEmpty()) return null;
            if (entry.isOccupied() and std.mem.eql(u8, &entry.key, &key)) {
                return self.arena.ptrAt(entry.value_offset, entry.value_len);
            }
            if (entry.probeDistance() < probes) return null;
            idx = (idx + 1) & self.mask;
        }
        return null;
    }

    /// Put a key/value pair. If key exists, old value is overwritten.
    pub fn put(self: *Self, key: [32]u8, value: []const u8) !void {
        const stripe = hashKey(key) % STRIPE_COUNT;
        self.stripe_locks[stripe].lock();
        defer self.stripe_locks[stripe].unlock();

        // Allocate value storage in Arena (cache-line aligned)
        const val_slice = self.arena.allocRaw(value.len) orelse return error.ArenaOutOfMemory;
        @memcpy(val_slice, value);
        const value_offset = @as(u32, @intCast(@intFromPtr(val_slice.ptr) - @intFromPtr(self.arena.base)));
        const value_len: u32 = @intCast(value.len);

        var idx = hashKey(key) & self.mask;
        var probe_dist: u32 = 0;

        var new_entry = Entry{
            .key = key,
            .value_offset = value_offset,
            .value_len = value_len,
            .flags = Entry.FLAG_OCCUPIED | Entry.FLAG_DIRTY,
            ._padding = [_]u8{0} ** 20,
        };
        new_entry.setProbeDistance(0);

        while (probe_dist < self.capacity) : (probe_dist += 1) {
            const slot = &self.entries[idx];

            if (slot.isEmpty()) {
                new_entry.setProbeDistance(probe_dist);
                slot.* = new_entry;
                _ = self.count.fetchAdd(1, .monotonic);

                // WAL
                if (self.wal) |wal| {
                    var wal_val: [32]u8 = [_]u8{0} ** 32;
                    const copy_len = @min(value.len, 32);
                    @memcpy(wal_val[0..copy_len], value[0..copy_len]);
                    wal.append(.StoragePut, key, wal_val) catch {};
                }
                return;
            }

            if (slot.isOccupied() and std.mem.eql(u8, &slot.key, &key)) {
                // Overwrite — offset already points to Arena memory
                slot.value_offset = value_offset;
                slot.value_len = value_len;
                slot.flags |= Entry.FLAG_DIRTY;
                return;
            }

            if (slot.probeDistance() < probe_dist) {
                new_entry.setProbeDistance(probe_dist);
                const displaced = slot.*;
                slot.* = new_entry;
                new_entry = displaced;
                probe_dist = displaced.probeDistance();
            }

            idx = (idx + 1) & self.mask;
        }

        return error.TableFull;
    }

    /// Delete a key from the table.
    pub fn delete(self: *Self, key: [32]u8) !void {
        const stripe = hashKey(key) % STRIPE_COUNT;
        self.stripe_locks[stripe].lock();
        defer self.stripe_locks[stripe].unlock();

        var idx = hashKey(key) & self.mask;
        var probes: u32 = 0;

        while (probes < self.capacity) : (probes += 1) {
            const slot = &self.entries[idx];
            if (slot.isEmpty()) return;
            if (slot.isOccupied() and std.mem.eql(u8, &slot.key, &key)) {
                slot.flags = 0; // Mark empty
                _ = self.count.fetchSub(1, .monotonic);

                // Shift subsequent entries back (Robin Hood deletion)
                var next = (idx + 1) & self.mask;
                while (self.entries[next].isOccupied() and self.entries[next].probeDistance() > 0) {
                    self.entries[idx] = self.entries[next];
                    var moved = &self.entries[idx];
                    moved.setProbeDistance(moved.probeDistance() - 1);
                    self.entries[next].flags = 0;
                    idx = next;
                    next = (next + 1) & self.mask;
                }
                return;
            }
            if (slot.probeDistance() < probes) return;
            idx = (idx + 1) & self.mask;
        }
    }

    /// Get approximate count of entries.
    pub fn entryCount(self: *const Self) u32 {
        return self.count.load(.acquire);
    }

    /// Get load factor as percentage.
    pub fn loadFactor(self: *const Self) f64 {
        return @as(f64, @floatFromInt(self.count.load(.acquire))) /
            @as(f64, @floatFromInt(self.capacity)) * 100.0;
    }
};

// ── Helpers ────────────────────────────────────────────────────

fn hashKey(key: [32]u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (key) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

fn nextPowerOfTwo(n: u32) u32 {
    if (n == 0) return 1;
    var v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

// ── Tests ──────────────────────────────────────────────────────

test "FlatTable basic put/get" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    var table = try FlatTable.initWithCapacity(&arena, null, 1000);
    defer table.deinit();

    const key = [_]u8{0xAA} ** 32;
    try table.put(key, "hello");

    const result = table.get(key);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("hello", result.?);
}

test "FlatTable overwrite" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    var table = try FlatTable.initWithCapacity(&arena, null, 1000);
    defer table.deinit();

    const key = [_]u8{0xBB} ** 32;
    try table.put(key, "first");
    try table.put(key, "second");

    const result = table.get(key);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("second", result.?);
}

test "FlatTable delete" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    var table = try FlatTable.initWithCapacity(&arena, null, 1000);
    defer table.deinit();

    const key = [_]u8{0xCC} ** 32;
    try table.put(key, "to_delete");
    try std.testing.expect(table.get(key) != null);

    try table.delete(key);
    try std.testing.expect(table.get(key) == null);
}

test "FlatTable many keys" {
    var arena = try Arena.initForTesting(std.testing.allocator, 64 * 1024 * 1024);
    defer arena.deinit();

    var table = try FlatTable.init(&arena, null);
    defer table.deinit();

    const num_keys = 1000;
    for (0..num_keys) |i| {
        var key: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, key[0..8], @intCast(i), .little);
        try table.put(key, "value");
    }

    try std.testing.expectEqual(@as(u32, num_keys), table.entryCount());
    try std.testing.expect(table.loadFactor() > 0.0);
}

test "FlatTable Robin Hood probe distance" {
    var arena = try Arena.initForTesting(std.testing.allocator, 64 * 1024 * 1024);
    defer arena.deinit();

    var table = try FlatTable.init(&arena, null);
    defer table.deinit();

    // Insert 50% load — Robin Hood should keep probe distance low
    const num_keys = table.capacity / 2;
    for (0..num_keys) |i| {
        var key: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, key[0..8], @intCast(i), .little);
        try table.put(key, "val");
    }

    // Verify all retrievable
    for (0..num_keys) |i| {
        var key: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, key[0..8], @intCast(i), .little);
        try std.testing.expect(table.get(key) != null);
    }
}
