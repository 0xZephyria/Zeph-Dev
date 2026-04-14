// ZephyrDB Slot Store — Per-account storage slot management
//
// Design: Each account has an inline array of 8 storage slots (256 bytes, 4 cache lines).
// Contracts using ≤8 slots (most ERC20s, simple contracts) never allocate overflow.
// Larger contracts spill to an overflow hash map backed by arena memory.
//
// Key derivation: keccak256(account_address || slot_index) — EVM-compatible storage layout.

const std = @import("std");
const Arena = @import("arena.zig").Arena;
const Atomic = std.atomic.Value;

/// 32-byte storage key
pub const StorageKey = [32]u8;

/// 32-byte storage value
pub const StorageValue = [32]u8;

/// Zero value
pub const ZERO_VALUE: StorageValue = [_]u8{0} ** 32;

/// Number of inline slots per account (fits in 1 arena B256 block = 256 bytes)
pub const INLINE_SLOTS: usize = 8;

/// Single storage slot entry
pub const SlotEntry = struct {
    key: StorageKey,
    value: StorageValue,
    dirty: bool,
    occupied: bool,

    pub const EMPTY = SlotEntry{
        .key = [_]u8{0} ** 32,
        .value = ZERO_VALUE,
        .dirty = false,
        .occupied = false,
    };
};

/// Inline storage block — 8 slots stored contiguously (no pointer chasing)
pub const InlineSlots = struct {
    slots: [INLINE_SLOTS]SlotEntry,
    count: u8,
    overflow: ?*OverflowMap,

    pub fn init() InlineSlots {
        return .{
            .slots = [_]SlotEntry{SlotEntry.EMPTY} ** INLINE_SLOTS,
            .count = 0,
            .overflow = null,
        };
    }

    /// Load a storage value by key
    pub fn load(self: *const InlineSlots, key: StorageKey) StorageValue {
        // Search inline slots first (hot path)
        for (&self.slots) |*slot| {
            if (slot.occupied and std.mem.eql(u8, &slot.key, &key)) {
                return slot.value;
            }
        }

        // Check overflow map
        if (self.overflow) |overflow| {
            return overflow.get(key);
        }

        return ZERO_VALUE;
    }

    /// Store a value. Returns the previous value.
    pub fn store(self: *InlineSlots, key: StorageKey, value: StorageValue, arena: *Arena) !StorageValue {
        // Check inline slots for existing key
        for (&self.slots) |*slot| {
            if (slot.occupied and std.mem.eql(u8, &slot.key, &key)) {
                const old = slot.value;
                slot.value = value;
                slot.dirty = true;
                return old;
            }
        }

        // Try to insert into an empty inline slot
        if (self.count < INLINE_SLOTS) {
            for (&self.slots) |*slot| {
                if (!slot.occupied) {
                    slot.key = key;
                    slot.value = value;
                    slot.occupied = true;
                    slot.dirty = true;
                    self.count += 1;
                    return ZERO_VALUE;
                }
            }
        }

        // Overflow to hash map
        if (self.overflow == null) {
            self.overflow = try OverflowMap.create(arena);
        }

        return self.overflow.?.put(key, value);
    }

    /// Check if a key exists in storage
    pub fn exists(self: *const InlineSlots, key: StorageKey) bool {
        for (&self.slots) |*slot| {
            if (slot.occupied and std.mem.eql(u8, &slot.key, &key)) {
                return true;
            }
        }
        if (self.overflow) |overflow| {
            return !std.mem.eql(u8, &overflow.get(key), &ZERO_VALUE);
        }
        return false;
    }

    /// Get total number of slots (inline + overflow)
    pub fn totalCount(self: *const InlineSlots) usize {
        var total: usize = self.count;
        if (self.overflow) |overflow| {
            total += overflow.count;
        }
        return total;
    }

    /// Iterate over all dirty slots (for WAL and checkpointing)
    pub fn iterateDirty(self: *InlineSlots) DirtyIterator {
        return DirtyIterator{
            .inline_slots = self,
            .inline_idx = 0,
            .overflow_idx = 0,
        };
    }

    /// Clear all dirty flags (after WAL flush)
    pub fn clearDirty(self: *InlineSlots) void {
        for (&self.slots) |*slot| {
            slot.dirty = false;
        }
        if (self.overflow) |overflow| {
            overflow.clearDirty();
        }
    }
};

/// Iterator over dirty slots
pub const DirtyIterator = struct {
    inline_slots: *InlineSlots,
    inline_idx: u8,
    overflow_idx: u32,

    pub fn next(self: *DirtyIterator) ?*SlotEntry {
        // First iterate inline dirty slots
        while (self.inline_idx < INLINE_SLOTS) {
            const slot = &self.inline_slots.slots[self.inline_idx];
            self.inline_idx += 1;
            if (slot.occupied and slot.dirty) {
                return slot;
            }
        }

        // Then iterate overflow dirty entries
        if (self.inline_slots.overflow) |overflow| {
            while (self.overflow_idx < overflow.capacity) {
                const entry = &overflow.entries[self.overflow_idx];
                self.overflow_idx += 1;
                if (entry.occupied and entry.dirty) {
                    return entry;
                }
            }
        }

        return null;
    }
};

/// Overflow hash map for accounts with >8 storage slots.
/// Uses open-addressing with linear probing, backed by arena memory.
pub const OverflowMap = struct {
    entries: [*]SlotEntry,
    capacity: u32,
    count: u32,
    mask: u32,

    const INITIAL_CAPACITY: u32 = 64;

    pub fn create(arena: *Arena) !*OverflowMap {
        const cap = INITIAL_CAPACITY;
        const entries_size = @as(usize, cap) * @sizeOf(SlotEntry);
        const map_mem = arena.allocRaw(@sizeOf(OverflowMap)) orelse return error.ArenaOutOfMemory;
        const entries_mem = arena.allocRaw(entries_size) orelse return error.ArenaOutOfMemory;

        @memset(entries_mem, 0);

        const self: *OverflowMap = @ptrCast(@alignCast(map_mem.ptr));
        self.* = .{
            .entries = @ptrCast(@alignCast(entries_mem.ptr)),
            .capacity = cap,
            .count = 0,
            .mask = cap - 1,
        };
        return self;
    }

    pub fn get(self: *const OverflowMap, key: StorageKey) StorageValue {
        var idx = hashKey(key) & self.mask;
        var probes: u32 = 0;

        while (probes < self.capacity) : (probes += 1) {
            const entry = &self.entries[idx];
            if (!entry.occupied) return ZERO_VALUE;
            if (std.mem.eql(u8, &entry.key, &key)) return entry.value;
            idx = (idx + 1) & self.mask;
        }
        return ZERO_VALUE;
    }

    pub fn put(self: *OverflowMap, key: StorageKey, value: StorageValue) StorageValue {
        var idx = hashKey(key) & self.mask;
        var probes: u32 = 0;

        while (probes < self.capacity) : (probes += 1) {
            const entry = &self.entries[idx];

            if (!entry.occupied) {
                entry.* = .{
                    .key = key,
                    .value = value,
                    .dirty = true,
                    .occupied = true,
                };
                self.count += 1;
                return ZERO_VALUE;
            }

            if (std.mem.eql(u8, &entry.key, &key)) {
                const old = entry.value;
                entry.value = value;
                entry.dirty = true;
                return old;
            }

            idx = (idx + 1) & self.mask;
        }

        return ZERO_VALUE; // Table full — should not happen with proper sizing
    }

    pub fn clearDirty(self: *OverflowMap) void {
        for (0..self.capacity) |i| {
            self.entries[i].dirty = false;
        }
    }
};

/// Slot Store — manages storage for all accounts
pub const SlotStore = struct {
    /// Map from account address to its InlineSlots
    /// Uses arena-backed hash map indexed by first 4 bytes of address
    slots: std.AutoHashMap([20]u8, *InlineSlots),
    arena: *Arena,
    allocator: std.mem.Allocator,

    /// Stats
    total_loads: Atomic(u64),
    total_stores: Atomic(u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, arena: *Arena) Self {
        return .{
            .slots = std.AutoHashMap([20]u8, *InlineSlots).init(allocator),
            .arena = arena,
            .allocator = allocator,
            .total_loads = Atomic(u64).init(0),
            .total_stores = Atomic(u64).init(0),
        };
    }

    pub fn deinit(self: *Self) void {
        self.slots.deinit();
    }

    /// Load a storage value for an account
    pub fn load(self: *Self, account: [20]u8, key: StorageKey) StorageValue {
        _ = self.total_loads.fetchAdd(1, .monotonic);
        if (self.slots.get(account)) |inline_slots| {
            return inline_slots.load(key);
        }
        return ZERO_VALUE;
    }

    /// Store a value for an account. Returns the previous value.
    pub fn store(self: *Self, account: [20]u8, key: StorageKey, value: StorageValue) !StorageValue {
        _ = self.total_stores.fetchAdd(1, .monotonic);

        const result = self.slots.getOrPut(account) catch return error.OutOfMemory;
        if (!result.found_existing) {
            // Allocate new InlineSlots from arena
            const mem = self.arena.allocRaw(@sizeOf(InlineSlots)) orelse return error.ArenaOutOfMemory;
            const inline_ptr: *InlineSlots = @ptrCast(@alignCast(mem.ptr));
            inline_ptr.* = InlineSlots.init();
            result.value_ptr.* = inline_ptr;
        }

        return result.value_ptr.*.store(key, value, self.arena);
    }

    /// Get total number of accounts with storage
    pub fn accountCount(self: *const Self) usize {
        return self.slots.count();
    }
};

fn hashKey(key: StorageKey) u32 {
    var hash: u32 = 0x811c9dc5;
    for (key[0..8]) |byte| {
        hash ^= byte;
        hash *%= 0x01000193;
    }
    return hash;
}

// ---- Tests ----

test "InlineSlots basic operations" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    var slots = InlineSlots.init();

    const key1 = [_]u8{0x01} ** 32;
    const key2 = [_]u8{0x02} ** 32;
    var val1: StorageValue = [_]u8{0} ** 32;
    val1[31] = 42;

    // Load from empty → zero
    try std.testing.expectEqualSlices(u8, &ZERO_VALUE, &slots.load(key1));

    // Store and load
    _ = try slots.store(key1, val1, &arena);
    try std.testing.expectEqual(@as(u8, 42), slots.load(key1)[31]);

    // Second store returns previous value
    var val2: StorageValue = [_]u8{0} ** 32;
    val2[31] = 99;
    const prev = try slots.store(key1, val2, &arena);
    try std.testing.expectEqual(@as(u8, 42), prev[31]);

    // Different key
    try std.testing.expectEqualSlices(u8, &ZERO_VALUE, &slots.load(key2));
}

test "InlineSlots overflow to hash map" {
    var arena = try Arena.initForTesting(std.testing.allocator, 4 * 1024 * 1024);
    defer arena.deinit();

    var slots = InlineSlots.init();

    // Fill all 8 inline slots
    for (0..INLINE_SLOTS) |i| {
        var key: StorageKey = [_]u8{0} ** 32;
        key[0] = @truncate(i);
        var val: StorageValue = [_]u8{0} ** 32;
        val[31] = @truncate(i + 1);
        _ = try slots.store(key, val, &arena);
    }

    try std.testing.expectEqual(@as(u8, INLINE_SLOTS), slots.count);

    // 9th slot should trigger overflow
    var key9: StorageKey = [_]u8{0xFF} ** 32;
    key9[0] = 0xFF;
    var val9: StorageValue = [_]u8{0} ** 32;
    val9[31] = 0xFF;
    _ = try slots.store(key9, val9, &arena);

    try std.testing.expect(slots.overflow != null);
    try std.testing.expectEqual(@as(u8, 0xFF), slots.load(key9)[31]);
}

test "SlotStore multi-account" {
    var arena = try Arena.initForTesting(std.testing.allocator, 4 * 1024 * 1024);
    defer arena.deinit();

    var store = SlotStore.init(std.testing.allocator, &arena);
    defer store.deinit();

    const acct1 = [_]u8{0xAA} ** 20;
    const acct2 = [_]u8{0xBB} ** 20;
    const key = [_]u8{0x01} ** 32;
    var val1: StorageValue = [_]u8{0} ** 32;
    val1[31] = 10;
    var val2: StorageValue = [_]u8{0} ** 32;
    val2[31] = 20;

    _ = try store.store(acct1, key, val1);
    _ = try store.store(acct2, key, val2);

    try std.testing.expectEqual(@as(u8, 10), store.load(acct1, key)[31]);
    try std.testing.expectEqual(@as(u8, 20), store.load(acct2, key)[31]);
    try std.testing.expectEqual(@as(usize, 2), store.accountCount());
}
