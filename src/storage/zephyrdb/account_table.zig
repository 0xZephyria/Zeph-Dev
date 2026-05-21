// ZephyrDB Account Table — Cache-line aligned open-addressing hash table
//
// TigerBeetle-inspired: 64-byte cache-line aligned entries with Robin Hood hashing.
// Zero dynamic allocation — all memory comes from the Arena.
//
// Design:
//   - Open-addressing with Robin Hood linear probing (minimize probe distance variance)
//   - Each AccountEntry is exactly 128 bytes (2 cache lines) for predictable memory access
//   - Supports ~16M accounts in 2GB of arena memory
//   - Thread-safe reads (lock-free), writes use per-bucket striped locks

const std = @import("std");
const Atomic = std.atomic.Value;
const Arena = @import("arena.zig").Arena;

/// 20-byte Ethereum address
pub const Address = [20]u8;

/// 32-byte hash
pub const Hash = [32]u8;

/// Account entry — exactly 128 bytes (2 cache lines, naturally aligned)
/// Layout is optimized for spatial locality of hot fields.
pub const AccountEntry = extern struct {
    // ---- Cache line 1 (64 bytes): Hot data ----
    address: Address, // 20 bytes — lookup key
    flags: u32, // 4 bytes — bitfield (exists, has_code, is_contract, dirty, etc.)
    nonce: u64, // 8 bytes — transaction nonce
    balance: [32]u8, // 32 bytes — u256 balance (big-endian)

    // ---- Cache line 2 (64 bytes): Cold data ----
    code_hash: Hash, // 32 bytes — keccak256 of contract code (or empty hash)
    storage_root: Hash, // 32 bytes — Verkle trie root of storage

    /// Probe distance for Robin Hood hashing (how far from ideal position)
    pub fn probeDistance(self: *const AccountEntry) u32 {
        return self.flags >> 24; // Top 8 bits store probe distance
    }

    pub fn setProbeDistance(self: *AccountEntry, dist: u32) void {
        self.flags = (self.flags & 0x00FFFFFF) | (dist << 24);
    }

    pub fn isEmpty(self: *const AccountEntry) bool {
        return self.flags & FLAG_EXISTS == 0;
    }

    pub fn isContract(self: *const AccountEntry) bool {
        return self.flags & FLAG_HAS_CODE != 0;
    }

    pub fn isDirty(self: *const AccountEntry) bool {
        return self.flags & FLAG_DIRTY != 0;
    }

    pub fn markDirty(self: *AccountEntry) void {
        self.flags |= FLAG_DIRTY;
    }

    pub fn clearDirty(self: *AccountEntry) void {
        self.flags &= ~FLAG_DIRTY;
    }
};

// Flag constants
pub const FLAG_EXISTS: u32 = 0x01;
pub const FLAG_HAS_CODE: u32 = 0x02;
pub const FLAG_IS_CONTRACT: u32 = 0x04;
pub const FLAG_DIRTY: u32 = 0x08;
pub const FLAG_SELF_DESTRUCT: u32 = 0x10;
pub const FLAG_WARM: u32 = 0x20; // EIP-2929 warm access

/// Empty code hash (keccak256 of empty bytes)
pub const EMPTY_CODE_HASH: Hash = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

/// Default initial capacity (256K slots ≈ 32MB)
pub const DEFAULT_CAPACITY: u32 = 256 * 1024;

/// Maximum load factor before resize (70%)
const MAX_LOAD_FACTOR_NUM: u32 = 7;
const MAX_LOAD_FACTOR_DEN: u32 = 10;

/// Striped lock count for write operations
const STRIPE_COUNT: usize = 64;

/// Account table with Robin Hood open-addressing hash map.
pub const AccountTable = struct {
    /// Pointer to the contiguous array of AccountEntry slots
    entries: []AccountEntry,
    /// Number of slots (always power of 2)
    capacity: u32,
    /// Mask for fast modulo: capacity - 1
    mask: u32,
    /// Number of occupied entries
    count: Atomic(u32),
    /// Striped mutexes for write operations (reduces contention)
    stripe_locks: [STRIPE_COUNT]std.Thread.Mutex,
    /// Backing arena (for resize operations)
    arena: *Arena,
    /// Stats
    total_probes: Atomic(u64),
    total_lookups: Atomic(u64),

    const Self = @This();

    // ── Progressive Resize State ──────────────────────────────────────
    /// New table being migrated into (null when not resizing).
    resize_entries: ?[]AccountEntry = null,
    /// Capacity of the new (resize) table.
    resize_capacity: u32 = 0,
    /// Mask for the new table: resize_capacity - 1.
    resize_mask: u32 = 0,
    /// Next old-table index to migrate (0..capacity).
    resize_progress: u32 = 0,
    /// True while incremental migration is in progress.
    is_resizing: bool = false,

    /// Initialize the account table with memory from the arena.
    pub fn init(arena: *Arena, capacity: u32) !Self {
        const actual_cap = nextPowerOfTwo(capacity);
        const byte_size = @as(usize, actual_cap) * @sizeOf(AccountEntry);
        const mem = arena.allocRaw(byte_size) orelse return error.ArenaOutOfMemory;

        // Zero-initialize all entries (flags=0 means empty)
        @memset(mem, 0);

        // Cast the raw memory to a slice of AccountEntry
        const entry_ptr: [*]AccountEntry = @ptrCast(@alignCast(mem.ptr));
        const entries = entry_ptr[0..actual_cap];

        var stripe_locks: [STRIPE_COUNT]std.Thread.Mutex = undefined;
        for (&stripe_locks) |*lock| {
            lock.* = .{};
        }

        return Self{
            .entries = entries,
            .capacity = actual_cap,
            .mask = actual_cap - 1,
            .count = Atomic(u32).init(0),
            .stripe_locks = stripe_locks,
            .arena = arena,
            .total_probes = Atomic(u64).init(0),
            .total_lookups = Atomic(u64).init(0),
        };
    }

    /// Look up an account by address. Lock-free read.
    /// During progressive resize, checks both old and new tables.
    pub fn get(self: *Self, address: Address) ?*AccountEntry {
        _ = self.total_lookups.fetchAdd(1, .monotonic);

        // Check new table first during resize (entries may have been migrated)
        if (self.is_resizing) {
            if (self.resize_entries) |new_entries| {
                var idx = hashAddress(address) & self.resize_mask;
                var probes: u32 = 0;
                while (probes < self.resize_capacity) : (probes += 1) {
                    const entry = &new_entries[idx];
                    if (entry.isEmpty()) break;
                    if (std.mem.eql(u8, &entry.address, &address)) {
                        _ = self.total_probes.fetchAdd(probes + 1, .monotonic);
                        return entry;
                    }
                    if (entry.probeDistance() < probes) break;
                    idx = (idx + 1) & self.resize_mask;
                }
            }
        }

        // Check old table
        var idx = hashAddress(address) & self.mask;
        var probes: u32 = 0;

        while (probes < self.capacity) : (probes += 1) {
            const entry = &self.entries[idx];

            if (entry.isEmpty()) {
                _ = self.total_probes.fetchAdd(probes + 1, .monotonic);
                return null;
            }

            if (std.mem.eql(u8, &entry.address, &address)) {
                _ = self.total_probes.fetchAdd(probes + 1, .monotonic);
                return entry;
            }

            if (entry.probeDistance() < probes) {
                _ = self.total_probes.fetchAdd(probes + 1, .monotonic);
                return null;
            }

            idx = (idx + 1) & self.mask;
        }

        return null;
    }

    /// Get or create an account entry. Returns the entry (existing or new).
    /// Triggers progressive rehashing when load factor exceeds 70%.
    pub fn getOrCreate(self: *Self, address: Address) !*AccountEntry {
        // Try lock-free read first
        if (self.get(address)) |entry| {
            return entry;
        }

        // Need to insert — acquire stripe lock
        const stripe = hashAddress(address) % STRIPE_COUNT;
        self.stripe_locks[stripe].lock();
        defer self.stripe_locks[stripe].unlock();

        // Double-check after acquiring lock
        if (self.get(address)) |entry| {
            return entry;
        }

        // Progress incremental migration if active
        if (self.is_resizing) {
            self.migrateChunk(64);
        }

        // Check load factor — begin resize instead of returning TableFull
        const active_cap = if (self.is_resizing) self.resize_capacity else self.capacity;
        const count = self.count.load(.acquire);
        if (count * MAX_LOAD_FACTOR_DEN >= active_cap * MAX_LOAD_FACTOR_NUM) {
            if (!self.is_resizing) {
                self.beginResize() catch return error.TableFull;
            }
        }

        // Determine which table to insert into
        const target_entries = if (self.is_resizing) (self.resize_entries orelse self.entries) else self.entries;
        const target_mask = if (self.is_resizing) self.resize_mask else self.mask;
        const target_cap = if (self.is_resizing) self.resize_capacity else self.capacity;

        // Insert with Robin Hood probing into the target table
        var new_entry = AccountEntry{
            .address = address,
            .flags = FLAG_EXISTS,
            .nonce = 0,
            .balance = [_]u8{0} ** 32,
            .code_hash = EMPTY_CODE_HASH,
            .storage_root = [_]u8{0} ** 32,
        };

        var idx = hashAddress(address) & target_mask;
        var probe_dist: u32 = 0;
        new_entry.setProbeDistance(0);

        while (probe_dist < target_cap) : (probe_dist += 1) {
            const slot = &target_entries[idx];

            if (slot.isEmpty()) {
                new_entry.setProbeDistance(probe_dist);
                slot.* = new_entry;
                _ = self.count.fetchAdd(1, .monotonic);
                return slot;
            }

            if (slot.probeDistance() < probe_dist) {
                new_entry.setProbeDistance(probe_dist);
                const displaced = slot.*;
                slot.* = new_entry;
                new_entry = displaced;
                probe_dist = displaced.probeDistance();
            }

            idx = (idx + 1) & target_mask;
        }

        return error.TableFull;
    }

    // ── Progressive Resize Methods ────────────────────────────────────

    /// Begin progressive resize to 2× capacity.
    fn beginResize(self: *Self) !void {
        if (self.is_resizing) return;

        const new_cap = self.capacity * 2;
        const byte_size = @as(usize, new_cap) * @sizeOf(AccountEntry);
        const mem = self.arena.allocRaw(byte_size) orelse return error.ArenaOutOfMemory;
        @memset(mem, 0);

        const entry_ptr: [*]AccountEntry = @ptrCast(@alignCast(mem.ptr));
        self.resize_entries = entry_ptr[0..new_cap];
        self.resize_capacity = new_cap;
        self.resize_mask = new_cap - 1;
        self.resize_progress = 0;
        self.is_resizing = true;
    }

    /// Migrate a chunk of entries from old table to new table.
    /// Called incrementally during getOrCreate() — 64 buckets per call.
    fn migrateChunk(self: *Self, batch_size: u32) void {
        if (!self.is_resizing) return;
        const new_entries = self.resize_entries orelse return;

        var migrated: u32 = 0;
        while (migrated < batch_size and self.resize_progress < self.capacity) {
            const old_entry = &self.entries[self.resize_progress];
            self.resize_progress += 1;

            if (old_entry.isEmpty()) {
                migrated += 1;
                continue;
            }

            // Re-insert into new table with Robin Hood probing
            var entry_copy = old_entry.*;
            var idx = hashAddress(entry_copy.address) & self.resize_mask;
            var probe_dist: u32 = 0;
            entry_copy.setProbeDistance(0);

            while (probe_dist < self.resize_capacity) : (probe_dist += 1) {
                const slot = &new_entries[idx];
                if (slot.isEmpty()) {
                    entry_copy.setProbeDistance(probe_dist);
                    slot.* = entry_copy;
                    break;
                }
                if (slot.probeDistance() < probe_dist) {
                    entry_copy.setProbeDistance(probe_dist);
                    const displaced = slot.*;
                    slot.* = entry_copy;
                    entry_copy = displaced;
                    probe_dist = displaced.probeDistance();
                }
                idx = (idx + 1) & self.resize_mask;
            }

            // Mark old entry as empty (migrated)
            old_entry.flags = 0;
            migrated += 1;
        }

        // Check if migration is complete
        if (self.resize_progress >= self.capacity) {
            self.completeResize();
        }
    }

    /// Complete the resize — swap tables.
    fn completeResize(self: *Self) void {
        self.entries = self.resize_entries.?;
        self.capacity = self.resize_capacity;
        self.mask = self.resize_mask;
        self.resize_entries = null;
        self.resize_capacity = 0;
        self.resize_mask = 0;
        self.resize_progress = 0;
        self.is_resizing = false;
    }

    /// Force-complete any pending resize (useful at epoch boundaries).
    pub fn finishResize(self: *Self) void {
        if (!self.is_resizing) return;
        self.migrateChunk(self.capacity); // Migrate everything remaining
    }

    /// Update balance for an account (creates if not exists)
    pub fn setBalance(self: *Self, address: Address, balance: [32]u8) !void {
        const entry = try self.getOrCreate(address);
        entry.balance = balance;
        entry.markDirty();
    }

    /// Get balance for an account
    pub fn getBalance(self: *Self, address: Address) [32]u8 {
        if (self.get(address)) |entry| {
            return entry.balance;
        }
        return [_]u8{0} ** 32;
    }

    /// Set nonce for an account
    pub fn setNonce(self: *Self, address: Address, nonce: u64) !void {
        const entry = try self.getOrCreate(address);
        entry.nonce = nonce;
        entry.markDirty();
    }

    /// Get nonce for an account
    pub fn getNonce(self: *Self, address: Address) u64 {
        if (self.get(address)) |entry| {
            return entry.nonce;
        }
        return 0;
    }

    /// Set code hash for an account (marks as contract)
    pub fn setCodeHash(self: *Self, address: Address, code_hash: Hash) !void {
        const entry = try self.getOrCreate(address);
        entry.code_hash = code_hash;
        if (!std.mem.eql(u8, &code_hash, &EMPTY_CODE_HASH)) {
            entry.flags |= FLAG_HAS_CODE | FLAG_IS_CONTRACT;
        }
        entry.markDirty();
    }

    /// Mark an account as self-destructed
    pub fn markSelfDestruct(self: *Self, address: Address) !void {
        const entry = try self.getOrCreate(address);
        entry.flags |= FLAG_SELF_DESTRUCT;
        entry.markDirty();
    }

    /// Iterate over all non-empty entries (for checkpointing)
    pub fn iterate(self: *Self) Iterator {
        return Iterator{ .table = self, .index = 0 };
    }

    /// Get average probe distance (measure of hash quality)
    pub fn avgProbeDistance(self: *const Self) f64 {
        const lookups = self.total_lookups.load(.acquire);
        if (lookups == 0) return 0.0;
        const probes = self.total_probes.load(.acquire);
        return @as(f64, @floatFromInt(probes)) / @as(f64, @floatFromInt(lookups));
    }

    /// Get load factor as percentage
    pub fn loadFactor(self: *const Self) f64 {
        return @as(f64, @floatFromInt(self.count.load(.acquire))) /
            @as(f64, @floatFromInt(self.capacity)) * 100.0;
    }

    pub const Iterator = struct {
        table: *AccountTable,
        index: u32,

        pub fn next(self: *Iterator) ?*AccountEntry {
            while (self.index < self.table.capacity) {
                const entry = &self.table.entries[self.index];
                self.index += 1;
                if (!entry.isEmpty()) {
                    return entry;
                }
            }
            return null;
        }
    };
};

// ---- Hashing ----

fn hashAddress(address: Address) u32 {
    // FNV-1a hash for 20-byte addresses — fast and well-distributed
    var hash: u32 = 0x811c9dc5;
    for (address) |byte| {
        hash ^= byte;
        hash *%= 0x01000193;
    }
    return hash;
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

// ---- Tests ----

test "AccountEntry size and alignment" {
    try std.testing.expectEqual(@as(usize, 128), @sizeOf(AccountEntry));
}

test "AccountTable basic operations" {
    var arena = try Arena.initForTesting(std.testing.allocator, 64 * 1024 * 1024); // 64MB
    defer arena.deinit();

    var table = try AccountTable.init(&arena, 1024);

    const addr1 = [_]u8{0x01} ** 20;
    const addr2 = [_]u8{0x02} ** 20;

    // Initially empty
    try std.testing.expect(table.get(addr1) == null);

    // Create and read
    _ = try table.getOrCreate(addr1);
    try std.testing.expect(table.get(addr1) != null);
    try std.testing.expect(table.get(addr2) == null);

    // Set and get balance
    var balance: [32]u8 = [_]u8{0} ** 32;
    balance[31] = 100; // 100 wei
    try table.setBalance(addr1, balance);
    const got = table.getBalance(addr1);
    try std.testing.expectEqual(@as(u8, 100), got[31]);

    // Set and get nonce
    try table.setNonce(addr1, 42);
    try std.testing.expectEqual(@as(u64, 42), table.getNonce(addr1));
}

test "AccountTable Robin Hood probing" {
    var arena = try Arena.initForTesting(std.testing.allocator, 64 * 1024 * 1024);
    defer arena.deinit();

    var table = try AccountTable.init(&arena, 256);

    // Insert 100 accounts — should handle collisions gracefully
    for (0..100) |i| {
        var addr: [20]u8 = [_]u8{0} ** 20;
        addr[0] = @truncate(i);
        addr[1] = @truncate(i >> 8);
        _ = try table.getOrCreate(addr);
    }

    try std.testing.expectEqual(@as(u32, 100), table.count.load(.acquire));

    // Verify all are retrievable
    for (0..100) |i| {
        var addr: [20]u8 = [_]u8{0} ** 20;
        addr[0] = @truncate(i);
        addr[1] = @truncate(i >> 8);
        try std.testing.expect(table.get(addr) != null);
    }

    // Check probe distance is reasonable (Robin Hood should keep it low)
    try std.testing.expect(table.avgProbeDistance() < 5.0);
}

test "AccountTable iterator" {
    var arena = try Arena.initForTesting(std.testing.allocator, 64 * 1024 * 1024);
    defer arena.deinit();

    var table = try AccountTable.init(&arena, 256);

    for (0..50) |i| {
        var addr: [20]u8 = [_]u8{0} ** 20;
        addr[0] = @truncate(i);
        _ = try table.getOrCreate(addr);
    }

    var iter = table.iterate();
    var count: u32 = 0;
    while (iter.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(u32, 50), count);
}
