// ZephyrDB — High-Performance In-Memory Storage Engine
//
// TigerBeetle-inspired zero-allocation storage for 1M+ TPS.
// Drop-in replacement for the LSM-based database.
//
// Architecture:
//   Arena (mmap) → AccountTable (Robin Hood) → SlotStore (inline + overflow)
//                → WAL (ring buffer, async) → Checkpoint (epoch snapshots)
//
// Public API implements the abstract DB trait from storage/mod.zig
// for backwards compatibility with existing node code.

const std = @import("std");
const Atomic = std.atomic.Value;

pub const arena = @import("arena.zig");
pub const account_table = @import("account_table.zig");
pub const slot_store = @import("slot_store.zig");
pub const wal_ring = @import("wal_ring.zig");
pub const checkpoint = @import("checkpoint.zig");

pub const Arena = arena.Arena;
pub const AccountTable = account_table.AccountTable;
pub const AccountEntry = account_table.AccountEntry;
pub const SlotStore = slot_store.SlotStore;
pub const WalRing = wal_ring.WalRing;
pub const WalConfig = wal_ring.WalConfig;
pub const CheckpointManager = checkpoint.CheckpointManager;
pub const CheckpointConfig = checkpoint.CheckpointConfig;

/// ZephyrDB configuration
pub const Config = struct {
    /// Arena size in bytes (default 4GB)
    arena_size: usize = arena.DEFAULT_ARENA_SIZE,
    /// Initial account table capacity
    account_capacity: u32 = account_table.DEFAULT_CAPACITY,
    /// WAL configuration
    wal: WalConfig = .{},
    /// Checkpoint configuration
    checkpoint_config: CheckpointConfig = .{},
    /// Data directory
    data_dir: []const u8 = "forgeyrdb_data",
};

/// ZephyrDB statistics
pub const Stats = struct {
    arena: arena.ArenaStats,
    accounts: struct {
        count: u32,
        load_factor: f64,
        avg_probe_dist: f64,
    },
    storage: struct {
        account_count: usize,
        total_loads: u64,
        total_stores: u64,
    },
    wal: wal_ring.WalStats,
    checkpoint: checkpoint.CheckpointStats,
};

/// ZephyrDB — the main database interface.
///
/// Provides a unified API over the arena-backed account table, storage slot store,
/// WAL ring buffer, and checkpoint manager.
pub const ZephyrDB = struct {
    mem_arena: Arena,
    accounts: AccountTable,
    storage: SlotStore,
    wal: WalRing,
    checkpointer: CheckpointManager,
    allocator: std.mem.Allocator,
    config: Config,
    current_block: Atomic(u64),

    const Self = @This();

    /// Initialize ZephyrDB with the given configuration.
    pub fn init(allocator: std.mem.Allocator, config: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Ensure data directory exists
        std.fs.cwd().makePath(config.data_dir) catch {};

        // Initialize arena (mmap-backed for production, heap for testing)
        var mem_arena = if (config.arena_size >= 1024 * 1024 * 1024)
            try Arena.init(allocator, config.arena_size)
        else
            try Arena.initForTesting(allocator, config.arena_size);

        // Initialize account table
        const accounts = try AccountTable.init(&mem_arena, config.account_capacity);

        // Initialize slot store
        const storage_store = SlotStore.init(allocator, &mem_arena);

        // Initialize WAL
        const wal_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
            config.data_dir,
            config.wal.file_path,
        });
        defer allocator.free(wal_path);

        var wal_config = config.wal;
        wal_config.file_path = wal_path;
        const wal_inst = try WalRing.init(allocator, wal_config);

        // Initialize checkpoint manager
        var ckpt_config = config.checkpoint_config;
        const ckpt_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
            config.data_dir,
            config.checkpoint_config.checkpoint_dir,
        });
        defer allocator.free(ckpt_dir);
        ckpt_config.checkpoint_dir = ckpt_dir;
        const checkpointer = try CheckpointManager.init(allocator, ckpt_config);

        self.* = Self{
            .mem_arena = mem_arena,
            .accounts = accounts,
            .storage = storage_store,
            .wal = wal_inst,
            .checkpointer = checkpointer,
            .allocator = allocator,
            .config = config,
            .current_block = Atomic(u64).init(0),
        };

        // Attempt crash recovery
        const recovered = self.wal.recover() catch 0;
        if (recovered > 0) {
            std.log.info("ZephyrDB: Recovered {d} WAL entries", .{recovered});
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.checkpointer.deinit();
        self.wal.deinit();
        self.storage.deinit();
        self.mem_arena.deinit();
        self.allocator.destroy(self);
    }

    // ================================================================
    // Account operations
    // ================================================================

    /// Get account entry (returns null if not found)
    pub fn getAccount(self: *Self, address: [20]u8) ?*AccountEntry {
        return self.accounts.get(address);
    }

    /// Get or create an account entry
    pub fn getOrCreateAccount(self: *Self, address: [20]u8) !*AccountEntry {
        return self.accounts.getOrCreate(address);
    }

    /// Get balance for an address
    pub fn getBalance(self: *Self, address: [20]u8) [32]u8 {
        return self.accounts.getBalance(address);
    }

    /// Set balance for an address (with WAL)
    pub fn setBalance(self: *Self, address: [20]u8, balance: [32]u8) !void {
        try self.accounts.setBalance(address, balance);
        try self.wal.appendAccountPut(address, balance);
    }

    /// Get nonce for an address
    pub fn getNonce(self: *Self, address: [20]u8) u64 {
        return self.accounts.getNonce(address);
    }

    /// Set nonce for an address
    pub fn setNonce(self: *Self, address: [20]u8, nonce: u64) !void {
        try self.accounts.setNonce(address, nonce);
        var key: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key[0..20], &address);
        var val: [32]u8 = [_]u8{0} ** 32;
        const nonce_bytes: [8]u8 = @bitCast(nonce);
        @memcpy(val[0..8], &nonce_bytes);
        try self.wal.append(.AccountPut, key, val);
    }

    // ================================================================
    // Storage operations (per-account key-value)
    // ================================================================

    /// Load a storage value
    pub fn sload(self: *Self, account: [20]u8, key: [32]u8) [32]u8 {
        return self.storage.load(account, key);
    }

    /// Store a value (with WAL)
    pub fn sstore(self: *Self, account: [20]u8, key: [32]u8, value: [32]u8) !void {
        _ = try self.storage.store(account, key, value);
        try self.wal.appendStoragePut(key, value);
    }

    // ================================================================
    // Block lifecycle
    // ================================================================

    /// Called at the start of block execution
    pub fn beginBlock(self: *Self, block_number: u64) void {
        self.current_block.store(block_number, .release);
        self.wal.setBlock(block_number);
    }

    /// Called at the end of block execution
    pub fn endBlock(self: *Self, block_number: u64, state_root: [32]u8) !void {
        try self.wal.markBlockBoundary(block_number);
        try self.wal.flush();

        // Check if we should create a checkpoint
        if (self.checkpointer.shouldCheckpoint(block_number)) {
            try self.checkpointer.createCheckpoint(
                block_number,
                state_root,
                &self.accounts,
                &self.storage,
                &self.wal,
            );
        }
    }

    // ================================================================
    // Abstract DB trait implementation (backwards compatibility)
    // ================================================================

    /// Returns an abstract DB interface for use with existing code
    pub fn asAbstractDB(self: *Self) @import("../mod.zig").DB {
        return @import("../mod.zig").DB{
            .ptr = self,
            .writeFn = abstractWrite,
            .readFn = abstractRead,
            .deleteFn = abstractDelete,
        };
    }

    fn abstractWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (key.len == 20) {
            // Account-level write
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            if (value.len >= 32) {
                var balance: [32]u8 = undefined;
                @memcpy(&balance, value[0..32]);
                try self.setBalance(addr, balance);
            }
        } else if (key.len == 32) {
            // Storage write (need account context — use first 20 bytes as account)
            var skey: [32]u8 = undefined;
            @memcpy(&skey, key[0..32]);
            var sval: [32]u8 = [_]u8{0} ** 32;
            const copy_len = @min(value.len, 32);
            @memcpy(sval[0..copy_len], value[0..copy_len]);
            try self.sstore([_]u8{0} ** 20, skey, sval);
        } else {
            // Generic key-value — hash to 32-byte key
            var hashed_key: [32]u8 = undefined;
            var hasher = std.crypto.hash.Blake3.init(.{});
            hasher.update(key);
            hasher.final(&hashed_key);
            var sval: [32]u8 = [_]u8{0} ** 32;
            const copy_len = @min(value.len, 32);
            @memcpy(sval[0..copy_len], value[0..copy_len]);
            try self.sstore([_]u8{0} ** 20, hashed_key, sval);
        }
    }

    /// Persistent read buffer for abstractRead — avoids returning pointer to stack.
    /// This is safe because abstractRead is always called synchronously from
    /// the RPC thread, and the result is consumed before the next call.
    var read_cache: [32]u8 = [_]u8{0} ** 32;

    fn abstractRead(ptr: *anyopaque, key: []const u8) ?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (key.len == 20) {
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            const entry = self.getAccount(addr) orelse return null;
            return &entry.balance;
        } else if (key.len == 32) {
            var skey: [32]u8 = undefined;
            @memcpy(&skey, key[0..32]);
            const val = self.storage.load([_]u8{0} ** 20, skey);
            // Store result in persistent buffer and return a slice to it
            read_cache = val;
            // Check for zero — return null for unset keys
            if (std.mem.eql(u8, &read_cache, &([_]u8{0} ** 32))) return null;
            return &read_cache;
        }
        return null;
    }

    fn abstractDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (key.len == 20) {
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            try self.accounts.markSelfDestruct(addr);
        }
    }

    // ================================================================
    // Statistics
    // ================================================================

    /// Get comprehensive database statistics
    pub fn getStats(self: *Self) Stats {
        return .{
            .arena = self.mem_arena.getStats(),
            .accounts = .{
                .count = self.accounts.count.load(.acquire),
                .load_factor = self.accounts.loadFactor(),
                .avg_probe_dist = self.accounts.avgProbeDistance(),
            },
            .storage = .{
                .account_count = self.storage.accountCount(),
                .total_loads = self.storage.total_loads.load(.acquire),
                .total_stores = self.storage.total_stores.load(.acquire),
            },
            .wal = self.wal.getStats(),
            .checkpoint = self.checkpointer.getStats(),
        };
    }

    /// Print a summary of database statistics
    pub fn printStats(self: *Self) void {
        const s = self.getStats();
        std.debug.print(
            \\
            \\╔══════════════════════════════════════════╗
            \\║          ZephyrDB Statistics              ║
            \\╚══════════════════════════════════════════╝
            \\  Arena: {d:.1} MB committed / {d:.1} MB capacity
            \\  Accounts: {d} (load: {d:.1}%, probe: {d:.2})
            \\  Storage: {d} accounts, {d} loads, {d} stores
            \\  WAL: {d} written, {d} flushed, {d} pending
            \\  Checkpoints: {d} total, last at block {d}
            \\
        , .{
            @as(f64, @floatFromInt(s.arena.bytes_committed)) / (1024.0 * 1024.0),
            @as(f64, @floatFromInt(s.arena.total_capacity)) / (1024.0 * 1024.0),
            s.accounts.count,
            s.accounts.load_factor,
            s.accounts.avg_probe_dist,
            s.storage.account_count,
            s.storage.total_loads,
            s.storage.total_stores,
            s.wal.entries_written,
            s.wal.entries_flushed,
            s.wal.pending_entries,
            s.checkpoint.total_checkpoints,
            s.checkpoint.last_checkpoint_block,
        });
    }
};

// ---- Tests ----

test "ZephyrDB basic operations" {
    var db = try ZephyrDB.init(std.testing.allocator, .{
        .arena_size = 4 * 1024 * 1024, // 4MB for testing
        .account_capacity = 256,
        .wal = .{ .ring_size = 64 * 1024, .file_path = "" },
        .data_dir = "/tmp/forgeyrdb_test",
    });
    defer db.deinit();

    const addr = [_]u8{ 0xDE, 0xAD } ++ [_]u8{0} ** 18;
    var balance: [32]u8 = [_]u8{0} ** 32;
    balance[31] = 100;

    // Set and get balance
    try db.setBalance(addr, balance);
    const got = db.getBalance(addr);
    try std.testing.expectEqual(@as(u8, 100), got[31]);

    // Set and get nonce
    try db.setNonce(addr, 5);
    try std.testing.expectEqual(@as(u64, 5), db.getNonce(addr));

    // Storage operations
    const key = [_]u8{0x01} ** 32;
    var val: [32]u8 = [_]u8{0} ** 32;
    val[31] = 42;
    try db.sstore(addr, key, val);
    try std.testing.expectEqual(@as(u8, 42), db.sload(addr, key)[31]);
}

test "ZephyrDB block lifecycle" {
    var db = try ZephyrDB.init(std.testing.allocator, .{
        .arena_size = 4 * 1024 * 1024,
        .account_capacity = 256,
        .wal = .{ .ring_size = 64 * 1024, .file_path = "" },
        .checkpoint_config = .{ .interval = 10, .checkpoint_dir = "/tmp/forgeyrdb_ckpt_test" },
        .data_dir = "/tmp/forgeyrdb_test2",
    });
    defer db.deinit();

    // Simulate block processing
    db.beginBlock(1);
    try db.setBalance([_]u8{0x01} ** 20, [_]u8{0xFF} ** 32);
    try db.endBlock(1, [_]u8{0xAA} ** 32);

    try std.testing.expectEqual(@as(u64, 1), db.current_block.load(.acquire));
}

test "ZephyrDB abstract DB interface" {
    var db = try ZephyrDB.init(std.testing.allocator, .{
        .arena_size = 4 * 1024 * 1024,
        .account_capacity = 256,
        .wal = .{ .ring_size = 64 * 1024, .file_path = "" },
        .data_dir = "/tmp/forgeyrdb_test3",
    });
    defer db.deinit();

    const abstract = db.asAbstractDB();
    const addr = [_]u8{ 0xBE, 0xEF } ++ [_]u8{0} ** 18;
    var balance: [32]u8 = [_]u8{0} ** 32;
    balance[31] = 50;

    try abstract.write(&addr, &balance);
    const result = abstract.read(&addr);
    try std.testing.expect(result != null);
}

// Verify all submodules compile
test {
    std.testing.refAllDecls(@This());
}
