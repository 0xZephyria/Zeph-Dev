const std = @import("std");
const Atomic = std.atomic.Value;

pub const arena = @import("arena.zig");
pub const account_table = @import("account_table.zig");
pub const slot_store = @import("slot_store.zig");
pub const wal_ring = @import("wal_ring.zig");
pub const checkpoint = @import("checkpoint.zig");
pub const flat_table = @import("flat_table.zig");

pub const Arena = arena.Arena;
pub const AccountTable = account_table.AccountTable;
pub const AccountEntry = account_table.AccountEntry;
pub const SlotStore = slot_store.SlotStore;
pub const WalRing = wal_ring.WalRing;
pub const WalConfig = wal_ring.WalConfig;
pub const CheckpointManager = checkpoint.CheckpointManager;
pub const CheckpointConfig = checkpoint.CheckpointConfig;
pub const FlatTable = flat_table.FlatTable;

pub const Config = struct {
    arena_size: usize = arena.DEFAULT_ARENA_SIZE,
    account_capacity: u32 = account_table.DEFAULT_CAPACITY,
    flat_table_capacity: u32 = 256 * 1024,
    wal: WalConfig = .{},
    checkpoint_config: CheckpointConfig = .{},
    data_dir: []const u8 = "forgeyrdb_data",
};

pub const Stats = struct {
    arena: arena.ArenaStats,
    accounts: struct {
        count: u32,
        load_factor: f64,
        avg_probe_dist: f64,
    },
    flat_table: struct {
        count: u32,
        load_factor: f64,
    },
    storage: struct {
        account_count: usize,
        total_loads: u64,
        total_stores: u64,
    },
    wal: wal_ring.WalStats,
    checkpoint: checkpoint.CheckpointStats,
};

pub const ZephyrDB = struct {
    mem_arena: Arena,
    accounts: AccountTable,
    storage: SlotStore,
    flat_kv: FlatTable,
    wal: WalRing,
    checkpointer: CheckpointManager,
    allocator: std.mem.Allocator,
    config: Config,
    current_block: Atomic(u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        std.fs.cwd().makePath(config.data_dir) catch {};

        var mem_arena = if (config.arena_size >= 1024 * 1024 * 1024)
            try Arena.init(allocator, config.arena_size)
        else
            try Arena.initForTesting(allocator, config.arena_size);

        const accounts = try AccountTable.init(&mem_arena, config.account_capacity);
        const storage_store = SlotStore.init(allocator, &mem_arena);

        var wal_config = config.wal;
        {
            const wal_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
                config.data_dir,
                config.wal.file_path,
            });
            defer allocator.free(wal_path);
            wal_config.file_path = wal_path;
        }

        var ckpt_config = config.checkpoint_config;
        {
            const ckpt_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
                config.data_dir,
                config.checkpoint_config.checkpoint_dir,
            });
            defer allocator.free(ckpt_dir);
            ckpt_config.checkpoint_dir = ckpt_dir;
        }

        // Init self first so flat_kv can point to self.wal
        self.* = Self{
            .mem_arena = mem_arena,
            .accounts = accounts,
            .storage = storage_store,
            .flat_kv = undefined,
            .wal = try WalRing.init(allocator, wal_config),
            .checkpointer = try CheckpointManager.init(allocator, ckpt_config),
            .allocator = allocator,
            .config = config,
            .current_block = Atomic(u64).init(0),
        };

        // Now flat_kv can reference self.wal (stable address)
        self.flat_kv = try FlatTable.initWithCapacity(&self.mem_arena, &self.wal, config.flat_table_capacity);

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
    // Account operations (20-byte address → AccountEntry)
    // ================================================================

    pub fn getAccount(self: *Self, address: [32]u8) ?*AccountEntry {
        return self.accounts.get(address);
    }

    pub fn getOrCreateAccount(self: *Self, address: [32]u8) !*AccountEntry {
        return self.accounts.getOrCreate(address);
    }

    pub fn getBalance(self: *Self, address: [32]u8) [32]u8 {
        return self.accounts.getBalance(address);
    }

    pub fn setBalance(self: *Self, address: [32]u8, balance: [32]u8) !void {
        try self.accounts.setBalance(address, balance);
        try self.wal.appendAccountPut(address, balance);
    }

    pub fn getNonce(self: *Self, address: [32]u8) u64 {
        return self.accounts.getNonce(address);
    }

    pub fn setNonce(self: *Self, address: [32]u8, nonce: u64) !void {
        try self.accounts.setNonce(address, nonce);
        var val: [32]u8 = [_]u8{0} ** 32;
        @memcpy(val[0..8], std.mem.asBytes(&nonce));
        try self.wal.append(.AccountPut, address, val);
    }

    // ================================================================
    // Storage operations (per-account key-value)
    // ================================================================

    pub fn sload(self: *Self, account: [32]u8, key: [32]u8) [32]u8 {
        return self.storage.load(account, key);
    }

    pub fn sstore(self: *Self, account: [32]u8, key: [32]u8, value: [32]u8) !void {
        _ = try self.storage.store(account, key, value);
        try self.wal.appendStoragePut(key, value);
    }

    // ================================================================
    // Flat KV operations (generic 32-byte key → variable value)
    // ================================================================

    pub fn flatPut(self: *Self, key: [32]u8, value: []const u8) !void {
        try self.flat_kv.put(key, value);
    }

    pub fn flatGet(self: *Self, key: [32]u8) ?[]const u8 {
        return self.flat_kv.get(key);
    }

    pub fn flatDelete(self: *Self, key: [32]u8) !void {
        try self.flat_kv.delete(key);
    }

    // ================================================================
    // Block lifecycle
    // ================================================================

    pub fn beginBlock(self: *Self, block_number: u64) void {
        self.current_block.store(block_number, .release);
        self.wal.setBlock(block_number);
    }

    pub fn endBlock(self: *Self, block_number: u64, state_root: [32]u8) !void {
        try self.wal.markBlockBoundary(block_number);
        try self.wal.flush();

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
    // storage.DB trait implementation (thread-safe, generic 32-byte KV)
    // ================================================================

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
        var k: [32]u8 = undefined;
        if (key.len >= 32) {
            @memcpy(&k, key[0..32]);
        } else {
            @memset(&k, 0);
            @memcpy(&k, key);
        }
        try self.flat_kv.put(k, value);
    }

    fn abstractRead(ptr: *anyopaque, key: []const u8) ?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        var k: [32]u8 = undefined;
        if (key.len >= 32) {
            @memcpy(&k, key[0..32]);
        } else {
            @memset(&k, 0);
            @memcpy(&k, key);
        }
        // Return borrowed pointer into Arena memory — safe because reads
        // during block execution don't race with writes (writes go to Overlay).
        return self.flat_kv.get(k);
    }

    fn abstractDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        var k: [32]u8 = undefined;
        if (key.len >= 32) {
            @memcpy(&k, key[0..32]);
        } else {
            @memset(&k, 0);
            @memcpy(&k, key);
        }
        try self.flat_kv.delete(k);
    }

    // ================================================================
    // Statistics
    // ================================================================

    pub fn getStats(self: *Self) Stats {
        return .{
            .arena = self.mem_arena.getStats(),
            .accounts = .{
                .count = self.accounts.count.load(.acquire),
                .load_factor = self.accounts.loadFactor(),
                .avg_probe_dist = self.accounts.avgProbeDistance(),
            },
            .flat_table = .{
                .count = self.flat_kv.entryCount(),
                .load_factor = self.flat_kv.loadFactor(),
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

    pub fn printStats(self: *Self) void {
        const s = self.getStats();
        std.debug.print(
            \\
            \\╔══════════════════════════════════════════╗
            \\║          ZephyrDB Statistics              ║
            \\╚══════════════════════════════════════════╝
            \\  Arena: {d:.1} MB committed / {d:.1} MB capacity
            \\  Accounts: {d} (load: {d:.1}%, probe: {d:.2})
            \\  FlatTable: {d} entries (load: {d:.1}%)
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
            s.flat_table.count,
            s.flat_table.load_factor,
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

// ── Tests ──────────────────────────────────────────────────────

test "ZephyrDB basic operations" {
    var db = try ZephyrDB.init(std.testing.allocator, .{
        .arena_size = 4 * 1024 * 1024,
        .account_capacity = 256,
        .wal = .{ .ring_size = 64 * 1024, .file_path = "" },
        .data_dir = "/tmp/forgeyrdb_test",
    });
    defer db.deinit();

    const addr = [_]u8{ 0xDE, 0xAD } ++ [_]u8{0} ** 30;
    var balance: [32]u8 = [_]u8{0} ** 32;
    balance[31] = 100;

    try db.setBalance(addr, balance);
    const got = db.getBalance(addr);
    try std.testing.expectEqual(@as(u8, 100), got[31]);

    try db.setNonce(addr, 5);
    try std.testing.expectEqual(@as(u64, 5), db.getNonce(addr));

    const key = [_]u8{0x01} ** 32;
    var val: [32]u8 = [_]u8{0} ** 32;
    val[31] = 42;
    try db.sstore(addr, key, val);
    try std.testing.expectEqual(@as(u8, 42), db.sload(addr, key)[31]);
}

test "ZephyrDB Flat KV via abstract DB" {
    var db = try ZephyrDB.init(std.testing.allocator, .{
        .arena_size = 4 * 1024 * 1024,
        .account_capacity = 256,
        .flat_table_capacity = 256,
        .wal = .{ .ring_size = 64 * 1024, .file_path = "" },
        .data_dir = "/tmp/forgeyrdb_flat_test",
    });
    defer db.deinit();

    const abstract = db.asAbstractDB();

    const key = [_]u8{0xAA} ** 32;
    try abstract.write(&key, "hello zephyr flat kv");

    const result = abstract.read(&key);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("hello zephyr flat kv", result.?);

    try abstract.delete(&key);
    try std.testing.expect(abstract.read(&key) == null);
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

    db.beginBlock(1);
    try db.setBalance([_]u8{0x01} ** 32, [_]u8{0xFF} ** 32);
    try db.endBlock(1, [_]u8{0xAA} ** 32);

    try std.testing.expectEqual(@as(u64, 1), db.current_block.load(.acquire));
}

test {
    std.testing.refAllDecls(@This());
}
