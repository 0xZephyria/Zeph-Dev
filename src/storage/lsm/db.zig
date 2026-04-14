const std = @import("std");
const Allocator = std.mem.Allocator;
const MemTable = @import("memtable.zig").MemTable;
const Wal = @import("wal.zig").WAL;
const io = @import("io.zig");

/// Simple LSM-based Key-Value Store
pub const DB = struct {
    allocator: Allocator,
    memtable: *MemTable,
    wal: *Wal,
    io_engine: io.IoEngine,
    data_dir: []const u8,

    pub fn init(allocator: Allocator, data_dir: []const u8) !*DB {
        const self = try allocator.create(DB);

        // Create data directory
        std.fs.cwd().makePath(data_dir) catch {};

        // Initialize IO Engine
        const io_engine = try io.create(allocator);

        // Initialize WAL
        const wal_path = try std.fmt.allocPrint(allocator, "{s}/log.wal", .{data_dir});
        defer allocator.free(wal_path);
        const wal = try Wal.init(allocator, io_engine, wal_path);

        // Initialize MemTable (will replay WAL)
        const memtable = try MemTable.init(allocator, wal);

        self.* = DB{
            .allocator = allocator,
            .memtable = memtable,
            .wal = wal,
            .io_engine = io_engine,
            .data_dir = data_dir,
        };

        return self;
    }

    pub fn deinit(self: *DB) void {
        self.memtable.deinit();
        self.wal.deinit();
        self.io_engine.deinit();
        self.allocator.destroy(self);
    }

    /// Hash a variable-length key to a fixed 32-byte key using Blake3
    pub fn hashKey(key_slice: []const u8) [32]u8 {
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(key_slice);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    pub fn put(self: *DB, key_slice: []const u8, value: []const u8) !void {
        const key = hashKey(key_slice);
        try self.memtable.put(key, key_slice, value);
    }

    pub fn get(self: *DB, key_slice: []const u8) ?[]const u8 {
        const key = hashKey(key_slice);
        return self.memtable.get(key);
    }

    pub fn delete(self: *DB, key_slice: []const u8) !void {
        const key = hashKey(key_slice);
        try self.memtable.delete(key, key_slice);
    }

    /// Flush memtable to an immutable SSTable file on disk.
    /// Called when memtable exceeds a size threshold or on explicit request.
    /// SSTable format: [entry_count:u32] [entries...] where each entry is:
    ///   [key:32 bytes] [value_len:u32] [value: value_len bytes]
    pub fn flush(self: *DB) !void {
        // Check if memtable has data worth flushing
        if (!self.memtable.should_flush()) return;

        // Create sstables directory
        const sstable_dir = try std.fmt.allocPrint(self.allocator, "{s}/sstables", .{self.data_dir});
        defer self.allocator.free(sstable_dir);
        std.fs.cwd().makePath(sstable_dir) catch {};

        // Generate SSTable filename from timestamp
        const ts: u64 = @intCast(@max(0, std.time.timestamp()));
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{d}.sst", .{ sstable_dir, ts });
        defer self.allocator.free(filename);

        // Write SSTable
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        // First pass: count entries
        var count: u32 = 0;
        {
            var it = self.memtable.table.iterator();
            while (it.next()) |_| count += 1;
        }

        // Header: entry count
        var count_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &count_buf, count, .little);
        try file.writeAll(&count_buf);

        // Entries: key (32 bytes) + value_len (4 bytes) + value
        var it = self.memtable.table.iterator();
        while (it.next()) |entry| {
            try file.writeAll(&entry.key_ptr.*);
            if (entry.value_ptr.value) |val| {
                var vlen_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &vlen_buf, @intCast(val.len), .little);
                try file.writeAll(&vlen_buf);
                try file.writeAll(val);
            } else {
                // Tombstone — mark with sentinel 0xFFFFFFFF
                var vlen_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &vlen_buf, 0xFFFFFFFF, .little);
                try file.writeAll(&vlen_buf);
            }
        }

        // Sync to ensure durability
        try file.sync();

        // Clear WAL after successful flush (reuse existing truncation)
        self.wal.truncateAfterReplay() catch {};
    }

    /// Get abstract database interface
    pub fn asAbstractDB(self: *DB) @import("../mod.zig").DB {
        return @import("../mod.zig").DB{
            .ptr = self,
            .writeFn = write,
            .readFn = read,
            .deleteFn = deleteWrapper,
        };
    }

    /// Wrapper for storage interface
    pub fn write(self: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const db: *DB = @ptrCast(@alignCast(self));
        if (key.len == 0 or value.len == 0) {
            return error.InvalidKeyOrValue;
        } else {
            return db.put(key, value);
        }
    }

    pub fn read(self: *anyopaque, key: []const u8) ?[]const u8 {
        const db: *DB = @ptrCast(@alignCast(self));
        return db.get(key);
    }

    pub fn deleteWrapper(self: *anyopaque, key: []const u8) anyerror!void {
        const db: *DB = @ptrCast(@alignCast(self));
        return db.delete(key);
    }
};
