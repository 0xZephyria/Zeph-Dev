const std = @import("std");
const Allocator = std.mem.Allocator;
const Wal = @import("wal.zig").WAL;

/// Entry in memtable
const Entry = struct {
    key: [32]u8,
    value: ?[]const u8, // null = tombstone
    timestamp: u64,
};

/// MemTable (Mutable In-Memory component)
pub const MemTable = struct {
    allocator: Allocator,
    table: std.AutoHashMap([32]u8, Entry),
    size_bytes: usize,
    wal: *Wal,

    const MAX_SIZE = 64 * 1024 * 1024; // 64MB

    pub fn init(allocator: Allocator, wal: *Wal) !*MemTable {
        const self = try allocator.create(MemTable);
        self.* = MemTable{
            .allocator = allocator,
            .table = std.AutoHashMap([32]u8, Entry).init(allocator),
            .size_bytes = 0,
            .wal = wal,
        };

        // REPLAY WAL
        try wal.replay(self, recoverFromWal);

        // Truncate WAL after successful replay — prevents re-replaying
        // the same entries if the node is restarted without new writes.
        wal.truncateAfterReplay() catch {};

        return self;
    }

    fn recoverFromWal(self: *MemTable, data: []const u8) !void {
        if (data.len < 1) return;
        const op = data[0];

        if (op == 1) {
            // Put: [1][OrigKeyLen:4][OrigKey...][ValLen:4][Val...]
            if (data.len < 5) return;

            var orig_key_len: u32 = undefined;
            @memcpy(std.mem.asBytes(&orig_key_len), data[1..5]);

            if (data.len < 5 + orig_key_len + 4) return;

            const orig_key = data[5 .. 5 + orig_key_len];

            var val_len: u32 = undefined;
            @memcpy(std.mem.asBytes(&val_len), data[5 + orig_key_len .. 5 + orig_key_len + 4]);

            if (data.len < 5 + orig_key_len + 4 + val_len) return;

            const val = data[5 + orig_key_len + 4 .. 5 + orig_key_len + 4 + val_len];

            // Hash the original key to get storage key
            const key = @import("db.zig").DB.hashKey(orig_key);

            const val_copy = try self.allocator.dupe(u8, val);

            if (self.table.get(key)) |old| {
                if (old.value) |v| self.allocator.free(v);
            }

            try self.table.put(key, Entry{
                .key = key,
                .value = val_copy,
                .timestamp = 0,
            });
            self.size_bytes += 32 + val.len + 8;
        } else if (op == 0) {
            // Delete: [0][OrigKeyLen:4][OrigKey...]
            if (data.len < 5) return;

            var orig_key_len: u32 = undefined;
            @memcpy(std.mem.asBytes(&orig_key_len), data[1..5]);

            if (data.len < 5 + orig_key_len) return;

            const orig_key = data[5 .. 5 + orig_key_len];

            // Hash the original key
            const key = @import("db.zig").DB.hashKey(orig_key);

            if (self.table.get(key)) |old| {
                if (old.value) |v| self.allocator.free(v);
            }

            try self.table.put(key, Entry{
                .key = key,
                .value = null,
                .timestamp = 0,
            });
            self.size_bytes += 32 + 8;
        }
    }

    pub fn deinit(self: *MemTable) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.value) |v| {
                self.allocator.free(v);
            }
        }
        self.table.deinit();
        self.allocator.destroy(self);
    }

    pub fn put(self: *MemTable, key: [32]u8, original_key: []const u8, value: []const u8) !void {
        // Write to WAL: [Op(1)][OrigKeyLen:4][OrigKey...][ValLen:4][Val...]
        // Store ORIGINAL key so we can hash it again during replay
        var wal_buf = std.ArrayListUnmanaged(u8){};
        defer wal_buf.deinit(self.allocator);

        try wal_buf.append(self.allocator, 1);
        try wal_buf.appendSlice(self.allocator, std.mem.asBytes(&@as(u32, @intCast(original_key.len))));
        try wal_buf.appendSlice(self.allocator, original_key);
        try wal_buf.appendSlice(self.allocator, std.mem.asBytes(&@as(u32, @intCast(value.len))));
        try wal_buf.appendSlice(self.allocator, value);

        try self.wal.append(wal_buf.items, 0);

        // Update Memory with HASHED key
        const val_copy = try self.allocator.dupe(u8, value);

        if (self.table.get(key)) |old_entry| {
            if (old_entry.value) |v| self.allocator.free(v);
        }

        try self.table.put(key, Entry{
            .key = key,
            .value = val_copy,
            .timestamp = @intCast(std.time.nanoTimestamp()),
        });
        self.size_bytes += 32 + value.len + 8;
    }

    pub fn delete(self: *MemTable, key: [32]u8, original_key: []const u8) !void {
        // Write to WAL: [Op(0)][OrigKeyLen:4][OrigKey...]
        var wal_buf = std.ArrayListUnmanaged(u8){};
        defer wal_buf.deinit(self.allocator);

        try wal_buf.append(self.allocator, 0);
        try wal_buf.appendSlice(self.allocator, std.mem.asBytes(&@as(u32, @intCast(original_key.len))));
        try wal_buf.appendSlice(self.allocator, original_key);

        try self.wal.append(wal_buf.items, 0);

        // Tombstone in Memory with HASHED key
        if (self.table.get(key)) |old_entry| {
            if (old_entry.value) |v| self.allocator.free(v);
        }

        try self.table.put(key, Entry{
            .key = key,
            .value = null,
            .timestamp = @intCast(std.time.nanoTimestamp()),
        });
        self.size_bytes += 32 + 8;
    }

    pub fn get(self: *MemTable, key: [32]u8) ?[]const u8 {
        if (self.table.get(key)) |entry| {
            return entry.value;
        }
        return null;
    }

    pub fn should_flush(self: *MemTable) bool {
        return self.size_bytes >= MAX_SIZE;
    }
};
