const std = @import("std");
const Allocator = std.mem.Allocator;
const io = @import("io.zig");

// TigerBeetle Style WAL
// - Pre-allocated file size
// - CRC32C checksums
// - Direct IO (via io engine)

pub const WalHeader = extern struct {
    magic: u64,
    version: u32,
    reserved: u32,
    checksum: u32, // Checksum of header
};

pub const EntryHeader = extern struct {
    checksum: u32, // Checksum of body
    len: u32,
    tx_id: u64,
};

pub const WAL = struct {
    allocator: Allocator,
    io_engine: io.IoEngine,
    file: std.fs.File,
    current_offset: u64,
    replayed: bool,

    const MAGIC = 0x5A4257414C; // ZBWAL
    const VERSION = 1;

    pub fn init(allocator: Allocator, io_engine: io.IoEngine, path: []const u8) !*WAL {
        const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });

        const self = try allocator.create(WAL);
        self.* = WAL{
            .allocator = allocator,
            .io_engine = io_engine,
            .file = file,
            .current_offset = 0,
            .replayed = false,
        };

        try self.recover();
        return self;
    }

    fn recover(self: *WAL) !void {
        try self.file.seekTo(0);
        const file_size = (try self.file.stat()).size;
        var offset: u64 = 0;

        while (offset < file_size) {
            // Check if we have enough space for a header
            if (offset + @sizeOf(EntryHeader) > file_size) {
                break;
            }

            // Read Header
            var header: EntryHeader = undefined;
            try self.file.seekTo(offset);
            const bytes_read = try self.file.readAll(std.mem.asBytes(&header));
            if (bytes_read != @sizeOf(EntryHeader)) break; // Should not happen given check above

            // Check if we have enough space for body
            if (offset + @sizeOf(EntryHeader) + header.len > file_size) {
                break;
            }

            // Read Body
            const body = try self.allocator.alloc(u8, header.len);
            defer self.allocator.free(body);
            try self.file.seekTo(offset + @sizeOf(EntryHeader));
            _ = try self.file.readAll(body);

            // Verify Checksum
            const calc_checksum = std.hash.Crc32.hash(body);
            if (calc_checksum != header.checksum) {
                break;
            }

            // Entry is valid
            offset += @sizeOf(EntryHeader) + header.len;
        }

        self.current_offset = offset;
        if (self.current_offset < file_size) {
            try self.file.setEndPos(self.current_offset);
        }

        // Seek to end for writing
        try self.file.seekTo(self.current_offset);
    }

    pub fn deinit(self: *WAL) void {
        self.file.close();
        self.allocator.destroy(self);
    }

    pub fn append(self: *WAL, data: []const u8, tx_id: u64) !void {
        // Prepare buffer (Header + Data)
        const total_len = @sizeOf(EntryHeader) + data.len;
        const buffer = try self.allocator.alloc(u8, total_len);
        defer self.allocator.free(buffer);

        // Fill Header
        const checksum = std.hash.Crc32.hash(data);
        const header = EntryHeader{
            .checksum = checksum,
            .len = @intCast(data.len),
            .tx_id = tx_id,
        };

        @memcpy(buffer[0..@sizeOf(EntryHeader)], std.mem.asBytes(&header));
        @memcpy(buffer[@sizeOf(EntryHeader)..], data);

        // SYNCHRONOUS WRITE: Write directly to file (no async I/O)
        try self.file.pwriteAll(buffer, self.current_offset);

        // Force sync to disk immediately
        try self.file.sync();

        self.current_offset += total_len;
    }

    pub fn replay(self: *WAL, context: anytype, callback: fn (@TypeOf(context), []const u8) anyerror!void) !void {
        // Guard against double-replay: recover() already validated & set offset.
        // replay() reads entries for the callback but must NOT move current_offset
        // since recover() already computed the correct write position.
        if (self.replayed) return;
        self.replayed = true;

        // Save the write offset that recover() computed
        const write_offset = self.current_offset;

        try self.file.seekTo(0);
        var read_offset: u64 = 0;

        while (read_offset < write_offset) {
            // Read Header
            var header: EntryHeader = undefined;
            try self.file.seekTo(read_offset);
            const bytes_read = try self.file.readAll(std.mem.asBytes(&header));
            if (bytes_read == 0) break; // EOF
            if (bytes_read < @sizeOf(EntryHeader)) {
                // Partial write/corruption at end
                break;
            }

            // Bounds check
            if (read_offset + @sizeOf(EntryHeader) + header.len > write_offset) break;

            // Allocate buffer for data
            const data = try self.allocator.alloc(u8, header.len);
            defer self.allocator.free(data);

            const data_read = try self.file.readAll(data);
            if (data_read < header.len) break;

            // Verify Checksum (Basic)
            if (std.hash.Crc32.hash(data) != header.checksum) {
                // Corruption
                break;
            }

            try callback(context, data);

            read_offset += @sizeOf(EntryHeader) + header.len;
        }

        // Restore the correct write offset (do NOT modify it from replay)
        self.current_offset = write_offset;

        // Seek to end for appending
        try self.file.seekTo(self.current_offset);
    }

    /// Truncate the WAL after a successful replay.
    /// Called after memtable has absorbed all replayed entries.
    /// Prevents re-replaying stale entries on subsequent restarts.
    pub fn truncateAfterReplay(self: *WAL) !void {
        // Only truncate if we actually replayed something
        if (self.current_offset == 0) return;

        try self.file.seekTo(0);
        try self.file.setEndPos(0);
        self.current_offset = 0;
    }
};
