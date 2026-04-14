// SSTable (Sorted String Table) Implementation
// Immutable, sorted on-disk data structure for LSM tree

const std = @import("std");
const Allocator = std.mem.Allocator;
const fs = std.fs;

/// SSTable file format:
/// [Header][DataBlocks...][IndexBlock][BloomFilter][Footer]
///
/// Header (64 bytes):
///   - Magic (8 bytes): "SSTABLE1"
///   - Version (4 bytes)
///   - Key count (8 bytes)
///   - Data size (8 bytes)
///   - Index offset (8 bytes)
///   - Index size (8 bytes)
///   - Bloom offset (8 bytes)
///   - Bloom size (8 bytes)
///   - Checksum (4 bytes)
///
/// DataBlock (variable):
///   - [KeyLen(4)][Key...][ValueLen(4)][Value...][Checksum(4)]
///
/// IndexBlock:
///   - [FirstKey(32)][Offset(8)][Size(4)] per block
///
/// BloomFilter:
///   - Bit array for fast negative lookups
pub const SSTABLE_MAGIC: [8]u8 = "SSTABLE1".*;
pub const SSTABLE_VERSION: u32 = 1;
pub const BLOCK_SIZE: usize = 4096; // 4KB blocks
pub const BLOOM_BITS_PER_KEY: usize = 10;

/// SSTable Header
pub const Header = extern struct {
    magic: [8]u8,
    version: u32,
    key_count: u64,
    data_size: u64,
    index_offset: u64,
    index_size: u64,
    bloom_offset: u64,
    bloom_size: u64,
    checksum: u32,
    reserved: [4]u8,

    const SIZE: usize = 64;

    pub fn init() Header {
        return Header{
            .magic = SSTABLE_MAGIC,
            .version = SSTABLE_VERSION,
            .key_count = 0,
            .data_size = 0,
            .index_offset = 0,
            .index_size = 0,
            .bloom_offset = 0,
            .bloom_size = 0,
            .checksum = 0,
            .reserved = [_]u8{0} ** 4,
        };
    }

    pub fn calculateChecksum(self: *Header) void {
        const bytes = std.mem.asBytes(self);
        self.checksum = 0;
        self.checksum = std.hash.Crc32.hash(bytes[0 .. bytes.len - 8]); // Exclude checksum + reserved
    }

    pub fn verifyChecksum(self: *const Header) bool {
        var copy = self.*;
        copy.checksum = 0;
        const bytes = std.mem.asBytes(&copy);
        const expected = std.hash.Crc32.hash(bytes[0 .. bytes.len - 8]);
        return self.checksum == expected;
    }
};

/// Index entry for block lookup
pub const IndexEntry = struct {
    first_key: [32]u8,
    offset: u64,
    size: u32,

    const SIZE: usize = 44;
};

/// Bloom Filter for fast negative lookups
pub const BloomFilter = struct {
    bits: []u8,
    allocator: Allocator,
    num_keys: usize,

    const Self = @This();
    const NUM_HASHES: usize = 7; // Optimal for ~1% FPR with 10 bits/key

    pub fn init(allocator: Allocator, expected_keys: usize) !Self {
        const num_bits = expected_keys * BLOOM_BITS_PER_KEY;
        const num_bytes = (num_bits + 7) / 8;
        const bits = try allocator.alloc(u8, num_bytes);
        @memset(bits, 0);

        return Self{
            .bits = bits,
            .allocator = allocator,
            .num_keys = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bits);
    }

    pub fn add(self: *Self, key: []const u8) void {
        const hashes = self.getHashes(key);
        const num_bits = self.bits.len * 8;

        for (hashes) |h| {
            const bit_index = h % num_bits;
            self.bits[bit_index / 8] |= @as(u8, 1) << @intCast(bit_index % 8);
        }
        self.num_keys += 1;
    }

    pub fn mightContain(self: *const Self, key: []const u8) bool {
        const hashes = self.getHashes(key);
        const num_bits = self.bits.len * 8;

        for (hashes) |h| {
            const bit_index = h % num_bits;
            if ((self.bits[bit_index / 8] & (@as(u8, 1) << @intCast(bit_index % 8))) == 0) {
                return false;
            }
        }
        return true;
    }

    fn getHashes(self: *const Self, key: []const u8) [NUM_HASHES]usize {
        _ = self;
        // Use double hashing: h(i) = h1 + i*h2
        var hasher1 = std.hash.XxHash64.init(0);
        hasher1.update(key);
        const h1 = hasher1.final();

        var hasher2 = std.hash.XxHash64.init(1);
        hasher2.update(key);
        const h2 = hasher2.final();

        var result: [NUM_HASHES]usize = undefined;
        for (0..NUM_HASHES) |i| {
            result[i] = @intCast((h1 +% (@as(u64, @intCast(i)) *% h2)));
        }
        return result;
    }

    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();

        try list.appendSlice(std.mem.asBytes(&@as(u64, self.bits.len)));
        try list.appendSlice(self.bits);

        return list.toOwnedSlice();
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !Self {
        if (data.len < 8) return error.InvalidData;

        const len = std.mem.readInt(u64, data[0..8], .little);
        if (8 + len > data.len) return error.TruncatedData;

        const bits = try allocator.dupe(u8, data[8..][0..len]);

        return Self{
            .bits = bits,
            .allocator = allocator,
            .num_keys = 0, // Unknown after deserialization
        };
    }
};

/// SSTable Writer - builds SSTable from sorted key/value pairs
pub const SSTableWriter = struct {
    allocator: Allocator,
    file: fs.File,
    path: []const u8,

    // Buffers
    data_buffer: std.ArrayList(u8),
    index_entries: std.ArrayList(IndexEntry),
    bloom: BloomFilter,

    // State
    key_count: u64,
    current_block_offset: u64,
    current_block_size: usize,
    first_key_in_block: ?[32]u8,
    last_key: ?[32]u8,

    const Self = @This();

    pub fn init(allocator: Allocator, path: []const u8, expected_keys: usize) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const file = try fs.cwd().createFile(path, .{ .truncate = true });
        errdefer file.close();

        // Write placeholder header
        var header = Header.init();
        try file.writeAll(std.mem.asBytes(&header));

        self.* = Self{
            .allocator = allocator,
            .file = file,
            .path = try allocator.dupe(u8, path),
            .data_buffer = std.ArrayList(u8).init(allocator),
            .index_entries = std.ArrayList(IndexEntry).init(allocator),
            .bloom = try BloomFilter.init(allocator, expected_keys),
            .key_count = 0,
            .current_block_offset = Header.SIZE,
            .current_block_size = 0,
            .first_key_in_block = null,
            .last_key = null,
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.data_buffer.deinit();
        self.index_entries.deinit();
        self.bloom.deinit();
        self.file.close();
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }

    /// Add a key/value pair (must be called in sorted order)
    pub fn add(self: *Self, key: [32]u8, value: []const u8) !void {
        // Verify sort order
        if (self.last_key) |last| {
            if (std.mem.order(u8, &key, &last) != .gt) {
                return error.KeysNotSorted;
            }
        }
        self.last_key = key;

        // Check if we need to flush current block
        const entry_size = 4 + 32 + 4 + value.len + 4; // keylen + key + vallen + val + checksum
        if (self.current_block_size + entry_size > BLOCK_SIZE and self.current_block_size > 0) {
            try self.flushBlock();
        }

        // Record first key in block
        if (self.first_key_in_block == null) {
            self.first_key_in_block = key;
        }

        // Write entry to buffer
        try self.data_buffer.appendSlice(std.mem.asBytes(&@as(u32, 32)));
        try self.data_buffer.appendSlice(&key);
        try self.data_buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(value.len))));
        try self.data_buffer.appendSlice(value);

        // Entry checksum
        var hasher = std.hash.Crc32.init();
        hasher.update(&key);
        hasher.update(value);
        const checksum = hasher.final();
        try self.data_buffer.appendSlice(std.mem.asBytes(&checksum));

        self.current_block_size += entry_size;
        self.key_count += 1;

        // Add to bloom filter
        self.bloom.add(&key);
    }

    /// Finish writing and return path
    pub fn finish(self: *Self) ![]const u8 {
        // Flush remaining block
        if (self.current_block_size > 0) {
            try self.flushBlock();
        }

        // Write index block
        const index_offset = try self.file.getPos();
        for (self.index_entries.items) |entry| {
            try self.file.writeAll(&entry.first_key);
            try self.file.writeAll(std.mem.asBytes(&entry.offset));
            try self.file.writeAll(std.mem.asBytes(&entry.size));
        }
        const index_size = (try self.file.getPos()) - index_offset;

        // Write bloom filter
        const bloom_offset = try self.file.getPos();
        const bloom_data = try self.bloom.serialize(self.allocator);
        defer self.allocator.free(bloom_data);
        try self.file.writeAll(bloom_data);
        const bloom_size = (try self.file.getPos()) - bloom_offset;

        // Update and write header
        var header = Header.init();
        header.key_count = self.key_count;
        header.data_size = index_offset - Header.SIZE;
        header.index_offset = index_offset;
        header.index_size = index_size;
        header.bloom_offset = bloom_offset;
        header.bloom_size = bloom_size;
        header.calculateChecksum();

        try self.file.seekTo(0);
        try self.file.writeAll(std.mem.asBytes(&header));

        return self.path;
    }

    fn flushBlock(self: *Self) !void {
        // Write block to file
        const block_data = self.data_buffer.items;
        try self.file.writeAll(block_data);

        // Add index entry
        try self.index_entries.append(.{
            .first_key = self.first_key_in_block.?,
            .offset = self.current_block_offset,
            .size = @intCast(block_data.len),
        });

        // Reset for next block
        self.current_block_offset += block_data.len;
        self.data_buffer.clearRetainingCapacity();
        self.current_block_size = 0;
        self.first_key_in_block = null;
    }
};

/// SSTable Reader - reads from existing SSTable
pub const SSTableReader = struct {
    allocator: Allocator,
    file: fs.File,
    path: []const u8,
    header: Header,
    index: []IndexEntry,
    bloom: BloomFilter,

    const Self = @This();

    pub fn open(allocator: Allocator, path: []const u8) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const file = try fs.cwd().openFile(path, .{ .mode = .read_only });
        errdefer file.close();

        // Read header
        var header: Header = undefined;
        const header_bytes = try file.readAll(std.mem.asBytes(&header));
        if (header_bytes < Header.SIZE) {
            allocator.destroy(self);
            return error.TruncatedHeader;
        }

        // Verify magic and checksum
        if (!std.mem.eql(u8, &header.magic, &SSTABLE_MAGIC)) {
            allocator.destroy(self);
            return error.InvalidMagic;
        }
        if (!header.verifyChecksum()) {
            allocator.destroy(self);
            return error.ChecksumMismatch;
        }

        // Read index
        try file.seekTo(header.index_offset);
        const num_entries = header.index_size / IndexEntry.SIZE;
        const index = try allocator.alloc(IndexEntry, num_entries);
        errdefer allocator.free(index);

        for (0..num_entries) |i| {
            _ = try file.readAll(&index[i].first_key);
            var offset_bytes: [8]u8 = undefined;
            _ = try file.readAll(&offset_bytes);
            index[i].offset = std.mem.readInt(u64, &offset_bytes, .little);
            var size_bytes: [4]u8 = undefined;
            _ = try file.readAll(&size_bytes);
            index[i].size = std.mem.readInt(u32, &size_bytes, .little);
        }

        // Read bloom filter
        try file.seekTo(header.bloom_offset);
        const bloom_data = try allocator.alloc(u8, header.bloom_size);
        defer allocator.free(bloom_data);
        _ = try file.readAll(bloom_data);
        const bloom = try BloomFilter.deserialize(allocator, bloom_data);

        self.* = Self{
            .allocator = allocator,
            .file = file,
            .path = try allocator.dupe(u8, path),
            .header = header,
            .index = index,
            .bloom = bloom,
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.index);
        self.bloom.deinit();
        self.file.close();
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }

    /// Get value for key (returns slice that must not be freed - valid until next get)
    pub fn get(self: *Self, key: [32]u8) !?[]const u8 {
        // Quick bloom filter check
        if (!self.bloom.mightContain(&key)) {
            return null;
        }

        // Binary search for the right block
        const block_idx = self.findBlockIndex(key);
        if (block_idx >= self.index.len) {
            return null;
        }

        // Read and search the block
        const entry = self.index[block_idx];
        try self.file.seekTo(entry.offset);

        const block_data = try self.allocator.alloc(u8, entry.size);
        defer self.allocator.free(block_data);
        _ = try self.file.readAll(block_data);

        // Parse block and search for key
        var offset: usize = 0;
        while (offset < block_data.len) {
            if (offset + 8 > block_data.len) break;

            const key_len = std.mem.readInt(u32, block_data[offset..][0..4], .little);
            offset += 4;

            if (offset + key_len > block_data.len) break;
            if (key_len != 32) {
                offset += key_len;
                if (offset + 4 > block_data.len) break;
                const val_len = std.mem.readInt(u32, block_data[offset..][0..4], .little);
                offset += 4 + val_len + 4;
                continue;
            }

            const entry_key = block_data[offset..][0..32];
            offset += 32;

            const val_len = std.mem.readInt(u32, block_data[offset..][0..4], .little);
            offset += 4;

            if (std.mem.eql(u8, entry_key, &key)) {
                // Found! Return a copy
                return try self.allocator.dupe(u8, block_data[offset..][0..val_len]);
            }

            offset += val_len + 4; // Skip value and checksum
        }

        return null;
    }

    /// Check if key might exist (uses bloom filter)
    pub fn mightContain(self: *const Self, key: [32]u8) bool {
        return self.bloom.mightContain(&key);
    }

    /// Get key count
    pub fn keyCount(self: *const Self) u64 {
        return self.header.key_count;
    }

    fn findBlockIndex(self: *const Self, key: [32]u8) usize {
        // Binary search for the block that might contain this key
        var left: usize = 0;
        var right: usize = self.index.len;

        while (left < right) {
            const mid = left + (right - left) / 2;
            const cmp = std.mem.order(u8, &self.index[mid].first_key, &key);

            if (cmp == .gt) {
                right = mid;
            } else {
                left = mid + 1;
            }
        }

        return if (left > 0) left - 1 else 0;
    }
};

// Tests

test "BloomFilter basic" {
    const allocator = std.testing.allocator;
    var bloom = try BloomFilter.init(allocator, 100);
    defer bloom.deinit();

    const key1 = "key1";
    const key2 = "key2";

    bloom.add(key1);
    bloom.add(key2);

    try std.testing.expect(bloom.mightContain(key1));
    try std.testing.expect(bloom.mightContain(key2));
    // key3 might be a false positive, but low probability
}

test "SSTable write and read" {
    const allocator = std.testing.allocator;

    const path = "test_sstable.sst";
    defer std.fs.cwd().deleteFile(path) catch {};

    // Write SSTable
    {
        var writer = try SSTableWriter.init(allocator, path, 10);
        defer writer.deinit();

        const key1: [32]u8 = [_]u8{0x01} ** 32;
        const key2: [32]u8 = [_]u8{0x02} ** 32;
        const key3: [32]u8 = [_]u8{0x03} ** 32;

        try writer.add(key1, "value1");
        try writer.add(key2, "value2");
        try writer.add(key3, "value3");

        _ = try writer.finish();
    }

    // Read SSTable
    {
        var reader = try SSTableReader.open(allocator, path);
        defer reader.deinit();

        try std.testing.expect(reader.keyCount() == 3);

        const key1: [32]u8 = [_]u8{0x01} ** 32;
        if (try reader.get(key1)) |value| {
            defer allocator.free(value);
            try std.testing.expectEqualStrings("value1", value);
        } else {
            return error.Key1NotFound;
        }

        const key2: [32]u8 = [_]u8{0x02} ** 32;
        if (try reader.get(key2)) |value| {
            defer allocator.free(value);
            try std.testing.expectEqualStrings("value2", value);
        } else {
            return error.Key2NotFound;
        }
    }
}
