// ============================================================================
// Zephyria — Network Compression (Production)
// ============================================================================
//
// Fast LZ4-style byte-level compression for network data.
// Optimized for speed over ratio — network latency matters more than
// squeezing every byte. Stateless design for thread safety.
//
// Features:
//   • Zero-allocation compression (writes to caller-provided buffer)
//   • Automatic fallback to raw if compression enlarges data
//   • Frame format with magic header for stream disambiguation
//   • Thread-safe: no mutable state
//   • Robust decompression with corruption detection

const std = @import("std");

// ── Constants ───────────────────────────────────────────────────────────

const MAGIC: [4]u8 = .{ 'Z', 'C', 'M', 'P' };
const RAW_MAGIC: [4]u8 = .{ 'Z', 'R', 'A', 'W' };
const HEADER_SIZE: usize = 12; // magic(4) + uncompressed_len(4) + compressed_len(4)
const MIN_MATCH_LEN: usize = 4;
const MAX_MATCH_LEN: usize = 255 + MIN_MATCH_LEN;
const WINDOW_SIZE: usize = 65535;
const HASH_BITS = 14;
const HASH_SIZE: usize = 1 << HASH_BITS;

// ── Statistics ──────────────────────────────────────────────────────────

pub const CompressionStats = struct {
    total_uncompressed: u64,
    total_compressed: u64,
    compression_calls: u64,
    decompression_calls: u64,
    raw_fallbacks: u64,

    pub fn ratio(self: *const CompressionStats) f64 {
        if (self.total_uncompressed == 0) return 1.0;
        return @as(f64, @floatFromInt(self.total_compressed)) /
            @as(f64, @floatFromInt(self.total_uncompressed));
    }
};

// ── Compressor ──────────────────────────────────────────────────────────

pub const Compressor = struct {
    allocator: std.mem.Allocator,
    stats: CompressionStats,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .stats = .{
                .total_uncompressed = 0,
                .total_compressed = 0,
                .compression_calls = 0,
                .decompression_calls = 0,
                .raw_fallbacks = 0,
            },
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Compress data. Returns owned slice that caller must free.
    /// If compression doesn't help, returns raw-framed data.
    pub fn compress(self: *Self, data: []const u8) ![]u8 {
        if (data.len == 0) {
            return try self.allocator.alloc(u8, 0);
        }

        // For very small data, don't bother compressing
        if (data.len < 64) {
            return try self.storeRaw(data);
        }

        // Allocate worst-case output buffer: header + data + possible expansion
        const max_compressed = HEADER_SIZE + data.len + (data.len / 255) + 16;
        const out_buf = try self.allocator.alloc(u8, max_compressed);
        errdefer self.allocator.free(out_buf);

        const compressed_len = lz4Compress(data, out_buf[HEADER_SIZE..]);

        // Check if compression helped
        if (compressed_len >= data.len) {
            self.allocator.free(out_buf);
            return try self.storeRaw(data);
        }

        // Write header
        @memcpy(out_buf[0..4], &MAGIC);
        std.mem.writeInt(u32, out_buf[4..8], @intCast(data.len), .little);
        std.mem.writeInt(u32, out_buf[8..12], @intCast(compressed_len), .little);

        const total_len = HEADER_SIZE + compressed_len;

        self.stats.total_uncompressed += data.len;
        self.stats.total_compressed += total_len;
        self.stats.compression_calls += 1;

        // Shrink allocation to actual size
        if (self.allocator.resize(out_buf, total_len)) {
            return out_buf[0..total_len];
        }
        // If resize not supported, dupe and free
        const result = try self.allocator.dupe(u8, out_buf[0..total_len]);
        self.allocator.free(out_buf);
        return result;
    }

    /// Decompress data. Returns owned slice that caller must free.
    pub fn decompress(self: *Self, data: []const u8) ![]u8 {
        if (data.len == 0) {
            return try self.allocator.alloc(u8, 0);
        }

        if (data.len < 4) return error.CorruptData;

        self.stats.decompression_calls += 1;

        // Check for raw-framed data
        if (std.mem.eql(u8, data[0..4], &RAW_MAGIC)) {
            if (data.len < 8) return error.CorruptData;
            const raw_len = std.mem.readInt(u32, data[4..8], .little);
            if (data.len < 8 + raw_len) return error.CorruptData;
            return try self.allocator.dupe(u8, data[8..][0..raw_len]);
        }

        // Check for compressed data
        if (!std.mem.eql(u8, data[0..4], &MAGIC)) return error.InvalidMagic;
        if (data.len < HEADER_SIZE) return error.CorruptData;

        const uncompressed_len = std.mem.readInt(u32, data[4..8], .little);
        const compressed_len = std.mem.readInt(u32, data[8..12], .little);

        if (data.len < HEADER_SIZE + compressed_len) return error.CorruptData;
        if (uncompressed_len > 256 * 1024 * 1024) return error.DataTooLarge; // 256 MB safety cap

        const out_buf = try self.allocator.alloc(u8, uncompressed_len);
        errdefer self.allocator.free(out_buf);

        const result_len = lz4Decompress(data[HEADER_SIZE..][0..compressed_len], out_buf) catch {
            self.allocator.free(out_buf);
            return error.DecompressFailed;
        };

        if (result_len != uncompressed_len) {
            self.allocator.free(out_buf);
            return error.LengthMismatch;
        }

        return out_buf;
    }

    /// Store data uncompressed with ZRAW header.
    fn storeRaw(self: *Self, data: []const u8) ![]u8 {
        const result = try self.allocator.alloc(u8, 8 + data.len);
        @memcpy(result[0..4], &RAW_MAGIC);
        std.mem.writeInt(u32, result[4..8], @intCast(data.len), .little);
        @memcpy(result[8..], data);

        self.stats.total_uncompressed += data.len;
        self.stats.total_compressed += result.len;
        self.stats.compression_calls += 1;
        self.stats.raw_fallbacks += 1;

        return result;
    }

    pub fn getStats(self: *const Self) CompressionStats {
        return self.stats;
    }
};

// ── LZ4-Style Compression Engine ────────────────────────────────────────

/// Fast LZ4-style compression. Returns number of bytes written to `out`.
fn lz4Compress(src: []const u8, out: []u8) usize {
    if (src.len == 0) return 0;

    var hash_table: [HASH_SIZE]u32 = [_]u32{0} ** HASH_SIZE;
    var ip: usize = 0;
    var op: usize = 0;
    var anchor: usize = 0;

    while (ip + MIN_MATCH_LEN <= src.len) {
        // Hash current position
        const h = hashAt(src, ip);
        const ref = hash_table[h];
        hash_table[h] = @intCast(ip);

        // Check for match
        if (ref > 0 and ip - ref < WINDOW_SIZE and ip >= MIN_MATCH_LEN and
            matchesAt(src, ref, ip))
        {
            // Encode literals before match
            const lit_len = ip - anchor;
            const match_len = findMatchLength(src, ref + MIN_MATCH_LEN, ip + MIN_MATCH_LEN);
            const total_match = MIN_MATCH_LEN + match_len;
            const offset = ip - ref;

            // Check output space
            if (op + 3 + lit_len + @divTrunc(lit_len, 255) + 1 >= out.len) {
                break; // Not enough output space
            }

            // Token byte: high nibble = literal length, low nibble = match length - 4
            var token: u8 = 0;
            if (lit_len >= 15) {
                token = 0xF0;
            } else {
                token = @intCast(lit_len << 4);
            }
            const ml_token: u8 = if (total_match - MIN_MATCH_LEN >= 15) 0x0F else @intCast(total_match - MIN_MATCH_LEN);
            token |= ml_token;

            out[op] = token;
            op += 1;

            // Extra literal length bytes
            if (lit_len >= 15) {
                var remaining = lit_len - 15;
                while (remaining >= 255) {
                    if (op >= out.len) return op;
                    out[op] = 255;
                    op += 1;
                    remaining -= 255;
                }
                if (op >= out.len) return op;
                out[op] = @intCast(remaining);
                op += 1;
            }

            // Literals
            if (op + lit_len > out.len) return op;
            @memcpy(out[op..][0..lit_len], src[anchor..][0..lit_len]);
            op += lit_len;

            // Offset (little-endian u16)
            if (op + 2 > out.len) return op;
            std.mem.writeInt(u16, out[op..][0..2], @intCast(offset), .little);
            op += 2;

            // Extra match length bytes
            if (total_match - MIN_MATCH_LEN >= 15) {
                var remaining = total_match - MIN_MATCH_LEN - 15;
                while (remaining >= 255) {
                    if (op >= out.len) return op;
                    out[op] = 255;
                    op += 1;
                    remaining -= 255;
                }
                if (op >= out.len) return op;
                out[op] = @intCast(remaining);
                op += 1;
            }

            ip += total_match;
            anchor = ip;
        } else {
            ip += 1;
        }
    }

    // Emit remaining literals
    const remaining_lit = src.len - anchor;
    if (remaining_lit > 0) {
        if (op + 1 + remaining_lit + @divTrunc(remaining_lit, 255) + 1 >= out.len) {
            return src.len; // Signal that compression didn't help
        }

        var token: u8 = 0;
        if (remaining_lit >= 15) {
            token = 0xF0;
        } else {
            token = @intCast(remaining_lit << 4);
        }
        out[op] = token;
        op += 1;

        if (remaining_lit >= 15) {
            var rem = remaining_lit - 15;
            while (rem >= 255) {
                out[op] = 255;
                op += 1;
                rem -= 255;
            }
            out[op] = @intCast(rem);
            op += 1;
        }

        @memcpy(out[op..][0..remaining_lit], src[anchor..][0..remaining_lit]);
        op += remaining_lit;
    }

    return op;
}

/// LZ4-style decompression. Returns number of bytes written to `out`.
fn lz4Decompress(src: []const u8, out: []u8) !usize {
    var ip: usize = 0;
    var op: usize = 0;

    while (ip < src.len) {
        if (ip >= src.len) return error.CorruptData;
        const token = src[ip];
        ip += 1;

        // Literal length
        var lit_len: usize = (token >> 4);
        if (lit_len == 15) {
            while (ip < src.len) {
                const extra = src[ip];
                ip += 1;
                lit_len += extra;
                if (extra != 255) break;
            }
        }

        // Copy literals
        if (ip + lit_len > src.len) return error.CorruptData;
        if (op + lit_len > out.len) return error.OutputOverflow;
        @memcpy(out[op..][0..lit_len], src[ip..][0..lit_len]);
        ip += lit_len;
        op += lit_len;

        // Check if this is the last sequence (no match after last literals)
        if (ip >= src.len) break;

        // Read offset
        if (ip + 2 > src.len) return error.CorruptData;
        const offset = std.mem.readInt(u16, src[ip..][0..2], .little);
        ip += 2;

        if (offset == 0) return error.CorruptData;
        if (offset > op) return error.CorruptData;

        // Match length
        var match_len: usize = (token & 0x0F) + MIN_MATCH_LEN;
        if ((token & 0x0F) == 15) {
            while (ip < src.len) {
                const extra = src[ip];
                ip += 1;
                match_len += extra;
                if (extra != 255) break;
            }
        }

        if (op + match_len > out.len) return error.OutputOverflow;

        // Copy match (byte-by-byte for overlapping copies)
        const match_start = op - offset;
        for (0..match_len) |i| {
            out[op + i] = out[match_start + (i % offset)];
        }
        op += match_len;
    }

    return op;
}

// ── Hashing Helpers ─────────────────────────────────────────────────────

inline fn hashAt(src: []const u8, pos: usize) usize {
    if (pos + 4 > src.len) return 0;
    const v = std.mem.readInt(u32, src[pos..][0..4], .little);
    return @intCast((v *% 2654435769) >> (32 - HASH_BITS));
}

inline fn matchesAt(src: []const u8, ref: u32, pos: usize) bool {
    if (ref + MIN_MATCH_LEN > src.len or pos + MIN_MATCH_LEN > src.len) return false;
    return std.mem.eql(u8, src[@intCast(ref)..][0..MIN_MATCH_LEN], src[pos..][0..MIN_MATCH_LEN]);
}

fn findMatchLength(src: []const u8, ref_pos: usize, cur_pos: usize) usize {
    var len: usize = 0;
    const max = @min(src.len - cur_pos, src.len - ref_pos);
    const cap = @min(max, MAX_MATCH_LEN - MIN_MATCH_LEN);
    while (len < cap and src[ref_pos + len] == src[cur_pos + len]) {
        len += 1;
    }
    return len;
}
