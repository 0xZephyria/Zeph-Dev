// ============================================================================
// Zephyria — Turbine Block Propagation (Loom Genesis Adaptive)
// ============================================================================
//
// Erasure-coded block propagation via deterministic propagation tree.
//
// Features:
//   • GF(2^8) Reed-Solomon erasure coding (encode + decode)
//   • Adaptive shred count based on block size
//   • Stake-weighted propagation tree with configurable fanout
//   • Shred signature verification
//   • Block reconstruction from any data_shreds-of-(data+parity) combination
//   • Bandwidth-aware: respects per-layer bandwidth budgets
//   • Thread-aware: each shred carries thread_id for targeted propagation

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const log = core.logger;
const Crc32 = std.hash.crc.Crc32IsoHdlc;

// ── Constants ───────────────────────────────────────────────────────────

pub const MAX_SHRED_PAYLOAD: usize = 1100; // Leave room for shred header in MTU
pub const DEFAULT_PARITY_RATIO: f64 = 0.25; // 25% parity shreds (base)
pub const MIN_PARITY_RATIO: f64 = 0.10; // 10% minimum parity for fast networks
pub const MAX_PARITY_RATIO: f64 = 0.50; // 50% maximum parity for lossy networks
pub const MAX_BLOCK_SIZE: usize = 256 * 1024 * 1024; // 256 MB
pub const MAX_SHREDS: u32 = 262144; // 256K shreds max
const STRIPE_COUNT: usize = 16; // Striped lock shards for TurbineEngine
const FAILURE_WINDOW_SIZE: u8 = 64; // Sliding window for failure rate tracking
const FAILURE_WINDOW_SECS: u64 = 300; // 5 minute window

// ── GF(2^8) Galois Field Arithmetic ─────────────────────────────────────

/// GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
const GF256 = struct {
    const POLYNOMIAL: u16 = 0x11D;

    /// Precomputed multiplication tables for fast GF arithmetic
    var log_table: [256]u8 = undefined;
    var exp_table: [512]u8 = undefined;
    var initialized: bool = false;

    fn ensureInit() void {
        if (initialized) return;
        initTables();
        initialized = true;
    }

    fn initTables() void {
        var x: u16 = 1;
        for (0..255) |i| {
            exp_table[i] = @intCast(x);
            exp_table[i + 255] = @intCast(x);
            log_table[@intCast(x)] = @intCast(i);
            x = gfMultiplyNoTable(x, 2);
        }
        log_table[0] = 0;
    }

    fn gfMultiplyNoTable(a: u16, b: u16) u16 {
        var result: u16 = 0;
        var aa = a;
        var bb = b;
        while (bb > 0) {
            if (bb & 1 != 0) result ^= aa;
            aa <<= 1;
            if (aa & 0x100 != 0) aa ^= POLYNOMIAL;
            bb >>= 1;
        }
        return result & 0xFF;
    }

    pub fn multiply(a: u8, b: u8) u8 {
        ensureInit();
        if (a == 0 or b == 0) return 0;
        const log_a = log_table[a];
        const log_b = log_table[b];
        return exp_table[@as(u16, log_a) + @as(u16, log_b)];
    }

    pub fn inverse(a: u8) u8 {
        ensureInit();
        if (a == 0) return 0;
        return exp_table[255 - @as(u16, log_table[a])];
    }

    pub fn divide(a: u8, b: u8) u8 {
        if (b == 0) return 0;
        return multiply(a, inverse(b));
    }

    // ── SIMD-Vectorized Multiply-by-Constant ────────────────────────
    //
    // Multiplies an entire buffer by a GF(2^8) constant using a
    // split-nibble lookup approach. For each byte x:
    //   result = low_table[x & 0x0F] ^ high_table[x >> 4]
    // This is equivalent to two SSSE3 pshufb + pxor when vectorized.
    // Processes 16 bytes at a time for ~16x speedup over scalar.

    /// Precomputed 16-entry lookup tables for multiply-by-constant.
    const MulTable = struct {
        low: [16]u8, // GF multiply for nibble values 0x0..0xF
        high: [16]u8, // GF multiply for (nibble << 4) values 0x00..0xF0
    };

    /// Build lookup tables for multiply-by-constant `c`.
    fn buildMulTable(c: u8) MulTable {
        var t: MulTable = undefined;
        for (0..16) |i| {
            t.low[i] = multiply(c, @intCast(i));
            t.high[i] = multiply(c, @intCast(i << 4));
        }
        return t;
    }

    /// SIMD-accelerated multiply-accumulate: dst[i] ^= c * src[i]
    /// Falls back to scalar for tail bytes.
    pub fn mulAccum(dst: []u8, src: []const u8, c: u8) void {
        if (c == 0) return;
        if (c == 1) {
            for (dst, src) |*d, s| d.* ^= s;
            return;
        }

        ensureInit();
        const tbl = buildMulTable(c);
        const len = @min(dst.len, src.len);
        var i: usize = 0;

        // Vectorized path: process 16 bytes at a time
        const VEC_SIZE = 16;
        const Vec = @Vector(VEC_SIZE, u8);
        const low_lookup: Vec = tbl.low;
        const high_lookup: Vec = tbl.high;
        const mask_0f: Vec = @splat(0x0F);

        while (i + VEC_SIZE <= len) : (i += VEC_SIZE) {
            const s: Vec = src[i..][0..VEC_SIZE].*;
            const d: Vec = dst[i..][0..VEC_SIZE].*;

            // Split nibble lookup: low_table[s & 0x0F] ^ high_table[s >> 4]
            const lo_nib = s & mask_0f;
            const hi_nib = (s >> @splat(4)) & mask_0f;

            // Manual lookup into the 16-byte tables
            var result: Vec = undefined;
            inline for (0..VEC_SIZE) |vi| {
                result[vi] = low_lookup[lo_nib[vi]] ^ high_lookup[hi_nib[vi]];
            }

            // XOR-accumulate into destination
            const out = d ^ result;
            dst[i..][0..VEC_SIZE].* = out;
        }

        // Scalar tail
        while (i < len) : (i += 1) {
            dst[i] ^= tbl.low[src[i] & 0x0F] ^ tbl.high[src[i] >> 4];
        }
    }
};

// ── Reed-Solomon Encoder ────────────────────────────────────────────────

pub const ReedSolomon = struct {
    dataShreds: u32,
    parityShreds: u32,
    totalShreds: u32,

    const Self = @This();

    pub fn init(dataShreds: u32, parityShreds: u32) Self {
        std.debug.assert(dataShreds + parityShreds <= 256);
        return .{
            .dataShreds = dataShreds,
            .parityShreds = parityShreds,
            .totalShreds = dataShreds + parityShreds,
        };
    }

    /// Encode: generate parity shreds from data shreds.
    /// `shards` must have length = totalShreds, first dataShreds are input,
    /// remaining parityShreds are written as output.
    /// All shards must have the same length.
    /// Encode: generate parity shreds using SIMD-accelerated GF multiply.
    pub fn encode(self: *const Self, shards: [][]u8) void {
        GF256.ensureInit();

        // Generate parity shards using SIMD multiply-accumulate
        for (0..self.parityShreds) |pi| {
            const parity_shard = shards[self.dataShreds + pi];
            @memset(parity_shard, 0);

            for (0..self.dataShreds) |di| {
                const coeff = vandermondeCoeff(@intCast(pi), @intCast(di));
                // SIMD path: ~16x faster than scalar byte-by-byte
                GF256.mulAccum(parity_shard, shards[di], coeff);
            }
        }
    }

    /// Decode: reconstruct missing shards. `shards` has total_shards entries.
    /// Missing shards should be zero-filled. `present` bitmap indicates which shards exist.
    /// Returns true on success.
    pub fn decode(self: *const Self, allocator: std.mem.Allocator, shards: [][]u8, present: []const bool) !bool {
        GF256.ensureInit();

        // Count present shards
        var present_count: u32 = 0;
        for (present) |p| {
            if (p) present_count += 1;
        }

        // Need at least dataShreds present
        if (present_count < self.dataShreds) return false;

        // If all data shards present, nothing to do
        var all_data_present = true;
        for (0..self.dataShreds) |i| {
            if (!present[i]) {
                all_data_present = false;
                break;
            }
        }
        if (all_data_present) return true;

        const shard_len = shards[0].len;

        // Build sub-matrix from present shards and invert
        // Select dataShreds present shards
        var selected_indices: [256]u32 = undefined;
        var selected_count: u32 = 0;
        for (0..self.totalShreds) |i| {
            if (present[i] and selected_count < self.dataShreds) {
                selected_indices[selected_count] = @intCast(i);
                selected_count += 1;
            }
        }

        if (selected_count < self.dataShreds) return false;

        // Build the encoding matrix for selected rows
        const n = self.dataShreds;
        const matrix = try allocator.alloc(u8, n * n);
        defer allocator.free(matrix);

        for (0..n) |row| {
            const shard_idx = selected_indices[row];
            for (0..n) |col| {
                if (shard_idx < self.dataShreds) {
                    // Identity row
                    matrix[row * n + col] = if (shard_idx == col) 1 else 0;
                } else {
                    // Parity row
                    const pi = shard_idx - self.dataShreds;
                    matrix[row * n + col] = vandermondeCoeff(@intCast(pi), @intCast(col));
                }
            }
        }

        // Invert the matrix using Gaussian elimination in GF(2^8)
        const inv_matrix = try allocator.alloc(u8, n * n);
        defer allocator.free(inv_matrix);

        if (!gaussianInvert(matrix, inv_matrix, n)) return false;

        // Reconstruct missing data shards
        for (0..self.dataShreds) |di| {
            if (present[di]) continue; // Already have this shard

            // Reconstruct shard[di] = sum of inv_matrix[di][j] * selected_shard[j]
            @memset(shards[di], 0);
            for (0..n) |j| {
                const coeff = inv_matrix[di * n + j];
                if (coeff == 0) continue;
                const src_shard = shards[selected_indices[j]];
                for (0..shard_len) |b| {
                    shards[di][b] ^= GF256.multiply(coeff, src_shard[b]);
                }
            }
        }

        return true;
    }

    fn vandermondeCoeff(row: u8, col: u8) u8 {
        GF256.ensureInit();
        // Switch from Vandermonde to Cauchy matrix coefficients to ensure systematic MDS code properties.
        // Element: 1 / (x_i ^ y_j) where x_i = row + 128 (range 128..255) and y_j = col (range 0..127).
        // Since the sets X and Y are completely disjoint, the denominator is never zero.
        const x = row +% 128;
        const y = col;
        const diff = x ^ y;
        return GF256.inverse(diff);
    }

    /// Gaussian elimination to invert matrix in GF(2^8)
    fn gaussianInvert(matrix: []u8, inv: []u8, n: u32) bool {
        // Initialize inv as identity
        for (0..n) |i| {
            for (0..n) |j| {
                inv[i * n + j] = if (i == j) 1 else 0;
            }
        }

        // Forward elimination
        for (0..n) |col| {
            // Find pivot
            var pivot_row: ?usize = null;
            for (col..n) |row| {
                if (matrix[row * n + col] != 0) {
                    pivot_row = row;
                    break;
                }
            }
            if (pivot_row == null) return false; // Singular

            const pr = pivot_row.?;

            // Swap rows if needed
            if (pr != col) {
                for (0..n) |j| {
                    std.mem.swap(u8, &matrix[col * n + j], &matrix[pr * n + j]);
                    std.mem.swap(u8, &inv[col * n + j], &inv[pr * n + j]);
                }
            }

            // Scale pivot row
            const pivot_val = matrix[col * n + col];
            const pivot_inv = GF256.inverse(pivot_val);
            for (0..n) |j| {
                matrix[col * n + j] = GF256.multiply(matrix[col * n + j], pivot_inv);
                inv[col * n + j] = GF256.multiply(inv[col * n + j], pivot_inv);
            }

            // Eliminate column
            for (0..n) |row| {
                if (row == col) continue;
                const factor = matrix[row * n + col];
                if (factor == 0) continue;
                for (0..n) |j| {
                    matrix[row * n + j] ^= GF256.multiply(factor, matrix[col * n + j]);
                    inv[row * n + j] ^= GF256.multiply(factor, inv[col * n + j]);
                }
            }
        }

        return true;
    }
};

// ── Shred ───────────────────────────────────────────────────────────────

pub const Shred = struct {
    /// Canonical block id — identifies the block this shred belongs to
    blockId: core.types.Hash,
    blockNumber: u64,
    shredIndex: u32,
    totalDataShreds: u32,
    totalParityShreds: u32,
    shredType: types.ShredType,
    payload: []const u8,
    /// Block-level BLS signature authenticates all shreds via reconstruction
    producerSignature: [96]u8,
    /// Thread ID for targeted propagation (Loom Genesis)
    threadId: u8,
    /// CRC32 over (block_number ++ shredIndex ++ payload) for fast integrity check
    crc32: u32,

    pub fn payloadSize(self: *const Shred) usize {
        return self.payload.len;
    }

    /// Compute the CRC32 for this shred's header + payload.
    pub fn computeCrc(self: *const Shred) u32 {
        var hasher = Crc32.init();
        hasher.update(std.mem.asBytes(&self.blockNumber));
        hasher.update(std.mem.asBytes(&self.shredIndex));
        hasher.update(self.payload);
        return hasher.final();
    }

    /// Verify CRC integrity. Returns false if payload was corrupted.
    pub fn verifyCrc(self: *const Shred) bool {
        return self.crc32 == self.computeCrc();
    }
};

// ── Shred Buffer Pool ───────────────────────────────────────────────────
//
// Pre-allocates shred payload buffers to avoid per-block allocation overhead.
// At 400ms blocks with 54K shreds, this eliminates ~60 MB of alloc/free per block.

pub const ShredBufferPool = struct {
    allocator: std.mem.Allocator,
    buffers: std.ArrayListUnmanaged([]u8),
    available: std.ArrayListUnmanaged(usize),
    bufSize: usize,
    mutex: std.Thread.Mutex,

    // Stats
    totalAllocated: u64,
    poolHits: u64,
    poolMisses: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, initial_count: usize, bufSize: usize) !Self {
        var pool = Self{
            .allocator = allocator,
            .buffers = .{},
            .available = .{},
            .bufSize = bufSize,
            .mutex = .{},
            .totalAllocated = 0,
            .poolHits = 0,
            .poolMisses = 0,
        };

        // Pre-allocate buffers
        for (0..initial_count) |_| {
            const buf = try allocator.alloc(u8, bufSize);
            try pool.buffers.append(allocator, buf);
            try pool.available.append(allocator, pool.buffers.items.len - 1);
        }
        pool.totalAllocated = initial_count;

        return pool;
    }

    pub fn deinit(self: *Self) void {
        for (self.buffers.items) |buf| {
            self.allocator.free(buf);
        }
        self.buffers.deinit(self.allocator);
        self.available.deinit(self.allocator);
    }

    /// Acquire a buffer from the pool, or allocate a new one if empty.
    pub fn acquire(self: *Self) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.available.items.len > 0) {
            const idx = self.available.pop().?;
            self.poolHits += 1;
            const buf = self.buffers.items[idx];
            @memset(buf, 0);
            return buf;
        }

        // Grow: allocate a new buffer
        self.poolMisses += 1;
        const buf = try self.allocator.alloc(u8, self.bufSize);
        @memset(buf, 0);
        try self.buffers.append(self.allocator, buf);
        self.totalAllocated += 1;
        return buf;
    }

    /// Return a buffer to the pool for reuse.
    pub fn release(self: *Self, buf: []u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Find the index of this buffer
        for (self.buffers.items, 0..) |b, i| {
            if (b.ptr == buf.ptr) {
                self.available.append(self.allocator, i) catch return;
                return;
            }
        }
        // Not from our pool — free it
        self.allocator.free(buf);
    }
};

// ── Shred Collector ─────────────────────────────────────────────────────

pub const ShredCollector = struct {
    allocator: std.mem.Allocator,
    blockNumber: u64,
    blockId: core.types.Hash,
    dataShreds: u32,
    parityShreds: u32,
    totalShreds: u32,
    shredSize: usize,
    shards: [][]u8,
    present: []bool,
    receivedCount: u32,
    complete: bool,
    lastRepairTime: i64,
    nextRepairTime: i64, // Next time to trigger repair request (monotonic)
    repairBackoffMs: u64, // Exponential backoff for repair requests
    createdTime: i64,
    producerSignature: [96]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, blockNumber: u64, dataShreds: u32, parityShreds: u32, shredSize: usize) !Self {
        const total = dataShreds + parityShreds;
        const shards = try allocator.alloc([]u8, total);
        const present = try allocator.alloc(bool, total);

        for (0..total) |i| {
            shards[i] = try allocator.alloc(u8, shredSize);
            @memset(shards[i], 0);
            present[i] = false;
        }

        return Self{
            .allocator = allocator,
            .blockNumber = blockNumber,
            .blockId = core.types.Hash.zero(),
            .dataShreds = dataShreds,
            .parityShreds = parityShreds,
            .totalShreds = total,
            .shredSize = shredSize,
            .shards = shards,
            .present = present,
            .receivedCount = 0,
            .complete = false,
            .lastRepairTime = 0,
            .nextRepairTime = std.time.milliTimestamp() + 200, // First repair after 200ms
            .repairBackoffMs = 200,
            .createdTime = std.time.milliTimestamp(),
            .producerSignature = [_]u8{0} ** 96,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.shards) |shard| {
            self.allocator.free(shard);
        }
        self.allocator.free(self.shards);
        self.allocator.free(self.present);
    }

    /// Insert a received shred. Returns true if we now have enough to reconstruct.
    pub fn insertShred(self: *Self, shred: *const Shred) bool {
        if (self.complete) return true;
        if (shred.shredIndex >= self.totalShreds) return false;

        const idx = shred.shredIndex;
        if (self.present[idx]) return false; // Duplicate

        // Copy payload into shard buffer
        const copy_len = @min(shred.payload.len, self.shredSize);
        @memcpy(self.shards[idx][0..copy_len], shred.payload[0..copy_len]);
        self.present[idx] = true;
        self.receivedCount += 1;

        // Check if we have enough for reconstruction across all FEC sets
        const FEC_SIZE = 128;
        const num_fec_sets = (self.dataShreds + FEC_SIZE - 1) / FEC_SIZE;
        var is_reconstructible = true;
        var f: u32 = 0;
        while (f < num_fec_sets) : (f += 1) {
            const data_start = f * FEC_SIZE;
            const data_end = @min((f + 1) * FEC_SIZE, self.dataShreds);
            const fec_data_count = data_end - data_start;

            const parity_start = f * self.parityShreds / num_fec_sets;
            const parity_end = (f + 1) * self.parityShreds / num_fec_sets;
            const fec_parity_count = parity_end - parity_start;

            // Count how many shreds are present in this FEC set
            var present_in_fec: u32 = 0;
            // Check data shreds
            var idx_check: usize = 0;
            while (idx_check < fec_data_count) : (idx_check += 1) {
                if (self.present[data_start + idx_check]) present_in_fec += 1;
            }
            // Check parity shreds
            idx_check = 0;
            while (idx_check < fec_parity_count) : (idx_check += 1) {
                if (self.present[self.dataShreds + parity_start + idx_check]) present_in_fec += 1;
            }

            if (present_in_fec < fec_data_count) {
                is_reconstructible = false;
                break;
            }
        }

        if (is_reconstructible) {
            self.complete = true;
            return true;
        }
        return false;
    }

    /// Reconstruct the original block from collected shreds.
    /// Requires at least dataShreds shreds to have been received.
    pub fn reconstruct(self: *Self) ![]u8 {
        if (self.receivedCount < self.dataShreds) return error.InsufficientShreds;

        // Run Reed-Solomon decode if any data shreds are missing
        var all_data_present = true;
        for (0..self.dataShreds) |i| {
            if (!self.present[i]) {
                all_data_present = false;
                break;
            }
        }

        if (!all_data_present) {
            const FEC_SIZE = 128;
            const num_fec_sets = (self.dataShreds + FEC_SIZE - 1) / FEC_SIZE;
            var f: u32 = 0;
            while (f < num_fec_sets) : (f += 1) {
                const data_start = f * FEC_SIZE;
                const data_end = @min((f + 1) * FEC_SIZE, self.dataShreds);
                const fec_data_count = data_end - data_start;

                const parity_start = f * self.parityShreds / num_fec_sets;
                const parity_end = (f + 1) * self.parityShreds / num_fec_sets;
                const fec_parity_count = parity_end - parity_start;

                // Check if this FEC set needs decoding
                var all_fec_data_present = true;
                var idx_check: usize = 0;
                while (idx_check < fec_data_count) : (idx_check += 1) {
                    if (!self.present[data_start + idx_check]) {
                        all_fec_data_present = false;
                        break;
                    }
                }

                if (all_fec_data_present) continue;

                // Build local slices for ReedSolomon.decode
                const fec_total = fec_data_count + fec_parity_count;
                const fec_shards = try self.allocator.alloc([]u8, fec_total);
                defer self.allocator.free(fec_shards);
                const fec_present = try self.allocator.alloc(bool, fec_total);
                defer self.allocator.free(fec_present);

                // Populate data shards and present flags
                var idx: usize = 0;
                while (idx < fec_data_count) : (idx += 1) {
                    fec_shards[idx] = self.shards[data_start + idx];
                    fec_present[idx] = self.present[data_start + idx];
                }
                // Populate parity shards and present flags
                idx = 0;
                while (idx < fec_parity_count) : (idx += 1) {
                    fec_shards[fec_data_count + idx] = self.shards[self.dataShreds + parity_start + idx];
                    fec_present[fec_data_count + idx] = self.present[self.dataShreds + parity_start + idx];
                }

                const rs = ReedSolomon.init(fec_data_count, fec_parity_count);
                const success = try rs.decode(self.allocator, fec_shards, fec_present);
                if (!success) return error.ReconstructionFailed;

                // Copy decoded data back to present flags
                idx = 0;
                while (idx < fec_data_count) : (idx += 1) {
                    self.present[data_start + idx] = fec_present[idx];
                }
            }
        }

        // Concatenate data shreds to form the block
        const total_size = @as(usize, self.dataShreds) * self.shredSize;
        const block_data = try self.allocator.alloc(u8, total_size);

        for (0..self.dataShreds) |i| {
            const offset = i * self.shredSize;
            @memcpy(block_data[offset..][0..self.shredSize], self.shards[i]);
        }

        return block_data;
    }

    pub fn progress(self: *const Self) f64 {
        if (self.dataShreds == 0) return 1.0;
        return @as(f64, @floatFromInt(self.receivedCount)) / @as(f64, @floatFromInt(self.dataShreds));
    }

    /// Returns indices of missing data shreds for repair requests.
    /// Only includes data shreds (not parity) — requesters reconstruct from
    /// any data shreds + sufficient parity, so repairing data is priority.
    /// Caller must free the returned slice.
    pub fn missingDataShredIndices(self: *const Self, allocator: std.mem.Allocator) ![]u32 {
        var missing = std.ArrayListUnmanaged(u32){};
        defer missing.deinit(allocator);

        for (0..self.dataShreds) |i| {
            if (!self.present[i]) {
                try missing.append(allocator, @intCast(i));
            }
        }

        const result = try allocator.alloc(u32, missing.items.len);
        @memcpy(result, missing.items);
        return result;
    }

    /// Check if it's time to trigger a repair request.
    pub fn shouldRequestRepair(self: *const Self) bool {
        if (self.complete) return false;
        if (self.receivedCount == 0) return false;
        return std.time.milliTimestamp() >= self.nextRepairTime;
    }

    /// Advance the repair timer with exponential backoff (capped at 2 seconds).
    pub fn advanceRepairTimer(self: *Self) void {
        self.nextRepairTime = std.time.milliTimestamp() + @as(i64, @intCast(self.repairBackoffMs));
        self.lastRepairTime = std.time.milliTimestamp();
        self.repairBackoffMs = @min(self.repairBackoffMs * 2, 2000); // Double, cap at 2s
    }
};

// ── Propagation Tree ────────────────────────────────────────────────────

pub const StakeWeightedPeer = struct {
    address: core.types.Address,
    stake: u256,
};

pub const TreeNode = struct {
    peerIndex: u32,
    layer: u8,
    childrenStart: u32,
    childrenCount: u16,
    shredStart: u32,
    shredCount: u32,
};

pub const PropagationTree = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayListUnmanaged(TreeNode),
    fanout: u32,
    totalLayers: u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .nodes = .{},
            .fanout = types.TURBINE_FANOUT,
            .totalLayers = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit(self.allocator);
    }

    /// Build the propagation tree from stake-weighted peers.
    /// Caller must sort peers by stake descending so that peerIndex 0 = highest stake.
    /// Higher-stake nodes get higher fanout (more children), lower-stake nodes are leaves.
    pub fn build(self: *Self, peers: []const StakeWeightedPeer, total_shreds: u32) !void {
        self.nodes.clearRetainingCapacity();

        const num_peers: u32 = @intCast(peers.len);
        if (num_peers == 0) return;

        // Calculate layers needed
        var layers: u8 = 1;
        var nodes_covered: u32 = 1;
        while (nodes_covered < num_peers) {
            nodes_covered *= self.fanout;
            layers += 1;
            if (layers >= 10) break;
        }
        self.totalLayers = layers;

        // Build tree level by level
        var peer_idx: u32 = 0;
        var current_layer_start: u32 = 0;

        // Root node (peer 0 = highest stake)
        try self.nodes.append(self.allocator, .{
            .peerIndex = 0,
            .layer = 0,
            .childrenStart = 1,
            .childrenCount = @intCast(@min(self.fanout, num_peers - 1)),
            .shredStart = 0,
            .shredCount = total_shreds,
        });
        peer_idx = 1;
        current_layer_start = 0;

        // Build subsequent layers
        for (1..layers) |layer| {
            const parent_start = current_layer_start;
            const parent_end = self.nodes.items.len;
            current_layer_start = @intCast(self.nodes.items.len);

            // Compute total stake of parents in this layer
            var total_parent_stake: u256 = 0;
            for (parent_start..parent_end) |pi| {
                const pidx = self.nodes.items[pi].peerIndex;
                if (pidx < num_peers) {
                    total_parent_stake += peers[pidx].stake;
                }
            }

            for (parent_start..parent_end) |pi| {
                if (peer_idx >= num_peers) break;

                const parent_shred_start = self.nodes.items[pi].shredStart;
                const parent_shred_count = self.nodes.items[pi].shredCount;
                const pidx = self.nodes.items[pi].peerIndex;
                const remaining = num_peers - peer_idx;

                // Stake-weighted children count: higher stake = more children
                var children: u32 = 0;
                if (remaining > 0) {
                    const parent_stake = if (pidx < num_peers) peers[pidx].stake else 0;
                    if (total_parent_stake > 0 and parent_stake > 0) {
                        // Integer proportion: (parent_stake / total_parent_stake) * remaining
                        // Low-stake parents get 0 (leaf), high-stake get proportionally more
                        const raw = @as(u256, parent_stake) * @as(u256, remaining) / total_parent_stake;
                        if (raw >= 1) {
                            children = @min(@as(u32, @intCast(@min(raw, std.math.maxInt(u32)))), self.fanout);
                        }
                        // raw == 0 → leaf (0 children)
                    } else {
                        // All stakes zero: uniform fanout
                        children = @min(self.fanout, remaining);
                    }
                    children = @min(children, remaining);
                }

                // Set children metadata on parent
                self.nodes.items[pi].childrenStart = @intCast(self.nodes.items.len);
                self.nodes.items[pi].childrenCount = @intCast(children);

                // Divide parent's shreds among children
                const shreds_per_child = if (children > 0) parent_shred_count / children else 0;
                var shred_offset = parent_shred_start;

                for (0..children) |ci| {
                    const this_shred_count = if (ci == children - 1)
                        parent_shred_count -| (shreds_per_child * @as(u32, @intCast(ci)))
                    else
                        shreds_per_child;

                    try self.nodes.append(self.allocator, .{
                        .peerIndex = peer_idx,
                        .layer = @intCast(layer),
                        .childrenStart = 0,
                        .childrenCount = 0,
                        .shredStart = shred_offset,
                        .shredCount = this_shred_count,
                    });
                    shred_offset += this_shred_count;
                    peer_idx += 1;
                    if (peer_idx >= num_peers) break;
                }
            }
            if (peer_idx >= num_peers) break;
        }
    }

    /// Get the shred range that a specific peer should forward.
    pub fn getShredAssignment(self: *const Self, peerIndex: u32) ?struct { start: u32, count: u32 } {
        for (self.nodes.items) |node| {
            if (node.peerIndex == peerIndex) {
                return .{ .start = node.shredStart, .count = node.shredCount };
            }
        }
        return null;
    }

    /// Get children of a specific peer in the tree.
    pub fn getChildren(self: *const Self, peerIndex: u32) []const TreeNode {
        for (self.nodes.items) |node| {
            if (node.peerIndex == peerIndex and node.childrenCount > 0) {
                const start = node.childrenStart;
                const end = start + node.childrenCount;
                if (end <= self.nodes.items.len) {
                    return self.nodes.items[start..end];
                }
            }
        }
        return &[_]TreeNode{};
    }

    /// Get the parent's peerIndex for a given peerIndex.
    pub fn getParentIndex(self: *const Self, peerIndex: u32) ?u32 {
        if (peerIndex == 0 or self.nodes.items.len == 0) return null;

        var node_idx_opt: ?usize = null;
        for (self.nodes.items, 0..) |node, i| {
            if (node.peerIndex == peerIndex) {
                node_idx_opt = i;
                break;
            }
        }
        const node_idx = node_idx_opt orelse return null;

        for (self.nodes.items) |parent| {
            if (parent.childrenCount > 0) {
                const start = parent.childrenStart;
                const end = start + parent.childrenCount;
                if (node_idx >= start and node_idx < end) {
                    return parent.peerIndex;
                }
            }
        }
        return null;
    }
};

// Cache of recently completed/shredded block shreds
pub const CachedBlockShreds = struct {
    blockNumber: u64,
    shreds: []Shred,
    timestamp: i64,
};

// ── Turbine Engine ──────────────────────────────────────────────────────

pub const TurbineEngine = struct {
    allocator: std.mem.Allocator,
    tree: PropagationTree,

    // Striped lock design: collectors are sharded by block_number % STRIPE_COUNT
    // so that shreds for different blocks never contend on the same lock.
    collectorStripes: [STRIPE_COUNT]CollectorStripe,

    // Stats (atomics for thread-safe updates across stripes)
    blocksShredded: std.atomic.Value(u64),
    blocksReconstructed: std.atomic.Value(u64),
    shredsSent: std.atomic.Value(u64),
    shredsReceived: std.atomic.Value(u64),
    reconstructionFailures: std.atomic.Value(u64),
    corruptedShreds: std.atomic.Value(u64),

    shredCache: [8]?CachedBlockShreds,
    shredCacheIdx: usize,
    shredCacheMutex: std.Thread.Mutex,

    // Dynamic FEC tracking
    failureTimestamps: [FAILURE_WINDOW_SIZE]u64,
    failureTimestampIdx: u8,
    avgPeerRttMs: std.atomic.Value(u64),
    repairRequestsSent: std.atomic.Value(u64),
    repairResponsesReceived: std.atomic.Value(u64),

    const CollectorStripe = struct {
        collectors: std.AutoHashMap(u64, *ShredCollector),
        mutex: std.Thread.Mutex,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        var stripes: [STRIPE_COUNT]CollectorStripe = undefined;
        for (&stripes) |*s| {
            s.* = .{
                .collectors = std.AutoHashMap(u64, *ShredCollector).init(allocator),
                .mutex = .{},
            };
        }

        return Self{
            .allocator = allocator,
            .tree = PropagationTree.init(allocator),
            .collectorStripes = stripes,
            .blocksShredded = std.atomic.Value(u64).init(0),
            .blocksReconstructed = std.atomic.Value(u64).init(0),
            .shredsSent = std.atomic.Value(u64).init(0),
            .shredsReceived = std.atomic.Value(u64).init(0),
            .reconstructionFailures = std.atomic.Value(u64).init(0),
            .corruptedShreds = std.atomic.Value(u64).init(0),
            .shredCache = [_]?CachedBlockShreds{null} ** 8,
            .shredCacheIdx = 0,
            .shredCacheMutex = .{},
            .failureTimestamps = [_]u64{0} ** FAILURE_WINDOW_SIZE,
            .failureTimestampIdx = 0,
            .avgPeerRttMs = std.atomic.Value(u64).init(50), // Default 50ms
            .repairRequestsSent = std.atomic.Value(u64).init(0),
            .repairResponsesReceived = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *Self) void {
        for (&self.collectorStripes) |*stripe| {
            var it = stripe.collectors.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.destroy(entry.value_ptr.*);
            }
            stripe.collectors.deinit();
        }
        self.tree.deinit();

        // Free cache
        self.shredCacheMutex.lock();
        defer self.shredCacheMutex.unlock();
        for (&self.shredCache) |*maybe_entry| {
            if (maybe_entry.*) |*entry| {
                for (entry.shreds) |s| {
                    self.allocator.free(s.payload);
                }
                self.allocator.free(entry.shreds);
                maybe_entry.* = null;
            }
        }
    }

    pub fn cacheShreds(self: *Self, blockNumber: u64, shreds: []const Shred) !void {
        self.shredCacheMutex.lock();
        defer self.shredCacheMutex.unlock();

        if (self.shredCache[self.shredCacheIdx]) |*old| {
            for (old.shreds) |s| {
                self.allocator.free(s.payload);
            }
            self.allocator.free(old.shreds);
            self.shredCache[self.shredCacheIdx] = null;
        }

        const cached_shreds = try self.allocator.alloc(Shred, shreds.len);
        errdefer self.allocator.free(cached_shreds);

        for (shreds, 0..) |s, i| {
            cached_shreds[i] = .{
                .blockId = s.blockId,
                .blockNumber = s.blockNumber,
                .shredIndex = s.shredIndex,
                .totalDataShreds = s.totalDataShreds,
                .totalParityShreds = s.totalParityShreds,
                .shredType = s.shredType,
                .payload = try self.allocator.dupe(u8, s.payload),
                .producerSignature = s.producerSignature,
                .threadId = s.threadId,
                .crc32 = s.crc32,
            };
        }

        self.shredCache[self.shredCacheIdx] = .{
            .blockNumber = blockNumber,
            .shreds = cached_shreds,
            .timestamp = std.time.milliTimestamp(),
        };
        self.shredCacheIdx = (self.shredCacheIdx + 1) % 8;
    }

    /// Record a reconstruction failure for dynamic FEC tuning.
    /// Stores the timestamp in a sliding window for failure rate calculation.
    pub fn recordReconstructionFailure(self: *Self) void {
        const now = @as(u64, @intCast(std.time.timestamp()));
        self.failureTimestamps[self.failureTimestampIdx] = now;
        self.failureTimestampIdx = (self.failureTimestampIdx + 1) % FAILURE_WINDOW_SIZE;
        _ = self.reconstructionFailures.fetchAdd(1, .monotonic);
    }

    /// Compute an adaptive parity ratio based on recent network conditions.
    /// Factors:
    ///   1. Reconstruction failure rate (last 5 min window) — more failures = more parity
    ///   2. Average peer RTT — higher RTT = more parity for reliability
    /// Returns a ratio clamped to [MIN_PARITY_RATIO, MAX_PARITY_RATIO].
    pub fn computeDynamicParityRatio(self: *const Self) f64 {
        const now: u64 = @intCast(std.time.timestamp());

        // Factor 1: Recent failure rate within the sliding window
        var recent_failures: u32 = 0;
        var recent_total: u32 = 0;
        for (self.failureTimestamps) |ts| {
            if (ts > 0 and now -| ts < FAILURE_WINDOW_SECS) {
                recent_failures += 1;
                recent_total += 1;
            }
        }
        const failure_rate: f64 = if (recent_total > 0)
            @as(f64, @floatFromInt(recent_failures)) / @as(f64, @floatFromInt(recent_total))
        else
            0.0;

        // Factor 2: Average peer RTT (capped at 500ms, normalized to 0-1)
        const avg_rtt = self.avgPeerRttMs.load(.acquire);
        const rtt_factor = @min(@as(f64, @floatFromInt(avg_rtt)) / 500.0, 1.0);

        // Compute: base(0.25) + failure_penalty(up to 0.15) + rtt_penalty(up to 0.10)
        const ratio = DEFAULT_PARITY_RATIO + failure_rate * 0.15 + rtt_factor * 0.10;

        return @max(MIN_PARITY_RATIO, @min(MAX_PARITY_RATIO, ratio));
    }

    /// Update the average peer RTT estimate (exponential moving average).
    pub fn updateAvgRtt(self: *Self, rtt_ms: u64) void {
        const current = self.avgPeerRttMs.load(.acquire);
        // EMA: new = 0.75 * current + 0.25 * sample (smoothing)
        const smoothed = (current * 3 + rtt_ms) / 4;
        self.avgPeerRttMs.store(smoothed, .release);
    }

    pub fn getCachedShred(self: *Self, blockNumber: u64, shredIndex: u32) ?Shred {
        self.shredCacheMutex.lock();
        defer self.shredCacheMutex.unlock();

        for (self.shredCache) |maybe_entry| {
            if (maybe_entry) |entry| {
                if (entry.blockNumber == blockNumber) {
                    for (entry.shreds) |s| {
                        if (s.shredIndex == shredIndex) {
                            return s;
                        }
                    }
                }
            }
        }
        return null;
    }

    fn getStripe(self: *Self, blockNumber: u64) *CollectorStripe {
        return &self.collectorStripes[@intCast(blockNumber % STRIPE_COUNT)];
    }

    /// Shred a block into data + parity shreds with Reed-Solomon encoding.
    /// Each shred includes a CRC32 integrity tag for corruption detection.
    pub fn shredBlock(self: *Self, block_data: []const u8, blockNumber: u64, blockId: core.types.Hash, signature: [96]u8, parity_ratio: ?f64) ![]Shred {
        if (block_data.len > MAX_BLOCK_SIZE) return error.BlockTooLarge;
        if (block_data.len == 0) return error.EmptyBlock;

        const ratio = parity_ratio orelse self.computeDynamicParityRatio();
        const dataShreds = @as(u32, @intCast(@divTrunc(block_data.len + MAX_SHRED_PAYLOAD - 1, MAX_SHRED_PAYLOAD)));
        const parityShreds = @max(1, @as(u32, @intFromFloat(@as(f64, @floatFromInt(dataShreds)) * ratio)));
        const totalShreds = dataShreds + parityShreds;

        const shard_bufs = try self.allocator.alloc([]u8, totalShreds);
        defer {
            for (shard_bufs) |buf| self.allocator.free(buf);
            self.allocator.free(shard_bufs);
        }

        for (0..totalShreds) |i| {
            shard_bufs[i] = try self.allocator.alloc(u8, MAX_SHRED_PAYLOAD);
            @memset(shard_bufs[i], 0);
        }

        for (0..dataShreds) |i| {
            const offset = i * MAX_SHRED_PAYLOAD;
            const end = @min(offset + MAX_SHRED_PAYLOAD, block_data.len);
            const copy_len = end - offset;
            @memcpy(shard_bufs[i][0..copy_len], block_data[offset..end]);
        }

        const FEC_SIZE = 128;
        const num_fec_sets = (dataShreds + FEC_SIZE - 1) / FEC_SIZE;
        var f: u32 = 0;
        while (f < num_fec_sets) : (f += 1) {
            const data_start = f * FEC_SIZE;
            const data_end = @min((f + 1) * FEC_SIZE, dataShreds);
            const fec_data_count = data_end - data_start;

            const parity_start = f * parityShreds / num_fec_sets;
            const parity_end = (f + 1) * parityShreds / num_fec_sets;
            const fec_parity_count = parity_end - parity_start;

            if (fec_parity_count == 0) continue;

            const fec_total = fec_data_count + fec_parity_count;
            const fec_shards = try self.allocator.alloc([]u8, fec_total);
            defer self.allocator.free(fec_shards);

            var idx: usize = 0;
            while (idx < fec_data_count) : (idx += 1) {
                fec_shards[idx] = shard_bufs[data_start + idx];
            }
            idx = 0;
            while (idx < fec_parity_count) : (idx += 1) {
                fec_shards[fec_data_count + idx] = shard_bufs[dataShreds + parity_start + idx];
            }

            const rs = ReedSolomon.init(fec_data_count, fec_parity_count);
            rs.encode(fec_shards);
        }

        const shreds = try self.allocator.alloc(Shred, totalShreds);
        for (0..totalShreds) |i| {
            const payload_copy = try self.allocator.dupe(u8, shard_bufs[i]);
            shreds[i] = .{
                .blockId = blockId,
                .blockNumber = blockNumber,
                .shredIndex = @intCast(i),
                .totalDataShreds = dataShreds,
                .totalParityShreds = parityShreds,
                .shredType = if (i < dataShreds) .Data else .Parity,
                .payload = payload_copy,
                .producerSignature = signature,
                .threadId = 0,
                .crc32 = 0, // Populated below
            };
            // Compute CRC32 integrity tag
            shreds[i].crc32 = shreds[i].computeCrc();
        }

        _ = self.blocksShredded.fetchAdd(1, .monotonic);
        _ = self.shredsSent.fetchAdd(totalShreds, .monotonic);

        try self.cacheShreds(blockNumber, shreds);

        return shreds;
    }

    /// Free shreds returned by shredBlock.
    pub fn freeShreds(self: *Self, shreds: []Shred) void {
        for (shreds) |shred| {
            self.allocator.free(shred.payload);
        }
        self.allocator.free(shreds);
    }

    /// Receive a shred for a block. Verifies CRC integrity before insertion.
    /// Returns reconstructed block data if complete, null otherwise.
    pub fn receiveShred(self: *Self, shred: *const Shred) !?[]u8 {
        // ── Firewall 1: CRC integrity check BEFORE acquiring any lock ──────
        if (!shred.verifyCrc()) {
            std.debug.print("[SHRED-CRC-ERR] Block {d}: shred {d} CRC mismatch (expected {d}, got {d})\n", .{
                shred.blockNumber, shred.shredIndex, shred.crc32, shred.computeCrc()
            });
            _ = self.corruptedShreds.fetchAdd(1, .monotonic);
            return null;
        }

        // ── Firewall 2: Validate shredIndex within total bound ─────────────
        const total_shreds = shred.totalDataShreds + shred.totalParityShreds;
        if (shred.shredIndex >= total_shreds) {
            _ = self.corruptedShreds.fetchAdd(1, .monotonic);
            return error.InvalidShredIndex;
        }
        if (total_shreds == 0 or total_shreds > MAX_BLOCK_SIZE / MAX_SHRED_PAYLOAD + 256) {
            _ = self.corruptedShreds.fetchAdd(1, .monotonic);
            return error.InvalidShredCount;
        }

        // ── Firewall 3: Validate threadId range (MAX_THREADS = 128) ───────
        if (shred.threadId >= 128) {
            _ = self.corruptedShreds.fetchAdd(1, .monotonic);
            return error.InvalidThreadId;
        }

        const stripe = self.getStripe(shred.blockNumber);
        stripe.mutex.lock();
        defer stripe.mutex.unlock();

        _ = self.shredsReceived.fetchAdd(1, .monotonic);

        const entry = try stripe.collectors.getOrPut(shred.blockNumber);
        if (!entry.found_existing) {
            const collector = try self.allocator.create(ShredCollector);
            collector.* = try ShredCollector.init(
                self.allocator,
                shred.blockNumber,
                shred.totalDataShreds,
                shred.totalParityShreds,
                MAX_SHRED_PAYLOAD,
            );
            entry.value_ptr.* = collector;
        }
        const collector = entry.value_ptr.*;

        // Duplicate check
        if (collector.present[shred.shredIndex]) {
            return error.DuplicateShred;
        }

        // Store producer signature and blockId on first shred
        if (collector.receivedCount == 0) {
            collector.producerSignature = shred.producerSignature;
            collector.blockId = shred.blockId;
        }

        // ── Firewall 4: Verify blockId consistency across all shreds ───────
        if (collector.receivedCount > 0 and
            !std.mem.eql(u8, &collector.blockId.bytes, &shred.blockId.bytes))
        {
            return error.ShredBlockIdMismatch;
        }

        if (collector.insertShred(shred)) {
            const block_data = collector.reconstruct() catch |err| {
                self.recordReconstructionFailure();
                log.debug("Turbine reconstruction failed for block {}: {}\n", .{ shred.blockNumber, err });
                return null;
            };

            _ = self.blocksReconstructed.fetchAdd(1, .monotonic);

            // Re-encode all shards (including parity) to cache the complete block
            const FEC_SIZE = 128;
            const num_fec_sets = (collector.dataShreds + FEC_SIZE - 1) / FEC_SIZE;
            var f: u32 = 0;
            while (f < num_fec_sets) : (f += 1) {
                const data_start = f * FEC_SIZE;
                const data_end = @min((f + 1) * FEC_SIZE, collector.dataShreds);
                const fec_data_count = data_end - data_start;

                const parity_start = f * collector.parityShreds / num_fec_sets;
                const parity_end = (f + 1) * collector.parityShreds / num_fec_sets;
                const fec_parity_count = parity_end - parity_start;

                if (fec_parity_count == 0) continue;

                const fec_total = fec_data_count + fec_parity_count;
                const fec_shards = try self.allocator.alloc([]u8, fec_total);
                defer self.allocator.free(fec_shards);

                var idx: usize = 0;
                while (idx < fec_data_count) : (idx += 1) {
                    fec_shards[idx] = collector.shards[data_start + idx];
                }
                idx = 0;
                while (idx < fec_parity_count) : (idx += 1) {
                    fec_shards[fec_data_count + idx] = collector.shards[collector.dataShreds + parity_start + idx];
                }

                const rs = ReedSolomon.init(fec_data_count, fec_parity_count);
                rs.encode(fec_shards);
            }

            // Create shreds list for caching
            var shreds_list = try self.allocator.alloc(Shred, collector.totalShreds);
            for (0..collector.totalShreds) |i| {
                shreds_list[i] = .{
                    .blockId = collector.blockId,
                    .blockNumber = collector.blockNumber,
                    .shredIndex = @intCast(i),
                    .totalDataShreds = collector.dataShreds,
                    .totalParityShreds = collector.parityShreds,
                    .shredType = if (i < collector.dataShreds) .Data else .Parity,
                    .payload = collector.shards[i],
                    .producerSignature = collector.producerSignature,
                    .threadId = 0,
                    .crc32 = 0,
                };
                shreds_list[i].crc32 = shreds_list[i].computeCrc();
            }
            try self.cacheShreds(collector.blockNumber, shreds_list);
            self.allocator.free(shreds_list);

            collector.deinit();
            self.allocator.destroy(collector);
            _ = stripe.collectors.remove(shred.blockNumber);

            return block_data;
        }

        return null;
    }

    /// Build the propagation tree for a set of stake-weighted peers.
    pub fn buildPropTree(self: *Self, peers: []const StakeWeightedPeer, total_shreds: u32) !void {
        try self.tree.build(peers, total_shreds);
    }

    /// Clean up collectors for blocks older than `before_block`.
    pub fn pruneCollectors(self: *Self, before_block: u64) void {
        for (&self.collectorStripes) |*stripe| {
            stripe.mutex.lock();
            defer stripe.mutex.unlock();

            var to_remove = std.ArrayListUnmanaged(u64){};
            defer to_remove.deinit(self.allocator);

            var it = stripe.collectors.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* < before_block) {
                    to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |key| {
                if (stripe.collectors.get(key)) |collector| {
                    collector.deinit();
                    self.allocator.destroy(collector);
                }
                _ = stripe.collectors.remove(key);
            }
        }
    }

    pub const TurbineStats = struct {
        blocksShredded: u64,
        blocksReconstructed: u64,
        shredsSent: u64,
        shredsReceived: u64,
        reconstructionFailures: u64,
        corruptedShreds: u64,
        activeCollectors: u32,
        avgPeerRttMs: u64,
        repairRequestsSent: u64,
        repairResponsesReceived: u64,
        dynamicParityRatio: f64,
    };

    pub fn getStats(self: *const Self) TurbineStats {
        var active: u32 = 0;
        for (&self.collectorStripes) |*stripe| {
            active += @intCast(stripe.collectors.count());
        }
        return .{
            .blocksShredded = self.blocksShredded.load(.acquire),
            .blocksReconstructed = self.blocksReconstructed.load(.acquire),
            .shredsSent = self.shredsSent.load(.acquire),
            .shredsReceived = self.shredsReceived.load(.acquire),
            .reconstructionFailures = self.reconstructionFailures.load(.acquire),
            .corruptedShreds = self.corruptedShreds.load(.acquire),
            .activeCollectors = active,
            .avgPeerRttMs = self.avgPeerRttMs.load(.acquire),
            .repairRequestsSent = self.repairRequestsSent.load(.acquire),
            .repairResponsesReceived = self.repairResponsesReceived.load(.acquire),
            .dynamicParityRatio = self.computeDynamicParityRatio(),
        };
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

test "GF256 multiply identity and commutativity" {
    GF256.ensureInit();
    // Multiply by 1 is identity
    for (0..256) |i| {
        const a: u8 = @intCast(i);
        try std.testing.expectEqual(a, GF256.multiply(a, 1));
        try std.testing.expectEqual(a, GF256.multiply(1, a));
    }
    // Commutativity
    try std.testing.expectEqual(GF256.multiply(0x53, 0xCA), GF256.multiply(0xCA, 0x53));
    // Multiply by 0
    try std.testing.expectEqual(@as(u8, 0), GF256.multiply(0xFF, 0));
}

test "GF256 inverse correctness" {
    GF256.ensureInit();
    for (1..256) |i| {
        const a: u8 = @intCast(i);
        const inv = GF256.inverse(a);
        try std.testing.expectEqual(@as(u8, 1), GF256.multiply(a, inv));
    }
}

test "GF256 SIMD mulAccum matches scalar" {
    GF256.ensureInit();
    const allocator = std.testing.allocator;

    const len: usize = 100; // Not aligned to 16 — tests scalar tail
    const src = try allocator.alloc(u8, len);
    defer allocator.free(src);
    const dst_simd = try allocator.alloc(u8, len);
    defer allocator.free(dst_simd);
    const dst_scalar = try allocator.alloc(u8, len);
    defer allocator.free(dst_scalar);

    // Fill with known pattern
    for (0..len) |i| {
        src[i] = @intCast(i % 256);
        dst_simd[i] = @intCast((i * 7) % 256);
    }
    @memcpy(dst_scalar, dst_simd);

    const c: u8 = 0x53;

    // Scalar reference
    for (0..len) |i| {
        dst_scalar[i] ^= GF256.multiply(c, src[i]);
    }

    // SIMD path
    GF256.mulAccum(dst_simd, src, c);

    try std.testing.expectEqualSlices(u8, dst_scalar, dst_simd);
}

test "Reed-Solomon round-trip encode-decode no loss" {
    const allocator = std.testing.allocator;
    const rs = ReedSolomon.init(4, 2);

    const shards = try allocator.alloc([]u8, 6);
    defer {
        for (shards) |s| allocator.free(s);
        allocator.free(shards);
    }

    // Fill data shards
    for (0..4) |i| {
        shards[i] = try allocator.alloc(u8, 16);
        for (0..16) |j| shards[i][j] = @intCast((i * 16 + j) % 256);
    }
    for (4..6) |i| {
        shards[i] = try allocator.alloc(u8, 16);
    }

    // Save originals
    var originals: [4][16]u8 = undefined;
    for (0..4) |i| @memcpy(&originals[i], shards[i]);

    rs.encode(shards);

    // No loss — decode should be no-op
    var present = [_]bool{true} ** 6;
    const ok = try rs.decode(allocator, shards, &present);
    try std.testing.expect(ok);

    for (0..4) |i| {
        try std.testing.expectEqualSlices(u8, &originals[i], shards[i]);
    }
}

test "Reed-Solomon decode with data shard loss" {
    const allocator = std.testing.allocator;
    const rs = ReedSolomon.init(4, 2);

    const shards = try allocator.alloc([]u8, 6);
    defer {
        for (shards) |s| allocator.free(s);
        allocator.free(shards);
    }

    for (0..4) |i| {
        shards[i] = try allocator.alloc(u8, 16);
        for (0..16) |j| shards[i][j] = @intCast((i * 16 + j) % 256);
    }
    for (4..6) |i| {
        shards[i] = try allocator.alloc(u8, 16);
    }

    var originals: [4][16]u8 = undefined;
    for (0..4) |i| @memcpy(&originals[i], shards[i]);

    rs.encode(shards);

    // Lose data shards 0 and 2
    @memset(shards[0], 0);
    @memset(shards[2], 0);
    var present = [_]bool{ false, true, false, true, true, true };

    const ok = try rs.decode(allocator, shards, &present);
    try std.testing.expect(ok);

    for (0..4) |i| {
        try std.testing.expectEqualSlices(u8, &originals[i], shards[i]);
    }
}

test "Shred CRC integrity" {
    const payload = [_]u8{ 1, 2, 3, 4, 5 };
    var shred = Shred{
        .blockId = core.types.Hash.zero(),
        .blockNumber = 42,
        .shredIndex = 7,
        .totalDataShreds = 10,
        .totalParityShreds = 3,
        .shredType = .Data,
        .payload = &payload,
        .producerSignature = [_]u8{0} ** 96,
        .threadId = 0,
        .crc32 = 0,
    };
    shred.crc32 = shred.computeCrc();

    // Valid CRC
    try std.testing.expect(shred.verifyCrc());

    // Tamper with block_number — CRC should fail
    shred.blockNumber = 99;
    try std.testing.expect(!shred.verifyCrc());
}

test "ShredBufferPool acquire and release" {
    const allocator = std.testing.allocator;
    var pool = try ShredBufferPool.init(allocator, 4, 64);
    defer pool.deinit();

    // Acquire all 4 pre-allocated
    var bufs: [4][]u8 = undefined;
    for (0..4) |i| bufs[i] = try pool.acquire();

    try std.testing.expectEqual(@as(u64, 4), pool.poolHits);
    try std.testing.expectEqual(@as(u64, 0), pool.poolMisses);

    // Next acquire should grow the pool
    const extra = try pool.acquire();
    try std.testing.expectEqual(@as(u64, 1), pool.poolMisses);

    // Release all
    for (&bufs) |b| pool.release(b);
    pool.release(extra);
}

test "TurbineEngine shred-reconstruct round-trip" {
    const allocator = std.testing.allocator;
    var engine = TurbineEngine.init(allocator);
    defer engine.deinit();

    // Create a 5500-byte block (will produce ~5 data shreds + ~1 parity)
    const block = try allocator.alloc(u8, 5500);
    defer allocator.free(block);
    for (0..5500) |i| block[i] = @intCast(i % 256);

    const sig = [_]u8{0xAA} ** 96;
    const shreds = try engine.shredBlock(block, 1, core.types.Hash.zero(), sig, null);
    defer engine.freeShreds(shreds);

    // Feed all shreds to a second engine (simulating receiver)
    var receiver = TurbineEngine.init(allocator);
    defer receiver.deinit();

    var reconstructed: ?[]u8 = null;
    for (shreds) |*s| {
        reconstructed = try receiver.receiveShred(s);
        if (reconstructed != null) break;
    }

    try std.testing.expect(reconstructed != null);
    const rdata = reconstructed.?;
    defer allocator.free(rdata);

    // First 5500 bytes must match
    try std.testing.expectEqualSlices(u8, block, rdata[0..5500]);
}

test "PropagationTree fanout" {
    const allocator = std.testing.allocator;
    var tree = PropagationTree.init(allocator);
    defer tree.deinit();

    const peers = try allocator.alloc(StakeWeightedPeer, 20);
    defer allocator.free(peers);
    for (peers, 0..) |*p, i| {
        var addr: core.types.Address = .{ .bytes = [_]u8{0} ** 32 };
        addr.bytes[0] = @intCast(i + 1);
        p.* = .{ .address = addr, .stake = 1 };
    }

    try tree.build(peers, 100);

    // Root should exist at layer 0
    try std.testing.expect(tree.nodes.items.len > 0);
    try std.testing.expectEqual(@as(u8, 0), tree.nodes.items[0].layer);

    // Root should have shredCount == total
    try std.testing.expectEqual(@as(u32, 100), tree.nodes.items[0].shredCount);
}
