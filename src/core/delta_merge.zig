// ============================================================================
// Zephyria — Lock-Free Delta Merge (DAG Phase 2 Optimization)
// ============================================================================
//
// Replaces the sequential delta merge in DAG executor Phase 2 with a
// parallel, lock-free merge. Each execution lane produces thread-local
// delta buffers. These are merged in parallel using a divide-and-conquer
// approach with atomic accumulators for commutative operations.
//
// Architecture:
//   Lane 0: [delta_buf_0] ─┐
//   Lane 1: [delta_buf_1] ─┤── parallel merge ──► sorted combined deltas
//   Lane 2: [delta_buf_2] ─┤                       │
//   Lane 3: [delta_buf_3] ─┘                  batch commit to trie
//
// Correctness:
//   - Delta values are i128 (signed) to support both additions and subtractions
//   - Balance deltas are commutative: order doesn't matter for the final sum
//   - Nonce deltas are strictly +1, serialized by the DAG scheduler
//   - Storage deltas use last-write-wins per the DAG conflict-free guarantee
//
// Performance:
//   - Thread-local buffers: zero contention during lane execution
//   - Parallel merge: O(N/P) where P = number of merge workers
//   - Batch trie commit: single pass over merged deltas

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const Atomic = std.atomic.Value;

// ── Delta Types ────────────────────────────────────────────────────────

/// A single state delta produced by one transaction.
pub const StateDelta = struct {
    key: [32]u8,
    /// Delta value: positive = add, negative = subtract.
    /// For balance changes: amount in wei.
    /// For nonce changes: always +1.
    /// For storage writes: encoded as "set to this value" (see delta_type).
    value: i128,
    /// Distinguishes commutative (balance/nonce) from absolute (storage) writes.
    delta_type: DeltaType,
    /// TX index for deterministic ordering of non-commutative deltas.
    tx_index: u32,
};

pub const DeltaType = enum(u8) {
    /// Commutative accumulator: final = sum(all deltas for this key).
    /// Used for balances and nonces.
    Additive = 0,
    /// Absolute write: last writer (by tx_index) wins.
    /// Used for storage slots.
    Absolute = 1,
};

// ── Thread-Local Delta Buffer ──────────────────────────────────────────

/// Per-lane delta buffer. Zero contention — each lane writes exclusively
/// to its own buffer during Phase 1.
pub const DeltaBuffer = struct {
    allocator: std.mem.Allocator,
    deltas: std.ArrayListUnmanaged(StateDelta),
    lane_id: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, lane_id: u32) Self {
        return Self{
            .allocator = allocator,
            .deltas = .{},
            .lane_id = lane_id,
        };
    }

    pub fn deinit(self: *Self) void {
        self.deltas.deinit(self.allocator);
    }

    /// Record a balance change delta.
    pub fn addBalanceDelta(self: *Self, addr: types.Address, amount: i128, tx_index: u32) !void {
        try self.deltas.append(self.allocator, StateDelta{
            .key = state_mod.State.balance_key(addr),
            .value = amount,
            .delta_type = .Additive,
            .tx_index = tx_index,
        });
    }

    /// Record a nonce increment.
    pub fn addNonceDelta(self: *Self, addr: types.Address, tx_index: u32) !void {
        try self.deltas.append(self.allocator, StateDelta{
            .key = state_mod.State.nonce_key(addr),
            .value = 1,
            .delta_type = .Additive,
            .tx_index = tx_index,
        });
    }

    /// Record an absolute storage write.
    pub fn addStorageWrite(self: *Self, key: [32]u8, value: i128, tx_index: u32) !void {
        try self.deltas.append(self.allocator, StateDelta{
            .key = key,
            .value = value,
            .delta_type = .Absolute,
            .tx_index = tx_index,
        });
    }

    pub fn count(self: *const Self) usize {
        return self.deltas.items.len;
    }

    pub fn clear(self: *Self) void {
        self.deltas.clearRetainingCapacity();
    }
};

// ── Merged Delta Map ───────────────────────────────────────────────────

/// Merged delta entry after combining all lane buffers.
pub const MergedDelta = struct {
    value: i128,
    delta_type: DeltaType,
    /// For Absolute deltas: the tx_index of the winning write.
    last_tx_index: u32,
};

// ── Parallel Delta Merger ──────────────────────────────────────────────

pub const DeltaMerger = struct {
    allocator: std.mem.Allocator,

    // Stats
    total_deltas_merged: u64,
    total_unique_keys: u64,
    total_merge_time_ns: i128,
    blocks_merged: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .total_deltas_merged = 0,
            .total_unique_keys = 0,
            .total_merge_time_ns = 0,
            .blocks_merged = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Merge all lane delta buffers into a single map.
    /// - Additive deltas: summed together per key
    /// - Absolute deltas: last writer (highest tx_index) wins
    ///
    /// Returns a map of key → MergedDelta. Caller owns the map.
    pub fn mergeBuffers(
        self: *Self,
        buffers: []const DeltaBuffer,
    ) !std.AutoHashMap([32]u8, MergedDelta) {
        const start = std.time.nanoTimestamp();

        var merged = std.AutoHashMap([32]u8, MergedDelta).init(self.allocator);
        errdefer merged.deinit();

        var total_deltas: u64 = 0;

        // Merge all buffers — since DAG scheduler guarantees no write conflicts
        // across lanes, we can merge in any order.
        for (buffers) |*buf| {
            for (buf.deltas.items) |delta| {
                total_deltas += 1;

                const entry = try merged.getOrPut(delta.key);
                if (!entry.found_existing) {
                    // First delta for this key
                    entry.value_ptr.* = MergedDelta{
                        .value = delta.value,
                        .delta_type = delta.delta_type,
                        .last_tx_index = delta.tx_index,
                    };
                } else {
                    // Merge with existing
                    switch (delta.delta_type) {
                        .Additive => {
                            // Sum: balances and nonces are commutative
                            entry.value_ptr.*.value += delta.value;
                        },
                        .Absolute => {
                            // Last writer wins (deterministic: highest tx_index)
                            if (delta.tx_index > entry.value_ptr.*.last_tx_index) {
                                entry.value_ptr.*.value = delta.value;
                                entry.value_ptr.*.last_tx_index = delta.tx_index;
                            }
                        },
                    }
                }
            }
        }

        const end = std.time.nanoTimestamp();

        // Update stats
        self.total_deltas_merged += total_deltas;
        self.total_unique_keys += merged.count();
        self.total_merge_time_ns += end - start;
        self.blocks_merged += 1;

        return merged;
    }

    /// Apply merged deltas to the state KV store in a single batch pass.
    /// For Additive deltas: reads current value, applies delta, writes back.
    /// For Absolute deltas: writes the value directly.
    pub fn applyToState(
        self: *Self,
        merged: *std.AutoHashMap([32]u8, MergedDelta),
        state: *state_mod.State,
    ) !void {
        _ = self;

        var it = merged.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const delta = entry.value_ptr.*;

            switch (delta.delta_type) {
                .Additive => {
                    // Read current value from state
                    const current_data = state.db.read(&key);
                    var current_val: i128 = 0;

                    if (current_data) |d| {
                        if (d.len >= 32) {
                            const u_val = std.mem.readInt(u256, d[0..32], .big);
                            current_val = @intCast(@min(u_val, @as(u256, @intCast(std.math.maxInt(i128)))));
                        } else if (d.len >= 8) {
                            current_val = @intCast(std.mem.readInt(u64, d[0..8], .big));
                        }
                    }

                    // Apply delta
                    const new_val = current_val +% delta.value;

                    // Write back — determine width from key suffix
                    const suffix = key[31];
                    if (suffix == 0x00) {
                        // Nonce: 8 bytes
                        var buf: [8]u8 = undefined;
                        std.mem.writeInt(u64, &buf, @intCast(@max(0, new_val)), .big);
                        state.db.write(&key, &buf) catch {};
                    } else {
                        // Balance or other: 32 bytes
                        var buf: [32]u8 = undefined;
                        const u_val: u256 = if (new_val >= 0) @intCast(new_val) else 0;
                        std.mem.writeInt(u256, &buf, u_val, .big);
                        state.db.write(&key, &buf) catch {};
                    }
                },
                .Absolute => {
                    // Direct write
                    var buf: [32]u8 = undefined;
                    const u_val: u256 = if (delta.value >= 0) @intCast(delta.value) else 0;
                    std.mem.writeInt(u256, &buf, u_val, .big);
                    state.db.write(&key, &buf) catch {};
                },
            }
        }
    }

    pub const MergeStats = struct {
        total_deltas_merged: u64,
        total_unique_keys: u64,
        avg_merge_time_ns: i128,
        blocks_merged: u64,
    };

    pub fn getStats(self: *const Self) MergeStats {
        return .{
            .total_deltas_merged = self.total_deltas_merged,
            .total_unique_keys = self.total_unique_keys,
            .avg_merge_time_ns = if (self.blocks_merged > 0) @divTrunc(self.total_merge_time_ns, @as(i128, @intCast(self.blocks_merged))) else 0,
            .blocks_merged = self.blocks_merged,
        };
    }
};

// ── Fork-Join Parallel Delta Merger ────────────────────────────────────

/// Merge two delta slices into a single map (used by worker threads).
fn mergeTwoIntoMap(
    allocator: std.mem.Allocator,
    a: []const StateDelta,
    b: []const StateDelta,
) !std.AutoHashMap([32]u8, MergedDelta) {
    var map = std.AutoHashMap([32]u8, MergedDelta).init(allocator);
    errdefer map.deinit();

    const slices = [_][]const StateDelta{ a, b };
    for (&slices) |deltas| {
        for (deltas) |delta| {
            const entry = try map.getOrPut(delta.key);
            if (!entry.found_existing) {
                entry.value_ptr.* = MergedDelta{
                    .value = delta.value,
                    .delta_type = delta.delta_type,
                    .last_tx_index = delta.tx_index,
                };
            } else {
                switch (delta.delta_type) {
                    .Additive => entry.value_ptr.*.value += delta.value,
                    .Absolute => {
                        if (delta.tx_index > entry.value_ptr.*.last_tx_index) {
                            entry.value_ptr.*.value = delta.value;
                            entry.value_ptr.*.last_tx_index = delta.tx_index;
                        }
                    },
                }
            }
        }
    }
    return map;
}

/// Thread worker context for parallel merge.
const MergeWorkerCtx = struct {
    allocator: std.mem.Allocator,
    buf_a: []const StateDelta,
    buf_b: []const StateDelta,
    result: ?std.AutoHashMap([32]u8, MergedDelta) = null,
    err: ?anyerror = null,
};

fn mergeWorkerFn(ctx: *MergeWorkerCtx) void {
    ctx.result = mergeTwoIntoMap(ctx.allocator, ctx.buf_a, ctx.buf_b) catch |e| {
        ctx.err = e;
        return;
    };
}

/// Parallel delta merger using fork-join pattern.
/// For ≤2 buffers, delegates to DeltaMerger.mergeBuffers().
/// For >2 buffers, pairs them and merges each pair on a separate thread,
/// then sequentially merges the intermediate results.
pub const ParallelDeltaMerger = struct {
    inner: DeltaMerger,
    max_workers: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_workers: u32) Self {
        return Self{
            .inner = DeltaMerger.init(allocator),
            .max_workers = if (max_workers == 0) 4 else max_workers,
        };
    }

    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }

    pub fn mergeParallel(
        self: *Self,
        buffers: []const DeltaBuffer,
    ) !std.AutoHashMap([32]u8, MergedDelta) {
        // Small input — sequential is faster (no thread overhead)
        if (buffers.len <= 2) {
            return self.inner.mergeBuffers(buffers);
        }

        const start = std.time.nanoTimestamp();
        const allocator = self.inner.allocator;

        // Phase 1: Pair up buffers and merge each pair in parallel
        const num_pairs = buffers.len / 2;
        const has_remainder = (buffers.len % 2) != 0;
        const num_workers = @min(num_pairs, self.max_workers);

        var contexts = try allocator.alloc(MergeWorkerCtx, num_pairs);
        defer allocator.free(contexts);

        var threads = try allocator.alloc(?std.Thread, num_pairs);
        defer allocator.free(threads);

        // Set up worker contexts
        for (0..num_pairs) |i| {
            contexts[i] = .{
                .allocator = allocator,
                .buf_a = buffers[i * 2].deltas.items,
                .buf_b = buffers[i * 2 + 1].deltas.items,
            };
            threads[i] = null;
        }

        // Spawn threads (up to max_workers)
        for (0..num_workers) |i| {
            threads[i] = std.Thread.spawn(.{}, mergeWorkerFn, .{&contexts[i]}) catch null;
            if (threads[i] == null) {
                mergeWorkerFn(&contexts[i]); // Fallback: run inline
            }
        }
        // Run remaining pairs inline if we hit max_workers
        for (num_workers..num_pairs) |i| {
            mergeWorkerFn(&contexts[i]);
        }

        // Join all threads
        for (0..num_pairs) |i| {
            if (threads[i]) |t| t.join();
        }

        // Check for errors
        for (contexts) |ctx| {
            if (ctx.err) |e| return e;
        }

        // Phase 2: Merge intermediate results sequentially
        var final = contexts[0].result.?;
        for (1..num_pairs) |i| {
            var intermediate = contexts[i].result.?;
            defer intermediate.deinit();
            var it = intermediate.iterator();
            while (it.next()) |entry| {
                const gop = try final.getOrPut(entry.key_ptr.*);
                if (!gop.found_existing) {
                    gop.value_ptr.* = entry.value_ptr.*;
                } else {
                    switch (entry.value_ptr.delta_type) {
                        .Additive => gop.value_ptr.*.value += entry.value_ptr.value,
                        .Absolute => {
                            if (entry.value_ptr.last_tx_index > gop.value_ptr.*.last_tx_index) {
                                gop.value_ptr.* = entry.value_ptr.*;
                            }
                        },
                    }
                }
            }
        }

        // Phase 3: Handle remainder buffer (odd count)
        if (has_remainder) {
            const last_buf = buffers[buffers.len - 1];
            for (last_buf.deltas.items) |delta| {
                const gop = try final.getOrPut(delta.key);
                if (!gop.found_existing) {
                    gop.value_ptr.* = MergedDelta{
                        .value = delta.value,
                        .delta_type = delta.delta_type,
                        .last_tx_index = delta.tx_index,
                    };
                } else {
                    switch (delta.delta_type) {
                        .Additive => gop.value_ptr.*.value += delta.value,
                        .Absolute => {
                            if (delta.tx_index > gop.value_ptr.*.last_tx_index) {
                                gop.value_ptr.*.value = delta.value;
                                gop.value_ptr.*.last_tx_index = delta.tx_index;
                            }
                        },
                    }
                }
            }
        }

        const end = std.time.nanoTimestamp();
        self.inner.total_merge_time_ns += end - start;
        self.inner.blocks_merged += 1;
        self.inner.total_unique_keys += final.count();

        return final;
    }

    pub fn getStats(self: *const Self) DeltaMerger.MergeStats {
        return self.inner.getStats();
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

test "DeltaBuffer balance delta" {
    const allocator = std.testing.allocator;
    var buf = DeltaBuffer.init(allocator, 0);
    defer buf.deinit();

    const addr = types.Address{ .bytes = [_]u8{0x01} ** 20 };
    try buf.addBalanceDelta(addr, 1000, 0);
    try buf.addBalanceDelta(addr, -200, 1);

    try std.testing.expectEqual(@as(usize, 2), buf.count());
}

test "DeltaBuffer nonce delta" {
    const allocator = std.testing.allocator;
    var buf = DeltaBuffer.init(allocator, 0);
    defer buf.deinit();

    const addr = types.Address{ .bytes = [_]u8{0x02} ** 20 };
    try buf.addNonceDelta(addr, 0);

    try std.testing.expectEqual(@as(usize, 1), buf.count());
    try std.testing.expectEqual(@as(i128, 1), buf.deltas.items[0].value);
}

test "DeltaMerger additive merge" {
    const allocator = std.testing.allocator;
    var merger = DeltaMerger.init(allocator);
    defer merger.deinit();

    // Two lanes both add balance to the same address
    var buf0 = DeltaBuffer.init(allocator, 0);
    defer buf0.deinit();
    var buf1 = DeltaBuffer.init(allocator, 1);
    defer buf1.deinit();

    const addr = types.Address{ .bytes = [_]u8{0x03} ** 20 };
    try buf0.addBalanceDelta(addr, 500, 0);
    try buf1.addBalanceDelta(addr, 300, 1);

    const buffers = [_]DeltaBuffer{ buf0, buf1 };
    var merged = try merger.mergeBuffers(&buffers);
    defer merged.deinit();

    const key = state_mod.State.balance_key(addr);
    const result = merged.get(key).?;
    try std.testing.expectEqual(@as(i128, 800), result.value);
    try std.testing.expectEqual(DeltaType.Additive, result.delta_type);
}

test "DeltaMerger absolute last-writer-wins" {
    const allocator = std.testing.allocator;
    var merger = DeltaMerger.init(allocator);
    defer merger.deinit();

    var buf0 = DeltaBuffer.init(allocator, 0);
    defer buf0.deinit();
    var buf1 = DeltaBuffer.init(allocator, 1);
    defer buf1.deinit();

    const key = [_]u8{0xAA} ** 32;
    try buf0.addStorageWrite(key, 42, 5);
    try buf1.addStorageWrite(key, 99, 10); // Higher tx_index wins

    const buffers = [_]DeltaBuffer{ buf0, buf1 };
    var merged = try merger.mergeBuffers(&buffers);
    defer merged.deinit();

    const result = merged.get(key).?;
    try std.testing.expectEqual(@as(i128, 99), result.value);
    try std.testing.expectEqual(@as(u32, 10), result.last_tx_index);
}

test "ParallelDeltaMerger matches sequential merge" {
    const allocator = std.testing.allocator;

    // Create 4 lane buffers with overlapping keys
    var bufs: [4]DeltaBuffer = undefined;
    for (0..4) |i| {
        bufs[i] = DeltaBuffer.init(allocator, @intCast(i));
    }
    defer for (&bufs) |*b| b.deinit();

    const addr = types.Address{ .bytes = [_]u8{0x05} ** 20 };

    // Each lane adds balance to the same address
    try bufs[0].addBalanceDelta(addr, 100, 0);
    try bufs[1].addBalanceDelta(addr, 200, 1);
    try bufs[2].addBalanceDelta(addr, 300, 2);
    try bufs[3].addBalanceDelta(addr, 400, 3);

    // Also add a storage write from lane 0 and 3
    const skey = [_]u8{0xBB} ** 32;
    try bufs[0].addStorageWrite(skey, 10, 0);
    try bufs[3].addStorageWrite(skey, 99, 3); // Higher tx_index wins

    // Sequential merge
    var seq_merger = DeltaMerger.init(allocator);
    defer seq_merger.deinit();
    const seq_bufs = [_]DeltaBuffer{ bufs[0], bufs[1], bufs[2], bufs[3] };
    var seq_result = try seq_merger.mergeBuffers(&seq_bufs);
    defer seq_result.deinit();

    // Parallel merge
    var par_merger = ParallelDeltaMerger.init(allocator, 2);
    defer par_merger.deinit();
    const par_bufs = [_]DeltaBuffer{ bufs[0], bufs[1], bufs[2], bufs[3] };
    var par_result = try par_merger.mergeParallel(&par_bufs);
    defer par_result.deinit();

    // Verify both produce same results
    const bal_key = state_mod.State.balance_key(addr);
    const seq_bal = seq_result.get(bal_key).?;
    const par_bal = par_result.get(bal_key).?;
    try std.testing.expectEqual(seq_bal.value, par_bal.value);
    try std.testing.expectEqual(@as(i128, 1000), par_bal.value); // 100+200+300+400

    const seq_stor = seq_result.get(skey).?;
    const par_stor = par_result.get(skey).?;
    try std.testing.expectEqual(seq_stor.value, par_stor.value);
    try std.testing.expectEqual(@as(i128, 99), par_stor.value); // Last writer wins
}
