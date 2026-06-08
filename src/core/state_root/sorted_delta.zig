const std = @import("std");
const StateDelta = @import("types.zig").StateDelta;

const Blake3 = std.crypto.hash.Blake3;

const Entry = struct {
    key: [32]u8,
    value: []const u8,
};

fn lessThan(_: void, a: Entry, b: Entry) bool {
    return std.mem.lessThan(u8, &a.key, &b.key);
}

/// Sorted-delta-chain state root computation.
///
/// For each block:
///   1. Collect all (key, value) modifications
///   2. Sort by key (deterministic ordering)
///   3. delta_hash = Blake3(Blake3(k1||v1) || Blake3(k2||v2) || ...)
///   4. stateRoot = Blake3(prev_root || delta_hash)
///
/// To switch strategies (e.g., Solana XOR, SMT), write a new file in this directory.
pub fn compute(allocator: std.mem.Allocator, delta: *const StateDelta, prev_root: [32]u8) ![32]u8 {
    if (delta.count == 0) return prev_root;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const entries = try arena_alloc.alloc(Entry, delta.count);
    for (0..delta.count) |i| {
        entries[i] = .{ .key = delta.keys[i], .value = delta.values[i] };
    }
    std.sort.block(Entry, entries, {}, lessThan);

    var outer = Blake3.init(.{});
    for (entries) |entry| {
        var inner = Blake3.init(.{});
        inner.update(&entry.key);
        inner.update(entry.value);
        var buf: [32]u8 = undefined;
        inner.final(&buf);
        outer.update(&buf);
    }
    var delta_hash: [32]u8 = undefined;
    outer.final(&delta_hash);

    var chain = Blake3.init(.{});
    chain.update(&prev_root);
    chain.update(&delta_hash);
    var result: [32]u8 = undefined;
    chain.final(&result);
    return result;
}
