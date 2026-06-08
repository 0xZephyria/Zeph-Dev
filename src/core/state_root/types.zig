const std = @import("std");

/// Per-block state delta: the set of key-value pairs modified in one block.
/// Passed from the executor to the state root computer.
pub const StateDelta = struct {
    keys: [][32]u8,
    values: [][]const u8,
    count: usize,

    pub fn deinit(self: *StateDelta, allocator: std.mem.Allocator) void {
        for (0..self.count) |i| {
            allocator.free(self.values[i]);
        }
        allocator.free(self.keys);
        allocator.free(self.values);
    }
};
