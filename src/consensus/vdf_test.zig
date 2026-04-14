const std = @import("std");
const VDF = @import("vdf.zig").VDF;

test "VDF basic compute and verify" {
    const allocator = std.testing.allocator;
    const input = "Hello VDF";
    const iterations = 100;

    const output = try VDF.compute(allocator, input, iterations);
    defer allocator.free(output);

    const valid = try VDF.verify(allocator, input, output, iterations);
    try std.testing.expect(valid);

    const invalid = try VDF.verify(allocator, input, output, iterations + 1);
    try std.testing.expect(!invalid);
}

test "VDF checkpoints and parallel verify" {
    const allocator = std.testing.allocator;
    const input = "Hello Checkpoints";
    const iterations = 50;
    const interval = 10;

    const checkpoints = try VDF.compute_checkpoints(allocator, input, iterations, interval);
    defer {
        for (checkpoints) |cp| allocator.free(cp);
        allocator.free(checkpoints);
    }

    try std.testing.expectEqual(@as(usize, 5), checkpoints.len);

    const valid = try VDF.verify_parallel(allocator, input, checkpoints, interval);
    try std.testing.expect(valid);
}
