const std = @import("std");
const VDF = @import("vdf.zig").VDF;
const zelius = @import("zelius.zig");
const types = @import("types.zig");
const core = @import("core");
const c = @import("core").crypto.blst.c;

comptime {
    _ = @import("votepool.zig");
}

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

    // Flatten checkpoints to a single buffer
    var flat_checkpoints = try allocator.alloc(u8, checkpoints.len * 32);
    defer allocator.free(flat_checkpoints);
    for (checkpoints, 0..) |cp, idx| {
        @memcpy(flat_checkpoints[idx * 32 ..][0..32], cp[0..32]);
    }

    const valid = try VDF.verify_parallel(allocator, input, flat_checkpoints, interval);
    try std.testing.expect(valid);
}

test "Zelius consensus sealing and verification" {
    const allocator = std.testing.allocator;

    // Generate keys
    const seed = [_]u8{42} ** 32;

    // Derive G1 public key from private key (seed is used directly in zelius.zig)
    var pk: c.blst_p1 = undefined;
    var sk: c.blst_scalar = undefined;
    c.blst_scalar_from_bendian(&sk, &seed);
    c.blst_sk_to_pk_in_g1(&pk, &sk);
    var pk_bytes: [48]u8 = undefined;
    c.blst_p1_compress(&pk_bytes, &pk);

    const validator_addr = core.types.Address{ .bytes = [_]u8{1} ** 32 };

    const validator = types.ValidatorInfo{
        .address = validator_addr,
        .stake = 100_000,
        .status = .Active,
        .blsPubKey = pk_bytes,
        .commission = 0,
        .activationBlock = 0,
        .slashCount = 0,
        .totalRewards = 0,
        .name = "test_val",
        .website = "",
    };

    const validators = [_]types.ValidatorInfo{validator};

    const engine = try zelius.ZeliusEngine.init(allocator, &validators);
    defer engine.deinit();

    // Set keys
    engine.setPrivKey(seed);
    engine.setBlsPrivKey(&seed);

    // Construct parent block
    var parent_block = core.types.Block{
        .header = core.types.Header{
            .number = 0,
            .parentHash = core.types.Hash.zero(),
            .txHash = core.types.Hash.zero(),
            .verkleRoot = core.types.Hash.zero(),
            .time = 1000,
            .coinbase = validator_addr,
            .extraData = &.{},
            .gasLimit = 8000000,
            .gasUsed = 0,
            .baseFee = 1000000000,
        },
        .transactions = &.{},
    };
    const parent_hash = parent_block.hash();

    // Construct block
    var block = core.types.Block{
        .header = core.types.Header{
            .number = 1,
            .parentHash = parent_hash,
            .txHash = core.types.Hash.zero(),
            .verkleRoot = core.types.Hash.zero(),
            .time = 2000,
            .coinbase = validator_addr,
            .extraData = &.{},
            .gasLimit = 8000000,
            .gasUsed = 0,
            .baseFee = 1000000000,
        },
        .transactions = &.{},
    };

    // Configure VDF iterations to be low for testing speed
    engine.vdfIterations = 20;
    engine.vdfCheckpointInterval = 10;

    // Seal block
    try engine.seal(&block);
    defer allocator.free(block.header.extraData);

    // Verify block
    try engine.verify(&block, &parent_block.header);
}
