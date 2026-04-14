// ============================================================================
// Zephyria — P2P Test Suite
// ============================================================================

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const turbine = @import("turbine.zig");
const compression = @import("compression.zig");
const discovery = @import("discovery.zig");
const gulf_stream = @import("gulf_stream.zig");
const peer_mod = @import("peer.zig");
const core = @import("core");

// ── Subnet Bitmap Tests ─────────────────────────────────────────────────

test "Subnet bitmap - set and check" {
    var bitmap: [8]u8 = [_]u8{0} ** 8;

    types.setSubnetBit(&bitmap, 0);
    try testing.expect(types.isSubnetSubscribed(bitmap, 0));
    try testing.expect(!types.isSubnetSubscribed(bitmap, 1));

    types.setSubnetBit(&bitmap, 63);
    try testing.expect(types.isSubnetSubscribed(bitmap, 63));

    types.setSubnetBit(&bitmap, 32);
    try testing.expect(types.isSubnetSubscribed(bitmap, 32));
}

test "Subnet bitmap - clear" {
    var bitmap: [8]u8 = [_]u8{0xFF} ** 8;

    types.clearSubnetBit(&bitmap, 10);
    try testing.expect(!types.isSubnetSubscribed(bitmap, 10));
    try testing.expect(types.isSubnetSubscribed(bitmap, 9));
    try testing.expect(types.isSubnetSubscribed(bitmap, 11));
}

test "Subnet bitmap - out of range" {
    var bitmap: [8]u8 = [_]u8{0} ** 8;
    types.setSubnetBit(&bitmap, 64); // Should be no-op
    try testing.expect(!types.isSubnetSubscribed(bitmap, 64));
}

// ── Participation Bitmap Tests ──────────────────────────────────────────

test "Participation bitmap - count and quorum" {
    var bitmap: [32]u8 = [_]u8{0} ** 32;

    // Set 171 bits (quorum for 256 committee)
    for (0..171) |i| {
        types.setParticipationBit(&bitmap, @intCast(i));
    }

    try testing.expectEqual(@as(u32, 171), types.countParticipation(bitmap));
    try testing.expect(types.hasQuorum(bitmap, 256));
}

test "Participation bitmap - no quorum" {
    var bitmap: [32]u8 = [_]u8{0} ** 32;

    // Set 170 bits (one short of quorum)
    for (0..170) |i| {
        types.setParticipationBit(&bitmap, @intCast(i));
    }

    try testing.expectEqual(@as(u32, 170), types.countParticipation(bitmap));
    try testing.expect(!types.hasQuorum(bitmap, 256));
}

test "Participation bitmap - isParticipating" {
    var bitmap: [32]u8 = [_]u8{0} ** 32;
    types.setParticipationBit(&bitmap, 42);
    try testing.expect(types.isParticipating(bitmap, 42));
    try testing.expect(!types.isParticipating(bitmap, 41));
    try testing.expect(!types.isParticipating(bitmap, 43));
}

// ── Compression Tests ───────────────────────────────────────────────────

test "Compression - roundtrip with compressible data" {
    var comp = compression.Compressor.init(testing.allocator);
    defer comp.deinit();

    // Create compressible data (lots of repetition)
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @intCast(i % 16);
    }

    const compressed = try comp.compress(&data);
    defer testing.allocator.free(compressed);

    const decompressed = try comp.decompress(compressed);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualSlices(u8, &data, decompressed);
}

test "Compression - small data uses raw framing" {
    var comp = compression.Compressor.init(testing.allocator);
    defer comp.deinit();

    const data = "hello world";
    const compressed = try comp.compress(data);
    defer testing.allocator.free(compressed);

    // Small data should use ZRAW header
    try testing.expectEqualSlices(u8, &[_]u8{ 'Z', 'R', 'A', 'W' }, compressed[0..4]);

    const decompressed = try comp.decompress(compressed);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualSlices(u8, data, decompressed);
}

test "Compression - empty data" {
    var comp = compression.Compressor.init(testing.allocator);
    defer comp.deinit();

    const compressed = try comp.compress("");
    defer testing.allocator.free(compressed);

    try testing.expectEqual(@as(usize, 0), compressed.len);
}

test "Compression - stats tracking" {
    var comp = compression.Compressor.init(testing.allocator);
    defer comp.deinit();

    var data: [1024]u8 = undefined;
    @memset(&data, 42);

    const compressed = try comp.compress(&data);
    defer testing.allocator.free(compressed);

    const stats = comp.getStats();
    try testing.expect(stats.compression_calls > 0);
    try testing.expect(stats.total_uncompressed > 0);
}

test "Compression - corrupt data detection" {
    var comp = compression.Compressor.init(testing.allocator);
    defer comp.deinit();

    // Invalid magic
    const bad_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.InvalidMagic, comp.decompress(&bad_data));
}

// ── Reed-Solomon Tests ──────────────────────────────────────────────────

test "Reed-Solomon - encode and decode with no loss" {
    const data_shards: u32 = 4;
    const parity_shards: u32 = 2;
    const total = data_shards + parity_shards;
    const shard_size: usize = 64;

    const rs = turbine.ReedSolomon.init(data_shards, parity_shards);

    // Create shards
    var shard_bufs: [total][]u8 = undefined;
    for (0..total) |i| {
        shard_bufs[i] = try testing.allocator.alloc(u8, shard_size);
    }
    defer for (shard_bufs) |buf| testing.allocator.free(buf);

    // Fill data shards with known values
    for (0..data_shards) |i| {
        for (0..shard_size) |j| {
            shard_bufs[i][j] = @intCast((i * 37 + j * 13) % 256);
        }
    }

    // Clear parity shards
    for (data_shards..total) |i| {
        @memset(shard_bufs[i], 0);
    }

    // Encode
    const shards_slice: [][]u8 = &shard_bufs;
    rs.encode(shards_slice);

    // Verify parity shards are non-zero (unless data is all zeros)
    var any_nonzero = false;
    for (shard_bufs[data_shards]) |b| {
        if (b != 0) any_nonzero = true;
    }
    try testing.expect(any_nonzero);

    // Verify decode with all present does nothing harmful
    var all_present: [total]bool = [_]bool{true} ** total;
    const success = try rs.decode(testing.allocator, shards_slice, &all_present);
    try testing.expect(success);
}

test "Reed-Solomon - decode with one data shard lost" {
    const data_shards: u32 = 4;
    const parity_shards: u32 = 2;
    const total = data_shards + parity_shards;
    const shard_size: usize = 32;

    const rs = turbine.ReedSolomon.init(data_shards, parity_shards);

    var shard_bufs: [total][]u8 = undefined;
    for (0..total) |i| {
        shard_bufs[i] = try testing.allocator.alloc(u8, shard_size);
    }
    defer for (shard_bufs) |buf| testing.allocator.free(buf);

    // Fill data shards
    for (0..data_shards) |i| {
        for (0..shard_size) |j| {
            shard_bufs[i][j] = @intCast((i * 23 + j * 7 + 5) % 256);
        }
    }
    for (data_shards..total) |i| {
        @memset(shard_bufs[i], 0);
    }

    // Save original data[1]
    const original = try testing.allocator.dupe(u8, shard_bufs[1]);
    defer testing.allocator.free(original);

    // Encode
    const shards_slice: [][]u8 = &shard_bufs;
    rs.encode(shards_slice);

    // Simulate loss of shard 1
    @memset(shard_bufs[1], 0);
    var present: [total]bool = [_]bool{true} ** total;
    present[1] = false;

    // Decode
    const success = try rs.decode(testing.allocator, shards_slice, &present);
    try testing.expect(success);

    // Verify reconstruction
    try testing.expectEqualSlices(u8, original, shard_bufs[1]);
}

test "Reed-Solomon - insufficient shards fails" {
    const rs = turbine.ReedSolomon.init(4, 2);

    var shard_bufs: [6][]u8 = undefined;
    for (0..6) |i| {
        shard_bufs[i] = try testing.allocator.alloc(u8, 16);
        @memset(shard_bufs[i], @intCast(i));
    }
    defer for (shard_bufs) |buf| testing.allocator.free(buf);

    const shards_slice: [][]u8 = &shard_bufs;

    // Only 3 present out of 4 needed
    var present = [_]bool{ true, false, false, true, true, false };
    const success = try rs.decode(testing.allocator, shards_slice, &present);
    try testing.expect(!success);
}

// ── GF(2^8) Arithmetic Tests ────────────────────────────────────────────
// (GF256 internal arithmetic is validated through Reed-Solomon encode/decode tests)

// ── Shred Collector Tests ───────────────────────────────────────────────

test "ShredCollector - collect and reconstruct" {
    var engine = turbine.TurbineEngine.init(testing.allocator);
    defer engine.deinit();

    // Create test block data
    const block_size = 4400; // Will create multiple shreds
    const block_data = try testing.allocator.alloc(u8, block_size);
    defer testing.allocator.free(block_data);

    for (0..block_size) |i| {
        block_data[i] = @intCast(i % 256);
    }

    const sig = [_]u8{0xAB} ** 64;

    // Shred the block
    const shreds = try engine.shredBlock(block_data, 42, sig);
    defer engine.freeShreds(shreds);

    try testing.expect(shreds.len > 0);

    // Feed shreds into a new engine to simulate receiving
    var receiver = turbine.TurbineEngine.init(testing.allocator);
    defer receiver.deinit();

    var reconstructed: ?[]u8 = null;
    for (shreds) |*shred| {
        const result = try receiver.receiveShred(shred);
        if (result) |data| {
            reconstructed = data;
            break;
        }
    }

    try testing.expect(reconstructed != null);
    defer testing.allocator.free(reconstructed.?);

    // Verify first block_size bytes match
    try testing.expectEqualSlices(u8, block_data, reconstructed.?[0..block_size]);
}

// ── Propagation Tree Tests ──────────────────────────────────────────────

test "PropagationTree - build with fanout" {
    var tree = turbine.PropagationTree.init(testing.allocator);
    defer tree.deinit();

    try tree.build(100, 2560);

    // Root should exist
    try testing.expect(tree.nodes.items.len > 0);
    try testing.expectEqual(@as(u32, 0), tree.nodes.items[0].peer_index);
    try testing.expectEqual(@as(u8, 0), tree.nodes.items[0].layer);

    // Root should have children
    try testing.expect(tree.nodes.items[0].children_count > 0);
}

test "PropagationTree - shred assignment" {
    var tree = turbine.PropagationTree.init(testing.allocator);
    defer tree.deinit();

    try tree.build(10, 100);

    const assignment = tree.getShredAssignment(0);
    try testing.expect(assignment != null);
    try testing.expectEqual(@as(u32, 100), assignment.?.count);
}

// ── Discovery Tests ─────────────────────────────────────────────────────

test "Discovery - add and find nodes" {
    const priv = [_]u8{1} ** 32;
    var d = try discovery.DiscoveryService.init(testing.allocator, &priv, 30303);
    defer d.deinit();

    // NOTE: No start()/stop() — those spawn blocking threads not suitable for unit tests

    // Add nodes
    for (0..5) |i| {
        var id: [64]u8 = [_]u8{0} ** 64;
        id[0] = @intCast(i + 2);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&id, &hash, .{});

        const node = discovery.Node{
            .id = id,
            .hash = hash,
            .address = try std.net.Address.parseIp4("127.0.0.1", @intCast(30304 + i)),
            .last_seen = std.time.milliTimestamp(),
            .last_ping = 0,
            .ping_failures = 0,
            .peer_role = .Validator,
            .validator_address = core.types.Address.zero(),
            .subscribed_subnets = [_]u8{0} ** 8,
            .stake_amount = 0,
        };
        try d.addNode(node);
    }

    // Find closest
    const target = [_]u8{0xFF} ** 32;
    const found = try d.findClosest(target, 3);
    defer testing.allocator.free(found);

    try testing.expect(found.len <= 3);
    try testing.expect(found.len > 0);
}

test "Discovery - subnet-aware search" {
    const priv = [_]u8{5} ** 32;
    var d = try discovery.DiscoveryService.init(testing.allocator, &priv, 30303);
    defer d.deinit();

    // Add a node in subnet 10
    var id: [64]u8 = [_]u8{0} ** 64;
    id[0] = 99;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&id, &hash, .{});

    var subnets: [8]u8 = [_]u8{0} ** 8;
    types.setSubnetBit(&subnets, 10);

    const node = discovery.Node{
        .id = id,
        .hash = hash,
        .address = try std.net.Address.parseIp4("10.0.0.1", 30303),
        .last_seen = std.time.milliTimestamp(),
        .last_ping = 0,
        .ping_failures = 0,
        .peer_role = .Validator,
        .validator_address = core.types.Address.zero(),
        .subscribed_subnets = subnets,
        .stake_amount = 100000,
    };
    try d.addNode(node);

    const found = try d.findClosestInSubnet(hash, 10, 5);
    defer testing.allocator.free(found);

    try testing.expect(found.len >= 1);
    try testing.expect(found[0].isInSubnet(10));
}

test "Discovery - ENR serialize/deserialize roundtrip" {
    const pubkey = [_]u8{0xAA} ** 33;
    var enr = discovery.EnrRecord.init(pubkey, [4]u8{ 192, 168, 1, 1 }, 30303);
    enr.seq = 42;
    enr.stake = 1000000;

    var buf: [128]u8 = undefined;
    const len = enr.serialize(&buf);
    try testing.expect(len > 0);

    const decoded = discovery.EnrRecord.deserialize(buf[0..len]);
    try testing.expect(decoded != null);
    try testing.expectEqual(@as(u64, 42), decoded.?.seq);
    try testing.expectEqualSlices(u8, &pubkey, &decoded.?.pubkey);
    try testing.expectEqual(@as(u16, 30303), decoded.?.udp_port);
    try testing.expectEqual(@as(u64, 1000000), decoded.?.stake);
}

test "Discovery - stats" {
    const priv = [_]u8{3} ** 32;
    var d = try discovery.DiscoveryService.init(testing.allocator, &priv, 30303);
    defer d.deinit();

    const stats = d.getStats();
    try testing.expectEqual(@as(u32, 0), stats.total_nodes);
}

// ── Peer Tests ──────────────────────────────────────────────────────────

test "Peer - score clamping" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    // Score should clamp to max
    p.updateScore(500);
    try testing.expect(p.score <= types.PEER_SCORE_MAX);
}

test "Peer - should disconnect on low score" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    p.updateScore(-200);
    try testing.expect(p.shouldDisconnect());
}

test "Peer - subnet management" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    p.subscribeSubnet(5);
    try testing.expect(p.isInSubnet(5));
    try testing.expect(!p.isInSubnet(4));

    p.unsubscribeSubnet(5);
    try testing.expect(!p.isInSubnet(5));
}

test "Peer - get subscribed subnets" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    p.subscribeSubnet(3);
    p.subscribeSubnet(7);
    p.subscribeSubnet(63);

    var buf: [64]types.SubnetID = undefined;
    const count = p.getSubscribedSubnets(&buf);
    try testing.expectEqual(@as(u32, 3), count);
}

test "Peer - rate limiting" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    const config = types.RateLimitConfig{};

    // Should allow first ~20 requests (base capacity)
    var allowed: u32 = 0;
    for (0..25) |_| {
        if (p.checkRateLimit(config)) allowed += 1;
    }
    try testing.expect(allowed >= 15 and allowed <= 22);
}

test "Peer - IP slice" {
    const p = try peer_mod.Peer.init(testing.allocator, "192.168.1.100", 30303);
    defer p.deinit();

    try testing.expectEqualSlices(u8, "192.168.1.100", p.ipSlice());
}

test "Peer - committee assignment" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    try testing.expect(!p.is_committee_member);

    p.setCommitteeAssignment(.{
        .epoch = 1,
        .slot_start = 0,
        .slot_end = 100,
        .committee_index = 5,
        .role = .Attestor,
        .aggregation_subnet = 3,
    });

    try testing.expect(p.is_committee_member);
    try testing.expect(p.committee_assignment != null);
    try testing.expectEqual(types.CommitteeRole.Attestor, p.committee_assignment.?.role);

    p.clearCommitteeAssignment();
    try testing.expect(!p.is_committee_member);
}

test "Peer - stats" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    p.recordReceived(1024);
    p.recordReceived(512);

    const stats = p.getStats();
    try testing.expectEqual(@as(u64, 1536), stats.bytes_received);
    try testing.expectEqual(@as(u64, 2), stats.packets_received);
}

// ── Gulf Stream Tests ───────────────────────────────────────────────────

test "GulfStream - queue transaction" {
    var gs = gulf_stream.GulfStream.init(testing.allocator);
    defer gs.deinit();

    const tx_data = [_]u8{ 0xDE, 0xAD } ** 50;
    const tx_hash = core.types.Hash.zero();

    const queued = try gs.queueTransaction(tx_hash, &tx_data);
    try testing.expect(queued);
    try testing.expect(gs.queueDepth() > 0);
}

test "GulfStream - batch expiry" {
    var gs = gulf_stream.GulfStream.init(testing.allocator);
    defer gs.deinit();

    // Queue a transaction at slot 0
    const tx_data = [_]u8{0xFF} ** 10;
    _ = try gs.queueTransaction(core.types.Hash.zero(), &tx_data);

    // Advance slot beyond expiry
    gs.advanceSlot(10, 0, &[_]gulf_stream.ValidatorInfo{});

    // Queue should be empty after expiry
    const batch = gs.getNextBatch();
    try testing.expect(batch == null);
}

test "GulfStream - leader schedule update" {
    var gs = gulf_stream.GulfStream.init(testing.allocator);
    defer gs.deinit();

    const validators = [_]gulf_stream.ValidatorInfo{
        .{ .index = 0, .address = core.types.Address.zero(), .stake = 100 },
        .{ .index = 1, .address = core.types.Address.zero(), .stake = 200 },
        .{ .index = 2, .address = core.types.Address.zero(), .stake = 300 },
    };

    gs.advanceSlot(100, 5, &validators);

    const targets = gs.getForwardTargets();
    // At least one target should be set
    var has_target = false;
    for (targets) |t| {
        if (t != null) has_target = true;
    }
    try testing.expect(has_target);
}

test "GulfStream - stats" {
    var gs = gulf_stream.GulfStream.init(testing.allocator);
    defer gs.deinit();

    const stats = gs.getStats();
    try testing.expectEqual(@as(u64, 0), stats.batches_forwarded);
}
