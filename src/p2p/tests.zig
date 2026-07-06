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
const consensus = @import("consensus");

// ── Subnet Bitmap Tests ─────────────────────────────────────────────────

test "Subnet bitmap - set and check" {
    var bitmap: [16]u8 = [_]u8{0} ** 16;

    types.setSubnetBit(&bitmap, 0);
    try testing.expect(types.isSubnetSubscribed(bitmap, 0));
    try testing.expect(!types.isSubnetSubscribed(bitmap, 1));

    types.setSubnetBit(&bitmap, 127);
    try testing.expect(types.isSubnetSubscribed(bitmap, 127));

    types.setSubnetBit(&bitmap, 64);
    try testing.expect(types.isSubnetSubscribed(bitmap, 64));
}

test "Subnet bitmap - clear" {
    var bitmap: [16]u8 = [_]u8{0xFF} ** 16;

    types.clearSubnetBit(&bitmap, 10);
    try testing.expect(!types.isSubnetSubscribed(bitmap, 10));
    try testing.expect(types.isSubnetSubscribed(bitmap, 9));
    try testing.expect(types.isSubnetSubscribed(bitmap, 11));
}

test "Subnet bitmap - out of range" {
    var bitmap: [16]u8 = [_]u8{0} ** 16;
    types.setSubnetBit(&bitmap, 128); // Should be no-op
    try testing.expect(!types.isSubnetSubscribed(bitmap, 128));
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
    try testing.expect(stats.compressionCalls > 0);
    try testing.expect(stats.totalUncompressed > 0);
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

    const sig = [_]u8{0xAB} ** 96;

    // Shred the block
    const bid = core.types.Hash.zero();
    const shreds = try engine.shredBlock(block_data, 42, bid, sig, null);
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

    const peers = try testing.allocator.alloc(turbine.StakeWeightedPeer, 100);
    defer testing.allocator.free(peers);
    for (peers, 0..) |*p, i| {
        var addr = core.types.Address.zero();
        addr.bytes[0] = @intCast(i + 1);
        p.* = .{ .address = addr, .stake = 1 };
    }

    try tree.build(peers, 2560);

    // Root should exist
    try testing.expect(tree.nodes.items.len > 0);
    try testing.expectEqual(@as(u32, 0), tree.nodes.items[0].peerIndex);
    try testing.expectEqual(@as(u8, 0), tree.nodes.items[0].layer);

    // Root should have children
    try testing.expect(tree.nodes.items[0].childrenCount > 0);
}

test "PropagationTree - shred assignment" {
    var tree = turbine.PropagationTree.init(testing.allocator);
    defer tree.deinit();

    const peers = try testing.allocator.alloc(turbine.StakeWeightedPeer, 10);
    defer testing.allocator.free(peers);
    for (peers, 0..) |*p, i| {
        var addr = core.types.Address.zero();
        addr.bytes[0] = @intCast(i + 1);
        p.* = .{ .address = addr, .stake = 1 };
    }

    try tree.build(peers, 100);

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
        std.crypto.hash.Blake3.hash(&id, &hash, .{});

        const node = discovery.Node{
            .id = id,
            .hash = hash,
            .address = try std.net.Address.parseIp4("127.0.0.1", @intCast(30304 + i)),
            .lastSeen = std.time.milliTimestamp(),
            .lastPing = 0,
            .pingFailures = 0,
            .peerRole = .Validator,
            .validatorAddress = core.types.Address.zero(),
            .subscribedSubnets = [_]u8{0} ** 16,
            .stakeAmount = 0,
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
    std.crypto.hash.Blake3.hash(&id, &hash, .{});

    var subnets: [16]u8 = [_]u8{0} ** 16;
    types.setSubnetBit(&subnets, 10);

    const node = discovery.Node{
        .id = id,
        .hash = hash,
        .address = try std.net.Address.parseIp4("10.0.0.1", 30303),
        .lastSeen = std.time.milliTimestamp(),
        .lastPing = 0,
        .pingFailures = 0,
        .peerRole = .Validator,
        .validatorAddress = core.types.Address.zero(),
        .subscribedSubnets = subnets,
        .stakeAmount = 100000,
    };
    try d.addNode(node);

    const found = try d.findClosestInSubnet(hash, 10, 5);
    defer testing.allocator.free(found);

    try testing.expect(found.len >= 1);
    try testing.expect(found[0].isInSubnet(10));
}

test "Discovery - ZNR serialize/deserialize roundtrip" {
    const pubkey = [_]u8{0xAA} ** 33;
    var znr = discovery.ZnrRecord.init(pubkey, [4]u8{ 192, 168, 1, 1 }, 30303);
    znr.seq = 42;
    znr.stake = 1000000;

    var buf: [128]u8 = undefined;
    const len = znr.serialize(&buf);
    try testing.expect(len > 0);

    const decoded = discovery.ZnrRecord.deserialize(buf[0..len]);
    try testing.expect(decoded != null);
    try testing.expectEqual(@as(u64, 42), decoded.?.seq);
    try testing.expectEqualSlices(u8, &pubkey, &decoded.?.pubkey);
    try testing.expectEqual(@as(u16, 30303), decoded.?.udpPort);
    try testing.expectEqual(@as(u64, 1000000), decoded.?.stake);
    try testing.expectEqualSlices(u8, "znr1", &decoded.?.id);
}

test "Discovery - ZNR connection string roundtrip" {
    const pubkey = [_]u8{0xBB} ** 33;
    var znr = discovery.ZnrRecord.init(pubkey, [4]u8{ 8, 8, 8, 8 }, 30303);
    znr.seq = 100;
    znr.stake = 50000;
    znr.subnets = [_]u8{0x55} ** 16;
    
    // Set a dummy validator address
    var val_addr_bytes = [_]u8{0xCC} ** 32;
    @memcpy(&znr.validatorAddr.bytes, &val_addr_bytes);

    var buf: [256]u8 = undefined;
    const conn_str = try znr.toConnectionString(&buf);
    
    const parsed = try discovery.ZnrRecord.fromConnectionString(conn_str);
    try testing.expectEqual(znr.seq, parsed.seq);
    try testing.expectEqualSlices(u8, &znr.pubkey, &parsed.pubkey);
    try testing.expectEqualSlices(u8, &znr.ip4, &parsed.ip4);
    try testing.expectEqual(znr.udpPort, parsed.udpPort);
    try testing.expectEqual(znr.stake, parsed.stake);
    try testing.expectEqualSlices(u8, &znr.subnets, &parsed.subnets);
    try testing.expectEqualSlices(u8, &znr.validatorAddr.bytes, &parsed.validatorAddr.bytes);
}

test "Discovery - Secure Identity Derivation" {
    const priv_key = [_]u8{0x42} ** 32;
    var d = try discovery.DiscoveryService.init(testing.allocator, &priv_key, 30303);
    defer d.deinit();

    // Verify node ID does not equal private key (to prevent leakage)
    try testing.expect(!std.mem.eql(u8, d.localNode.id[0..32], &priv_key));
    // Verify ZNR public key does not equal private key
    try testing.expect(!std.mem.eql(u8, d.localZnr.pubkey[0..32], &priv_key));

    // Verify they equal the derived Ed25519 public key
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(priv_key);
    const expected_pub = key_pair.public_key.toBytes();
    try testing.expectEqualSlices(u8, &expected_pub, d.localNode.id[0..32]);
    try testing.expectEqualSlices(u8, &expected_pub, d.localZnr.pubkey[0..32]);
}

test "Discovery - stats" {
    const priv = [_]u8{3} ** 32;
    var d = try discovery.DiscoveryService.init(testing.allocator, &priv, 30303);
    defer d.deinit();

    const stats = d.getStats();
    try testing.expectEqual(@as(u32, 0), stats.totalNodes);
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

    var buf: [128]types.SubnetID = undefined;
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

    try testing.expect(!p.isCommitteeMember);

    p.setCommitteeAssignment(.{
        .epoch = 1,
        .slotStart = 0,
        .slotEnd = 100,
        .committeeIndex = 5,
        .role = .Attestor,
        .threadId = 3,
    });

    try testing.expect(p.isCommitteeMember);
    try testing.expect(p.committeeAssignment != null);
    try testing.expectEqual(types.CommitteeRole.Attestor, p.committeeAssignment.?.role);

    p.clearCommitteeAssignment();
    try testing.expect(!p.isCommitteeMember);
}

test "Peer - stats" {
    const p = try peer_mod.Peer.init(testing.allocator, "127.0.0.1", 30303);
    defer p.deinit();

    p.recordReceived(1024);
    p.recordReceived(512);

    const stats = p.getStats();
    try testing.expectEqual(@as(u64, 1536), stats.bytesReceived);
    try testing.expectEqual(@as(u64, 2), stats.packetsReceived);
}

// ── Gulf Stream Tests ───────────────────────────────────────────────────

test "GulfStream - advance slot resets throttle" {
    var gs = gulf_stream.GulfStream.init(testing.allocator, null, undefined);
    defer gs.deinit();

    gs.advanceSlot(100);
    try testing.expectEqual(@as(u64, 100), gs.current_slot);
}

test "GulfStream - leader schedule (no engine — all null targets)" {
    var gs = gulf_stream.GulfStream.init(testing.allocator, null, undefined);
    defer gs.deinit();

    gs.advanceSlot(100);

    const targets = gs.getForwardTargets();
    // Without engine, all targets should be null
    for (targets) |t| {
        try testing.expect(t == null);
    }
}

test "GulfStream - drain batch returns null without engine" {
    var gs = gulf_stream.GulfStream.init(testing.allocator, null, undefined);
    defer gs.deinit();

    gs.advanceSlot(100);
    const result = try gs.drainBatch();
    try testing.expect(result == null);
}

test "GulfStream - stats" {
    var gs = gulf_stream.GulfStream.init(testing.allocator, null, undefined);
    defer gs.deinit();

    const stats = gs.getStats();
    try testing.expectEqual(@as(u64, 0), stats.batchesForwarded);
}

test "Turbine - parent index resolution" {
    var tree = turbine.PropagationTree.init(testing.allocator);
    defer tree.deinit();

    const peers = try testing.allocator.alloc(turbine.StakeWeightedPeer, 5);
    defer testing.allocator.free(peers);
    for (peers, 0..) |*p, i| {
        var addr = core.types.Address.zero();
        addr.bytes[0] = @intCast(i + 1);
        p.* = .{ .address = addr, .stake = 1 };
    }

    try tree.build(peers, 100);

    try testing.expectEqual(@as(?u32, null), tree.getParentIndex(0));

    try testing.expectEqual(@as(?u32, 0), tree.getParentIndex(1));
    try testing.expectEqual(@as(?u32, 0), tree.getParentIndex(2));
    try testing.expectEqual(@as(?u32, 0), tree.getParentIndex(3));
    try testing.expectEqual(@as(?u32, 0), tree.getParentIndex(4));
}

test "Turbine - mock network propagation with 30% packet loss and repair recovery" {
    const allocator = testing.allocator;

    var addrs: [5]core.types.Address = undefined;
    for (0..5) |i| {
        addrs[i] = core.types.Address.zero();
        addrs[i].bytes[0] = @intCast(i + 1);
    }

    var engines: [5]turbine.TurbineEngine = undefined;

    for (0..5) |i| {
        engines[i] = turbine.TurbineEngine.init(allocator);
    }
    defer {
        for (0..5) |i| {
            engines[i].deinit();
        }
    }

    const block_size = 8000;
    const block_data = try allocator.alloc(u8, block_size);
    defer allocator.free(block_data);
    for (0..block_size) |i| block_data[i] = @intCast(i % 256);

    const producer_sig: [96]u8 = [_]u8{0} ** 96;
    const bid = core.types.Hash.zero();

    const shreds = try engines[0].shredBlock(block_data, 1, bid, producer_sig, 0.25);
    defer engines[0].freeShreds(shreds);

    var prng = std.Random.DefaultPrng.init(0xABC123);
    const random = prng.random();

    for (shreds) |s| {
        for (1..5) |child_idx| {
            if (random.float(f32) < 0.30) {
                continue;
            }
            var child_shred = s;
            child_shred.payload = try allocator.dupe(u8, s.payload);
            defer allocator.free(child_shred.payload);

            const maybe_block = try engines[child_idx].receiveShred(&child_shred);
            if (maybe_block) |data| {
                allocator.free(data);
            }
        }
    }

    for (1..5) |child_idx| {
        var stripe = &engines[child_idx].collectorStripes[1 % 16];
        var missing_shreds = std.ArrayList(u32).empty;
        defer missing_shreds.deinit(allocator);

        stripe.mutex.lock();
        if (stripe.collectors.get(1)) |collector| {
            for (collector.present, 0..) |p, s_idx| {
                if (!p) {
                    try missing_shreds.append(allocator, @intCast(s_idx));
                }
            }
        }
        stripe.mutex.unlock();

        for (missing_shreds.items) |s_idx| {
            if (engines[0].getCachedShred(1, s_idx)) |cached_shred| {
                var recovered_shred = cached_shred;
                recovered_shred.payload = try allocator.dupe(u8, cached_shred.payload);
                defer allocator.free(recovered_shred.payload);

                const maybe_block = try engines[child_idx].receiveShred(&recovered_shred);
                if (maybe_block) |data| {
                    allocator.free(data);
                }
            }
        }
    }

    for (1..5) |i| {
        const stats = engines[i].getStats();
        try testing.expectEqual(@as(u64, 1), stats.blocksReconstructed);
    }
}

test "STUN - response parsing & decryption" {
    const stun = @import("stun.zig");
    
    // Construct a mock STUN Binding Success Response
    var response: [100]u8 = undefined;
    @memset(&response, 0);

    // Header: Type = 0x0101 (Success response), length = 12 (XOR-MAPPED-ADDRESS attribute length + header (4 bytes))
    std.mem.writeInt(u16, response[0..2], 0x0101, .big);
    std.mem.writeInt(u16, response[2..4], 12, .big);
    std.mem.writeInt(u32, response[4..8], stun.STUN_MAGIC_COOKIE, .big);
    
    const transaction_id = [_]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    @memcpy(response[8..20], &transaction_id);

    // Attribute: Type = 0x0020 (XOR-MAPPED-ADDRESS), Length = 8
    std.mem.writeInt(u16, response[20..22], 0x0020, .big);
    std.mem.writeInt(u16, response[22..24], 8, .big);

    // Value: Reserved (1 byte), Family = 0x01 (IPv4, 1 byte), Port XOR-ed (2 bytes), IP XOR-ed (4 bytes)
    response[24] = 0x00; // Reserved
    response[25] = 0x01; // Family IPv4

    // Target Port: 12345
    // Target IP: 192.168.1.50 -> 0xC0A80132
    const target_port: u16 = 12345;
    const target_ip_u32: u32 = 0xC0A80132;

    const cookie_high = @as(u16, @intCast(stun.STUN_MAGIC_COOKIE >> 16));
    const xor_port = target_port ^ cookie_high;
    const xor_ip = target_ip_u32 ^ stun.STUN_MAGIC_COOKIE;

    std.mem.writeInt(u16, response[26..28], xor_port, .big);
    std.mem.writeInt(u32, response[28..32], xor_ip, .big);

    const parsed_addr = try stun.parseStunResponse(response[0..32], transaction_id);
    
    // Check decrypted port and IP
    try testing.expectEqual(target_port, parsed_addr.getPort());
    
    const parsed_ip_bytes = @as(*const [4]u8, @ptrCast(&parsed_addr.in.sa.addr)).*;
    try testing.expectEqual(@as(u8, 192), parsed_ip_bytes[0]);
    try testing.expectEqual(@as(u8, 168), parsed_ip_bytes[1]);
    try testing.expectEqual(@as(u8, 1), parsed_ip_bytes[2]);
    try testing.expectEqual(@as(u8, 50), parsed_ip_bytes[3]);
}

test "STUN - mapped address parsing" {
    const stun = @import("stun.zig");
    
    var response: [100]u8 = undefined;
    @memset(&response, 0);

    std.mem.writeInt(u16, response[0..2], 0x0101, .big);
    std.mem.writeInt(u16, response[2..4], 12, .big);
    std.mem.writeInt(u32, response[4..8], stun.STUN_MAGIC_COOKIE, .big);
    
    const transaction_id = [_]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    @memcpy(response[8..20], &transaction_id);

    // Attribute: Type = 0x0001 (MAPPED-ADDRESS), Length = 8
    std.mem.writeInt(u16, response[20..22], 0x0001, .big);
    std.mem.writeInt(u16, response[22..24], 8, .big);

    response[24] = 0x00;
    response[25] = 0x01; // Family IPv4

    const target_port: u16 = 54321;
    const target_ip_bytes = [_]u8{8, 8, 8, 8};

    std.mem.writeInt(u16, response[26..28], target_port, .big);
    @memcpy(response[28..32], &target_ip_bytes);

    const parsed_addr = try stun.parseStunResponse(response[0..32], transaction_id);
    
    try testing.expectEqual(target_port, parsed_addr.getPort());
    
    const parsed_ip_bytes = @as(*const [4]u8, @ptrCast(&parsed_addr.in.sa.addr)).*;
    try testing.expectEqualSlices(u8, &target_ip_bytes, &parsed_ip_bytes);
}

// ── Phase 3: Turbine Shred Firewall Tests ─────────────────────────────

test "Turbine - reject shred with invalid threadId (Firewall 3)" {
    const allocator = testing.allocator;
    var engine = turbine.TurbineEngine.init(allocator);
    defer engine.deinit();

    const block_data = try allocator.alloc(u8, 200);
    defer allocator.free(block_data);
    for (0..200) |i| block_data[i] = @intCast(i % 256);

    const sig: [96]u8 = [_]u8{0} ** 96;
    var blockId = core.types.Hash.zero();
    blockId.bytes[0] = 0xAB;

    const shreds = try engine.shredBlock(block_data, 1, blockId, sig, 0.25);
    defer engine.freeShreds(shreds);

    // Modify the first shred's threadId to 200 (>= 128, invalid)
    var bad_shred = shreds[0];
    bad_shred.threadId = 200;
    bad_shred.payload = try allocator.dupe(u8, shreds[0].payload);
    defer allocator.free(bad_shred.payload);

    try testing.expectError(error.InvalidThreadId, engine.receiveShred(&bad_shred));
}

test "Turbine - reject shred with inconsistent blockId (Firewall 4)" {
    const allocator = testing.allocator;
    var engine = turbine.TurbineEngine.init(allocator);
    defer engine.deinit();

    // Use block > MAX_SHRED_PAYLOAD (1100) to require at least 2 data shreds
    const block_data = try allocator.alloc(u8, 1200);
    defer allocator.free(block_data);
    for (0..1200) |i| block_data[i] = @intCast(i % 256);

    const sig: [96]u8 = [_]u8{0} ** 96;
    var blockIdA = core.types.Hash.zero();
    blockIdA.bytes[0] = 0xAA;
    var blockIdB = core.types.Hash.zero();
    blockIdB.bytes[0] = 0xBB;

    const shreds = try engine.shredBlock(block_data, 2, blockIdA, sig, 0.25);
    defer engine.freeShreds(shreds);

    // First shred with blockIdA is OK — not yet reconstructable (needs 2nd data shred)
    {
        var first = shreds[0];
        first.payload = try allocator.dupe(u8, shreds[0].payload);
        defer allocator.free(first.payload);
        const result = try engine.receiveShred(&first);
        try testing.expect(result == null); // Not yet reconstructable
    }

    // Second shred with wrong blockIdB should be rejected
    {
        var second = shreds[1];
        second.blockId = blockIdB;
        second.payload = try allocator.dupe(u8, shreds[1].payload);
        defer allocator.free(second.payload);
        // CRC does NOT cover blockId, so no need to recompute

        try testing.expectError(error.ShredBlockIdMismatch, engine.receiveShred(&second));
    }
}

test "Turbine - reject shred with invalid shredIndex (Firewall 2)" {
    const allocator = testing.allocator;
    var engine = turbine.TurbineEngine.init(allocator);
    defer engine.deinit();

    const block_data = try allocator.alloc(u8, 200);
    defer allocator.free(block_data);
    for (0..200) |i| block_data[i] = @intCast(i % 256);

    const sig: [96]u8 = [_]u8{0} ** 96;
    var blockId = core.types.Hash.zero();
    blockId.bytes[0] = 0xCC;

    const shreds = try engine.shredBlock(block_data, 3, blockId, sig, 0.25);
    defer engine.freeShreds(shreds);

    var bad_shred = shreds[0];
    bad_shred.shredIndex = 999;
    bad_shred.payload = try allocator.dupe(u8, shreds[0].payload);
    defer allocator.free(bad_shred.payload);

    // Fix CRC since shredIndex changed
    bad_shred.crc32 = bad_shred.computeCrc();

    try testing.expectError(error.InvalidShredIndex, engine.receiveShred(&bad_shred));
}

// ── Phase 4: Gulf Stream Firewall Tests ───────────────────────────────

test "GulfStream - canForwardToTarget respects per-target rate limit (Firewall 3)" {
    var gs = gulf_stream.GulfStream.init(testing.allocator, null, undefined);
    defer gs.deinit();

    gs.advanceSlot(100);

    var addr = core.types.Address.zero();
    addr.bytes[0] = 0xDD;

    // Initially should be allowed
    try testing.expect(gs.canForwardToTarget(addr));

    // Simulate forwarding to this target 11 times
    for (0..11) |i| {
        gs.peerForwardCount.put(addr, @intCast(i + 1)) catch {};
    }

    // Now should be blocked (exceeds MAX_FORWARD_BATCHES_PER_TARGET = 10)
    try testing.expect(!gs.canForwardToTarget(addr));

    // Advance slot — counter should reset
    gs.advanceSlot(101);
    try testing.expect(gs.canForwardToTarget(addr));
}

test "GulfStream - advance slot resets per-target counter (Firewall 3)" {
    var gs = gulf_stream.GulfStream.init(testing.allocator, null, undefined);
    defer gs.deinit();

    gs.advanceSlot(10);

    var addr = core.types.Address.zero();
    addr.bytes[0] = 0xEE;
    gs.peerForwardCount.put(addr, 9) catch {};

    try testing.expect(gs.canForwardToTarget(addr));

    // Advance to next slot — counter cleared
    gs.advanceSlot(11);
    const count = gs.peerForwardCount.get(addr);
    try testing.expect(count == null); // Should be reset
}

// ── Phase 6: Pipeline Firewall Tests ──────────────────────────────────

test "Pipeline - reject stale blockNumber (Firewall 2)" {
    var pipe = consensus.pipeline.Pipeline.init(testing.allocator, .{ .validatorCount = 1, .ourIndex = 0 });
    defer pipe.deinit();
    pipe.setValidatorStakes(&[_]u256{100_000_000_000}, 100_000_000_000);

    // First proposal for block 1 succeeds with non-zero parentId
    var parentId1 = core.types.Hash.zero();
    parentId1.bytes[0] = 0xF1;
    _ = try pipe.propose(1, parentId1, &[_]core.types.Hash{});

    // Proposing block 1 again should fail (stale)
    try testing.expectError(error.BlockNumberStale, pipe.propose(1, parentId1, &[_]core.types.Hash{}));
}

test "Pipeline - genesis block with zero parentId is allowed (Firewall 1)" {
    var pipe = consensus.pipeline.Pipeline.init(testing.allocator, .{ .validatorCount = 1, .ourIndex = 0 });
    defer pipe.deinit();
    pipe.setValidatorStakes(&[_]u256{100_000_000_000}, 100_000_000_000);

    // Block 0 with zero parentId should be accepted (genesis case — head is 0 so BlockNumberStale is skipped)
    _ = try pipe.propose(0, core.types.Hash.zero(), &[_]core.types.Hash{});
}

test "Pipeline - reject skipping blockNumber (Firewall 2)" {
    var pipe = consensus.pipeline.Pipeline.init(testing.allocator, .{ .validatorCount = 1, .ourIndex = 0 });
    defer pipe.deinit();
    pipe.setValidatorStakes(&[_]u256{100_000_000_000}, 100_000_000_000);

    // Proposing block 2 when head is 0 should fail (skip)
    try testing.expectError(error.BlockNumberSkipsSlot, pipe.propose(2, core.types.Hash.zero(), &[_]core.types.Hash{}));
}

test "Pipeline - reject zero parentId for non-genesis (Firewall 1)" {
    var pipe = consensus.pipeline.Pipeline.init(testing.allocator, .{ .validatorCount = 1, .ourIndex = 0 });
    defer pipe.deinit();
    pipe.setValidatorStakes(&[_]u256{100_000_000_000}, 100_000_000_000);

    // Block 1 with zero parentId should be rejected (non-genesis must have valid parent)
    try testing.expectError(error.InvalidParentId, pipe.propose(1, core.types.Hash.zero(), &[_]core.types.Hash{}));
}

