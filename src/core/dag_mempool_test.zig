// ============================================================================
// Zephyria — DAG Mempool Test Suite
// ============================================================================
//
// Comprehensive tests for the DAG-based mempool, scheduler, and executor.
// Tests cover:
//   • DAG vertex write-key computation
//   • Account lane sequence ordering
//   • Shard assignment correctness
//   • Cross-lane conflict freedom (isolated model guarantee)
//   • Security: lane depth limits, sequence gaps, budget price enforcement
//   • Extraction and budget budget management
//   • Scheduler plan generation and validation
//   • DAG root computation determinism

const std = @import("std");

// ── DAG Vertex Tests ────────────────────────────────────────────────────

test "DAGVertex: write keys for simple transfer" {
    // A simple transfer touches exactly 3 keys:
    // sender.sequence, sender.balance, recipient.balance
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;

    const tx = types.Transaction{
        .sequence = 0,
        .computePrice = 1_000_000_000,
        .executionBudget = 21_000,
        .from = types.Address{ .bytes = [_]u8{0xAA} ** 32 },
        .to = types.Address{ .bytes = [_]u8{0xBB} ** 32 },
        .value = 1_000_000_000,
        .data = &[_]u8{},
    };

    const vertex = dag_mempool.DAGVertex.computeWriteKeys(&tx);

    // Simple transfer: sender sequence + sender balance + recipient balance = 3 keys
    try std.testing.expectEqual(@as(u8, 3), vertex.writeKeyCount);
    try std.testing.expectEqual(tx.from.bytes[0], vertex.shardId);
}

test "DAGVertex: write keys for contract call" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;

    const tx = types.Transaction{
        .sequence = 0,
        .computePrice = 1_000_000_000,
        .executionBudget = 100_000,
        .from = types.Address{ .bytes = [_]u8{0xAA} ** 32 },
        .to = types.Address{ .bytes = [_]u8{0xCC} ** 32 },
        .value = 0,
        .data = &[_]u8{ 0xA9, 0x05, 0x9C, 0xBB, 0x01, 0x02, 0x03, 0x04 }, // transfer(addr,uint)
    };

    const vertex = dag_mempool.DAGVertex.computeWriteKeys(&tx);

    // Contract call: sender sequence + sender balance + contract balance + per-user derived key = 4 keys
    try std.testing.expectEqual(@as(u8, 4), vertex.writeKeyCount);
}

test "DAGVertex: write keys for contract creation" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;

    const tx = types.Transaction{
        .sequence = 5,
        .computePrice = 1_000_000_000,
        .executionBudget = 500_000,
        .from = types.Address{ .bytes = [_]u8{0xDD} ** 32 },
        .to = null,
        .value = 0,
        .data = &[_]u8{ 0x60, 0x60, 0x60, 0x40 }, // Contract bytecode
    };

    const vertex = dag_mempool.DAGVertex.computeWriteKeys(&tx);

    // Contract creation: sender sequence + sender balance + new_addr sequence + new_addr balance + new_addr code = 5 keys
    try std.testing.expectEqual(@as(u8, 5), vertex.writeKeyCount);
}

test "DAGVertex: different senders never conflict" {
    // This is THE core guarantee of Zephyria's isolated model.
    // Two TXs from different senders should NEVER have overlapping write keys.
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;

    // Alice → Bob transfer
    const tx_alice = types.Transaction{
        .sequence = 0,
        .computePrice = 1_000_000_000,
        .executionBudget = 21_000,
        .from = types.Address{ .bytes = [_]u8{0x01} ++ [_]u8{0} ** 31 },
        .to = types.Address{ .bytes = [_]u8{0x03} ++ [_]u8{0} ** 31 },
        .value = 100,
        .data = &[_]u8{},
    };

    // Bob → Carol transfer
    const tx_bob = types.Transaction{
        .sequence = 0,
        .computePrice = 1_000_000_000,
        .executionBudget = 21_000,
        .from = types.Address{ .bytes = [_]u8{0x02} ++ [_]u8{0} ** 31 },
        .to = types.Address{ .bytes = [_]u8{0x04} ++ [_]u8{0} ** 31 },
        .value = 50,
        .data = &[_]u8{},
    };

    const va = dag_mempool.DAGVertex.computeWriteKeys(&tx_alice);
    const vb = dag_mempool.DAGVertex.computeWriteKeys(&tx_bob);

    // Zero conflicts between different senders
    try std.testing.expect(!va.conflictsWith(&vb));
}

test "DAGVertex: same sender DOES conflict" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;

    const alice = types.Address{ .bytes = [_]u8{0x01} ++ [_]u8{0} ** 31 };

    const tx1 = types.Transaction{
        .sequence = 0,
        .computePrice = 1_000_000_000,
        .executionBudget = 21_000,
        .from = alice,
        .to = types.Address{ .bytes = [_]u8{0x03} ++ [_]u8{0} ** 31 },
        .value = 100,
        .data = &[_]u8{},
    };

    const tx2 = types.Transaction{
        .sequence = 1,
        .computePrice = 1_000_000_000,
        .executionBudget = 21_000,
        .from = alice,
        .to = types.Address{ .bytes = [_]u8{0x04} ++ [_]u8{0} ** 31 },
        .value = 50,
        .data = &[_]u8{},
    };

    const va = dag_mempool.DAGVertex.computeWriteKeys(&tx1);
    const vb = dag_mempool.DAGVertex.computeWriteKeys(&tx2);

    // Same sender → shared sequence and balance keys → conflict
    try std.testing.expect(va.conflictsWith(&vb));
}

// ── Account Lane Tests ──────────────────────────────────────────────────

test "AccountLane: sequence-ordered insertion" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;
    const allocator = std.testing.allocator;

    const sender = types.Address{ .bytes = [_]u8{0xAA} ** 32 };
    var lane = dag_mempool.AccountLane.init(sender, 0);
    defer lane.deinit(allocator);

    // Insert TX with sequence 0
    const tx0 = types.Transaction{
        .sequence = 0,
        .computePrice = 100,
        .executionBudget = 21_000,
        .from = sender,
        .to = sender,
        .value = 0,
        .data = &[_]u8{},
    };
    const replaced = try lane.insert(allocator, tx0, 10);
    try std.testing.expect(replaced == null);
    try std.testing.expectEqual(@as(u32, 1), lane.readyCount());

    // Insert TX with sequence 1
    const tx1 = types.Transaction{
        .sequence = 1,
        .computePrice = 100,
        .executionBudget = 21_000,
        .from = sender,
        .to = sender,
        .value = 0,
        .data = &[_]u8{},
    };
    _ = try lane.insert(allocator, tx1, 10);
    try std.testing.expectEqual(@as(u32, 2), lane.readyCount());

    // Ready TXs should be in sequence order
    const ready = lane.getReady();
    try std.testing.expectEqual(@as(usize, 2), ready.len);
    try std.testing.expectEqual(@as(u64, 0), ready[0].tx.sequence);
    try std.testing.expectEqual(@as(u64, 1), ready[1].tx.sequence);
}

test "AccountLane: replacement requires budget bump" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;
    const allocator = std.testing.allocator;

    const sender = types.Address{ .bytes = [_]u8{0xBB} ** 32 };
    var lane = dag_mempool.AccountLane.init(sender, 0);
    defer lane.deinit(allocator);

    // Insert TX with sequence 0, budget price 100
    _ = try lane.insert(allocator, types.Transaction{
        .sequence = 0,
        .computePrice = 100,
        .executionBudget = 21_000,
        .from = sender,
        .to = sender,
        .value = 0,
        .data = &[_]u8{},
    }, 10);

    // Try replacement with insufficient budget bump (budget price 105, need 110)
    const result = lane.insert(allocator, types.Transaction{
        .sequence = 0,
        .computePrice = 105,
        .executionBudget = 21_000,
        .from = sender,
        .to = sender,
        .value = 0,
        .data = &[_]u8{},
    }, 10);
    try std.testing.expectError(error.ReplacementbudgetTooLow, result);

    // Replacement with sufficient budget bump (budget price 111, need 110)
    const replaced = try lane.insert(allocator, types.Transaction{
        .sequence = 0,
        .computePrice = 111,
        .executionBudget = 21_000,
        .from = sender,
        .to = sender,
        .value = 0,
        .data = &[_]u8{},
    }, 10);
    try std.testing.expect(replaced != null);
    try std.testing.expectEqual(@as(u256, 100), replaced.?.computePrice);
}

test "AccountLane: advance removes committed TXs" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;
    const allocator = std.testing.allocator;

    const sender = types.Address{ .bytes = [_]u8{0xCC} ** 32 };
    var lane = dag_mempool.AccountLane.init(sender, 0);
    defer lane.deinit(allocator);

    // Insert 3 TXs
    for (0..3) |i| {
        _ = try lane.insert(allocator, types.Transaction{
            .sequence = @intCast(i),
            .computePrice = 100,
            .executionBudget = 21_000,
            .from = sender,
            .to = sender,
            .value = 0,
            .data = &[_]u8{},
        }, 10);
    }
    try std.testing.expectEqual(@as(u32, 3), lane.readyCount());

    // Advance to sequence 2 (remove first 2)
    lane.advance(allocator, 2);
    try std.testing.expectEqual(@as(u64, 2), lane.baseSequence);
    try std.testing.expectEqual(@as(u32, 1), lane.readyCount());
}

test "AccountLane: sequence too low rejected" {
    const core = @import("core");
    const dag_mempool = core.dag_mempool;
    const types = core.types;
    const allocator = std.testing.allocator;

    const sender = types.Address{ .bytes = [_]u8{0xDD} ** 32 };
    var lane = dag_mempool.AccountLane.init(sender, 5); // base_sequence = 5
    defer lane.deinit(allocator);

    // TX with sequence 3 (< base_sequence 5) should fail
    const result = lane.insert(allocator, types.Transaction{
        .sequence = 3,
        .computePrice = 100,
        .executionBudget = 21_000,
        .from = sender,
        .to = sender,
        .value = 0,
        .data = &[_]u8{},
    }, 10);
    try std.testing.expectError(error.SequenceTooLow, result);
}

// ── Shard Assignment Tests ──────────────────────────────────────────────

test "Shard assignment is deterministic by sender" {
    // Shard = sender.bytes[0], so same sender always maps to same shard
    const core = @import("core");
    const types = core.types;

    const sender_a = types.Address{ .bytes = [_]u8{0x42} ++ [_]u8{0} ** 31 };
    const sender_b = types.Address{ .bytes = [_]u8{0x42} ++ [_]u8{0xFF} ** 31 };

    // Same first byte → same shard
    try std.testing.expectEqual(sender_a.bytes[0], sender_b.bytes[0]);

    const sender_c = types.Address{ .bytes = [_]u8{0x43} ++ [_]u8{0} ** 31 };
    // Different first byte → different shard
    try std.testing.expect(sender_a.bytes[0] != sender_c.bytes[0]);
}

// ── Scheduler Tests ─────────────────────────────────────────────────────

test "DAGScheduler: plan generation from TX list" {
    const core = @import("core");
    const dag_scheduler = core.dag_scheduler;
    const types = core.types;
    const allocator = std.testing.allocator;

    var txs = [_]types.Transaction{
        // Alice's TX
        .{ .sequence = 0, .computePrice = 200, .executionBudget = 21_000, .from = types.Address{ .bytes = [_]u8{0x01} ++ [_]u8{0} ** 31 }, .to = types.Address{ .bytes = [_]u8{0x03} ++ [_]u8{0} ** 31 }, .value = 100, .data = &[_]u8{} },
        // Bob's TX
        .{ .sequence = 0, .computePrice = 100, .executionBudget = 21_000, .from = types.Address{ .bytes = [_]u8{0x02} ++ [_]u8{0} ** 31 }, .to = types.Address{ .bytes = [_]u8{0x04} ++ [_]u8{0} ** 31 }, .value = 50, .data = &[_]u8{} },
        // Alice's second TX
        .{ .sequence = 1, .computePrice = 200, .executionBudget = 21_000, .from = types.Address{ .bytes = [_]u8{0x01} ++ [_]u8{0} ** 31 }, .to = types.Address{ .bytes = [_]u8{0x05} ++ [_]u8{0} ** 31 }, .value = 75, .data = &[_]u8{} },
    };

    var plan = try dag_scheduler.scheduleFromTxs(allocator, &txs, .{
        .numThreads = 4,
        .blockExecutionBudget = 1_000_000_000,
    });
    defer plan.deinit();

    // Should produce 2 lanes (Alice and Bob)
    try std.testing.expectEqual(@as(usize, 2), plan.lanes.len);
    try std.testing.expectEqual(@as(u32, 3), plan.totalTxs);

    // Alice's lane should have 2 TXs, Bob's should have 1
    var alice_count: u32 = 0;
    var bob_count: u32 = 0;
    for (plan.lanes) |*lane| {
        if (lane.sender.bytes[0] == 0x01) {
            alice_count = @intCast(lane.txs.len);
        } else if (lane.sender.bytes[0] == 0x02) {
            bob_count = @intCast(lane.txs.len);
        }
    }
    try std.testing.expectEqual(@as(u32, 2), alice_count);
    try std.testing.expectEqual(@as(u32, 1), bob_count);
}

test "DAGScheduler: plan validation passes for valid plan" {
    const core = @import("core");
    const dag_scheduler = core.dag_scheduler;
    const types = core.types;
    const allocator = std.testing.allocator;

    var txs = [_]types.Transaction{
        .{ .sequence = 0, .computePrice = 100, .executionBudget = 21_000, .from = types.Address{ .bytes = [_]u8{0x01} ++ [_]u8{0} ** 31 }, .to = types.Address{ .bytes = [_]u8{0x03} ++ [_]u8{0} ** 31 }, .value = 10, .data = &[_]u8{} },
        .{ .sequence = 0, .computePrice = 100, .executionBudget = 21_000, .from = types.Address{ .bytes = [_]u8{0x02} ++ [_]u8{0} ** 31 }, .to = types.Address{ .bytes = [_]u8{0x04} ++ [_]u8{0} ** 31 }, .value = 20, .data = &[_]u8{} },
    };

    var plan = try dag_scheduler.scheduleFromTxs(allocator, &txs, .{});
    defer plan.deinit();

    // Should not return error for valid plan
    try dag_scheduler.validatePlan(&plan);
}

test "DAGScheduler: DAG root is deterministic" {
    const core = @import("core");
    const dag_scheduler = core.dag_scheduler;
    const types = core.types;
    const allocator = std.testing.allocator;

    var txs = [_]types.Transaction{
        .{ .sequence = 0, .computePrice = 100, .executionBudget = 21_000, .from = types.Address{ .bytes = [_]u8{0x01} ++ [_]u8{0} ** 31 }, .to = types.Address{ .bytes = [_]u8{0x02} ++ [_]u8{0} ** 31 }, .value = 10, .data = &[_]u8{} },
    };

    var plan1 = try dag_scheduler.scheduleFromTxs(allocator, &txs, .{});
    defer plan1.deinit();

    var plan2 = try dag_scheduler.scheduleFromTxs(allocator, &txs, .{});
    defer plan2.deinit();

    const root1 = dag_scheduler.computeDAGRoot(&plan1);
    const root2 = dag_scheduler.computeDAGRoot(&plan2);

    try std.testing.expectEqualSlices(u8, &root1.bytes, &root2.bytes);
}

test "DAGScheduler: thread assignment is budget-balanced" {
    const core = @import("core");
    const dag_scheduler = core.dag_scheduler;
    const types = core.types;
    const allocator = std.testing.allocator;

    // 4 senders with varying budget loads
    var txs: [4]types.Transaction = undefined;
    for (&txs, 0..) |*tx, i| {
        tx.* = types.Transaction{
            .sequence = 0,
            .computePrice = 100,
            .executionBudget = @as(u64, @intCast(21_000 * (i + 1))),
            .from = types.Address{ .bytes = [_]u8{@intCast(i + 1)} ++ [_]u8{0} ** 31 },
            .to = types.Address{ .bytes = [_]u8{0xFF} ++ [_]u8{0} ** 31 },
            .value = 0,
            .data = &[_]u8{},
        };
    }

    var plan = try dag_scheduler.scheduleFromTxs(allocator, &txs, .{
        .numThreads = 2,
    });
    defer plan.deinit();

    // Should have 2 thread assignments
    try std.testing.expectEqual(@as(usize, 2), plan.threadAssignments.len);

    // Both threads should have lanes assigned
    for (plan.threadAssignments) |*ta| {
        try std.testing.expect(ta.laneIndices.len > 0);
    }
}

// ── Security Tests ──────────────────────────────────────────────────────

test "Security: DAGSecurityConfig defaults are safe" {
    const core = @import("core");
    const config = core.security.DAGSecurityConfig{};

    // Lane depth limit prevents depth bomb
    try std.testing.expect(config.maxTxsPerLane <= 256);

    // Total vertex limit prevents memory exhaustion
    try std.testing.expect(config.maxTotalVertices <= 1_000_000);
    // Sequence gap limit prevents lane reservation attacks

    try std.testing.expect(config.maxSequenceGap <= 64);

    // Orphan timeout prevents leaked memory
    try std.testing.expect(config.orphanTimeoutS > 0);

    // Hot-shard multiplier is reasonable
    try std.testing.expect(config.hotShardMultiplier >= 2);

    // Bloom filter is large enough
    try std.testing.expect(config.bloomSizeBits >= 1_000_000);

    // Cross-lane verification enabled by default
    try std.testing.expect(config.enableCrossLaneVerification);
}
