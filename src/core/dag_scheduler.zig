// ============================================================================
// Zephyria — DAG-Native Zero-Conflict Scheduler
// ============================================================================
//
// Replaces the greedy wavefront scheduler with a DAG-native scheduler
// that exploits Zephyria's isolated account model.
//
// Key insight: Since every TX's write set is isolated per-sender (unique
// sequence key + balance key + per-user derived storage keys), the ONLY
// dependency is same-sender sequence ordering. This means:
//
//   • Each sender forms an independent execution lane
//   • All lanes can execute in parallel with ZERO coordination
//   • Within each lane, TXs execute sequentially in sequence order
//   • No wavefront computation needed — lanes ARE the parallel schedule
//
// Scheduling cost: O(n) where n = number of TXs (just group by sender)
// vs. old wavefront: O(n × w × k) where w = waves, k = keys per TX
//
// The scheduler also handles:
//   • budget budget allocation across lanes
//   • Priority ordering (highest budget price lanes execute first)
//   • Thread assignment (round-robin across available cores)
//   • Accumulator delta collection for global state merge

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const accounts = @import("accounts/mod.zig");
const dag_mempool = @import("dag_mempool.zig");

// ── Execution Plan ──────────────────────────────────────────────────────

/// The output of the DAG scheduler: a set of independent execution lanes
/// that can run in parallel with guaranteed zero conflicts.
pub const ExecutionPlan = struct {
    lanes: []ExecutionLane,
    totalTxs: u32,
    totalbudget: u64,
    threadAssignments: []ThreadAssignment,
    allocator: std.mem.Allocator,
    all_txs: ?[]types.Transaction = null,

    pub fn deinit(self: *ExecutionPlan) void {
        if (self.all_txs) |txs| {
            self.allocator.free(txs);
        } else {
            for (self.lanes) |*lane| {
                self.allocator.free(lane.txs);
            }
        }
        self.allocator.free(self.lanes);
        for (self.threadAssignments) |*ta| {
            ta.deinit();
        }
        self.allocator.free(self.threadAssignments);
    }

    pub fn laneCount(self: *const ExecutionPlan) usize {
        return self.lanes.len;
    }
};

/// A single execution lane — all TXs from one sender, sequence-ordered.
/// Guaranteed no write-set overlap with any other lane.
pub const ExecutionLane = struct {
    sender: types.Address,
    txs: []types.Transaction,
    baseSequence: u64,
    totalbudget: u64,
    priority: u256, // Max budget price in this lane (for ordering)
};

/// Maps lanes to threads for parallel execution.
pub const ThreadAssignment = struct {
    threadId: u32,
    laneIndices: []u32,
    totalbudget: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ThreadAssignment) void {
        self.allocator.free(self.laneIndices);
    }
};

// ── Scheduler Configuration ─────────────────────────────────────────────

pub const SchedulerConfig = struct {
    /// Number of execution threads
    numThreads: u32 = 8,
    /// Minimum TXs per thread to avoid spawn overhead
    minTxsPerThread: u32 = 4,
    /// Maximum lanes per thread (load balancing)
    maxLanesPerThread: u32 = 10_000,
    /// Block execution budget
    blockExecutionBudget: u64 = 1_000_000_000, // 1B budget
    /// Producer address for fee collection
    producer: types.Address = types.Address.zero(),
};

// ── DAG Scheduler ───────────────────────────────────────────────────────

/// Build a zero-conflict execution plan from DAG mempool extraction.
///
/// This is the core scheduling function. It takes the extracted lanes from
/// the DAG mempool and produces a thread-assigned execution plan.
///
/// Complexity: O(n log n) where n = number of lanes (for priority sort)
/// No conflict detection needed — isolation is guaranteed by construction.
pub fn schedule(
    allocator: std.mem.Allocator,
    extraction: *dag_mempool.ExtractionResult,
    config: SchedulerConfig,
) !ExecutionPlan {
    if (extraction.lanes.len == 0) {
        return ExecutionPlan{
            .lanes = try allocator.alloc(ExecutionLane, 0),
            .totalTxs = 0,
            .totalbudget = 0,
            .threadAssignments = try allocator.alloc(ThreadAssignment, 0),
            .allocator = allocator,
        };
    }

    // 1. Convert extracted lanes to execution lanes with priority
    var exec_lanes = std.ArrayListUnmanaged(ExecutionLane){};
    defer exec_lanes.deinit(allocator);

    var total_txs: u32 = 0;
    var total_budget: u64 = 0;
    var remaining_budget = config.blockExecutionBudget;

    for (extraction.lanes) |*extracted| {
        if (extracted.txs.len == 0) continue;

        // Compute lane priority and budget
        var max_price: u256 = 0;
        var lane_budget: u64 = 0;
        var valid_count: usize = 0;

        for (extracted.txs) |*tx| {
            if (tx.executionBudget > remaining_budget) break;
            if (tx.computePrice > max_price) max_price = tx.computePrice;
            lane_budget += tx.executionBudget;
            remaining_budget -= tx.executionBudget;
            valid_count += 1;
        }

        if (valid_count == 0) continue;

        const txs = try allocator.alloc(types.Transaction, valid_count);
        @memcpy(txs, extracted.txs[0..valid_count]);

        try exec_lanes.append(allocator, ExecutionLane{
            .sender = extracted.sender,
            .txs = txs,
            .baseSequence = extracted.baseSequence,
            .totalbudget = lane_budget,
            .priority = max_price,
        });

        total_txs += @intCast(valid_count);
        total_budget += lane_budget;
    }

    // 2. Sort lanes by priority (highest budget price first)
    std.mem.sortUnstable(ExecutionLane, exec_lanes.items, {}, struct {
        pub fn lessThan(_: void, a: ExecutionLane, b: ExecutionLane) bool {
            return a.priority > b.priority;
        }
    }.lessThan);

    // 3. Assign lanes to threads (budget-balanced round-robin)
    const num_threads = @min(config.numThreads, @as(u32, @intCast(exec_lanes.items.len)));
    const assignments = try assignToThreads(allocator, exec_lanes.items, num_threads);

    // 4. Build final plan
    const lanes = try allocator.alloc(ExecutionLane, exec_lanes.items.len);
    @memcpy(lanes, exec_lanes.items);

    return ExecutionPlan{
        .lanes = lanes,
        .totalTxs = total_txs,
        .totalbudget = total_budget,
        .threadAssignments = assignments,
        .allocator = allocator,
    };
}

/// Build a plan directly from a TX slice (for block validation).
/// Groups TXs by sender automatically.
pub fn scheduleFromTxs(
    allocator: std.mem.Allocator,
    transactions: []const types.Transaction,
    config: SchedulerConfig,
) !ExecutionPlan {
    if (transactions.len == 0) {
        return ExecutionPlan{
            .lanes = try allocator.alloc(ExecutionLane, 0),
            .totalTxs = 0,
            .totalbudget = 0,
            .threadAssignments = try allocator.alloc(ThreadAssignment, 0),
            .allocator = allocator,
        };
    }

    // Group TXs by sender
    var sender_txs = std.AutoHashMap(types.Address, std.ArrayListUnmanaged(types.Transaction)).init(allocator);
    defer {
        var it = sender_txs.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        sender_txs.deinit();
    }

    for (transactions) |tx| {
        const gop = try sender_txs.getOrPut(tx.from);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(allocator, tx);
    }

    // Sort each sender's TXs by sequence
    var it = sender_txs.iterator();
    while (it.next()) |entry| {
        std.mem.sortUnstable(types.Transaction, entry.value_ptr.items, {}, struct {
            pub fn lessThan(_: void, a: types.Transaction, b: types.Transaction) bool {
                return a.sequence < b.sequence;
            }
        }.lessThan);
    }

    // Build execution lanes
    var exec_lanes = std.ArrayListUnmanaged(ExecutionLane){};
    defer exec_lanes.deinit(allocator);

    var total_txs: u32 = 0;
    var total_budget: u64 = 0;

    const all_txs_contig = try allocator.alloc(types.Transaction, transactions.len);
    errdefer allocator.free(all_txs_contig);
    var current_tx_offset: usize = 0;

    var it2 = sender_txs.iterator();
    while (it2.next()) |entry| {
        const txs_list = entry.value_ptr.items;
        if (txs_list.len == 0) continue;

        var max_price: u256 = 0;
        var lane_budget: u64 = 0;
        for (txs_list) |*tx| {
            if (tx.computePrice > max_price) max_price = tx.computePrice;
            lane_budget += tx.executionBudget;
        }

        const start_offset = current_tx_offset;
        const end_offset = start_offset + txs_list.len;
        @memcpy(all_txs_contig[start_offset..end_offset], txs_list);
        current_tx_offset = end_offset;

        try exec_lanes.append(allocator, ExecutionLane{
            .sender = entry.key_ptr.*,
            .txs = all_txs_contig[start_offset..end_offset],
            .baseSequence = txs_list[0].sequence,
            .totalbudget = lane_budget,
            .priority = max_price,
        });

        total_txs += @intCast(txs_list.len);
        total_budget += lane_budget;
    }

    // Sort by priority
    std.mem.sortUnstable(ExecutionLane, exec_lanes.items, {}, struct {
        pub fn lessThan(_: void, a: ExecutionLane, b: ExecutionLane) bool {
            return a.priority > b.priority;
        }
    }.lessThan);

    const num_threads = @min(config.numThreads, @as(u32, @intCast(exec_lanes.items.len)));
    const assignments = try assignToThreads(allocator, exec_lanes.items, num_threads);

    const lanes = try allocator.alloc(ExecutionLane, exec_lanes.items.len);
    @memcpy(lanes, exec_lanes.items);

    return ExecutionPlan{
        .lanes = lanes,
        .totalTxs = total_txs,
        .totalbudget = total_budget,
        .threadAssignments = assignments,
        .allocator = allocator,
        .all_txs = all_txs_contig,
    };
}

// ── Thread Assignment ───────────────────────────────────────────────────

/// Assign lanes to threads using budget-balanced round-robin.
/// This ensures each thread gets roughly equal budget load.
fn assignToThreads(
    allocator: std.mem.Allocator,
    lanes: []const ExecutionLane,
    num_threads: u32,
) ![]ThreadAssignment {
    if (num_threads == 0) {
        return try allocator.alloc(ThreadAssignment, 0);
    }

    // Track per-thread budget load for balancing
    const thread_budget = try allocator.alloc(u64, num_threads);
    defer allocator.free(thread_budget);
    @memset(thread_budget, 0);

    // Temporary storage for per-thread lane indices
    const thread_lanes = try allocator.alloc(std.ArrayListUnmanaged(u32), num_threads);
    defer {
        for (thread_lanes) |*tl| tl.deinit(allocator);
        allocator.free(thread_lanes);
    }
    for (thread_lanes) |*tl| tl.* = .{};

    // Assign each lane to the thread with lowest current budget load
    for (lanes, 0..) |*lane, lane_idx| {
        var min_budget: u64 = std.math.maxInt(u64);
        var min_thread: u32 = 0;

        for (0..num_threads) |t| {
            if (thread_budget[t] < min_budget) {
                min_budget = thread_budget[t];
                min_thread = @intCast(t);
            }
        }

        try thread_lanes[min_thread].append(allocator, @intCast(lane_idx));
        thread_budget[min_thread] += lane.totalbudget;
    }

    // Build final assignments
    const assignments = try allocator.alloc(ThreadAssignment, num_threads);
    for (0..num_threads) |t| {
        const indices = try allocator.alloc(u32, thread_lanes[t].items.len);
        @memcpy(indices, thread_lanes[t].items);

        assignments[t] = ThreadAssignment{
            .threadId = @intCast(t),
            .laneIndices = indices,
            .totalbudget = thread_budget[t],
            .allocator = allocator,
        };
    }

    return assignments;
}

// ── Validation ──────────────────────────────────────────────────────────

/// Validate that an execution plan has zero conflicts.
/// Used by validators to verify block proposals.
pub fn validatePlan(plan: *const ExecutionPlan) !void {
    // 1. Check that no two lanes share a sender
    for (plan.lanes, 0..) |*lane_a, i| {
        for (plan.lanes[i + 1 ..]) |*lane_b| {
            if (std.mem.eql(u8, &lane_a.sender.bytes, &lane_b.sender.bytes)) {
                return error.DuplicateSenderInPlan;
            }
        }
    }

    // 2. Check that sequences are contiguous within each lane
    for (plan.lanes) |*lane| {
        var expected_sequence = lane.baseSequence;
        for (lane.txs) |*tx| {
            if (tx.sequence != expected_sequence) {
                return error.NonContiguousSequence;
            }
            expected_sequence += 1;
        }
    }

    // 3. Verify write-set independence using DAG vertex computation
    //    For Zephyria's isolated model, this is guaranteed by construction
    //    (different senders → different keys), but we verify anyway for defense.
    for (plan.lanes, 0..) |*lane_a, i| {
        for (plan.lanes[i + 1 ..]) |*lane_b| {
            for (lane_a.txs) |*tx_a| {
                const va = dag_mempool.DAGVertex.computeWriteKeys(tx_a);
                for (lane_b.txs) |*tx_b| {
                    const vb = dag_mempool.DAGVertex.computeWriteKeys(tx_b);
                    if (va.conflictsWith(&vb)) {
                        return error.CrossLaneConflict;
                    }
                }
            }
        }
    }
}

/// Compute the DAG root hash for a plan (included in block header).
/// Validators use this to verify DAG structure.
pub fn computeDAGRoot(plan: *const ExecutionPlan) types.Hash {
    var hasher = std.crypto.hash.Blake3.init(.{});

    for (plan.lanes) |*lane| {
        hasher.update(&lane.sender.bytes);
        var sequence_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequence_buf, lane.baseSequence, .big);
        hasher.update(&sequence_buf);

        for (lane.txs) |*tx| {
            const tx_hash = tx.id();
            hasher.update(&tx_hash.bytes);
        }
    }

    var root: types.Hash = undefined;
    hasher.final(&root.bytes);
    return root;
}
