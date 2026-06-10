// ============================================================================
// Zephyria — DAG-Native Parallel Executor
// ============================================================================
//
// Unified executor that replaces both executor.zig and turbo_executor.zig.
// Designed for the DAG mempool's zero-conflict execution model.
//
// Execution Pipeline:
//   Phase 1 — Parallel Lane Execution:
//     Each lane runs in its own thread with its own Overlay.
//     Within a lane, TXs execute sequentially (same sender → sequence ordering).
//     Across lanes, zero coordination — guaranteed no write-set overlap.
//
//   Phase 2 — Delta Merge:
//     Collect AccumulatorDelta entries from all lanes.
//     Sort by TX index. Apply to world state deterministically.
//     This handles global state (totalSupply, pool reserves) that
//     uses commutative accumulators.
//
//   Phase 3 — State Root:
//     Batch-commit all overlays to the state store.
//     Compute state root for block header.
//
// Thread model:
//   • Pre-allocated thread arenas (avoid per-TX allocation)
//   • budget-balanced lane-to-thread assignment from scheduler
//   • Small lanes (1-2 TXs) batched on one thread
//   • Work-stealing not needed — budget balancing is sufficient

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const accounts = @import("accounts/mod.zig");
const dag_scheduler = @import("dag_scheduler.zig");
const security = @import("security.zig");
const log = @import("logger.zig");
const state_root_mod = @import("state_root/mod.zig");

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration options for the DAGExecutor.
pub const ExecutorConfig = struct {
    /// Number of execution threads
    numThreads: u32 = 8,
    /// Block execution budget
    blockExecutionBudget: u64 = 1_000_000_000,
    /// Producer for fee collection
    producer: types.Address = types.Address.zero(),
    /// Execution timeout per TX (ms)
    txTimeoutMs: u64 = 5_000,
    /// Fast-path for simple transfers (skip VM)
    transferFastPath: bool = true,
    /// Maximum call depth
    maxCallDepth: u32 = 256,
    /// Block reward config — applied after TX execution but before state root
    blockReward: BlockRewardConfig = .{},
};

/// Per-block reward configuration embedded in the executor.
pub const BlockRewardConfig = struct {
    base_reward: u256 = 2_000_000_000_000_000_000,
    per_budget_reward: u256 = 0,
    per_tx_reward: u256 = 0,
    enabled: bool = true,
};

// ── VM Callback ─────────────────────────────────────────────────────────

/// Result of a single VM execution call.
pub const VMResult = struct {
    success: bool,
    budgetUsed: u64,
    returnData: []const u8,
};

/// VM callback interface for the DAGExecutor.
pub const VMCallback = struct {
    ctx: *anyopaque,
    exec_fn: *const fn (
        ctx: *anyopaque,
        code: []const u8,
        input: []const u8,
        budget: u64,
        overlay: *state_mod.Overlay,
        caller: types.Address,
        self_address: types.Address,
        value: u256,
        delta_queue: ?*accounts.DeltaQueue,
        receipt_queue: ?*accounts.ReceiptQueue,
        tx_index: u32,
    ) VMResult,
    prewarm_fn: ?*const fn (
        ctx: *anyopaque,
        code: []const u8,
    ) anyerror!void = null,

    /// Executes a contract call through the provided VM implementation.
    pub fn execute(
        self: *const VMCallback,
        code: []const u8,
        input: []const u8,
        budget: u64,
        overlay: *state_mod.Overlay,
        caller: types.Address,
        self_address: types.Address,
        value: u256,
        delta_queue: ?*accounts.DeltaQueue,
        receipt_queue: ?*accounts.ReceiptQueue,
        tx_index: u32,
    ) VMResult {
        return self.exec_fn(
            self.ctx,
            code,
            input,
            budget,
            overlay,
            caller,
            self_address,
            value,
            delta_queue,
            receipt_queue,
            tx_index,
        );
    }

    /// Pre-warms the VM JIT/AOT cache with the given contract bytecode.
    pub fn preWarm(self: *const VMCallback, code: []const u8) !void {
        if (self.prewarm_fn) |pw| {
            try pw(self.ctx, code);
        }
    }
};

// ── Execution Results ───────────────────────────────────────────────────

/// Aggregate result of executing a block using the DAG pipeline.
pub const BlockResult = struct {
    stateRoot: types.Hash,
    budgetUsed: u64,
    txCount: u32,
    txResults: []TxResult,
    laneCount: u32,
    executionTimeNs: i128,
    mergeTimeNs: i128,
    commitTimeNs: i128,
    receiptsRoot: types.Hash,

    /// Frees the transaction results slice.
    pub fn deinit(self: *BlockResult, allocator: std.mem.Allocator) void {
        allocator.free(self.txResults);
    }
};

/// Result of a single transaction execution within the DAG pipeline.
pub const TxResult = struct {
    success: bool,
    budgetUsed: u64,
    fee: u256,
    txHash: types.Hash,
    errorMessage: ?[]const u8 = null,
    laneId: u32,
    txIndex: u32, // Global TX index for deterministic ordering
};

// ── Lane Execution Context ──────────────────────────────────────────────

const LaneContext = struct {
    executor: *DAGExecutor,
    lane: *const dag_scheduler.ExecutionLane,
    overlay: *state_mod.Overlay,
    results: []TxResult,
    deltaQueue: *accounts.DeltaQueue,
    receiptQueue: *accounts.ReceiptQueue,
    laneId: u32,
    globalTxOffset: u32,
    totalBudgetUsed: u64,
};

/// A batch of lanes assigned to one thread — eliminates per-lane thread pool overhead.
const LaneGroup = struct {
    executor: *DAGExecutor,
    contexts: []const LaneContext,
};

// ── DAG Executor ────────────────────────────────────────────────────────

/// Unified executor for the DAG mempool's zero-conflict execution model.
/// Each lane runs in its own thread with its own Overlay, and zero coordination
/// is required between lanes during Phase 1.
pub const DAGExecutor = struct {
    allocator: std.mem.Allocator,
    config: ExecutorConfig,
    state: *state_mod.State,
    vmCallback: ?VMCallback,
    metadata_registry: ?*const accounts.MetadataRegistry,

    /// Per-block code cache: maps contract address → code bytes.
    /// Populated on first access within a block, reused for all TXs
    /// calling the same contract. Cleared between blocks.
    code_cache: std.AutoHashMap(types.Address, []const u8),
    code_cache_lock: std.Thread.Mutex = .{},

    /// Per-lane arena allocators — zero-syscall bump allocation during execution,
    /// bulk-reset after each block. Replaces per-allocation free overhead.
    lane_arenas: []std.heap.ArenaAllocator = &[_]std.heap.ArenaAllocator{},

    /// Tracks the previous block's state root for chaining with current delta.
    lastStateRoot: [32]u8 = [_]u8{0} ** 32,

    // Stats
    blocksExecuted: u64,
    txsExecuted: u64,
    transfersFastPath: u64,
    totalLanes: u64,

    /// Initializes a new DAGExecutor instance.
    pub fn init(
        allocator: std.mem.Allocator,
        state: *state_mod.State,
        config: ExecutorConfig,
    ) DAGExecutor {
        return .{
            .allocator = allocator,
            .config = config,
            .state = state,
            .vmCallback = null,
            .metadata_registry = null,
            .code_cache = std.AutoHashMap(types.Address, []const u8).init(allocator),
            .blocksExecuted = 0,
            .txsExecuted = 0,
            .transfersFastPath = 0,
            .totalLanes = 0,
        };
    }

    /// Registers the VM implementation callback.
    pub fn setVMCallback(self: *DAGExecutor, callback: VMCallback) void {
        self.vmCallback = callback;
    }

    pub fn setMetadataRegistry(self: *DAGExecutor, registry: *const accounts.MetadataRegistry) void {
        self.metadata_registry = registry;
    }

    /// Reset per-lane arena allocators — bulk-frees all execution memory
    /// allocated during the previous block. Call this AFTER the caller has
    /// finished reading BlockResult data (returnData, logs, etc.).
    pub fn resetLaneArenas(self: *DAGExecutor) void {
        for (self.lane_arenas) |*la| la.deinit();
        self.allocator.free(self.lane_arenas);
        self.lane_arenas = &[_]std.heap.ArenaAllocator{};
    }

    // ── Block Execution ─────────────────────────────────────────────────

    /// Execute a full block using the DAG execution plan.
    /// All lanes execute in parallel. Zero conflicts guaranteed by Phase 1.
    pub fn executeBlock(
        self: *DAGExecutor,
        plan: *dag_scheduler.ExecutionPlan,
    ) !BlockResult {
        // Clear per-block code cache (free previously cached code bytes)
        {
            var it = self.code_cache.iterator();
            while (it.next()) |entry| {
                self.state.allocator.free(entry.value_ptr.*);
            }
            self.code_cache.clearRetainingCapacity();
        }

        // Allocate result arrays
        const tx_results = try self.allocator.alloc(TxResult, plan.totalTxs);

        // Allocate per-lane overlays, delta queues, and receipt queues
        const num_lanes = plan.lanes.len;
        const overlays = try self.allocator.alloc(state_mod.Overlay, num_lanes);
        var initialized_overlays: usize = 0;
        defer {
            for (overlays[0..initialized_overlays]) |*overlay| {
                overlay.deinit();
            }
            self.allocator.free(overlays);
        }

        const delta_queues = try self.allocator.alloc(accounts.DeltaQueue, num_lanes);
        var initialized_deltas: usize = 0;
        defer {
            for (delta_queues[0..initialized_deltas]) |*dq| {
                dq.deinit();
            }
            self.allocator.free(delta_queues);
        }

        const receipt_queues = try self.allocator.alloc(accounts.ReceiptQueue, num_lanes);
        var initialized_receipts: usize = 0;
        defer {
            for (receipt_queues[0..initialized_receipts]) |*rq| {
                rq.deinit();
            }
            self.allocator.free(receipt_queues);
        }

        // Clean up previous block's arenas (if any)
        for (self.lane_arenas) |*la| la.deinit();
        self.allocator.free(self.lane_arenas);

        // Create per-lane ArenaAllocators — zero-syscall bump allocation
        self.lane_arenas = try self.allocator.alloc(std.heap.ArenaAllocator, num_lanes);
        for (0..num_lanes) |i| {
            self.lane_arenas[i] = std.heap.ArenaAllocator.init(self.allocator);
            overlays[i] = state_mod.Overlay.init(self.lane_arenas[i].allocator(), self.state);
            overlays[i].finalizeInit();
            initialized_overlays += 1;
            delta_queues[i] = accounts.DeltaQueue.init(self.allocator);
            initialized_deltas += 1;
            receipt_queues[i] = accounts.ReceiptQueue.init(self.allocator);
            initialized_receipts += 1;
        }

        // Compute global TX offsets for each lane (for deterministic ordering)
        const lane_offsets = try self.allocator.alloc(u32, plan.lanes.len);
        defer self.allocator.free(lane_offsets);
        var offset: u32 = 0;
        for (plan.lanes, 0..) |*lane, i| {
            lane_offsets[i] = offset;
            offset += @intCast(lane.txs.len);
        }

        // ── Phase 0.5: AOT Cache Pre-warming ───────────────────────────
        // Sequentially compile/load AOT shared libraries to prevent thread contention.
        if (self.vmCallback) |callback| {
            if (callback.prewarm_fn != null) {
                var unique_contracts = std.AutoHashMap(types.Address, void).init(self.allocator);
                defer unique_contracts.deinit();

                for (plan.lanes) |*lane| {
                    for (lane.txs) |*tx| {
                        if (tx.to) |to_addr| {
                            if (tx.data.len > 0) {
                                unique_contracts.put(to_addr, {}) catch {};
                            }
                        }
                    }
                }

                var it = unique_contracts.keyIterator();
                while (it.next()) |addr_ptr| {
                    const addr = addr_ptr.*;
                    const code_data = self.fetchCode(addr) catch &[_]u8{};
                    if (code_data.len > 0) {
                        callback.preWarm(code_data) catch {};
                    }
                }
            }
        }

        // ── Phase 1: Parallel Lane Execution ────────────────────────────

        const exec_start = std.time.nanoTimestamp();

        // Use thread pool for parallel execution — avoids per-thread spawn overhead
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = self.allocator, .n_jobs = self.config.numThreads });
        defer pool.deinit();

        var wg = std.Thread.WaitGroup{};

        // Group lanes into numThreads batches — reduces per-lane thread pool overhead
        const num_threads = @max(@as(u32, 1), self.config.numThreads);
        const contexts = try self.allocator.alloc(LaneContext, plan.lanes.len);
        defer self.allocator.free(contexts);

        for (plan.lanes, 0..) |*lane, i| {
            contexts[i] = LaneContext{
                .executor = self,
                .lane = lane,
                .overlay = &overlays[i],
                .results = tx_results[lane_offsets[i]..],
                .deltaQueue = &delta_queues[i],
                .receiptQueue = &receipt_queues[i],
                .laneId = @intCast(i),
                .globalTxOffset = lane_offsets[i],
                .totalBudgetUsed = 0,
            };
        }

        // Build lane groups — round-robin assignment to balance TX count
        const max_groups = @min(num_threads, @as(u32, @intCast(plan.lanes.len)));
        const groups = try self.allocator.alloc(LaneGroup, max_groups);
        defer self.allocator.free(groups);

        {
            var group_start: usize = 0;
            for (0..max_groups) |g| {
                const lanes_rem = plan.lanes.len - group_start;
                const groups_rem = max_groups - g;
                const chunk = lanes_rem / groups_rem + @intFromBool(lanes_rem % groups_rem != 0);
                const chunk_end = @min(group_start + chunk, plan.lanes.len);
                groups[g] = LaneGroup{
                    .executor = self,
                    .contexts = contexts[group_start..chunk_end],
                };
                group_start = chunk_end;
            }
        }

        for (groups) |*group| {
            pool.spawnWg(&wg, executeLaneGroup, .{group});
        }
        wg.wait();

        const exec_end = std.time.nanoTimestamp();

        // ── Phase 1.5: Cross-Lane Conflict Re-execution ─────────────────
        // Scans for read-write conflicts across lanes (same recipient balance,
        // shared storage). Conflicted lanes are re-executed sequentially against
        // the correct state. Expected rate: <1% of blocks.

        var had_conflicts = false;
        if (overlays.len > 1) {
            var conflicted = try self.allocator.alloc(bool, overlays.len);
            defer self.allocator.free(conflicted);
            @memset(conflicted, false);
            var conflict_count: u32 = 0;

            for (1..overlays.len) |b| {
                for (0..b) |a| {
                    if (overlays[b].hasReadConflictWith(&overlays[a])) {
                        conflicted[b] = true;
                        conflict_count += 1;
                        break;
                    }
                }
            }

            if (conflict_count > 0) {
                had_conflicts = true;
                for (0..overlays.len) |i| {
                    if (!conflicted[i]) overlays[i].commit() catch {};
                }
                for (0..overlays.len) |i| {
                    if (!conflicted[i]) continue;
                    // Reset the lane arena instead of individual overlay deinit
                    // — bulk-free all allocations from the previous execution.
                    self.lane_arenas[i].deinit();
                    self.lane_arenas[i] = std.heap.ArenaAllocator.init(self.allocator);
                    overlays[i] = state_mod.Overlay.init(self.lane_arenas[i].allocator(), self.state);
                    overlays[i].finalizeInit();
                    delta_queues[i].clear();
                    receipt_queues[i].clear();
                    self.executeLaneSequential(
                        &plan.lanes[i],
                        &overlays[i],
                        tx_results[lane_offsets[i]..lane_offsets[i] + plan.lanes[i].txs.len],
                        &delta_queues[i],
                        &receipt_queues[i],
                        @intCast(i),
                        lane_offsets[i],
                    );
                    overlays[i].commit() catch {};
                }
                log.info("Zelius-OPE: {} cross-lane conflict(s) re-executed\n", .{conflict_count});
            }
        }

        // ── Phase 2: Delta Merge (deterministic) ────────────────────────

        const merge_start = std.time.nanoTimestamp();

        // Merge accumulator deltas from all lanes
        var combined_deltas = accounts.DeltaQueue.init(self.allocator);
        defer combined_deltas.deinit();

        for (delta_queues) |*dq| {
            for (dq.items.items) |delta| {
                try combined_deltas.push(delta);
            }
        }

        // Apply merged deltas to state (deterministic — sorted by TX index)
        if (combined_deltas.count() > 0) {
            var merged = try combined_deltas.merge(self.allocator);
            defer merged.deinit();

            var merge_it = merged.iterator();
            while (merge_it.next()) |entry| {
                const key = entry.key_ptr.*;
                const delta = entry.value_ptr.*;
                if (delta != 0) {
                    // Read current value from state, apply delta
                    const current_data = self.state.db.read(&key);
                    var current: u256 = 0;
                    if (current_data) |d| {
                        if (d.len >= 32) {
                            current = std.mem.readInt(u256, d[0..32], .big);
                        }
                    }

                    const new_val: u256 = if (delta > 0)
                        current +% @as(u256, @intCast(delta))
                    else
                        current -% @as(u256, @intCast(-delta));

                    var buf: [32]u8 = undefined;
                    std.mem.writeInt(u256, &buf, new_val, .big);
                    try self.state.db.write(&key, &buf);
                }
            }
        }

        // Apply credit receipts (deterministically sorted by TX index)
        for (receipt_queues) |*rq| {
            rq.sort();
            for (rq.items.items) |receipt| {
                // CreditReceipt stores delta as [32]u8; interpret as u256
                const delta_val = std.mem.readInt(u256, &receipt.deltaValue, .big);
                if (receipt.isAddition) {
                    self.state.addBalance(receipt.recipient, @intCast(delta_val)) catch {};
                } else {
                    const neg: i256 = -@as(i256, @intCast(delta_val));
                    self.state.addBalance(receipt.recipient, neg) catch {};
                }
            }
        }

        // Commit all lane overlays to state.
        // Note: conflicting overlays were already committed in Phase 1.5
        // sequentially. Non-conflicting overlays were committed there too
        // when conflicts were present. Only commit here when no conflicts ran.
        if (!had_conflicts) {
            for (overlays) |*overlay| {
                overlay.commit() catch {};
            }
        }

        const merge_end = std.time.nanoTimestamp();

        // ── Phase 2.5: Block Rewards (applied through overlay → captured in StateDelta) ──

        var reward_overlay: ?state_mod.Overlay = null;
        if (self.config.blockReward.enabled and self.config.blockReward.base_reward > 0) {
            var ro = state_mod.Overlay.init(self.allocator, self.state);
            ro.finalizeInit();

            const current_balance = ro.getBalance(self.config.producer);
            ro.setBalance(self.config.producer, current_balance + self.config.blockReward.base_reward) catch {};
            reward_overlay = ro;
        }

        // ── Phase 3: State Root Computation (synchronous) ───────────────
        // Compute exact per-block state root from sorted delta chain.
        // No lag, no background thread — just a quick Blake3 hash.

        const commit_start = std.time.nanoTimestamp();

        const state_root: types.Hash = blk: {
            // Merge dirty entries from all lane overlays + reward overlay into a StateDelta.
            var total: usize = 0;
            for (overlays[0..initialized_overlays]) |*o| {
                total += o.dirty.count();
            }
            if (reward_overlay) |*ro| total += ro.dirty.count();

            if (total == 0) break :blk types.Hash{ .bytes = self.lastStateRoot };

            // Build delta from all dirty entries
            const keys = try self.allocator.alloc([32]u8, total);
            defer self.allocator.free(keys);
            const values = try self.allocator.alloc([]const u8, total);
            var idx: usize = 0;
            for (overlays[0..initialized_overlays]) |*o| {
                var it = o.dirty.iterator();
                while (it.next()) |entry| {
                    keys[idx] = entry.key_ptr.*;
                    values[idx] = try self.allocator.dupe(u8, entry.value_ptr.*);
                    idx += 1;
                }
            }
            if (reward_overlay) |*ro| {
                var it = ro.dirty.iterator();
                while (it.next()) |entry| {
                    keys[idx] = entry.key_ptr.*;
                    values[idx] = try self.allocator.dupe(u8, entry.value_ptr.*);
                    idx += 1;
                }
            }

            // Compute root synchronously
            var delta = state_root_mod.StateDelta{
                .keys = keys,
                .values = values,
                .count = total,
            };
            const result_bytes = state_root_mod.sorted_delta.compute(self.allocator, &delta, self.lastStateRoot) catch self.lastStateRoot;

            // Free duped values (delta no longer needed)
            for (values) |v| self.allocator.free(v);
            self.allocator.free(values);

            break :blk types.Hash{ .bytes = result_bytes };
        };

        // Commit reward overlay to base state (after StateDelta capture)
        if (reward_overlay) |*ro| {
            ro.commit() catch {};
            ro.deinit();
        }

        const commit_end = std.time.nanoTimestamp();

        // ── Firewall 3: Verify stateRoot transitions when TXs execute ──
        if (plan.totalTxs > 0 and std.mem.eql(u8, &state_root.bytes, &self.lastStateRoot)) {
            return error.StateRootNotAdvanced;
        }
        // Commit new state root AFTER firewall check
        self.lastStateRoot = state_root.bytes;

        // Compute total budget used
        var total_budget: u64 = 0;
        for (tx_results) |*r| {
            total_budget += r.budgetUsed;
        }

        // ── Firewall 4: Verify budget used does not exceed block budget limit ──
        if (total_budget > self.config.blockExecutionBudget) {
            return error.BudgetExceedsBlockBudget;
        }

        // Update stats
        self.blocksExecuted += 1;
        self.txsExecuted += plan.totalTxs;
        self.totalLanes += @intCast(plan.lanes.len);

        return BlockResult{
            .stateRoot = state_root,
            .budgetUsed = total_budget,
            .txCount = plan.totalTxs,
            .txResults = tx_results,
            .laneCount = @intCast(plan.lanes.len),
            .executionTimeNs = exec_end - exec_start,
            .mergeTimeNs = merge_end - merge_start,
            .commitTimeNs = commit_end - commit_start,
            .receiptsRoot = types.Hash.zero(),
        };
    }

    // ── Lane Execution (Thread Entry Point) ─────────────────────────────

    fn executeLaneGroup(group: *LaneGroup) void {
        for (group.contexts) |*ctx| {
            ctx.executor.executeLaneSequential(
                ctx.lane,
                ctx.overlay,
                ctx.results,
                ctx.deltaQueue,
                ctx.receiptQueue,
                ctx.laneId,
                ctx.globalTxOffset,
            );
        }
    }

    fn executeLaneSequential(
        self: *DAGExecutor,
        lane: *const dag_scheduler.ExecutionLane,
        overlay: *state_mod.Overlay,
        results: []TxResult,
        delta_queue: *accounts.DeltaQueue,
        receipt_queue: *accounts.ReceiptQueue,
        lane_id: u32,
        global_offset: u32,
    ) void {
        for (lane.txs, 0..) |*tx, i| {
            const tx_idx = global_offset + @as(u32, @intCast(i));
            const result = self.executeSingleTx(overlay, tx.*, delta_queue, receipt_queue, tx_idx);
            results[i] = TxResult{
                .success = result.success,
                .budgetUsed = result.budgetUsed,
                .fee = result.fee,
                .txHash = tx.id(),
                .errorMessage = result.errorMessage,
                .laneId = lane_id,
                .txIndex = global_offset + @as(u32, @intCast(i)),
            };
        }
    }

    // ── Single TX Execution ─────────────────────────────────────────────

    fn executeSingleTx(
        self: *DAGExecutor,
        overlay: *state_mod.Overlay,
        tx: types.Transaction,
        delta_queue: ?*accounts.DeltaQueue,
        receipt_queue: ?*accounts.ReceiptQueue,
        tx_idx: u32,
    ) TxResult {
        // 1. Verify sequence
        const current_sequence = overlay.getSequence(tx.from);
        if (tx.sequence != current_sequence) {
            return TxResult{
                .success = false,
                .budgetUsed = 0,
                .fee = 0,
                .txHash = tx.id(),
                .errorMessage = "sequence mismatch",
                .laneId = 0,
                .txIndex = 0,
            };
        }

        // 1.5 Ensure sender EOA type discriminator exists (for new accounts)
        overlay.ensureSenderEOA(tx.from) catch {};

        // 2. Compute intrinsic budget
        const intrinsic: u64 = computeIntrinsicBudget(&tx);
        if (intrinsic > tx.executionBudget) {
            return TxResult{
                .success = false,
                .budgetUsed = intrinsic,
                .fee = 0,
                .txHash = tx.id(),
                .errorMessage = "intrinsic budget exceeds limit",
                .laneId = 0,
                .txIndex = 0,
            };
        }

        // 3. Check balance for budget + value
        const sender_balance = overlay.getBalance(tx.from);
        const max_fee = @as(u256, tx.executionBudget) * tx.computePrice;
        const total_cost = tx.value + max_fee;
        if (total_cost > sender_balance) {
            return TxResult{
                .success = false,
                .budgetUsed = 0,
                .fee = 0,
                .txHash = tx.id(),
                .errorMessage = "insufficient balance",
                .laneId = 0,
                .txIndex = 0,
            };
        }

        // 4. Deduct max budget and increment sequence
        overlay.setBalance(tx.from, sender_balance - max_fee) catch
            return TxResult{ .success = false, .budgetUsed = 0, .fee = 0, .txHash = tx.id(), .errorMessage = "state error", .laneId = 0, .txIndex = 0 };
        overlay.setSequence(tx.from, current_sequence + 1) catch
            return TxResult{ .success = false, .budgetUsed = 0, .fee = 0, .txHash = tx.id(), .errorMessage = "state error", .laneId = 0, .txIndex = 0 };

        // 5. Execute
        var budget_used: u64 = intrinsic;
        var success = true;

        // 5a. Resolve target account type and validate
        if (tx.to) |to_addr| {
            const resolution = accounts.resolver.resolve(&self.state.db, to_addr);

            // Transfer value — any address type can receive value
            if (tx.value > 0) {
                overlay.addBalance(to_addr, @intCast(tx.value)) catch {
                    success = false;
                };
            }

            // Contract call (if data present)
            if (tx.data.len > 0 and self.vmCallback != null) {
                // Type check: only ContractRoot and System accounts are callable
                if (resolution.exists and resolution.account_type != .ContractRoot and resolution.account_type != .System) {
                    return TxResult{
                        .success = false,
                        .budgetUsed = 0,
                        .fee = 0,
                        .txHash = tx.id(),
                        .errorMessage = "target not callable",
                        .laneId = 0,
                        .txIndex = 0,
                    };
                }

                const code_data = self.fetchCode(to_addr) catch &[_]u8{};
                if (code_data.len > 0) {
                    const remaining_budget = tx.executionBudget - intrinsic;
                    const vm_result = self.vmCallback.?.execute(
                        code_data,
                        tx.data,
                        remaining_budget,
                        overlay,
                        tx.from,
                        to_addr,
                        tx.value,
                        delta_queue,
                        receipt_queue,
                        tx_idx,
                    );
                    budget_used += vm_result.budgetUsed;
                    success = vm_result.success;
                }
            } else if (tx.data.len == 0 and self.config.transferFastPath) {
                // Simple transfer — fast path complete, no VM needed
                _ = @atomicRmw(u64, &self.transfersFastPath, .Add, 1, .monotonic);
            }
        } else {
            // Contract creation
            const new_addr = tx.deriveContractAddress();
            overlay.markCreated(new_addr, .ContractRoot) catch {};

            if (tx.value > 0) {
                overlay.addBalance(new_addr, @intCast(tx.value)) catch {
                    success = false;
                };
            }

            if (self.vmCallback != null and tx.data.len > 0) {
                const remaining_budget = tx.executionBudget - intrinsic;
                const vm_result = self.vmCallback.?.execute(
                    tx.data,
                    &[_]u8{},
                    remaining_budget,
                    overlay,
                    tx.from,
                    new_addr,
                    tx.value,
                    delta_queue,
                    receipt_queue,
                    tx_idx,
                );
                budget_used += vm_result.budgetUsed;
                success = vm_result.success;

                if (success) {
                    const code_to_store = if (std.mem.startsWith(u8, tx.data, "\x7fELF") or std.mem.startsWith(u8, tx.data, "FORG")) tx.data else vm_result.returnData;
                    if (code_to_store.len > 0) {
                        overlay.setCode(new_addr, code_to_store) catch {
                            success = false;
                        };
                    }
                }
            }
        }

        // 6. Refund unused budget (EIP-3529 refunds are removed, only refund unused limit)
        const actual_fee = tx.computePrice * @as(u256, budget_used);
        const refund_amount = max_fee - actual_fee;
        if (refund_amount > 0) {
            overlay.addBalance(tx.from, @intCast(refund_amount)) catch {};
        }

        // 7. Pay fee to producer

        if (actual_fee > 0) {
            overlay.addBalance(self.config.producer, @intCast(actual_fee)) catch {};
        }

        return TxResult{
            .success = success,
            .budgetUsed = budget_used,
            .fee = actual_fee,
            .txHash = tx.id(),
            .errorMessage = if (success) null else "execution failed",
            .laneId = 0,
            .txIndex = 0,
        };
    }

    /// Fetch contract code, using per-block cache to avoid redundant state reads.
    /// Returns cached bytes (no allocation or deallocation needed by caller).
    fn fetchCode(self: *DAGExecutor, addr: types.Address) ![]const u8 {
        // Fast path — check cache under lock
        self.code_cache_lock.lock();
        if (self.code_cache.get(addr)) |cached| {
            self.code_cache_lock.unlock();
            return cached;
        }
        self.code_cache_lock.unlock();

        // Miss — fetch from state (outside lock)
        const code = try self.state.getCode(addr);
        if (code.len == 0) return code;

        // Store in cache (re-lock, re-check to avoid double insert)
        self.code_cache_lock.lock();
        defer self.code_cache_lock.unlock();

        const g = try self.code_cache.getOrPut(addr);
        if (g.found_existing) {
            self.state.allocator.free(code);
            return g.value_ptr.*;
        } else {
            g.value_ptr.* = code;
            return code;
        }
    }

    /// Get performance statistics.
    /// Returns performance statistics for the executor.
    pub fn getStats(self: *const DAGExecutor) DAGExecutorStats {
        return .{
            .blocksExecuted = self.blocksExecuted,
            .txsExecuted = self.txsExecuted,
            .transfersFastPath = self.transfersFastPath,
            .totalLanes = self.totalLanes,
        };
    }
};

fn computeIntrinsicBudget(tx: *const types.Transaction) u64 {
    var budget: u64 = 1_000;

    if (tx.to == null) budget += 5_000;

    for (tx.data) |byte| {
        budget += if (byte == 0) 1 else 2;
    }

    return budget;
}

// ── Stats ───────────────────────────────────────────────────────────────

/// Performance statistics for the DAGExecutor.
pub const DAGExecutorStats = struct {
    blocksExecuted: u64,
    txsExecuted: u64,
    transfersFastPath: u64,
    totalLanes: u64,
};
