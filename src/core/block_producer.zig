// ============================================================================
// Zephyria — Block Producer
// ============================================================================
//
// Unified block production interface (DAG primary path).
//
// Hash contract:
//   - parentId stored in header.parentId = parent.id()  (Block.id())
//   - txMerkleRoot = Block.computeTxMerkleRoot(txs)
//   - Block.id() is computed ONCE after all header fields are set
//   - Nothing modifies the header after production (no wovenRoot overwrite)

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const blockchain_mod = @import("blockchain.zig");
const dag_mempool_mod = @import("dag_mempool.zig");
const dag_scheduler_mod = @import("dag_scheduler.zig");
const dag_executor_mod = @import("dag_executor.zig");
const log = @import("logger.zig");

pub const BuildResult = struct {
    block: *types.Block,
    budgetUsed: u64,
    txCount: u32,
    elapsedNs: u64,
    tps: u64,
    laneCount: u32,
    dagRoot: types.Hash,
};

pub const BlockProducer = struct {
    allocator: std.mem.Allocator,
    chain: *blockchain_mod.Blockchain,
    worldState: *state_mod.State,
    producer: types.Address,
    executionBudget: u64,

    dagPool: ?*dag_mempool_mod.DAGMempool,
    dagExecutor: ?*dag_executor_mod.DAGExecutor,

    // Pre-allocated buffer for block production hot path (16 MB).
    // Reset at the start of each produce() call to avoid heap reallocations.
    block_buf: [16 * 1024 * 1024]u8,
    block_fba: std.heap.FixedBufferAllocator,

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *blockchain_mod.Blockchain,
        worldState: *state_mod.State,
        producer: types.Address,
        executionBudget: u64,
    ) BlockProducer {
        var bp = BlockProducer{
            .allocator = allocator,
            .chain = chain,
            .worldState = worldState,
            .producer = producer,
            .executionBudget = executionBudget,
            .dagPool = null,
            .dagExecutor = null,
            .block_buf = undefined,
            .block_fba = undefined,
        };
        bp.block_fba = std.heap.FixedBufferAllocator.init(&bp.block_buf);
        return bp;
    }

    pub fn setDAGPipeline(
        self: *BlockProducer,
        pool: *dag_mempool_mod.DAGMempool,
        executor: *dag_executor_mod.DAGExecutor,
    ) void {
        self.dagPool = pool;
        self.dagExecutor = executor;
    }

    pub fn produce(self: *BlockProducer) !BuildResult {
        // Reset the fixed-buffer arena for this block's transient allocations.
        // This avoids heap reallocations on every ArrayList append in the hot path.
        self.block_fba = std.heap.FixedBufferAllocator.init(&self.block_buf);
        const hot_alloc = self.block_fba.allocator();

        const start = std.time.nanoTimestamp();

        var pool = self.dagPool orelse return error.NoPipelineConfigured;
        var executor = self.dagExecutor orelse return error.NoPipelineConfigured;

        var extraction = try pool.extract(self.allocator, self.executionBudget);
        defer extraction.deinit();

        // Get parent block and compute parent id using the canonical Block.id()
        const parent = self.chain.getHead();
        const parentId: types.Hash = if (parent) |p| p.id() else types.Hash.zero();

        executor.config.producer = self.producer;
        executor.config.blockExecutionBudget = self.executionBudget;
        if (parent) |p| {
            executor.lastStateRoot = p.header.stateRoot.bytes;
        }

        var plan = try dag_scheduler_mod.schedule(
            self.allocator,
            &extraction,
            .{
                .numThreads = executor.config.numThreads,
                .blockExecutionBudget = self.executionBudget,
                .producer = self.producer,
            },
        );
        defer plan.deinit();

        const dagRoot = dag_scheduler_mod.computeDAGRoot(&plan);

        var blockResult = try executor.executeBlock(&plan);
        defer blockResult.deinit(self.allocator);

        // Pre-compute total tx count to allocate ArrayList with exact capacity.
        var total_tx_count: usize = 0;
        for (plan.lanes) |*lane| {
            total_tx_count += lane.txs.len;
        }

        var all_txs = try std.ArrayListUnmanaged(types.Transaction).initCapacity(hot_alloc, total_tx_count);
        // No defer deinit — allocations are from block_fba which is reset at each produce() call.

        for (plan.lanes) |*lane| {
            for (lane.txs) |tx| {
                all_txs.appendAssumeCapacity(tx);
            }
        }

        const parentNumber = if (parent) |p| p.header.number else 0;

        const txs = try self.allocator.alloc(types.Transaction, all_txs.items.len);
        @memcpy(txs, all_txs.items);

        // Compute TX merkle root from all transactions in this block.
        // This is the canonical txMerkleRoot that goes into the header
        // and is included in Block.id(). It must NOT be overwritten later.
        const txMerkleRoot = types.Block.computeTxMerkleRoot(txs);

        const parentTime = if (parent) |p| p.header.time else 0;
        const now = @as(u64, @intCast(std.time.timestamp()));
        const blockTime = @max(now, parentTime + 1);

        const block = try self.allocator.create(types.Block);
        block.* = types.Block{
            .header = types.Header{
                // parentId uses Block.id() — the single canonical identifier
                .parentId = parentId,
                .number = parentNumber + 1,
                .time = blockTime,
                .stateRoot = blockResult.stateRoot,
                // txMerkleRoot is set once here and never modified again
                .txMerkleRoot = txMerkleRoot,
                .producer = self.producer,
                .extraData = &[_]u8{},
                .executionBudget = self.executionBudget,
                .budgetUsed = blockResult.budgetUsed,
            },
            .transactions = txs,
        };

        pool.removeCommitted(all_txs.items);

        const end = std.time.nanoTimestamp();
        const elapsedNs: u64 = @intCast(end - start);
        const tps = if (elapsedNs > 0)
            @as(u64, all_txs.items.len) * 1_000_000_000 / elapsedNs
        else
            0;

        log.info("Block #{d} produced: {d} TXs, {d} lanes, {d} budget, {d} TPS", .{
            block.header.number,
            txs.len,
            plan.lanes.len,
            blockResult.budgetUsed,
            tps,
        });

        return BuildResult{
            .block = block,
            .budgetUsed = blockResult.budgetUsed,
            .txCount = @intCast(txs.len),
            .elapsedNs = elapsedNs,
            .tps = tps,
            .laneCount = @intCast(plan.lanes.len),
            .dagRoot = dagRoot,
        };
    }
};
