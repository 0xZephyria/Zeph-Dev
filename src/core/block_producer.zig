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
    gasUsed: u64,
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

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *blockchain_mod.Blockchain,
        worldState: *state_mod.State,
        producer: types.Address,
        executionBudget: u64,
    ) BlockProducer {
        return BlockProducer{
            .allocator = allocator,
            .chain = chain,
            .worldState = worldState,
            .producer = producer,
            .executionBudget = executionBudget,
            .dagPool = null,
            .dagExecutor = null,
        };
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
        const start = std.time.nanoTimestamp();

        var pool = self.dagPool orelse return error.NoPipelineConfigured;
        var executor = self.dagExecutor orelse return error.NoPipelineConfigured;

        var extraction = try pool.extract(self.allocator, self.executionBudget);
        defer extraction.deinit();

        const parent = self.chain.getHead();
        const parentHash = if (parent) |p| p.hash() else types.Hash.zero();

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

        var all_txs = std.ArrayListUnmanaged(types.Transaction){};
        defer all_txs.deinit(self.allocator);

        for (plan.lanes) |*lane| {
            for (lane.txs) |tx| {
                try all_txs.append(self.allocator, tx);
            }
        }

        const parentNumber = if (parent) |p| p.header.number else 0;

        const txs = try self.allocator.alloc(types.Transaction, all_txs.items.len);
        @memcpy(txs, all_txs.items);

        const parentTime = if (parent) |p| p.header.time else 0;
        const now = @as(u64, @intCast(std.time.timestamp()));
        const blockTime = @max(now, parentTime + 1);

        const block = try self.allocator.create(types.Block);
        block.* = types.Block{
            .header = types.Header{
                .parentHash = parentHash,
                .number = parentNumber + 1,
                .time = blockTime,
                .stateRoot = blockResult.stateRoot,
                .txHash = computeTxRoot(txs),
                .producer = self.producer,
                .extraData = &[_]u8{},
                .executionBudget = self.executionBudget,
                .gasUsed = blockResult.gasUsed,
            },
            .transactions = txs,
        };

        pool.removeCommitted(all_txs.items);

        const end = std.time.nanoTimestamp();
        const elapsedNs: u64 = @intCast(end - start);
        const tps = if (elapsedNs > 0) @as(u64, all_txs.items.len) * 1_000_000_000 / elapsedNs else 0;

        log.info("Block #{d} produced: {d} TXs, {d} lanes, {d} gas, {d} TPS", .{
            block.header.number,
            txs.len,
            plan.lanes.len,
            blockResult.gasUsed,
            tps,
        });

        return BuildResult{
            .block = block,
            .gasUsed = blockResult.gasUsed,
            .txCount = @intCast(txs.len),
            .elapsedNs = elapsedNs,
            .tps = tps,
            .laneCount = @intCast(plan.lanes.len),
            .dagRoot = dagRoot,
        };
    }
};

fn computeTxRoot(txs: []const types.Transaction) types.Hash {
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (txs) |*tx| {
        const tx_hash = tx.hash();
        hasher.update(&tx_hash.bytes);
    }
    var root: types.Hash = undefined;
    hasher.final(&root.bytes);
    return root;
}
