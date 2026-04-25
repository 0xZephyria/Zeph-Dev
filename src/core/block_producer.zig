// ============================================================================
// Zephyria — Block Producer (DAG-Based)
// ============================================================================
//
// Block production pipeline using DAG mempool + DAG executor:
//   1. Extract independent execution lanes from DAG mempool
//   2. Schedule lanes with gas-balanced thread assignment
//   3. Execute all lanes in parallel (zero conflicts)
//   4. Merge accumulator deltas for global state
//   5. Compute state root via Verkle batch commit
//   6. Assemble block header with computed roots

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const blockchain_mod = @import("blockchain.zig");
const dag_mempool_mod = @import("dag_mempool.zig");
const dag_scheduler_mod = @import("dag_scheduler.zig");
const dag_executor_mod = @import("dag_executor.zig");
const async_root_mod = @import("async_state_root.zig");
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
    coinbase: types.Address,
    gasLimit: u64,

    // DAG-based pipeline (primary)
    dagPool: ?*dag_mempool_mod.DAGMempool,
    dagExecutor: ?*dag_executor_mod.DAGExecutor,

    // Async state root computer (production path)
    asyncRootComputer: ?*async_root_mod.AsyncStateRootComputer,

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *blockchain_mod.Blockchain,
        worldState: *state_mod.State,
        coinbase: types.Address,
        gasLimit: u64,
    ) BlockProducer {
        return BlockProducer{
            .allocator = allocator,
            .chain = chain,
            .worldState = worldState,
            .coinbase = coinbase,
            .gasLimit = gasLimit,
            .dagPool = null,
            .dagExecutor = null,
            .asyncRootComputer = null,
        };
    }

    /// Configure for DAG-based execution (primary path).
    pub fn setDAGPipeline(
        self: *BlockProducer,
        pool: *dag_mempool_mod.DAGMempool,
        executor: *dag_executor_mod.DAGExecutor,
    ) void {
        self.dagPool = pool;
        self.dagExecutor = executor;
    }

    /// Configure async state root computation (production path).
    /// When set, block headers use 2-block-lagged state roots and
    /// trie commitment runs on a dedicated background thread.
    pub fn setAsyncRoot(self: *BlockProducer, computer: *async_root_mod.AsyncStateRootComputer) void {
        self.asyncRootComputer = computer;
        // Also wire it into the DAG executor
        if (self.dagExecutor) |executor| {
            executor.setAsyncRoot(computer);
        }
    }

    /// Produce a new block from pending transactions.
    pub fn produce(self: *BlockProducer) !BuildResult {
        const start = std.time.nanoTimestamp();

        var pool = self.dagPool orelse return error.NoPipelineConfigured;
        var executor = self.dagExecutor orelse return error.NoPipelineConfigured;

        // 1. Extract independent lanes from DAG mempool
        var extraction = try pool.extract(self.allocator, self.gasLimit);
        defer extraction.deinit();

        // 2. Schedule lanes with gas-balanced thread assignment
        const parent = self.chain.getHead();
        const parentHash = if (parent) |p| p.hash() else types.Hash.zero();
        const baseFee: u256 = if (parent) |p|
            blockchain_mod.Blockchain.calcBaseFee(&p.header)
        else
            0;

        executor.config.coinbase = self.coinbase;
        executor.config.blockGasLimit = self.gasLimit;
        executor.config.baseFee = baseFee;

        var plan = try dag_scheduler_mod.schedule(
            self.allocator,
            &extraction,
            .{
                .numThreads = executor.config.numThreads,
                .blockGasLimit = self.gasLimit,
                .coinbase = self.coinbase,
                .baseFee = baseFee,
            },
        );
        defer plan.deinit();

        // 3. Compute DAG root for block header
        const dagRoot = dag_scheduler_mod.computeDAGRoot(&plan);

        // 4. Execute all lanes in parallel
        var blockResult = try executor.executeBlock(&plan);
        defer blockResult.deinit(self.allocator);

        // 5. Collect all TXs for block assembly
        var all_txs = std.ArrayListUnmanaged(types.Transaction){};
        defer all_txs.deinit(self.allocator);

        for (plan.lanes) |*lane| {
            for (lane.txs) |tx| {
                try all_txs.append(self.allocator, tx);
            }
        }

        // 6. Assemble block
        const parentNumber = if (parent) |p| p.header.number else 0;

        const txs = try self.allocator.alloc(types.Transaction, all_txs.items.len);
        @memcpy(txs, all_txs.items);

        const block = try self.allocator.create(types.Block);
        block.* = types.Block{
            .header = types.Header{
                .parentHash = parentHash,
                .number = parentNumber + 1,
                .time = @intCast(std.time.timestamp()),
                .verkleRoot = blockResult.stateRoot,
                .txHash = computeTxRoot(txs),
                .coinbase = self.coinbase,
                .extraData = &[_]u8{},
                .gasLimit = self.gasLimit,
                .gasUsed = blockResult.gasUsed,
                .baseFee = baseFee,
            },
            .transactions = txs,
        };

        // 7. Remove committed TXs from pool
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
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    for (txs) |*tx| {
        const tx_hash = tx.hash();
        hasher.update(&tx_hash.bytes);
    }
    var root: types.Hash = undefined;
    hasher.final(&root.bytes);
    return root;
}
