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
//
// Also supports legacy mode using the old tx_pool + executor for
// backward compatibility during migration.

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const executor_mod = @import("executor.zig");
const blockchain_mod = @import("blockchain.zig");
const tx_pool_mod = @import("tx_pool.zig");
const dag_mempool_mod = @import("dag_mempool.zig");
const dag_scheduler_mod = @import("dag_scheduler.zig");
const dag_executor_mod = @import("dag_executor.zig");
const async_root_mod = @import("async_state_root.zig");
const log = @import("logger.zig");

pub const BuildResult = struct {
    block: *types.Block,
    gas_used: u64,
    tx_count: u32,
    elapsed_ns: u64,
    tps: u64,
    lane_count: u32,
    dag_root: types.Hash,
};

pub const BlockProducer = struct {
    allocator: std.mem.Allocator,
    chain: *blockchain_mod.Blockchain,
    world_state: *state_mod.State,
    coinbase: types.Address,
    gas_limit: u64,

    // DAG-based pipeline (primary)
    dag_pool: ?*dag_mempool_mod.DAGMempool,
    dag_executor: ?*dag_executor_mod.DAGExecutor,

    // Async state root computer (production path)
    async_root_computer: ?*async_root_mod.AsyncStateRootComputer,

    // Legacy pipeline (backward compatibility)
    legacy_pool: ?*tx_pool_mod.TxPool,
    legacy_executor: ?*executor_mod.Executor,

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *blockchain_mod.Blockchain,
        world_state: *state_mod.State,
        coinbase: types.Address,
        gas_limit: u64,
    ) BlockProducer {
        return BlockProducer{
            .allocator = allocator,
            .chain = chain,
            .world_state = world_state,
            .coinbase = coinbase,
            .gas_limit = gas_limit,
            .dag_pool = null,
            .dag_executor = null,
            .async_root_computer = null,
            .legacy_pool = null,
            .legacy_executor = null,
        };
    }

    /// Configure for DAG-based execution (primary path).
    pub fn setDAGPipeline(
        self: *BlockProducer,
        pool: *dag_mempool_mod.DAGMempool,
        executor: *dag_executor_mod.DAGExecutor,
    ) void {
        self.dag_pool = pool;
        self.dag_executor = executor;
    }

    /// Configure for legacy execution (backward compat).
    pub fn setLegacyPipeline(
        self: *BlockProducer,
        pool: *tx_pool_mod.TxPool,
        executor: *executor_mod.Executor,
    ) void {
        self.legacy_pool = pool;
        self.legacy_executor = executor;
    }

    /// Configure async state root computation (production path).
    /// When set, block headers use 2-block-lagged state roots and
    /// trie commitment runs on a dedicated background thread.
    pub fn setAsyncRoot(self: *BlockProducer, computer: *async_root_mod.AsyncStateRootComputer) void {
        self.async_root_computer = computer;
        // Also wire it into the DAG executor
        if (self.dag_executor) |executor| {
            executor.setAsyncRoot(computer);
        }
    }

    /// Produce a new block from pending transactions.
    /// Strictly uses DAG pipeline if configured, otherwise legacy.
    pub fn produce(self: *BlockProducer) !BuildResult {
        if (self.dag_pool != null and self.dag_executor != null) {
            return self.produceDAG();
        }
        return self.produceLegacy();
    }

    // ── DAG-Based Production ────────────────────────────────────────────

    fn produceDAG(self: *BlockProducer) !BuildResult {
        const start = std.time.nanoTimestamp();

        var pool = self.dag_pool.?;
        var executor = self.dag_executor.?;

        // 1. Extract independent lanes from DAG mempool
        var extraction = try pool.extract(self.allocator, self.gas_limit);
        defer extraction.deinit();

        // 2. Schedule lanes with gas-balanced thread assignment
        const parent = self.chain.get_head();
        const parent_hash = if (parent) |p| p.hash() else types.Hash.zero();
        const base_fee: u256 = if (parent) |p|
            blockchain_mod.Blockchain.calc_base_fee(&p.header)
        else
            0;

        executor.config.coinbase = self.coinbase;
        executor.config.block_gas_limit = self.gas_limit;
        executor.config.base_fee = base_fee;

        var plan = try dag_scheduler_mod.schedule(
            self.allocator,
            &extraction,
            .{
                .num_threads = executor.config.num_threads,
                .block_gas_limit = self.gas_limit,
                .coinbase = self.coinbase,
                .base_fee = base_fee,
            },
        );
        defer plan.deinit();

        // 3. Compute DAG root for block header
        const dag_root = dag_scheduler_mod.computeDAGRoot(&plan);

        // 4. Execute all lanes in parallel
        var block_result = try executor.executeBlock(&plan);
        defer block_result.deinit(self.allocator);

        // 5. Collect all TXs for block assembly
        var all_txs = std.ArrayListUnmanaged(types.Transaction){};
        defer all_txs.deinit(self.allocator);

        for (plan.lanes) |*lane| {
            for (lane.txs) |tx| {
                try all_txs.append(self.allocator, tx);
            }
        }

        // 6. Assemble block
        const parent_number = if (parent) |p| p.header.number else 0;

        const txs = try self.allocator.alloc(types.Transaction, all_txs.items.len);
        @memcpy(txs, all_txs.items);

        const block = try self.allocator.create(types.Block);
        block.* = types.Block{
            .header = types.Header{
                .parent_hash = parent_hash,
                .number = parent_number + 1,
                .time = @intCast(std.time.timestamp()),
                .verkle_root = block_result.state_root,
                .tx_hash = computeTxRoot(txs),
                .coinbase = self.coinbase,
                .extra_data = &[_]u8{},
                .gas_limit = self.gas_limit,
                .gas_used = block_result.gas_used,
                .base_fee = base_fee,
            },
            .transactions = txs,
        };

        // 7. Remove committed TXs from pool
        pool.removeCommitted(all_txs.items);

        const end = std.time.nanoTimestamp();
        const elapsed_ns: u64 = @intCast(end - start);
        const tps = if (elapsed_ns > 0) @as(u64, all_txs.items.len) * 1_000_000_000 / elapsed_ns else 0;

        log.info("Block #{d} produced (DAG): {d} TXs, {d} lanes, {d} gas, {d} TPS", .{
            block.header.number,
            txs.len,
            plan.lanes.len,
            block_result.gas_used,
            tps,
        });

        return BuildResult{
            .block = block,
            .gas_used = block_result.gas_used,
            .tx_count = @intCast(txs.len),
            .elapsed_ns = elapsed_ns,
            .tps = tps,
            .lane_count = @intCast(plan.lanes.len),
            .dag_root = dag_root,
        };
    }

    // ── Legacy Production (Backward Compatibility) ──────────────────────

    fn produceLegacy(self: *BlockProducer) !BuildResult {
        const start = std.time.nanoTimestamp();

        var pool = self.legacy_pool orelse return error.NoPipelineConfigured;
        var executor = self.legacy_executor orelse return error.NoPipelineConfigured;

        // 1. Select transactions
        const pending_txs = try pool.pending(self.allocator);
        defer self.allocator.free(pending_txs);

        // 2. Filter by gas budget
        var selected = std.ArrayListUnmanaged(types.Transaction){};
        defer selected.deinit(self.allocator);

        var gas_budget = self.gas_limit;
        for (pending_txs) |tx| {
            if (tx.gas_limit <= gas_budget) {
                try selected.append(self.allocator, tx);
                gas_budget -= tx.gas_limit;
            }
        }

        // 3. Execute (wavefronts + parallel)
        executor.config.coinbase = self.coinbase;
        executor.config.block_gas_limit = self.gas_limit;

        const parent = self.chain.get_head();
        const parent_hash = if (parent) |p| p.hash() else types.Hash.zero();
        if (parent) |p| {
            executor.config.base_fee = blockchain_mod.Blockchain.calc_base_fee(&p.header);
        }

        var block_result = try executor.apply_block(
            self.world_state,
            selected.items,
        );
        defer block_result.deinit(self.allocator);

        // 4. Assemble block
        const parent_number = if (parent) |p| p.header.number else 0;

        const txs = try self.allocator.alloc(types.Transaction, selected.items.len);
        @memcpy(txs, selected.items);

        const block = try self.allocator.create(types.Block);
        block.* = types.Block{
            .header = types.Header{
                .parent_hash = parent_hash,
                .number = parent_number + 1,
                .time = @intCast(std.time.timestamp()),
                .verkle_root = block_result.state_root,
                .tx_hash = computeTxRoot(txs),
                .coinbase = self.coinbase,
                .extra_data = &[_]u8{},
                .gas_limit = self.gas_limit,
                .gas_used = block_result.gas_used,
                .base_fee = executor.config.base_fee,
            },
            .transactions = txs,
        };

        // 5. Remove executed from pool
        pool.remove_executed(selected.items);

        const end = std.time.nanoTimestamp();
        const elapsed_ns: u64 = @intCast(end - start);
        const tps = if (elapsed_ns > 0) @as(u64, selected.items.len) * 1_000_000_000 / elapsed_ns else 0;

        log.info("Block #{d} produced (legacy): {d} TXs, {d} gas, {d} TPS", .{
            block.header.number,
            txs.len,
            block_result.gas_used,
            tps,
        });

        return BuildResult{
            .block = block,
            .gas_used = block_result.gas_used,
            .tx_count = @intCast(txs.len),
            .elapsed_ns = elapsed_ns,
            .tps = tps,
            .lane_count = 0,
            .dag_root = types.Hash.zero(),
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
