// ============================================================================
// Zephyria — Block Producer (Miner) — Loom Genesis Adaptive
// ============================================================================
//
// Production-grade block production pipeline with adaptive consensus:
//   • DAG mempool → scheduler → parallel executor (primary path)
//   • Legacy tx_pool → executor fallback (backward compat)
//   • BlockProducer unifies both paths — miner just orchestrates
//   • Thread-partitioned woven root computation
//   • VRF-based proposer eligibility (replaces round-robin)
//   • Adaptive tier/thread parameters at epoch boundaries
//   • Pipeline integration with thread root submission
//   • Thread attestation pool integration
//   • Proper ordering: produce → rewards → seal → verify → add → broadcast

const std = @import("std");
const core = @import("core");
const types = core.types;
const consensus = @import("consensus");
const zelius = consensus.zelius;
const blockchain_mod = core.blockchain;
const tx_pool_mod = core.tx_pool;
const executor_mod = core.executor;
const block_producer_mod = core.block_producer;
const state_mod = core.state;
const block_rewards = core.block_rewards;
const dag_mempool_mod = core.dag_mempool;
const dag_executor_mod = core.dag_executor;
const p2p = @import("p2p");
const EpochIntegration = @import("epoch_integration.zig").EpochIntegration;
const log = core.logger;
const cons_types = consensus.types;

/// Convert a 32-byte array to a 64-char lowercase hex string.
fn hexEncode(bytes: [32]u8) [64]u8 {
    const hex_chars = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

/// Block time in milliseconds (400ms optimal for Zephyria's architecture)
const BLOCK_TIME_MS: u64 = 400;

pub const Miner = struct {
    allocator: std.mem.Allocator,
    chain: *blockchain_mod.Blockchain,
    engine: *zelius.ZeliusEngine,
    state: *state_mod.State,

    // Unified block producer (DAG + legacy support)
    producer: *block_producer_mod.BlockProducer,

    // Legacy references kept for backward compat on RPC/pool queries
    tx_pool: *tx_pool_mod.TxPool,
    executor: *executor_mod.Executor,

    running: *std.atomic.Value(bool),
    validator_addr: types.Address,
    p2p_server: ?*p2p.Server,

    // Consensus pipeline
    pipeline: ?*consensus.Pipeline,
    staking: ?*consensus.Staking,

    // Our validator index in the active set
    our_validator_index: u32,

    // Epoch integration for constant-size blockchain
    epoch_integration: ?*EpochIntegration,

    // Block rewards config
    reward_config: block_rewards.RewardConfig,

    // Stats
    blocks_produced: u64,
    total_txs_processed: u64,
    total_gas_used: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *blockchain_mod.Blockchain,
        pool: *tx_pool_mod.TxPool,
        engine: *zelius.ZeliusEngine,
        exec: *executor_mod.Executor,
        state_obj: *state_mod.State,
        addr: types.Address,
        running_flag: *std.atomic.Value(bool),
        producer: *block_producer_mod.BlockProducer,
    ) !*Miner {
        const self = try allocator.create(Miner);
        self.* = Miner{
            .allocator = allocator,
            .chain = chain,
            .tx_pool = pool,
            .engine = engine,
            .executor = exec,
            .producer = producer,
            .running = running_flag,
            .validator_addr = addr,
            .state = state_obj,
            .p2p_server = null,
            .pipeline = null,
            .staking = null,
            .our_validator_index = 0,
            .epoch_integration = null,
            .reward_config = .{},
            .blocks_produced = 0,
            .total_txs_processed = 0,
            .total_gas_used = 0,
        };
        return self;
    }

    pub fn deinit(self: *Miner) void {
        self.allocator.destroy(self);
    }

    pub fn set_p2p(self: *Miner, server: *p2p.Server) void {
        self.p2p_server = server;
    }

    pub fn setPipeline(self: *Miner, pipe: *consensus.Pipeline) void {
        self.pipeline = pipe;
    }

    pub fn setStaking(self: *Miner, stk: *consensus.Staking) void {
        self.staking = stk;
    }

    pub fn setEpochIntegration(self: *Miner, integration: *EpochIntegration) void {
        self.epoch_integration = integration;
    }

    pub fn setValidatorIndex(self: *Miner, idx: u32) void {
        self.our_validator_index = idx;
    }

    pub fn start(self: *Miner) !void {
        const tier_name = @tagName(self.engine.getCurrentTier());
        const thread_count = self.engine.getThreadCount();
        const has_dag = self.producer.dag_pool != null;
        log.info("Block production started ({}ms block time, tier={s}, threads={d}, dag={s})", .{
            BLOCK_TIME_MS, tier_name, thread_count, if (has_dag) "active" else "legacy",
        });

        while (self.running.load(.seq_cst)) {
            const block_start_ns = std.time.nanoTimestamp();

            const parent = self.chain.current_block orelse return error.NoGenesis;
            const next_number = parent.header.number + 1;

            // 1. Check proposer eligibility (adaptive VRF-based)
            const eligible = self.checkProposerEligibility(parent, next_number);
            if (!eligible) {
                std.Thread.sleep(BLOCK_TIME_MS * std.time.ns_per_ms);
                continue;
            }

            // 2. Begin epoch tracking (if enabled)
            if (self.epoch_integration) |integration| {
                try integration.beginBlock();
            }

            // 3. Produce block via unified BlockProducer (DAG or legacy)
            const build_result = self.producer.produce() catch |err| {
                log.err("Block production failed: {}", .{err});
                std.Thread.sleep(BLOCK_TIME_MS * std.time.ns_per_ms);
                continue;
            };
            const block = build_result.block;

            // 4. Apply block rewards
            const reward_ctx = block_rewards.RewardContext{
                .coinbase = self.validator_addr,
                .block_number = next_number,
                .gas_used = build_result.gas_used,
                .tx_count = @as(u64, build_result.tx_count),
                .timestamp = block.header.time,
            };
            _ = try block_rewards.applyRewards(self.state, self.reward_config, reward_ctx);

            // 5. Commit Verkle trie and recompute state root
            try self.state.trie.commit();
            block.header.verkle_root = types.Hash{ .bytes = self.state.trie.rootHash() };

            // 6. Compute woven root from thread partitioning
            const thread_count_now = self.engine.getThreadCount();
            var thread_roots: [cons_types.MAX_THREADS]core.types.Hash = undefined;
            for (0..cons_types.MAX_THREADS) |ti| {
                thread_roots[ti] = core.types.Hash.zero();
            }

            // Partition TXs by sender address for thread root computation
            var thread_tx_counts: [cons_types.MAX_THREADS]u32 = [_]u32{0} ** cons_types.MAX_THREADS;
            for (block.transactions) |tx| {
                const tid = partitionToThread(tx.from, thread_count_now);
                thread_tx_counts[tid] += 1;
            }

            var tc: u8 = 0;
            while (tc < thread_count_now) : (tc += 1) {
                var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                hasher.update(&block.header.verkle_root.bytes);
                hasher.update(&[_]u8{tc});
                var count_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &count_buf, thread_tx_counts[tc], .big);
                hasher.update(&count_buf);
                hasher.final(&thread_roots[tc].bytes);
            }
            const woven_root = computeWovenRoot(thread_roots[0..thread_count_now]);
            block.header.tx_hash = woven_root;

            // 7. Seal with BLS signature + VDF proof
            self.engine.seal(block) catch |err| {
                log.err("Block seal failed: {}", .{err});
                std.Thread.sleep(BLOCK_TIME_MS * std.time.ns_per_ms);
                continue;
            };

            // 8. Cache hashes BEFORE add_block — add_block calls set_head which
            //    frees the old current_block (== parent), invalidating the pointer.
            const block_hash = block.hash();
            const parent_hash = parent.hash();

            // 9. Record proposal for double-sign tracking
            if (try self.engine.recordProposal(next_number, block_hash, self.validator_addr)) |slash| {
                log.err("Double-signing detected at block {d}! Reason: {}", .{ slash.block_number, slash.reason });
                continue;
            }

            // 10. Add to chain (NOTE: after this, `parent` is a dangling pointer — do NOT use it)
            self.chain.add_block(block) catch |err| {
                log.err("Block add failed: {}", .{err});
                continue;
            };

            // 11. Submit to consensus pipeline (adaptive — with thread roots)
            if (self.pipeline) |pipe| {
                var tx_hashes_buf: [0]types.Hash = undefined;
                if (pipe.propose(next_number, parent_hash, &tx_hashes_buf)) |_| {
                    // Self-vote
                    _ = pipe.vote(next_number, self.our_validator_index) catch {};
                } else |_| {}

                // Set thread roots
                pipe.setThreadRoots(next_number, thread_roots[0..thread_count_now], woven_root);
            }

            // 11. Record proposed block for staking rewards
            if (self.staking) |stk| {
                stk.recordProposedBlock(self.validator_addr);
                _ = stk.distributeRewards(self.validator_addr) catch {};
            }

            // 12. Epoch finalization (if enabled)
            if (self.epoch_integration) |integration| {
                _ = try integration.endBlock(block);
                integration.recordGas(block.header.gas_used);
            }

            // 13. Broadcast to P2P network
            if (self.p2p_server) |server| {
                const msg = p2p.types.NewBlockMsg{
                    .block = block.*,
                    .total_difficulty = 1,
                    .hop_count = 0,
                };
                server.broadcast(p2p.types.MsgNewBlock, msg) catch {};
            }

            // 14. Epoch rotation at epoch boundary (adaptive)
            if (self.engine.isEpochBoundary(next_number)) {
                try self.handleEpochRotation(next_number, block_hash);
            }

            // 15. Sync legacy pool with state for RPC queries
            self.tx_pool.sync_with_state();

            self.blocks_produced += 1;
            self.total_txs_processed += build_result.tx_count;
            self.total_gas_used += build_result.gas_used;

            // Block log with adaptive info + DAG metrics
            const current_tier = @tagName(self.engine.getCurrentTier());
            const current_threads = self.engine.getThreadCount();
            std.debug.print("\x1b[38;5;84m⬥\x1b[0m Block \x1b[1m\x1b[38;5;87m#{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m txs \x1b[38;5;183m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m gas \x1b[38;5;221m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m lanes \x1b[38;5;75m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m \x1b[38;5;141m{s}\x1b[0m T{d}" ++
                " \x1b[38;5;245m│\x1b[0m \x1b[38;5;84m{d}\x1b[0m TPS\n", .{
                next_number,
                block.transactions.len,
                block.header.gas_used,
                build_result.lane_count,
                current_tier,
                current_threads,
                build_result.tps,
            });
            std.debug.print("  \x1b[38;5;245m├─\x1b[0m hash  \x1b[38;5;75m0x{s}\x1b[0m\n" ++
                "  \x1b[38;5;245m└─\x1b[0m state \x1b[38;5;141m0x{s}\x1b[0m\n", .{
                hexEncode(block_hash.bytes),
                hexEncode(block.header.verkle_root.bytes),
            });

            // 16. Sleep remaining block time
            const elapsed_ns = std.time.nanoTimestamp() - block_start_ns;
            const target_ns: i128 = @as(i128, BLOCK_TIME_MS) * std.time.ns_per_ms;
            if (elapsed_ns < target_ns) {
                const sleep_ns: u64 = @intCast(target_ns - elapsed_ns);
                std.Thread.sleep(sleep_ns);
            }
        }
    }

    // ── Adaptive Proposer Eligibility ────────────────────────────────

    fn checkProposerEligibility(self: *Miner, parent: *types.Block, next_number: u64) bool {
        _ = parent;
        // Single-validator mode: always eligible
        if (self.engine.active_validators.len <= 1) return true;

        // Use the adaptive engine's proposer selection
        return self.engine.isProposerForSlot(next_number, self.our_validator_index);
    }

    // ── Epoch Rotation (Adaptive) ───────────────────────────────────

    fn handleEpochRotation(self: *Miner, block_number: u64, block_hash: types.Hash) !void {
        // Collect validator stakes for adaptive epoch transition
        // getValidatorStakes() heap-allocates the slice — must free after use
        var stakes_owned: ?[]u64 = null;
        defer if (stakes_owned) |s| self.allocator.free(s);

        const stakes: []const u64 = if (self.staking) |stk| blk: {
            const s = stk.getValidatorStakes() catch break :blk &[_]u64{};
            stakes_owned = s;
            break :blk s;
        } else &[_]u64{};

        self.engine.rotateEpoch(block_number, block_hash.bytes, stakes) catch |err| {
            log.err("Epoch rotation failed: {}", .{err});
            return;
        };

        // Update pipeline with new adaptive parameters
        if (self.pipeline) |pipe| {
            pipe.setAdaptiveParams(
                self.engine.getThreadCount(),
                self.engine.getCurrentTier(),
            );
        }

        // Broadcast epoch transition to P2P network
        if (self.p2p_server) |server| {
            const epoch_msg = p2p.types.EpochTransitionMsg{
                .new_epoch = self.engine.current_epoch,
                .tier = @intFromEnum(self.engine.getCurrentTier()),
                .thread_count = self.engine.getThreadCount(),
                .validator_count = @intCast(self.engine.active_validators.len),
                .epoch_seed = self.engine.epoch_seed,
            };
            server.broadcast(p2p.types.MsgEpochTransition, epoch_msg) catch {};
        }

        log.info("Epoch rotated at block {d} (epoch {d}, tier={s}, threads={d})", .{
            block_number,
            self.engine.current_epoch,
            @tagName(self.engine.getCurrentTier()),
            self.engine.getThreadCount(),
        });
    }

    // ── Thread Partitioning ─────────────────────────────────────────

    /// Partition a transaction to a thread based on sender address.
    /// Uses the first byte of the address hash for O(1) deterministic assignment.
    fn partitionToThread(sender: types.Address, thread_count: u8) u8 {
        if (thread_count <= 1) return 0;
        return sender.bytes[0] % thread_count;
    }

    /// Compute the woven root (binary Merkle tree of thread roots).
    fn computeWovenRoot(roots: []const core.types.Hash) core.types.Hash {
        if (roots.len == 0) return core.types.Hash.zero();
        if (roots.len == 1) return roots[0];

        // Binary Merkle tree
        var current: [cons_types.MAX_THREADS]core.types.Hash = undefined;
        const count = roots.len;
        for (0..count) |i| {
            current[i] = roots[i];
        }

        var len = count;
        while (len > 1) {
            var next_len: usize = 0;
            var i: usize = 0;
            while (i + 1 < len) : (i += 2) {
                var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                hasher.update(&current[i].bytes);
                hasher.update(&current[i + 1].bytes);
                hasher.final(&current[next_len].bytes);
                next_len += 1;
            }
            if (i < len) {
                // Odd node: hash with itself
                var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                hasher.update(&current[i].bytes);
                hasher.update(&current[i].bytes);
                hasher.final(&current[next_len].bytes);
                next_len += 1;
            }
            len = next_len;
        }
        return current[0];
    }

    // ── Stats ───────────────────────────────────────────────────────

    pub fn getStats(self: *const Miner) struct {
        blocks: u64,
        txs: u64,
        gas: u64,
        tier: cons_types.ConsensusTier,
        threads: u8,
    } {
        return .{
            .blocks = self.blocks_produced,
            .txs = self.total_txs_processed,
            .gas = self.total_gas_used,
            .tier = self.engine.getCurrentTier(),
            .threads = self.engine.getThreadCount(),
        };
    }
};
