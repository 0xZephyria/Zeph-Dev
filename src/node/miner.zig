const std = @import("std");
const core = @import("core");
const types = core.types;
const consensus = @import("consensus");
const zelius = consensus.zelius;
const blockchain_mod = core.blockchain;
const dag_mempool_mod = core.dag_mempool;
const dag_executor_mod = core.dag_executor;
const block_producer_mod = core.block_producer;
const state_mod = core.state;
const block_rewards = core.block_rewards;
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

    // Unified block producer (DAG primary)
    producer: *block_producer_mod.BlockProducer,

    // DAG Components
    dagPool: *dag_mempool_mod.DAGMempool,
    dagExecutor: *dag_executor_mod.DAGExecutor,

    running: *std.atomic.Value(bool),
    validatorAddr: types.Address,
    p2pServer: ?*p2p.Server,

    // Consensus pipeline
    pipeline: ?*consensus.Pipeline,
    staking: ?*consensus.Staking,

    // Our validator index in the active set
    ourValidatorIndex: u32,

    // Epoch integration for constant-size blockchain
    epochIntegration: ?*EpochIntegration,

    // Block rewards config
    rewardConfig: block_rewards.RewardConfig,

    // Stats
    blocksProduced: u64,
    totalTxsProcessed: u64,
    totalGasUsed: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *blockchain_mod.Blockchain,
        pool: *dag_mempool_mod.DAGMempool,
        engine: *zelius.ZeliusEngine,
        executor: *dag_executor_mod.DAGExecutor,
        state_obj: *state_mod.State,
        addr: types.Address,
        running_flag: *std.atomic.Value(bool),
        producer: *block_producer_mod.BlockProducer,
    ) !*Miner {
        const self = try allocator.create(Miner);
        self.* = Miner{
            .allocator = allocator,
            .chain = chain,
            .dagPool = pool,
            .engine = engine,
            .dagExecutor = executor,
            .producer = producer,
            .running = running_flag,
            .validatorAddr = addr,
            .state = state_obj,
            .p2pServer = null,
            .pipeline = null,
            .staking = null,
            .ourValidatorIndex = 0,
            .epochIntegration = null,
            .rewardConfig = .{},
            .blocksProduced = 0,
            .totalTxsProcessed = 0,
            .totalGasUsed = 0,
        };
        return self;
    }

    pub fn deinit(self: *Miner) void {
        self.allocator.destroy(self);
    }

    pub fn setP2p(self: *Miner, server: *p2p.Server) void {
        self.p2pServer = server;
    }

    pub fn setPipeline(self: *Miner, pipe: *consensus.Pipeline) void {
        self.pipeline = pipe;
    }

    pub fn setStaking(self: *Miner, stk: *consensus.Staking) void {
        self.staking = stk;
    }

    pub fn setEpochIntegration(self: *Miner, integration: *EpochIntegration) void {
        self.epochIntegration = integration;
    }

    pub fn setValidatorIndex(self: *Miner, idx: u32) void {
        self.ourValidatorIndex = idx;
    }

    pub fn start(self: *Miner) !void {
        const tier_name = @tagName(self.engine.getCurrentTier());
        const thread_count = self.engine.getThreadCount();
        log.info("Block production started ({}ms block time, tier={s}, threads={d})", .{
            BLOCK_TIME_MS, tier_name, thread_count,
        });

        while (self.running.load(.seq_cst)) {
            const blockStartNs = std.time.nanoTimestamp();

            const parent = self.chain.currentBlock orelse return error.NoGenesis;
            const nextNumber = parent.header.number + 1;

            // 1. Check proposer eligibility (adaptive VRF-based)
            const eligible = self.checkProposerEligibility(parent, nextNumber);
            if (!eligible) {
                std.Thread.sleep(BLOCK_TIME_MS * std.time.ns_per_ms);
                continue;
            }

            // 2. Begin epoch tracking (if enabled)
            if (self.epochIntegration) |integration| {
                try integration.beginBlock();
            }

            // 3. Produce block via unified BlockProducer
            const buildResult = self.producer.produce() catch |err| {
                log.err("Block production failed: {}", .{err});
                std.Thread.sleep(BLOCK_TIME_MS * std.time.ns_per_ms);
                continue;
            };
            const block = buildResult.block;

            // 4. Apply block rewards
            const rewardCtx = block_rewards.RewardContext{
                .coinbase = self.validatorAddr,
                .block_number = nextNumber,
                .gas_used = buildResult.gasUsed,
                .tx_count = @as(u64, buildResult.txCount),
                .timestamp = block.header.time,
            };
            _ = try block_rewards.applyRewards(self.state, self.rewardConfig, rewardCtx);

            // 5. Commit Verkle trie and recompute state root
            try self.state.trie.commit();
            block.header.verkleRoot = types.Hash{ .bytes = self.state.trie.rootHash() };

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
                hasher.update(&block.header.verkleRoot.bytes);
                hasher.update(&[_]u8{tc});
                var count_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &count_buf, thread_tx_counts[tc], .big);
                hasher.update(&count_buf);
                hasher.final(&thread_roots[tc].bytes);
            }
            const wovenRoot = computeWovenRoot(thread_roots[0..thread_count_now]);
            block.header.txHash = wovenRoot;

            // 7. Seal with BLS signature + VDF proof
            self.engine.seal(block) catch |err| {
                log.err("Block seal failed: {}", .{err});
                std.Thread.sleep(BLOCK_TIME_MS * std.time.ns_per_ms);
                continue;
            };

            // 8. Cache hashes BEFORE addBlock — addBlock calls setHead which
            //    frees the old current_block (== parent), invalidating the pointer.
            const blockHash = block.hash();
            const parentHash = parent.hash();

            // 9. Record proposal for double-sign tracking
            if (try self.engine.recordProposal(nextNumber, blockHash, self.validatorAddr)) |slash| {
                log.err("Double-signing detected at block {d}! Reason: {}", .{ slash.blockNumber, slash.reason });
                continue;
            }

            // 10. Add to chain (NOTE: after this, `parent` is a dangling pointer — do NOT use it)
            self.chain.addBlock(block) catch |err| {
                log.err("Block add failed: {}", .{err});
                continue;
            };

            // 11. Submit to consensus pipeline (adaptive — with thread roots)
            if (self.pipeline) |pipe| {
                var txHashesBuf: [0]types.Hash = undefined;
                if (pipe.propose(nextNumber, parentHash, &txHashesBuf)) |_| {
                    // Self-vote
                    _ = pipe.vote(nextNumber, self.ourValidatorIndex) catch {};
                } else |_| {}

                // Set thread roots
                pipe.setThreadRoots(nextNumber, thread_roots[0..thread_count_now], wovenRoot);
            }

            // 11. Record proposed block for staking rewards
            if (self.staking) |stk| {
                stk.recordProposedBlock(self.validatorAddr);
                _ = stk.distributeRewards(self.validatorAddr) catch {};
            }

            // 12. Epoch finalization (if enabled)
            if (self.epochIntegration) |integration| {
                _ = try integration.endBlock(block);
                integration.recordGas(block.header.gasUsed);
            }

            // 13. Broadcast to P2P network
            if (self.p2pServer) |server| {
                const msg = p2p.types.NewBlockMsg{
                    .block = block.*,
                    .totalDifficulty = 1,
                    .hopCount = 0,
                };
                server.broadcast(p2p.types.MsgNewBlock, msg) catch {};
            }

            // 14. Epoch rotation at epoch boundary (adaptive)
            if (self.engine.isEpochBoundary(nextNumber)) {
                try self.handleEpochRotation(nextNumber, blockHash);
            }

            // 15. Sync DAG pool with state for RPC queries
            self.dagPool.syncWithState();

            self.blocksProduced += 1;
            self.totalTxsProcessed += buildResult.txCount;
            self.totalGasUsed += buildResult.gasUsed;

            // Block log with adaptive info + DAG metrics
            const current_tier = @tagName(self.engine.getCurrentTier());
            const current_threads = self.engine.getThreadCount();
            std.debug.print("\x1b[38;5;84m⬥\x1b[0m Block \x1b[1m\x1b[38;5;87m#{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m txs \x1b[38;5;183m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m gas \x1b[38;5;221m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m lanes \x1b[38;5;75m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m \x1b[38;5;141m{s}\x1b[0m T{d}" ++
                " \x1b[38;5;245m│\x1b[0m \x1b[38;5;84m{d}\x1b[0m TPS\n", .{
                nextNumber,
                block.transactions.len,
                block.header.gasUsed,
                buildResult.laneCount,
                current_tier,
                current_threads,
                buildResult.tps,
            });
            std.debug.print("  \x1b[38;5;245m├─\x1b[0m hash  \x1b[38;5;75m0x{s}\x1b[0m\n" ++
                "  \x1b[38;5;245m└─\x1b[0m state \x1b[38;5;141m0x{s}\x1b[0m\n", .{
                hexEncode(blockHash.bytes),
                hexEncode(block.header.verkleRoot.bytes),
            });

            // 16. Sleep remaining block time
            const elapsedNs = std.time.nanoTimestamp() - blockStartNs;
            const targetNs: i128 = @as(i128, BLOCK_TIME_MS) * std.time.ns_per_ms;
            if (elapsedNs < targetNs) {
                const sleepNs: u64 = @intCast(targetNs - elapsedNs);
                std.Thread.sleep(sleepNs);
            }
        }
    }

    // ── Adaptive Proposer Eligibility ────────────────────────────────

    fn checkProposerEligibility(self: *Miner, parent: *types.Block, next_number: u64) bool {
        _ = parent;
        // Single-validator mode: always eligible
        if (self.engine.activeValidators.len <= 1) return true;

        // Use the adaptive engine's proposer selection
        return self.engine.isProposerForSlot(next_number, self.ourValidatorIndex);
    }

    // ── Epoch Rotation (Adaptive) ───────────────────────────────────

    fn handleEpochRotation(self: *Miner, blockNumber: u64, blockHash: types.Hash) !void {
        // Collect validator stakes for adaptive epoch transition
        var stakesOwned: ?[]u64 = null;
        defer if (stakesOwned) |s| self.allocator.free(s);

        const stakes: []const u64 = if (self.staking) |stk| blk: {
            const s = stk.getValidatorStakes() catch break :blk &[_]u64{};
            stakesOwned = s;
            break :blk s;
        } else &[_]u64{};

        self.engine.rotateEpoch(blockNumber, blockHash.bytes, stakes) catch |err| {
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
        if (self.p2pServer) |server| {
            const epoch_msg = p2p.types.EpochTransitionMsg{
                .newEpoch = self.engine.currentEpoch,
                .tier = @intFromEnum(self.engine.getCurrentTier()),
                .threadCount = self.engine.getThreadCount(),
                .validatorCount = @intCast(self.engine.activeValidators.len),
                .epochSeed = self.engine.epochSeed,
            };
            server.broadcast(p2p.types.MsgEpochTransition, epoch_msg) catch {};
        }

        log.info("Epoch rotated at block {d} (epoch {d}, tier={s}, threads={d})", .{
            blockNumber,
            self.engine.currentEpoch,
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
            .blocks = self.blocksProduced,
            .txs = self.totalTxsProcessed,
            .gas = self.totalGasUsed,
            .tier = self.engine.getCurrentTier(),
            .threads = self.engine.getThreadCount(),
        };
    }
};
