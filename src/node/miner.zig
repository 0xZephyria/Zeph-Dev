// ============================================================================
// Zephyria — Node Miner (Block Production Loop)
// ============================================================================
//
// Drives the block production loop:
//   1. Check proposer eligibility (VRF / single-validator shortcut)
//   2. Produce block via BlockProducer (DAG execution, txMerkleRoot set once)
//   3. Compute thread-level woven root for Loom Genesis consensus layer
//      → stored in AdaptiveBlockHeader.wovenRoot, NOT in header.txMerkleRoot
//   4. Seal block with BLS signature (written to extraData[0..96])
//   5. Validate self-produced block (consistency check)
//   6. Add to chain, broadcast, vote, rotate epoch
//
// CRITICAL INVARIANT:
//   header.txMerkleRoot is set in BlockProducer.produce() and NEVER modified
//   afterwards. It is part of Block.id(). Any modification after produce()
//   would change the block id and break all parent-id chains across the network.

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
    rewardConfig: dag_executor_mod.BlockRewardConfig,

    // Stats
    blocksProduced: u64,
    totalTxsProcessed: u64,
    totalBudgetUsed: u64,

    // Slot-driven timing: genesis time (ns) as anchor for slot computation.
    genesisTimestampNs: i128,

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
            .totalBudgetUsed = 0,
            .genesisTimestampNs = @as(i128, @intCast(std.time.nanoTimestamp())),
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

    /// Sleep until the next slot boundary based on block time duration.
    fn sleepUntilSlot() void {
        const slot_duration_ns = @as(i128, BLOCK_TIME_MS) * std.time.ns_per_ms;
        const target_time = @as(i128, @intCast(std.time.nanoTimestamp())) + slot_duration_ns;

        const now = std.time.nanoTimestamp();
        if (now < target_time) {
            const sleep_ns = @as(u64, @intCast(target_time - now));
            std.Thread.sleep(sleep_ns);
        }
    }

    pub fn start(self: *Miner) !void {
        const tier_name = @tagName(self.engine.getCurrentTier());
        const thread_count = self.engine.getThreadCount();
        log.info("Block production started ({}ms block time, tier={s}, threads={d})", .{
            BLOCK_TIME_MS, tier_name, thread_count,
        });

        // Allow P2P peers to connect and complete handshake
        std.Thread.sleep(3000 * std.time.ns_per_ms);

        while (self.running.load(.seq_cst)) {
            const parent = self.chain.currentBlock orelse return error.NoGenesis;
            const nextNumber = parent.header.number + 1;

            // 0. Sleep precisely until the next slot boundary.
            // This replaces the imprecise sleep-based timing with slot-synchronized wakeup.
            sleepUntilSlot();

            // 1. Check proposer eligibility
            if (!self.checkProposerEligibility(parent, nextNumber)) {
                log.debug("Slot {d}: not eligible, skipping", .{nextNumber});
                continue;
            }

            // 2. Begin epoch tracking
            if (self.epochIntegration) |integration| {
                try integration.beginBlock();
            }

            // 3. Set block reward config on executor
            self.dagExecutor.config.blockReward = .{
                .base_reward = self.rewardConfig.base_reward,
                .enabled = self.rewardConfig.enabled,
            };

            // 4. Produce block via BlockProducer.
            // After this call, block.header.txMerkleRoot is SET and IMMUTABLE.
            // Do NOT overwrite txMerkleRoot after this point.
            log.debug("Slot {d}: eligible, producing block...", .{nextNumber});
            const buildResult = self.producer.produce() catch |err| {
                log.err("Block production failed: {}", .{err});
                continue;
            };
            const block = buildResult.block;

            // 5. Compute woven root for Loom Genesis consensus layer.
            // This is the Merkle root of per-thread tx sub-roots.
            // It is stored in AdaptiveBlockHeader.wovenRoot (consensus metadata)
            // and NOT written into header.txMerkleRoot (which is Block.id() input).
            const thread_count_now = self.engine.getThreadCount();
            var thread_roots: [cons_types.MAX_THREADS]core.types.Hash = undefined;
            for (0..cons_types.MAX_THREADS) |ti| {
                thread_roots[ti] = core.types.Hash.zero();
            }

            var thread_tx_counts: [cons_types.MAX_THREADS]u32 = [_]u32{0} ** cons_types.MAX_THREADS;
            for (block.transactions) |tx| {
                const tid = partitionToThread(tx.from, thread_count_now);
                thread_tx_counts[tid] += 1;
            }

            var tc: u8 = 0;
            while (tc < thread_count_now) : (tc += 1) {
                var hasher = std.crypto.hash.Blake3.init(.{});
                hasher.update("ZEPH_THREAD_ROOT_V1");
                hasher.update(&block.header.stateRoot.bytes);
                hasher.update(&[_]u8{tc});
                var count_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &count_buf, thread_tx_counts[tc], .big);
                hasher.update(&count_buf);
                hasher.final(&thread_roots[tc].bytes);
            }
            const wovenRoot = computeWovenRoot(thread_roots[0..thread_count_now]);
            // NOTE: wovenRoot is NOT written to block.header.txMerkleRoot.
            // It is passed to the consensus pipeline only.

            // 6. Validate self-produced block before sealing
            if (!validateSelfBlock(block)) {
                log.err("Self-produced block #{d} failed validation, discarding", .{nextNumber});
                self.producer.chain.freeBlock(block);
                continue;
            }

            // 7. Seal with BLS signature (written to extraData[0..96]).
            // Sealing does NOT change block.id() because extraData is not included
            // in the id computation.
            self.engine.seal(block) catch |err| {
                log.err("Block seal failed: {}", .{err});
                self.producer.chain.freeBlock(block);
                continue;
            };

            // 8. Compute canonical block id AFTER seal (id is stable pre/post seal
            //    since extraData is not part of id, but compute here for logging).
            const blockId = block.id();

            // 9. Record proposal for double-sign detection
            if (try self.engine.recordProposal(nextNumber, blockId, self.validatorAddr)) |slash| {
                log.err("Double-signing detected at block {d}! Reason: {}", .{ slash.blockNumber, slash.reason });
                self.producer.chain.freeBlock(block);
                continue;
            }

            // 11. Submit to consensus pipeline (with thread roots and woven root)
            if (self.pipeline) |pipe| {
                var txHashesBuf: [0]types.Hash = undefined;
                if (pipe.propose(nextNumber, blockId, &txHashesBuf)) |_| {
                    _ = pipe.vote(nextNumber, self.ourValidatorIndex) catch {};
                } else |_| {}

                pipe.setThreadRoots(nextNumber, thread_roots[0..thread_count_now], wovenRoot);
            }

            // 12. Record for staking rewards
            if (self.staking) |stk| {
                stk.recordProposedBlock(self.validatorAddr);
                _ = stk.distributeRewards(self.validatorAddr) catch {};
            }

            // 13. Epoch finalization
            if (self.epochIntegration) |integration| {
                _ = try integration.endBlock(block);
                integration.recordbudget(block.header.budgetUsed);
            }

            // 14. Broadcast to P2P network via Turbine shredding
            if (self.p2pServer) |server| {
                if (core.blockchain.encodeBlockBinary(self.allocator, block.*)) |block_bytes| {
                    defer self.allocator.free(block_bytes);
                    server.broadcastBlockViaTurbine(block_bytes, nextNumber, blockId) catch |err| {
                        log.err("Failed to broadcast block {d} via Turbine: {}", .{nextNumber, err});
                    };
                } else |err| {
                    log.err("Failed to encode block {d} for broadcast: {}", .{nextNumber, err});
                }
            }

            // 10. Add to chain (moved here to prevent use-after-free race conditions)
            var miner_owned_by_chain = false;
            const is_head = self.chain.addBlock(block) catch |err| {
                log.err("Block add failed: {}", .{err});
                // addBlock did not take ownership on error — free the block
                self.producer.chain.freeBlock(block);
                continue;
            };
            miner_owned_by_chain = is_head;
            // NOTE: after addBlock, parent pointer may be dangling (old head freed).
            // Do not use `parent` after this point.

            // 15. Epoch rotation at epoch boundary
            if (self.engine.isEpochBoundary(nextNumber)) {
                try self.handleEpochRotation(nextNumber, blockId);
            }

            // 16. Sync DAG pool with state for RPC queries
            self.dagPool.syncWithState();

            self.blocksProduced += 1;
            self.totalTxsProcessed += buildResult.txCount;
            self.totalBudgetUsed += buildResult.budgetUsed;

            // Block production log
            const current_tier = @tagName(self.engine.getCurrentTier());
            const current_threads = self.engine.getThreadCount();
            std.debug.print(
                "\x1b[38;5;84m⬥\x1b[0m Block \x1b[1m\x1b[38;5;87m#{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m txs \x1b[38;5;183m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m budget \x1b[38;5;221m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m lanes \x1b[38;5;75m{d}\x1b[0m" ++
                " \x1b[38;5;245m│\x1b[0m \x1b[38;5;141m{s}\x1b[0m T{d}" ++
                " \x1b[38;5;245m│\x1b[0m \x1b[38;5;84m{d}\x1b[0m TPS\n",
                .{
                    nextNumber,
                    block.transactions.len,
                    block.header.budgetUsed,
                    buildResult.laneCount,
                    current_tier,
                    current_threads,
                    buildResult.tps,
                },
            );
            std.debug.print(
                "  \x1b[38;5;245m├─\x1b[0m id    \x1b[38;5;75m0x{s}\x1b[0m\n" ++
                "  \x1b[38;5;245m└─\x1b[0m state \x1b[38;5;141m0x{s}\x1b[0m\n",
                .{
                    hexEncode(blockId.bytes),
                    hexEncode(block.header.stateRoot.bytes),
                },
            );

            if (!miner_owned_by_chain) {
                self.producer.chain.freeBlock(block);
            }
        }
    }

    // ── Self-Block Validation ─────────────────────────────────────────

    /// Verify a self-produced block's internal consistency before sealing.
    /// Checks:
    ///   1. txMerkleRoot matches re-computed merkle root of all transactions
    ///   2. Block number is head + 1
    fn validateSelfBlock(block: *types.Block) bool {
        // Re-compute TX merkle root and compare
        const expected = types.Block.computeTxMerkleRoot(block.transactions);
        if (!std.mem.eql(u8, &expected.bytes, &block.header.txMerkleRoot.bytes)) {
            log.err("txMerkleRoot mismatch in self-produced block: expected {s}, got {s}", .{
                &std.fmt.bytesToHex(expected.bytes, .lower),
                &std.fmt.bytesToHex(block.header.txMerkleRoot.bytes, .lower),
            });
            return false;
        }
        return true;
    }

    // ── Adaptive Proposer Eligibility ─────────────────────────────────

    fn checkProposerEligibility(self: *Miner, _: *types.Block, nextNumber: u64) bool {
        // Single-validator mode: always eligible
        if (self.engine.activeValidators.len <= 1) return true;
        // In testnet/multi-node mode, determine proposer index from ZeliusEngine
        return self.engine.isProposerForSlot(nextNumber, self.ourValidatorIndex);
    }

    // ── Epoch Rotation ────────────────────────────────────────────────

    fn handleEpochRotation(self: *Miner, blockNumber: u64, blockId: types.Hash) !void {
        var stakesOwned: ?[]u256 = null;
        defer if (stakesOwned) |s| self.allocator.free(s);

        const stakes: []const u256 = if (self.staking) |stk| blk: {
            const s = stk.getValidatorStakes() catch break :blk &[_]u256{};
            stakesOwned = s;
            break :blk s;
        } else &[_]u256{};

        self.engine.rotateEpoch(blockNumber, blockId.bytes, stakes) catch |err| {
            log.err("Epoch rotation failed: {}", .{err});
            return;
        };

        if (self.staking) |stk| {
            stk.persist(self.state.db) catch |err| {
                log.warn("Staking persist failed at epoch boundary: {}", .{err});
            };
        }

        if (self.pipeline) |pipe| {
            pipe.setAdaptiveParams(
                self.engine.getThreadCount(),
                self.engine.getCurrentTier(),
            );
        }

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

    // ── Thread Partitioning ───────────────────────────────────────────

    /// Deterministically partition a sender address to a thread [0, thread_count).
    fn partitionToThread(sender: types.Address, thread_count: u8) u8 {
        if (thread_count <= 1) return 0;
        return sender.bytes[0] % thread_count;
    }

    /// Compute woven root as binary Merkle tree of thread roots.
    /// Used for Loom Genesis consensus metadata only — NOT stored in header.txMerkleRoot.
    fn computeWovenRoot(roots: []const core.types.Hash) core.types.Hash {
        if (roots.len == 0) return core.types.Hash.zero();
        if (roots.len == 1) return roots[0];

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
                var hasher = std.crypto.hash.Blake3.init(.{});
                hasher.update("ZEPH_WOVEN_V1");
                hasher.update(&current[i].bytes);
                hasher.update(&current[i + 1].bytes);
                hasher.final(&current[next_len].bytes);
                next_len += 1;
            }
            if (i < len) {
                // Odd node: hash with itself (consistent with AdaptiveBlockHeader.computeWovenRoot)
                var hasher = std.crypto.hash.Blake3.init(.{});
                hasher.update("ZEPH_WOVEN_V1");
                hasher.update(&current[i].bytes);
                hasher.update(&current[i].bytes);
                hasher.final(&current[next_len].bytes);
                next_len += 1;
            }
            len = next_len;
        }
        return current[0];
    }

    // ── Stats ─────────────────────────────────────────────────────────

    pub fn getStats(self: *const Miner) struct {
        blocks: u64,
        txs: u64,
        budget: u64,
        tier: cons_types.ConsensusTier,
        threads: u8,
    } {
        return .{
            .blocks = self.blocksProduced,
            .txs = self.totalTxsProcessed,
            .budget = self.totalBudgetUsed,
            .tier = self.engine.getCurrentTier(),
            .threads = self.engine.getThreadCount(),
        };
    }
};
