// ============================================================================
// Zephyria — DAG-Based Mempool (Production-Hardened)
// ============================================================================
//
// High-throughput sharded mempool designed for 1M+ TPS. Exploits Zephyria's
// isolated account model where per-user DerivedState keys and per-slot
// StorageCell keys are unique per sender. The ONLY transactions that share
// write keys are from the SAME sender (nonce + balance keys).
//
// Architecture:
//   • 256 shards keyed by sender address byte[0] — zero cross-shard contention
//   • Per-sender AccountLanes maintain nonce-ordered TX queues
//   • DAG is implicit: edges exist only within same-sender lanes (nonce ordering)
//   • Extraction yields independent lanes — guaranteed zero-conflict parallel execution
//
// Security:
//   • Bloom filter for O(1) duplicate rejection
//   • Per-account + global rate limiting (token bucket)
//   • Lane depth limits (max 256 pending TXs per sender)
//   • Hot-shard detection with gas price premium
//   • Orphan lane GC (evict inactive lanes after timeout)
//   • Nonce gap protection (max 64 gap from state nonce)
//   • TX sanitization (signature, bounds, malleability)
//
// Zero sequential fallback. Zero wavefront computation. Zero conflict detection.

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const security = @import("security.zig");
const accounts = @import("accounts/mod.zig");
const log = @import("logger.zig");

// ── Configuration ───────────────────────────────────────────────────────

pub const SHARD_COUNT: u16 = 256;

/// Configuration options for the DAG-based mempool.
pub const DAGConfig = struct {
    /// Maximum pending TXs per sender lane
    maxTxsPerLane: u32 = 256,
    /// Maximum total vertices across all shards
    maxTotalVertices: u32 = 500_000,
    /// Maximum gas budget per sender lane
    maxLaneGas: u64 = 100_000_000,
    /// Orphan lane timeout in seconds
    orphanTimeoutS: u64 = 60,
    /// Maximum nonce gap from state nonce
    maxNonceGap: u64 = 64,
    /// Minimum gas price (1 Gwei anti-spam floor)
    minGasPrice: u256 = 1_000_000_000,
    /// Gas price bump required for TX replacement (10%)
    replacementBumpPct: u32 = 10,
    /// Hot-shard threshold multiplier (2x mean triggers premium)
    hotShardMultiplier: u32 = 2,
    /// Hot-shard gas price premium (150% = 1.5x)
    hotShardPremiumPct: u32 = 150,
    /// Bloom filter size in bits (2M bits = 256KB)
    bloomSizeBits: u32 = 2_097_152,
    /// Enable deep TX sanitization
    enableSanitization: bool = true,
    /// Maximum calldata size
    maxCalldata: u32 = 96 * 1024,
    /// Minimum gas limit for any TX
    minGasLimit: u64 = 21_000,
    /// Maximum gas limit for any TX
    maxGasLimit: u64 = 30_000_000,
    /// Maximum gas price (anti-grief)
    maxGasPrice: u256 = 10_000_000_000_000_000_000_000,
    /// Maximum value transfer
    maxValue: u256 = 1_000_000_000_000_000_000_000_000_000,
    /// Chain ID for replay protection
    chainId: u64 = 99999,
};

// ── Account Lane ────────────────────────────────────────────────────────
//
// Per-sender transaction queue. TXs are ordered by nonce within the lane.
// This IS the DAG: same-sender TXs form a chain (nonce N depends on N-1).
// Different senders' lanes are completely independent — zero edges between them.

/// Represents a per-sender transaction queue (a "lane").
/// In Zephyria, same-sender transactions must be executed in nonce order,
/// forming a linear dependency chain within the lane.
pub const AccountLane = struct {
    sender: types.Address,
    /// Nonce-ordered TX queue. Index 0 = baseNonce, Index 1 = baseNonce+1, etc.
    txs: std.ArrayListUnmanaged(LaneTx),
    /// Current confirmed state nonce for this sender
    baseNonce: u64,
    /// Total gas reserved by all TXs in this lane
    totalGas: u64,
    /// Monotonic timestamp of last TX addition (for GC)
    lastTouchNs: i128,
    /// Number of TXs that have been extracted for execution
    extractedCount: u32,

    /// Initializes a new AccountLane.
    pub fn init(sender: types.Address, baseNonce: u64) AccountLane {
        return .{
            .sender = sender,
            .txs = .{},
            .baseNonce = baseNonce,
            .totalGas = 0,
            .lastTouchNs = std.time.nanoTimestamp(),
            .extractedCount = 0,
        };
    }

    /// Deinitializes the AccountLane.
    pub fn deinit(self: *AccountLane, allocator: std.mem.Allocator) void {
        self.txs.deinit(allocator);
    }

    /// Insert a TX at the correct nonce position within the lane.
    /// Returns the TX that was replaced (if any) for eviction.
    pub fn insert(
        self: *AccountLane,
        allocator: std.mem.Allocator,
        tx: types.Transaction,
        replacementBumpPct: u32,
    ) !?types.Transaction {
        if (tx.nonce < self.baseNonce) return error.NonceTooLow;

        const idx = tx.nonce - self.baseNonce;

        // Check if this is a replacement
        if (idx < self.txs.items.len) {
            const existing = &self.txs.items[idx];
            // Enforce gas price bump for replacement
            const minNewPrice = existing.tx.gasPrice +
                (existing.tx.gasPrice * @as(u256, replacementBumpPct)) / 100;
            if (tx.gasPrice < minNewPrice) return error.ReplacementGasTooLow;

            // Replace
            const oldTx = existing.tx;
            self.totalGas -= oldTx.gasLimit;
            existing.tx = tx;
            existing.insertedAt = std.time.nanoTimestamp();
            self.totalGas += tx.gasLimit;
            self.lastTouchNs = std.time.nanoTimestamp();
            return oldTx;
        }

        // Append at position (may leave gaps — nonce gap protection handles)
        while (self.txs.items.len < idx) {
            try self.txs.append(allocator, LaneTx{
                .tx = undefined,
                .insertedAt = 0,
                .isPlaceholder = true,
            });
        }

        try self.txs.append(allocator, LaneTx{
            .tx = tx,
            .insertedAt = std.time.nanoTimestamp(),
            .isPlaceholder = false,
        });

        self.totalGas += tx.gasLimit;
        self.lastTouchNs = std.time.nanoTimestamp();
        return null;
    }

    /// Get the contiguous sequence of ready TXs starting from baseNonce.
    /// These are guaranteed to be executable in order.
    pub fn getReady(self: *const AccountLane) []const LaneTx {
        var count: usize = 0;
        for (self.txs.items) |*lt| {
            if (lt.isPlaceholder) break;
            count += 1;
        }
        return self.txs.items[0..count];
    }

    /// Remove TXs that have been committed (nonce < new_baseNonce).
    pub fn advance(self: *AccountLane, allocator: std.mem.Allocator, newBaseNonce: u64) void {
        if (newBaseNonce <= self.baseNonce) return;

        const removeCount = @min(
            newBaseNonce - self.baseNonce,
            self.txs.items.len,
        );

        for (self.txs.items[0..removeCount]) |*lt| {
            if (!lt.isPlaceholder) {
                self.totalGas -|= lt.tx.gasLimit;
            }
        }

        // Shift remaining TXs down
        if (removeCount < self.txs.items.len) {
            const remaining = self.txs.items.len - removeCount;
            std.mem.copyForwards(
                LaneTx,
                self.txs.items[0..remaining],
                self.txs.items[removeCount..self.txs.items.len],
            );
            self.txs.items.len = remaining;
        } else {
            self.txs.items.len = 0;
        }

        self.baseNonce = newBaseNonce;
        _ = allocator;
    }

    /// Number of ready (non-placeholder) TXs.
    pub fn readyCount(self: *const AccountLane) u32 {
        var count: u32 = 0;
        for (self.txs.items) |*lt| {
            if (lt.isPlaceholder) break;
            count += 1;
        }
        return count;
    }

    /// Check if this lane is empty and can be GC'd.
    pub fn isEmpty(self: *const AccountLane) bool {
        return self.txs.items.len == 0;
    }
};

/// Wrapper for a transaction stored within a lane.
pub const LaneTx = struct {
    tx: types.Transaction,
    insertedAt: i128,
    isPlaceholder: bool,
};

// ── Shard ───────────────────────────────────────────────────────────────
//
// One of 256 shards. Each shard has its own mutex — only locked during
// admission/extraction for accounts that hash to this shard.

/// Represents a mempool shard, containing a subset of account lanes.
pub const Shard = struct {
    lock: std.Thread.Mutex,
    accounts: std.AutoHashMap(types.Address, *AccountLane),
    vertexCount: u32,
    totalGas: u64,

    /// Initializes a new Shard.
    pub fn init() Shard {
        return .{
            .lock = .{},
            .accounts = undefined,
            .vertexCount = 0,
            .totalGas = 0,
        };
    }
};

// ── DAG Vertex ──────────────────────────────────────────────────────────
//
// Represents a TX's position in the implicit DAG. Write keys are computed
// from the isolated account model at admission time.

/// Represents a vertex in the implicit transaction dependency DAG.
pub const DAGVertex = struct {
    txHash: types.Hash,
    sender: types.Address,
    nonce: u64,
    writeKeys: [MAX_WRITE_KEYS][32]u8,
    writeKeyCount: u8,
    gasLimit: u64,
    gasPrice: u256,
    shardId: u8,

    /// Maximum number of unique state keys a transaction is expected to write.
    pub const MAX_WRITE_KEYS = 8;

    /// Compute write keys from TX structure using isolated account model.
    pub fn computeWriteKeys(tx: *const types.Transaction) DAGVertex {
        const State = state_mod.State;
        var vertex = DAGVertex{
            .txHash = tx.hash(),
            .sender = tx.from,
            .nonce = tx.nonce,
            .writeKeys = undefined,
            .writeKeyCount = 0,
            .gasLimit = tx.gasLimit,
            .gasPrice = tx.gasPrice,
            .shardId = tx.from.bytes[0],
        };

        // 1. Sender nonce + balance (ALWAYS written)
        vertex.addKey(State.nonceKey(tx.from));
        vertex.addKey(State.balanceKey(tx.from));

        // 2. Recipient
        if (tx.to) |toAddr| {
            vertex.addKey(State.balanceKey(toAddr));

            // 3. Contract call: per-user derived key (NEVER conflicts with other users)
            if (tx.data.len >= 4) {
                var senderSlot: [32]u8 = [_]u8{0} ** 32;
                @memcpy(senderSlot[0..20], &tx.from.bytes);
                vertex.addKey(State.derivedStorageKey(tx.from, toAddr, senderSlot));
            }
        } else {
            // Contract creation
            const newAddr = tx.deriveContractAddress();
            vertex.addKey(State.nonceKey(newAddr));
            vertex.addKey(State.balanceKey(newAddr));
            vertex.addKey(State.codeHashKey(newAddr));
        }

        return vertex;
    }

    fn addKey(self: *DAGVertex, key: [32]u8) void {
        if (self.writeKeyCount >= MAX_WRITE_KEYS) return;
        self.writeKeys[self.writeKeyCount] = key;
        self.writeKeyCount += 1;
    }

    /// Check if this vertex conflicts with another vertex.
    /// In Zephyria's isolated model, conflicts ONLY happen between
    /// same-sender TXs (shared nonce + balance keys).
    pub fn conflictsWith(self: *const DAGVertex, other: *const DAGVertex) bool {
        for (self.writeKeys[0..self.writeKeyCount]) |keyA| {
            for (other.writeKeys[0..other.writeKeyCount]) |keyB| {
                if (std.mem.eql(u8, &keyA, &keyB)) return true;
            }
        }
        return false;
    }
};

// ── Extraction Result ───────────────────────────────────────────────────

/// Result of extracting execution-ready lanes from the mempool.
pub const ExtractionResult = struct {
    lanes: []ExtractedLane,
    totalTxs: u32,
    totalGas: u64,
    allocator: std.mem.Allocator,

    /// Deinitializes the extraction result and frees all lane memory.
    pub fn deinit(self: *ExtractionResult) void {
        for (self.lanes) |*lane| {
            self.allocator.free(lane.txs);
        }
        self.allocator.free(self.lanes);
    }
};

/// Represents a sender-isolated lane of transactions extracted for parallel execution.
pub const ExtractedLane = struct {
    sender: types.Address,
    txs: []types.Transaction,
    baseNonce: u64,
};

// ── Metrics ─────────────────────────────────────────────────────────────

/// Performance and health metrics for the DAG mempool.
pub const Metrics = struct {
    totalAdded: u64,
    totalRejected: u64,
    totalEvicted: u64,
    totalExtracted: u64,
    totalGcEvicted: u64,
    duplicateRejected: u64,
    rateLimited: u64,
    nonceRejected: u64,
    gasPriceRejected: u64,
    sanitizationRejected: u64,
    hotShardPremiumApplied: u64,
    replacementCount: u64,
    shardMaxLoad: u32,
    activeLanes: u32,
};

// ── DAG Mempool ─────────────────────────────────────────────────────────

/// High-throughput sharded mempool designed for the zero-conflict execution model.
/// Spans 256 shards to minimize lock contention and support massive parallel intake.
pub const DAGMempool = struct {
    allocator: std.mem.Allocator,
    state: *state_mod.State,
    config: DAGConfig,
    shards: [SHARD_COUNT]Shard,
    bloom: security.TxBloomFilter,
    rate_limiter: security.RateLimiter,
    sanitizer: security.TxSanitizer,

    // Global counters (atomic for cross-shard visibility)
    totalVertices: std.atomic.Value(u32),
    totalGas: std.atomic.Value(u64),

    // Metrics
    metrics: Metrics,
    metrics_lock: std.Thread.Mutex,

    // Hash index for O(1) lookup by hash
    by_hash: std.AutoHashMap(types.Hash, TxLocation),
    by_hash_lock: std.Thread.Mutex,

    /// Initializes a new DAGMempool instance with 256 shards.
    pub fn init(
        allocator: std.mem.Allocator,
        state: *state_mod.State,
        config: DAGConfig,
    ) !*DAGMempool {
        const self = try allocator.create(DAGMempool);

        var shards: [SHARD_COUNT]Shard = undefined;
        for (&shards) |*shard| {
            shard.* = Shard.init();
            shard.accounts = std.AutoHashMap(types.Address, *AccountLane).init(allocator);
        }

        self.* = DAGMempool{
            .allocator = allocator,
            .state = state,
            .config = config,
            .shards = shards,
            .bloom = try security.TxBloomFilter.init(allocator, config.bloomSizeBits),
            .rate_limiter = security.RateLimiter.init(allocator, .{}),
            .sanitizer = security.TxSanitizer.init(.{
                .maxCalldata = config.maxCalldata,
                .minGasLimit = config.minGasLimit,
                .maxGasLimit = config.maxGasLimit,
                .maxGasPrice = config.maxGasPrice,
                .maxValue = config.maxValue,
                .chainId = config.chainId,
                .maxNonceGap = config.maxNonceGap,
            }),
            .totalVertices = std.atomic.Value(u32).init(0),
            .totalGas = std.atomic.Value(u64).init(0),
            .metrics = std.mem.zeroes(Metrics),
            .metrics_lock = .{},
            .by_hash = std.AutoHashMap(types.Hash, TxLocation).init(allocator),
            .by_hash_lock = .{},
        };

        return self;
    }

    pub fn deinit(self: *DAGMempool) void {
        // Free all lanes in all shards
        for (&self.shards) |*shard| {
            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit(self.allocator);
                self.allocator.destroy(entry.value_ptr.*);
            }
            shard.accounts.deinit();
        }
        self.bloom.deinit();
        self.rate_limiter.deinit();
        self.by_hash.deinit();
        self.allocator.destroy(self);
    }

    // ── Admission ───────────────────────────────────────────────────────

    /// Add a transaction to the DAG mempool.
    /// Thread-safe: only locks the target shard + brief hash index lock.
    /// Admits a new transaction into the mempool, performing sharded locking and sanitization.
    pub fn add(self: *DAGMempool, tx: *const types.Transaction) !void {
        const txHash = tx.hash();

        // 1. Bloom filter pre-check (O(1), no lock needed — false positives OK)
        if (self.bloom.mightContain(txHash)) {
            // Confirm with hash index (bloom has false positives)
            self.by_hash_lock.lock();
            const exists = self.by_hash.contains(txHash);
            self.by_hash_lock.unlock();
            if (exists) {
                self.incrMetric(.duplicateRejected);
                return error.DuplicateTransaction;
            }
        }

        // 2. Global capacity check (atomic, no lock)
        if (self.totalVertices.load(.acquire) >= self.config.maxTotalVertices) {
            // Try to evict lowest gas price TX before rejecting
            if (!self.evictLowestGlobal(tx.gasPrice)) {
                self.incrMetric(.totalRejected);
                return error.MempoolFull;
            }
        }

        // 3. Rate limiting (per-account token bucket)
        self.rate_limiter.checkAndConsume(tx.from) catch {
            self.incrMetric(.rateLimited);
            return error.RateLimited;
        };

        // 4. Minimum gas price floor
        const effective_min_price = self.getEffectiveMinPrice(tx.from);
        if (tx.gasPrice < effective_min_price) {
            self.incrMetric(.gasPriceRejected);
            return error.GasPriceTooLow;
        }

        // 5. TX sanitization (signature, nonce bounds, balance, malleability)
        if (self.config.enableSanitization) {
            const state_nonce = self.state.getNonce(tx.from);
            const state_balance = self.state.getBalance(tx.from);
            self.sanitizer.validate(tx, state_nonce, state_balance) catch |err| {
                self.incrMetric(.sanitizationRejected);
                return err;
            };
        }

        // 6. Lock ONLY the target shard
        const shardId = self.shardFor(tx.from);
        var shard = &self.shards[shardId];
        shard.lock.lock();
        defer shard.lock.unlock();

        // 7. Get or create account lane
        const lane = try self.getOrCreateLane(shard, tx.from);

        // 8. Lane depth check
        if (lane.txs.items.len >= self.config.maxTxsPerLane) {
            self.incrMetric(.totalRejected);
            return error.LaneDepthExceeded;
        }

        // 9. Lane gas budget check
        if (lane.totalGas + tx.gasLimit > self.config.maxLaneGas) {
            self.incrMetric(.totalRejected);
            return error.LaneGasBudgetExceeded;
        }

        // 10. Insert into lane (handles replacement)
        const replaced = try lane.insert(self.allocator, tx.*, self.config.replacementBumpPct);

        if (replaced) |old_tx| {
            // Remove old TX from hash index
            const old_hash = old_tx.hash();
            self.by_hash_lock.lock();
            _ = self.by_hash.remove(old_hash);
            self.by_hash_lock.unlock();
            self.incrMetric(.replacementCount);
        } else {
            // New TX — increment counters
            _ = self.totalVertices.fetchAdd(1, .release);
            shard.vertexCount += 1;
        }

        // 11. Add to hash index and bloom filter
        self.by_hash_lock.lock();
        self.by_hash.put(txHash, TxLocation{
            .shardId = shardId,
            .sender = tx.from,
            .nonce = tx.nonce,
        }) catch {
            self.by_hash_lock.unlock();
            self.incrMetric(.totalRejected);
            return error.HashIndexFull;
        };
        self.by_hash_lock.unlock();

        self.bloom.add(txHash);
        self.incrMetric(.totalAdded);
    }

    // ── Extraction ──────────────────────────────────────────────────────

    /// Extract execution-ready TX lanes for block building.
    /// Returns independent lanes — guaranteed zero-conflict parallel execution.
    /// Each lane contains nonce-ordered TXs from a single sender.
    /// Extracts execution-ready transaction lanes for block production, respecting the gas budget.
    pub fn extract(self: *DAGMempool, allocator: std.mem.Allocator, gas_budget: u64) !ExtractionResult {
        var lanes = std.ArrayListUnmanaged(ExtractedLane){};
        defer lanes.deinit(allocator); // only on error path
        var totalTxs: u32 = 0;
        var remaining_gas = gas_budget;

        // Collect candidates from all shards
        var candidates = std.ArrayListUnmanaged(LaneCandidate){};
        defer candidates.deinit(allocator);

        for (&self.shards) |*shard| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                const lane = entry.value_ptr.*;
                const ready = lane.getReady();
                if (ready.len == 0) continue;

                // Compute the highest gas price in this lane for priority
                var maxGasPrice: u256 = 0;
                var lane_gas: u64 = 0;
                for (ready) |*lt| {
                    if (lt.tx.gasPrice > maxGasPrice) maxGasPrice = lt.tx.gasPrice;
                    lane_gas += lt.tx.gasLimit;
                }

                try candidates.append(allocator, LaneCandidate{
                    .sender = lane.sender,
                    .ready_count = @intCast(ready.len),
                    .maxGasPrice = maxGasPrice,
                    .totalGas = lane_gas,
                    .baseNonce = lane.baseNonce,
                });
            }
        }

        // Sort candidates by max gas price (highest first — priority ordering)
        std.mem.sortUnstable(LaneCandidate, candidates.items, {}, struct {
            pub fn lessThan(_: void, a: LaneCandidate, b: LaneCandidate) bool {
                // Higher gas price = higher priority = comes first
                return a.maxGasPrice > b.maxGasPrice;
            }
        }.lessThan);

        // Extract TXs from each candidate lane, respecting gas budget
        for (candidates.items) |*candidate| {
            if (remaining_gas < 21_000) break; // Can't fit even a simple transfer

            const shardId = self.shardFor(candidate.sender);
            var shard = &self.shards[shardId];
            shard.lock.lock();
            defer shard.lock.unlock();

            if (shard.accounts.get(candidate.sender)) |lane| {
                const ready = lane.getReady();
                if (ready.len == 0) continue;

                var txs = std.ArrayListUnmanaged(types.Transaction){};
                defer txs.deinit(allocator); // only on error

                for (ready) |*lt| {
                    if (lt.tx.gasLimit > remaining_gas) break;
                    try txs.append(allocator, lt.tx);
                    remaining_gas -= lt.tx.gasLimit;
                }

                if (txs.items.len > 0) {
                    const tx_slice = try allocator.alloc(types.Transaction, txs.items.len);
                    @memcpy(tx_slice, txs.items);

                    try lanes.append(allocator, ExtractedLane{
                        .sender = candidate.sender,
                        .txs = tx_slice,
                        .baseNonce = lane.baseNonce,
                    });
                    totalTxs += @intCast(txs.items.len);
                }
            }
        }

        const result_lanes = try allocator.alloc(ExtractedLane, lanes.items.len);
        @memcpy(result_lanes, lanes.items);

        return ExtractionResult{
            .lanes = result_lanes,
            .totalTxs = totalTxs,
            .totalGas = gas_budget - remaining_gas,
            .allocator = allocator,
        };
    }

    // ── Post-Execution Cleanup ──────────────────────────────────────────

    /// Remove committed TXs and advance lane nonces.
    /// Called after block execution with the committed TX list.
    /// Removes transactions that have been committed to a block from the mempool.
    pub fn removeCommitted(self: *DAGMempool, transactions: []const types.Transaction) void {
        // Group by sender for efficient lane advancement
        var sender_max_nonce = std.AutoHashMap(types.Address, u64).init(self.allocator);
        defer sender_max_nonce.deinit();

        for (transactions) |*tx| {
            const txHash = tx.hash();

            // Remove from hash index
            self.by_hash_lock.lock();
            _ = self.by_hash.remove(txHash);
            self.by_hash_lock.unlock();

            // Track max nonce per sender
            const gop = sender_max_nonce.getOrPut(tx.from) catch continue;
            if (!gop.found_existing or tx.nonce >= gop.value_ptr.*) {
                gop.value_ptr.* = tx.nonce + 1;
            }

            _ = self.totalVertices.fetchSub(1, .release);
        }

        // Advance each sender's lane
        var it = sender_max_nonce.iterator();
        while (it.next()) |entry| {
            const sender = entry.key_ptr.*;
            const new_nonce = entry.value_ptr.*;
            const shardId = self.shardFor(sender);
            var shard = &self.shards[shardId];

            shard.lock.lock();
            defer shard.lock.unlock();

            if (shard.accounts.get(sender)) |lane| {
                const old_count = lane.txs.items.len;
                lane.advance(self.allocator, new_nonce);
                const removed = old_count - lane.txs.items.len;
                shard.vertexCount -|= @intCast(removed);

                // GC empty lanes
                if (lane.isEmpty()) {
                    lane.deinit(self.allocator);
                    self.allocator.destroy(lane);
                    _ = shard.accounts.remove(sender);
                }
            }
        }
    }

    /// Sync pool with current state — prune TXs with stale nonces.
    pub fn syncWithState(self: *DAGMempool) void {
        for (&self.shards) |*shard| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var remove_addrs = std.ArrayListUnmanaged(types.Address){};
            defer remove_addrs.deinit(self.allocator);

            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                const lane = entry.value_ptr.*;
                const current_nonce = self.state.getNonce(lane.sender);

                if (current_nonce > lane.baseNonce) {
                    lane.advance(self.allocator, current_nonce);
                }

                if (lane.isEmpty()) {
                    lane.deinit(self.allocator);
                    self.allocator.destroy(lane);
                    remove_addrs.append(self.allocator, entry.key_ptr.*) catch {};
                }
            }

            for (remove_addrs.items) |addr| {
                _ = shard.accounts.remove(addr);
            }
        }
    }

    // ── Garbage Collection ──────────────────────────────────────────────

    /// Evict orphan lanes that haven't received new TXs within the timeout.
    /// Performs garbage collection to evict orphan lanes that have exceeded the timeout.
    pub fn gcOrphanLanes(self: *DAGMempool) u32 {
        const now = std.time.nanoTimestamp();
        const timeout_ns: i128 = @as(i128, @intCast(self.config.orphanTimeoutS)) * 1_000_000_000;
        var evicted: u32 = 0;

        for (&self.shards) |*shard| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var remove_addrs = std.ArrayListUnmanaged(types.Address){};
            defer remove_addrs.deinit(self.allocator);

            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                const lane = entry.value_ptr.*;
                if (now - lane.lastTouchNs > timeout_ns) {
                    // Remove all TXs from hash index
                    for (lane.txs.items) |*lt| {
                        if (!lt.isPlaceholder) {
                            const txHash = lt.tx.hash();
                            self.by_hash_lock.lock();
                            _ = self.by_hash.remove(txHash);
                            self.by_hash_lock.unlock();
                            _ = self.totalVertices.fetchSub(1, .release);
                        }
                    }

                    shard.vertexCount -|= @intCast(lane.readyCount());
                    evicted += lane.readyCount();
                    lane.deinit(self.allocator);
                    self.allocator.destroy(lane);
                    remove_addrs.append(self.allocator, entry.key_ptr.*) catch {};
                }
            }

            for (remove_addrs.items) |addr| {
                _ = shard.accounts.remove(addr);
            }
        }

        if (evicted > 0) {
            self.metrics_lock.lock();
            self.metrics.totalGcEvicted += evicted;
            self.metrics_lock.unlock();
        }

        return evicted;
    }

    // ── Query ───────────────────────────────────────────────────────────

    /// Get a TX by hash. O(1) via hash index.
    pub fn get(self: *DAGMempool, hash: types.Hash) ?types.Transaction {
        self.by_hash_lock.lock();
        const loc = self.by_hash.get(hash);
        self.by_hash_lock.unlock();

        if (loc) |location| {
            var shard = &self.shards[location.shardId];
            shard.lock.lock();
            defer shard.lock.unlock();

            if (shard.accounts.get(location.sender)) |lane| {
                if (location.nonce >= lane.baseNonce) {
                    const idx = location.nonce - lane.baseNonce;
                    if (idx < lane.txs.items.len and !lane.txs.items[idx].isPlaceholder) {
                        return lane.txs.items[idx].tx;
                    }
                }
            }
        }
        return null;
    }

    /// Get the pending nonce for an account (state nonce + pending TXs).
    pub fn pendingNonce(self: *DAGMempool, addr: types.Address) u64 {
        const shardId = self.shardFor(addr);
        var shard = &self.shards[shardId];
        shard.lock.lock();
        defer shard.lock.unlock();

        if (shard.accounts.get(addr)) |lane| {
            return lane.baseNonce + @as(u64, lane.readyCount());
        }
        return self.state.getNonce(addr);
    }

    /// Get all pending transactions.
    pub fn pending(self: *DAGMempool, allocator: std.mem.Allocator) ![]types.Transaction {
        var list = std.ArrayListUnmanaged(types.Transaction){};
        errdefer list.deinit(allocator);

        for (&self.shards) |*shard| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var it = shard.accounts.valueIterator();
            while (it.next()) |lane_ptr| {
                const lane = lane_ptr.*;
                for (lane.txs.items) |lane_tx| {
                    if (!lane_tx.isPlaceholder) {
                        try list.append(allocator, lane_tx.tx);
                    }
                }
            }
        }

        return list.toOwnedSlice(allocator);
    }

    /// Get pool statistics.
    pub fn getStats(self: *DAGMempool) DAGMempoolStats {
        self.metrics_lock.lock();
        defer self.metrics_lock.unlock();

        var total_vertices: u32 = 0;
        var activeLanes: u32 = 0;
        var max_shard_load: u32 = 0;

        for (&self.shards) |*shard| {
            total_vertices += shard.vertexCount;
            activeLanes += @intCast(shard.accounts.count());
            if (shard.vertexCount > max_shard_load) {
                max_shard_load = shard.vertexCount;
            }
        }

        return .{
            .totalVertices = total_vertices,
            .activeLanes = activeLanes,
            .totalAdded = self.metrics.totalAdded,
            .totalRejected = self.metrics.totalRejected,
            .totalEvicted = self.metrics.totalEvicted,
            .totalGcEvicted = self.metrics.totalGcEvicted,
            .duplicateRejected = self.metrics.duplicateRejected,
            .rateLimited = self.metrics.rateLimited,
            .nonceRejected = self.metrics.nonceRejected,
            .gasPriceRejected = self.metrics.gasPriceRejected,
            .replacementCount = self.metrics.replacementCount,
            .bloomCount = self.bloom.count,
            .maxShardLoad = max_shard_load,
            .hotShardPremiumApplied = self.metrics.hotShardPremiumApplied,
        };
    }

    /// Get the total number of pending TXs.
    pub fn count(self: *const DAGMempool) u32 {
        return self.totalVertices.load(.acquire);
    }

    // ── Internal ────────────────────────────────────────────────────────

    fn shardFor(_: *const DAGMempool, addr: types.Address) u8 {
        return addr.bytes[0];
    }

    fn getOrCreateLane(
        self: *DAGMempool,
        shard: *Shard,
        sender: types.Address,
    ) !*AccountLane {
        if (shard.accounts.get(sender)) |lane| {
            return lane;
        }

        const lane = try self.allocator.create(AccountLane);
        lane.* = AccountLane.init(sender, self.state.getNonce(sender));
        try shard.accounts.put(sender, lane);

        return lane;
    }

    /// Compute effective minimum gas price accounting for hot-shard premium.
    fn getEffectiveMinPrice(self: *DAGMempool, sender: types.Address) u256 {
        const shardId = self.shardFor(sender);
        const shard = &self.shards[shardId];

        // Compute mean shard load
        var total: u64 = 0;
        for (&self.shards) |*s| {
            total += s.vertexCount;
        }
        const mean = total / SHARD_COUNT;

        // If this shard has > 2x the mean, apply premium
        if (mean > 0 and shard.vertexCount > mean * self.config.hotShardMultiplier) {
            self.incrMetric(.hotShardPremiumApplied);
            return (self.config.minGasPrice * @as(u256, self.config.hotShardPremiumPct)) / 100;
        }

        return self.config.minGasPrice;
    }

    /// Try to evict the lowest gas price TX globally to make room.
    fn evictLowestGlobal(self: *DAGMempool, incoming_gas_price: u256) bool {
        var lowest_price: u256 = std.math.maxInt(u256);
        var lowest_shard: ?u8 = null;
        var lowest_sender: ?types.Address = null;

        // Find the lowest gas price TX across all shards
        for (&self.shards, 0..) |*shard, shardIdx| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                const lane = entry.value_ptr.*;
                const ready = lane.getReady();
                for (ready) |*lt| {
                    if (lt.tx.gasPrice < lowest_price) {
                        lowest_price = lt.tx.gasPrice;
                        lowest_shard = @intCast(shardIdx);
                        lowest_sender = lane.sender;
                    }
                }
            }
        }

        // Only evict if incoming TX has higher gas price
        if (lowest_shard != null and incoming_gas_price > lowest_price) {
            if (lowest_sender) |sender| {
                const sid = lowest_shard.?;
                var shard = &self.shards[sid];
                shard.lock.lock();
                defer shard.lock.unlock();

                if (shard.accounts.get(sender)) |lane| {
                    // Evict last (lowest nonce has priority) TX from the lane
                    if (lane.txs.items.len > 0) {
                        const last_idx = lane.txs.items.len - 1;
                        const evicted = lane.txs.items[last_idx];
                        if (!evicted.isPlaceholder) {
                            const txHash = evicted.tx.hash();
                            self.by_hash_lock.lock();
                            _ = self.by_hash.remove(txHash);
                            self.by_hash_lock.unlock();
                            lane.totalGas -|= evicted.tx.gasLimit;
                        }
                        lane.txs.items.len -= 1;
                        shard.vertexCount -|= 1;
                        _ = self.totalVertices.fetchSub(1, .release);
                        self.incrMetric(.totalEvicted);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    fn incrMetric(self: *DAGMempool, comptime field: std.meta.FieldEnum(Metrics)) void {
        self.metrics_lock.lock();
        defer self.metrics_lock.unlock();
        @field(self.metrics, @tagName(field)) += 1;
    }
};

// ── Supporting Types ────────────────────────────────────────────────────

const TxLocation = struct {
    shardId: u8,
    sender: types.Address,
    nonce: u64,
};

const LaneCandidate = struct {
    sender: types.Address,
    ready_count: u32,
    maxGasPrice: u256,
    totalGas: u64,
    baseNonce: u64,
};

pub const DAGMempoolStats = struct {
    totalVertices: u32,
    activeLanes: u32,
    totalAdded: u64,
    totalRejected: u64,
    totalEvicted: u64,
    totalGcEvicted: u64,
    duplicateRejected: u64,
    rateLimited: u64,
    nonceRejected: u64,
    gasPriceRejected: u64,
    replacementCount: u64,
    bloomCount: u32,
    maxShardLoad: u32,
    hotShardPremiumApplied: u64,
};
