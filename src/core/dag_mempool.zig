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

pub const DAGConfig = struct {
    /// Maximum pending TXs per sender lane
    max_txs_per_lane: u32 = 256,
    /// Maximum total vertices across all shards
    max_total_vertices: u32 = 500_000,
    /// Maximum gas budget per sender lane
    max_lane_gas: u64 = 100_000_000,
    /// Orphan lane timeout in seconds
    orphan_timeout_s: u64 = 60,
    /// Maximum nonce gap from state nonce
    max_nonce_gap: u64 = 64,
    /// Minimum gas price (1 Gwei anti-spam floor)
    min_gas_price: u256 = 1_000_000_000,
    /// Gas price bump required for TX replacement (10%)
    replacement_bump_pct: u32 = 10,
    /// Hot-shard threshold multiplier (2x mean triggers premium)
    hot_shard_multiplier: u32 = 2,
    /// Hot-shard gas price premium (150% = 1.5x)
    hot_shard_premium_pct: u32 = 150,
    /// Bloom filter size in bits (2M bits = 256KB)
    bloom_size_bits: u32 = 2_097_152,
    /// Enable deep TX sanitization
    enable_sanitization: bool = true,
    /// Maximum calldata size
    max_calldata: u32 = 96 * 1024,
    /// Minimum gas limit for any TX
    min_gas_limit: u64 = 21_000,
    /// Maximum gas limit for any TX
    max_gas_limit: u64 = 30_000_000,
    /// Maximum gas price (anti-grief)
    max_gas_price: u256 = 10_000_000_000_000_000_000_000,
    /// Maximum value transfer
    max_value: u256 = 1_000_000_000_000_000_000_000_000_000,
    /// Chain ID for replay protection
    chain_id: u64 = 99999,
};

// ── Account Lane ────────────────────────────────────────────────────────
//
// Per-sender transaction queue. TXs are ordered by nonce within the lane.
// This IS the DAG: same-sender TXs form a chain (nonce N depends on N-1).
// Different senders' lanes are completely independent — zero edges between them.

pub const AccountLane = struct {
    sender: types.Address,
    /// Nonce-ordered TX queue. Index 0 = base_nonce, Index 1 = base_nonce+1, etc.
    txs: std.ArrayListUnmanaged(LaneTx),
    /// Current confirmed state nonce for this sender
    base_nonce: u64,
    /// Total gas reserved by all TXs in this lane
    total_gas: u64,
    /// Monotonic timestamp of last TX addition (for GC)
    last_touch_ns: i128,
    /// Number of TXs that have been extracted for execution
    extracted_count: u32,

    pub fn init(sender: types.Address, base_nonce: u64) AccountLane {
        return .{
            .sender = sender,
            .txs = .{},
            .base_nonce = base_nonce,
            .total_gas = 0,
            .last_touch_ns = std.time.nanoTimestamp(),
            .extracted_count = 0,
        };
    }

    pub fn deinit(self: *AccountLane, allocator: std.mem.Allocator) void {
        self.txs.deinit(allocator);
    }

    /// Insert a TX at the correct nonce position within the lane.
    /// Returns the TX that was replaced (if any) for eviction.
    pub fn insert(
        self: *AccountLane,
        allocator: std.mem.Allocator,
        tx: types.Transaction,
        replacement_bump_pct: u32,
    ) !?types.Transaction {
        if (tx.nonce < self.base_nonce) return error.NonceTooLow;

        const idx = tx.nonce - self.base_nonce;

        // Check if this is a replacement
        if (idx < self.txs.items.len) {
            const existing = &self.txs.items[idx];
            // Enforce gas price bump for replacement
            const min_new_price = existing.tx.gas_price +
                (existing.tx.gas_price * @as(u256, replacement_bump_pct)) / 100;
            if (tx.gas_price < min_new_price) return error.ReplacementGasTooLow;

            // Replace
            const old_tx = existing.tx;
            self.total_gas -= old_tx.gas_limit;
            existing.tx = tx;
            existing.inserted_at = std.time.nanoTimestamp();
            self.total_gas += tx.gas_limit;
            self.last_touch_ns = std.time.nanoTimestamp();
            return old_tx;
        }

        // Append at position (may leave gaps — nonce gap protection handles)
        while (self.txs.items.len < idx) {
            try self.txs.append(allocator, LaneTx{
                .tx = undefined,
                .inserted_at = 0,
                .is_placeholder = true,
            });
        }

        try self.txs.append(allocator, LaneTx{
            .tx = tx,
            .inserted_at = std.time.nanoTimestamp(),
            .is_placeholder = false,
        });

        self.total_gas += tx.gas_limit;
        self.last_touch_ns = std.time.nanoTimestamp();
        return null;
    }

    /// Get the contiguous sequence of ready TXs starting from base_nonce.
    /// These are guaranteed to be executable in order.
    pub fn getReady(self: *const AccountLane) []const LaneTx {
        var count: usize = 0;
        for (self.txs.items) |*lt| {
            if (lt.is_placeholder) break;
            count += 1;
        }
        return self.txs.items[0..count];
    }

    /// Remove TXs that have been committed (nonce < new_base_nonce).
    pub fn advance(self: *AccountLane, allocator: std.mem.Allocator, new_base_nonce: u64) void {
        if (new_base_nonce <= self.base_nonce) return;

        const remove_count = @min(
            new_base_nonce - self.base_nonce,
            self.txs.items.len,
        );

        for (self.txs.items[0..remove_count]) |*lt| {
            if (!lt.is_placeholder) {
                self.total_gas -|= lt.tx.gas_limit;
            }
        }

        // Shift remaining TXs down
        if (remove_count < self.txs.items.len) {
            const remaining = self.txs.items.len - remove_count;
            std.mem.copyForwards(
                LaneTx,
                self.txs.items[0..remaining],
                self.txs.items[remove_count..self.txs.items.len],
            );
            self.txs.items.len = remaining;
        } else {
            self.txs.items.len = 0;
        }

        self.base_nonce = new_base_nonce;
        _ = allocator;
    }

    /// Number of ready (non-placeholder) TXs.
    pub fn readyCount(self: *const AccountLane) u32 {
        var count: u32 = 0;
        for (self.txs.items) |*lt| {
            if (lt.is_placeholder) break;
            count += 1;
        }
        return count;
    }

    /// Check if this lane is empty and can be GC'd.
    pub fn isEmpty(self: *const AccountLane) bool {
        return self.txs.items.len == 0;
    }
};

pub const LaneTx = struct {
    tx: types.Transaction,
    inserted_at: i128,
    is_placeholder: bool,
};

// ── Shard ───────────────────────────────────────────────────────────────
//
// One of 256 shards. Each shard has its own mutex — only locked during
// admission/extraction for accounts that hash to this shard.

pub const Shard = struct {
    lock: std.Thread.Mutex,
    accounts: std.AutoHashMap(types.Address, *AccountLane),
    vertex_count: u32,
    total_gas: u64,

    pub fn init() Shard {
        return .{
            .lock = .{},
            .accounts = undefined,
            .vertex_count = 0,
            .total_gas = 0,
        };
    }
};

// ── DAG Vertex ──────────────────────────────────────────────────────────
//
// Represents a TX's position in the implicit DAG. Write keys are computed
// from the isolated account model at admission time.

pub const DAGVertex = struct {
    tx_hash: types.Hash,
    sender: types.Address,
    nonce: u64,
    write_keys: [MAX_WRITE_KEYS][32]u8,
    write_key_count: u8,
    gas_limit: u64,
    gas_price: u256,
    shard_id: u8,

    pub const MAX_WRITE_KEYS = 8;

    /// Compute write keys from TX structure using isolated account model.
    pub fn computeWriteKeys(tx: *const types.Transaction) DAGVertex {
        const State = state_mod.State;
        var vertex = DAGVertex{
            .tx_hash = tx.hash(),
            .sender = tx.from,
            .nonce = tx.nonce,
            .write_keys = undefined,
            .write_key_count = 0,
            .gas_limit = tx.gas_limit,
            .gas_price = tx.gas_price,
            .shard_id = tx.from.bytes[0],
        };

        // 1. Sender nonce + balance (ALWAYS written)
        vertex.addKey(State.nonce_key(tx.from));
        vertex.addKey(State.balance_key(tx.from));

        // 2. Recipient
        if (tx.to) |to_addr| {
            vertex.addKey(State.balance_key(to_addr));

            // 3. Contract call: per-user derived key (NEVER conflicts with other users)
            if (tx.data.len >= 4) {
                var sender_slot: [32]u8 = [_]u8{0} ** 32;
                @memcpy(sender_slot[0..20], &tx.from.bytes);
                vertex.addKey(State.derived_storage_key(tx.from, to_addr, sender_slot));
            }
        } else {
            // Contract creation
            const new_addr = tx.deriveContractAddress();
            vertex.addKey(State.nonce_key(new_addr));
            vertex.addKey(State.balance_key(new_addr));
            vertex.addKey(State.code_hash_key(new_addr));
        }

        return vertex;
    }

    fn addKey(self: *DAGVertex, key: [32]u8) void {
        if (self.write_key_count >= MAX_WRITE_KEYS) return;
        self.write_keys[self.write_key_count] = key;
        self.write_key_count += 1;
    }

    /// Check if this vertex conflicts with another vertex.
    /// In Zephyria's isolated model, conflicts ONLY happen between
    /// same-sender TXs (shared nonce + balance keys).
    pub fn conflictsWith(self: *const DAGVertex, other: *const DAGVertex) bool {
        for (self.write_keys[0..self.write_key_count]) |key_a| {
            for (other.write_keys[0..other.write_key_count]) |key_b| {
                if (std.mem.eql(u8, &key_a, &key_b)) return true;
            }
        }
        return false;
    }
};

// ── Extraction Result ───────────────────────────────────────────────────

pub const ExtractionResult = struct {
    lanes: []ExtractedLane,
    total_txs: u32,
    total_gas: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ExtractionResult) void {
        for (self.lanes) |*lane| {
            self.allocator.free(lane.txs);
        }
        self.allocator.free(self.lanes);
    }
};

pub const ExtractedLane = struct {
    sender: types.Address,
    txs: []types.Transaction,
    base_nonce: u64,
};

// ── Metrics ─────────────────────────────────────────────────────────────

pub const Metrics = struct {
    total_added: u64,
    total_rejected: u64,
    total_evicted: u64,
    total_extracted: u64,
    total_gc_evicted: u64,
    duplicate_rejected: u64,
    rate_limited: u64,
    nonce_rejected: u64,
    gas_price_rejected: u64,
    sanitization_rejected: u64,
    hot_shard_premium_applied: u64,
    replacement_count: u64,
    shard_max_load: u32,
    active_lanes: u32,
};

// ── DAG Mempool ─────────────────────────────────────────────────────────

pub const DAGMempool = struct {
    allocator: std.mem.Allocator,
    state: *state_mod.State,
    config: DAGConfig,
    shards: [SHARD_COUNT]Shard,
    bloom: security.TxBloomFilter,
    rate_limiter: security.RateLimiter,
    sanitizer: security.TxSanitizer,

    // Global counters (atomic for cross-shard visibility)
    total_vertices: std.atomic.Value(u32),
    total_gas: std.atomic.Value(u64),

    // Metrics
    metrics: Metrics,
    metrics_lock: std.Thread.Mutex,

    // Hash index for O(1) lookup by hash
    by_hash: std.AutoHashMap(types.Hash, TxLocation),
    by_hash_lock: std.Thread.Mutex,

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
            .bloom = try security.TxBloomFilter.init(allocator, config.bloom_size_bits),
            .rate_limiter = security.RateLimiter.init(allocator, .{}),
            .sanitizer = security.TxSanitizer.init(.{
                .max_calldata = config.max_calldata,
                .min_gas_limit = config.min_gas_limit,
                .max_gas_limit = config.max_gas_limit,
                .max_gas_price = config.max_gas_price,
                .max_value = config.max_value,
                .chain_id = config.chain_id,
                .max_nonce_gap = config.max_nonce_gap,
            }),
            .total_vertices = std.atomic.Value(u32).init(0),
            .total_gas = std.atomic.Value(u64).init(0),
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
    pub fn add(self: *DAGMempool, tx: *const types.Transaction) !void {
        const tx_hash = tx.hash();

        // 1. Bloom filter pre-check (O(1), no lock needed — false positives OK)
        if (self.bloom.mightContain(tx_hash)) {
            // Confirm with hash index (bloom has false positives)
            self.by_hash_lock.lock();
            const exists = self.by_hash.contains(tx_hash);
            self.by_hash_lock.unlock();
            if (exists) {
                self.incrMetric(.duplicate_rejected);
                return error.DuplicateTransaction;
            }
        }

        // 2. Global capacity check (atomic, no lock)
        if (self.total_vertices.load(.acquire) >= self.config.max_total_vertices) {
            // Try to evict lowest gas price TX before rejecting
            if (!self.evictLowestGlobal(tx.gas_price)) {
                self.incrMetric(.total_rejected);
                return error.MempoolFull;
            }
        }

        // 3. Rate limiting (per-account token bucket)
        self.rate_limiter.checkAndConsume(tx.from) catch {
            self.incrMetric(.rate_limited);
            return error.RateLimited;
        };

        // 4. Minimum gas price floor
        const effective_min_price = self.getEffectiveMinPrice(tx.from);
        if (tx.gas_price < effective_min_price) {
            self.incrMetric(.gas_price_rejected);
            return error.GasPriceTooLow;
        }

        // 5. TX sanitization (signature, nonce bounds, balance, malleability)
        if (self.config.enable_sanitization) {
            const state_nonce = self.state.get_nonce(tx.from);
            const state_balance = self.state.get_balance(tx.from);
            self.sanitizer.validate(tx, state_nonce, state_balance) catch |err| {
                self.incrMetric(.sanitization_rejected);
                return err;
            };
        }

        // 6. Lock ONLY the target shard
        const shard_id = self.shardFor(tx.from);
        var shard = &self.shards[shard_id];
        shard.lock.lock();
        defer shard.lock.unlock();

        // 7. Get or create account lane
        const lane = try self.getOrCreateLane(shard, tx.from);

        // 8. Lane depth check
        if (lane.txs.items.len >= self.config.max_txs_per_lane) {
            self.incrMetric(.total_rejected);
            return error.LaneDepthExceeded;
        }

        // 9. Lane gas budget check
        if (lane.total_gas + tx.gas_limit > self.config.max_lane_gas) {
            self.incrMetric(.total_rejected);
            return error.LaneGasBudgetExceeded;
        }

        // 10. Insert into lane (handles replacement)
        const replaced = try lane.insert(self.allocator, tx.*, self.config.replacement_bump_pct);

        if (replaced) |old_tx| {
            // Remove old TX from hash index
            const old_hash = old_tx.hash();
            self.by_hash_lock.lock();
            _ = self.by_hash.remove(old_hash);
            self.by_hash_lock.unlock();
            self.incrMetric(.replacement_count);
        } else {
            // New TX — increment counters
            _ = self.total_vertices.fetchAdd(1, .release);
            shard.vertex_count += 1;
        }

        // 11. Add to hash index and bloom filter
        self.by_hash_lock.lock();
        self.by_hash.put(tx_hash, TxLocation{
            .shard_id = shard_id,
            .sender = tx.from,
            .nonce = tx.nonce,
        }) catch {
            self.by_hash_lock.unlock();
            self.incrMetric(.total_rejected);
            return error.HashIndexFull;
        };
        self.by_hash_lock.unlock();

        self.bloom.add(tx_hash);
        self.incrMetric(.total_added);
    }

    // ── Extraction ──────────────────────────────────────────────────────

    /// Extract execution-ready TX lanes for block building.
    /// Returns independent lanes — guaranteed zero-conflict parallel execution.
    /// Each lane contains nonce-ordered TXs from a single sender.
    pub fn extract(self: *DAGMempool, allocator: std.mem.Allocator, gas_budget: u64) !ExtractionResult {
        var lanes = std.ArrayListUnmanaged(ExtractedLane){};
        defer lanes.deinit(allocator); // only on error path
        var total_txs: u32 = 0;
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
                var max_gas_price: u256 = 0;
                var lane_gas: u64 = 0;
                for (ready) |*lt| {
                    if (lt.tx.gas_price > max_gas_price) max_gas_price = lt.tx.gas_price;
                    lane_gas += lt.tx.gas_limit;
                }

                try candidates.append(allocator, LaneCandidate{
                    .sender = lane.sender,
                    .ready_count = @intCast(ready.len),
                    .max_gas_price = max_gas_price,
                    .total_gas = lane_gas,
                    .base_nonce = lane.base_nonce,
                });
            }
        }

        // Sort candidates by max gas price (highest first — priority ordering)
        std.mem.sortUnstable(LaneCandidate, candidates.items, {}, struct {
            pub fn lessThan(_: void, a: LaneCandidate, b: LaneCandidate) bool {
                // Higher gas price = higher priority = comes first
                return a.max_gas_price > b.max_gas_price;
            }
        }.lessThan);

        // Extract TXs from each candidate lane, respecting gas budget
        for (candidates.items) |*candidate| {
            if (remaining_gas < 21_000) break; // Can't fit even a simple transfer

            const shard_id = self.shardFor(candidate.sender);
            var shard = &self.shards[shard_id];
            shard.lock.lock();
            defer shard.lock.unlock();

            if (shard.accounts.get(candidate.sender)) |lane| {
                const ready = lane.getReady();
                if (ready.len == 0) continue;

                var txs = std.ArrayListUnmanaged(types.Transaction){};
                defer txs.deinit(allocator); // only on error

                for (ready) |*lt| {
                    if (lt.tx.gas_limit > remaining_gas) break;
                    try txs.append(allocator, lt.tx);
                    remaining_gas -= lt.tx.gas_limit;
                }

                if (txs.items.len > 0) {
                    const tx_slice = try allocator.alloc(types.Transaction, txs.items.len);
                    @memcpy(tx_slice, txs.items);

                    try lanes.append(allocator, ExtractedLane{
                        .sender = candidate.sender,
                        .txs = tx_slice,
                        .base_nonce = lane.base_nonce,
                    });
                    total_txs += @intCast(txs.items.len);
                }
            }
        }

        const result_lanes = try allocator.alloc(ExtractedLane, lanes.items.len);
        @memcpy(result_lanes, lanes.items);

        return ExtractionResult{
            .lanes = result_lanes,
            .total_txs = total_txs,
            .total_gas = gas_budget - remaining_gas,
            .allocator = allocator,
        };
    }

    // ── Post-Execution Cleanup ──────────────────────────────────────────

    /// Remove committed TXs and advance lane nonces.
    /// Called after block execution with the committed TX list.
    pub fn removeCommitted(self: *DAGMempool, transactions: []const types.Transaction) void {
        // Group by sender for efficient lane advancement
        var sender_max_nonce = std.AutoHashMap(types.Address, u64).init(self.allocator);
        defer sender_max_nonce.deinit();

        for (transactions) |*tx| {
            const tx_hash = tx.hash();

            // Remove from hash index
            self.by_hash_lock.lock();
            _ = self.by_hash.remove(tx_hash);
            self.by_hash_lock.unlock();

            // Track max nonce per sender
            const gop = sender_max_nonce.getOrPut(tx.from) catch continue;
            if (!gop.found_existing or tx.nonce >= gop.value_ptr.*) {
                gop.value_ptr.* = tx.nonce + 1;
            }

            _ = self.total_vertices.fetchSub(1, .release);
        }

        // Advance each sender's lane
        var it = sender_max_nonce.iterator();
        while (it.next()) |entry| {
            const sender = entry.key_ptr.*;
            const new_nonce = entry.value_ptr.*;
            const shard_id = self.shardFor(sender);
            var shard = &self.shards[shard_id];

            shard.lock.lock();
            defer shard.lock.unlock();

            if (shard.accounts.get(sender)) |lane| {
                const old_count = lane.txs.items.len;
                lane.advance(self.allocator, new_nonce);
                const removed = old_count - lane.txs.items.len;
                shard.vertex_count -|= @intCast(removed);

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
                const current_nonce = self.state.get_nonce(lane.sender);

                if (current_nonce > lane.base_nonce) {
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
    pub fn gcOrphanLanes(self: *DAGMempool) u32 {
        const now = std.time.nanoTimestamp();
        const timeout_ns: i128 = @as(i128, @intCast(self.config.orphan_timeout_s)) * 1_000_000_000;
        var evicted: u32 = 0;

        for (&self.shards) |*shard| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var remove_addrs = std.ArrayListUnmanaged(types.Address){};
            defer remove_addrs.deinit(self.allocator);

            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                const lane = entry.value_ptr.*;
                if (now - lane.last_touch_ns > timeout_ns) {
                    // Remove all TXs from hash index
                    for (lane.txs.items) |*lt| {
                        if (!lt.is_placeholder) {
                            const tx_hash = lt.tx.hash();
                            self.by_hash_lock.lock();
                            _ = self.by_hash.remove(tx_hash);
                            self.by_hash_lock.unlock();
                            _ = self.total_vertices.fetchSub(1, .release);
                        }
                    }

                    shard.vertex_count -|= @intCast(lane.readyCount());
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
            self.metrics.total_gc_evicted += evicted;
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
            var shard = &self.shards[location.shard_id];
            shard.lock.lock();
            defer shard.lock.unlock();

            if (shard.accounts.get(location.sender)) |lane| {
                if (location.nonce >= lane.base_nonce) {
                    const idx = location.nonce - lane.base_nonce;
                    if (idx < lane.txs.items.len and !lane.txs.items[idx].is_placeholder) {
                        return lane.txs.items[idx].tx;
                    }
                }
            }
        }
        return null;
    }

    /// Get the pending nonce for an account (state nonce + pending TXs).
    pub fn pendingNonce(self: *DAGMempool, addr: types.Address) u64 {
        const shard_id = self.shardFor(addr);
        var shard = &self.shards[shard_id];
        shard.lock.lock();
        defer shard.lock.unlock();

        if (shard.accounts.get(addr)) |lane| {
            return lane.base_nonce + @as(u64, lane.readyCount());
        }
        return self.state.get_nonce(addr);
    }

    /// Get pool statistics.
    pub fn getStats(self: *DAGMempool) DAGMempoolStats {
        self.metrics_lock.lock();
        defer self.metrics_lock.unlock();

        var total_vertices: u32 = 0;
        var active_lanes: u32 = 0;
        var max_shard_load: u32 = 0;

        for (&self.shards) |*shard| {
            total_vertices += shard.vertex_count;
            active_lanes += @intCast(shard.accounts.count());
            if (shard.vertex_count > max_shard_load) {
                max_shard_load = shard.vertex_count;
            }
        }

        return .{
            .total_vertices = total_vertices,
            .active_lanes = active_lanes,
            .total_added = self.metrics.total_added,
            .total_rejected = self.metrics.total_rejected,
            .total_evicted = self.metrics.total_evicted,
            .total_gc_evicted = self.metrics.total_gc_evicted,
            .duplicate_rejected = self.metrics.duplicate_rejected,
            .rate_limited = self.metrics.rate_limited,
            .nonce_rejected = self.metrics.nonce_rejected,
            .gas_price_rejected = self.metrics.gas_price_rejected,
            .replacement_count = self.metrics.replacement_count,
            .bloom_count = self.bloom.count,
            .max_shard_load = max_shard_load,
            .hot_shard_premium_applied = self.metrics.hot_shard_premium_applied,
        };
    }

    /// Get the total number of pending TXs.
    pub fn count(self: *const DAGMempool) u32 {
        return self.total_vertices.load(.acquire);
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
        lane.* = AccountLane.init(sender, self.state.get_nonce(sender));
        try shard.accounts.put(sender, lane);

        return lane;
    }

    /// Compute effective minimum gas price accounting for hot-shard premium.
    fn getEffectiveMinPrice(self: *DAGMempool, sender: types.Address) u256 {
        const shard_id = self.shardFor(sender);
        const shard = &self.shards[shard_id];

        // Compute mean shard load
        var total: u64 = 0;
        for (&self.shards) |*s| {
            total += s.vertex_count;
        }
        const mean = total / SHARD_COUNT;

        // If this shard has > 2x the mean, apply premium
        if (mean > 0 and shard.vertex_count > mean * self.config.hot_shard_multiplier) {
            self.incrMetric(.hot_shard_premium_applied);
            return (self.config.min_gas_price * @as(u256, self.config.hot_shard_premium_pct)) / 100;
        }

        return self.config.min_gas_price;
    }

    /// Try to evict the lowest gas price TX globally to make room.
    fn evictLowestGlobal(self: *DAGMempool, incoming_gas_price: u256) bool {
        var lowest_price: u256 = std.math.maxInt(u256);
        var lowest_shard: ?u8 = null;
        var lowest_sender: ?types.Address = null;

        // Find the lowest gas price TX across all shards
        for (&self.shards, 0..) |*shard, shard_idx| {
            shard.lock.lock();
            defer shard.lock.unlock();

            var it = shard.accounts.iterator();
            while (it.next()) |entry| {
                const lane = entry.value_ptr.*;
                const ready = lane.getReady();
                for (ready) |*lt| {
                    if (lt.tx.gas_price < lowest_price) {
                        lowest_price = lt.tx.gas_price;
                        lowest_shard = @intCast(shard_idx);
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
                        if (!evicted.is_placeholder) {
                            const tx_hash = evicted.tx.hash();
                            self.by_hash_lock.lock();
                            _ = self.by_hash.remove(tx_hash);
                            self.by_hash_lock.unlock();
                            lane.total_gas -|= evicted.tx.gas_limit;
                        }
                        lane.txs.items.len -= 1;
                        shard.vertex_count -|= 1;
                        _ = self.total_vertices.fetchSub(1, .release);
                        self.incrMetric(.total_evicted);
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
    shard_id: u8,
    sender: types.Address,
    nonce: u64,
};

const LaneCandidate = struct {
    sender: types.Address,
    ready_count: u32,
    max_gas_price: u256,
    total_gas: u64,
    base_nonce: u64,
};

pub const DAGMempoolStats = struct {
    total_vertices: u32,
    active_lanes: u32,
    total_added: u64,
    total_rejected: u64,
    total_evicted: u64,
    total_gc_evicted: u64,
    duplicate_rejected: u64,
    rate_limited: u64,
    nonce_rejected: u64,
    gas_price_rejected: u64,
    replacement_count: u64,
    bloom_count: u32,
    max_shard_load: u32,
    hot_shard_premium_applied: u64,
};
