// ============================================================================
// Zephyria — Security Module
// ============================================================================
//
// Production-grade security primitives:
//   • Token-bucket rate limiting (per-IP and per-account)
//   • Deep TX sanitization (field bounds, signature malleability, replay)
//   • Anti-DoS policies (size limits, gas floor, mempool eviction)
//   • Reentrancy guard for state mutations
//   • Bloom filter for fast duplicate detection

const std = @import("std");
const types = @import("types.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

// ── Rate Limiter ────────────────────────────────────────────────────────

/// Token-bucket rate limiter.
/// Each bucket refills at `refill_rate` tokens per second up to `capacity`.
pub const RateLimiter = struct {
    buckets: std.AutoHashMap(types.Address, Bucket),
    global_bucket: Bucket,
    config: RateLimitConfig,
    lock: std.Thread.Mutex,

    pub const RateLimitConfig = struct {
        /// Max tokens per account bucket
        per_account_capacity: u32 = 64,
        /// Tokens refilled per second per account
        per_account_refill: u32 = 8,
        /// Max tokens in global bucket
        global_capacity: u32 = 50_000,
        /// Global refill rate per second
        global_refill: u32 = 10_000,
        /// Minimum interval between TXs from same sender (nanoseconds)
        min_tx_interval_ns: u64 = 10_000_000, // 10ms
    };

    const Bucket = struct {
        tokens: u32,
        last_refill: i64, // timestamp in seconds
        last_tx_ns: i128, // nanosecond timestamp of last TX

        fn refill(self: *Bucket, capacity: u32, rate: u32, now: i64) void {
            const elapsed = now - self.last_refill;
            if (elapsed <= 0) return;
            const added = @as(u32, @intCast(@min(
                @as(u64, @intCast(elapsed)) * @as(u64, rate),
                capacity,
            )));
            self.tokens = @min(self.tokens + added, capacity);
            self.last_refill = now;
        }

        fn consume(self: *Bucket) bool {
            if (self.tokens == 0) return false;
            self.tokens -= 1;
            return true;
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: RateLimitConfig) RateLimiter {
        const now = std.time.timestamp();
        return .{
            .buckets = std.AutoHashMap(types.Address, Bucket).init(allocator),
            .global_bucket = .{
                .tokens = config.global_capacity,
                .last_refill = now,
                .last_tx_ns = 0,
            },
            .config = config,
            .lock = .{},
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.buckets.deinit();
    }

    /// Check if a TX from `sender` is allowed. Returns error if rate limited.
    pub fn checkAndConsume(self: *RateLimiter, sender: types.Address) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const now = std.time.timestamp();
        const now_ns = std.time.nanoTimestamp();

        // 1. Global rate check
        self.global_bucket.refill(self.config.global_capacity, self.config.global_refill, now);
        if (!self.global_bucket.consume()) return error.GlobalRateLimited;

        // 2. Per-account rate check
        const gop = try self.buckets.getOrPut(sender);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .tokens = self.config.per_account_capacity,
                .last_refill = now,
                .last_tx_ns = 0,
            };
        }

        var bucket = gop.value_ptr;
        bucket.refill(self.config.per_account_capacity, self.config.per_account_refill, now);

        // 3. Minimum interval check
        if (bucket.last_tx_ns > 0) {
            const elapsed_ns = now_ns - bucket.last_tx_ns;
            if (elapsed_ns < self.config.min_tx_interval_ns) return error.TooFrequent;
        }

        if (!bucket.consume()) return error.AccountRateLimited;
        bucket.last_tx_ns = now_ns;
    }
};

// ── TX Sanitizer ────────────────────────────────────────────────────────

/// Deep transaction validation before pool admission.
pub const TxSanitizer = struct {
    config: SanitizerConfig,

    pub const SanitizerConfig = struct {
        /// Maximum TX size in bytes (calldata + overhead)
        max_tx_size: u32 = 128 * 1024, // 128 KB
        /// Maximum calldata size
        max_calldata: u32 = 96 * 1024, // 96 KB
        /// Minimum gas limit for any TX
        min_gas_limit: u64 = 21_000,
        /// Maximum gas limit for any TX
        max_gas_limit: u64 = 30_000_000,
        /// Maximum gas price (anti-grief: 10,000 ZEE per gas)
        max_gas_price: u256 = 10_000_000_000_000_000_000_000, // 10k ZEE
        /// Maximum value transfer
        max_value: u256 = 1_000_000_000_000_000_000_000_000_000, // 1B ZEE
        /// Chain ID for replay protection
        chain_id: u64 = 99999,
        /// Maximum nonce gap from current state nonce
        max_nonce_gap: u64 = 64,
    };

    pub fn init(config: SanitizerConfig) TxSanitizer {
        return .{ .config = config };
    }

    /// Validate a transaction. Returns error describing the rejection reason.
    pub fn validate(self: *const TxSanitizer, tx: *const types.Transaction, state_nonce: u64, state_balance: u256) !void {
        // 1. Calldata size check
        if (tx.data.len > self.config.max_calldata)
            return error.CalldataTooLarge;

        // 2. Gas limit bounds
        if (tx.gas_limit < self.config.min_gas_limit)
            return error.IntrinsicGasTooLow;
        if (tx.gas_limit > self.config.max_gas_limit)
            return error.GasLimitExceeded;

        // 3. Gas price sanity
        if (tx.gas_price > self.config.max_gas_price)
            return error.GasPriceTooHigh;

        // 4. Value sanity
        if (tx.value > self.config.max_value)
            return error.ValueTooHigh;

        // 5. Nonce validation
        if (tx.nonce < state_nonce)
            return error.NonceTooLow;
        if (tx.nonce > state_nonce + self.config.max_nonce_gap)
            return error.NonceTooHigh;

        // 6. Balance sufficiency (value + gas * gasPrice)
        const gas_cost = @as(u256, tx.gas_limit) * tx.gas_price;
        const total_cost = tx.value + gas_cost;
        if (total_cost > state_balance)
            return error.InsufficientFunds;

        // 7. Signature malleability check (s must be in lower half of curve order)
        // secp256k1 order N / 2
        const SECP256K1_N_DIV_2: u256 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
        if (tx.s > SECP256K1_N_DIV_2)
            return error.SignatureMalleability;

        // 8. Signature components must be non-zero
        if (tx.r == 0 or tx.s == 0)
            return error.InvalidSignature;

        // 9. Recovery ID must be 0 or 1
        if (tx.v > 1 and tx.v != 27 and tx.v != 28) {
            // EIP-155: v = chainId * 2 + 35 + recovery_id
            const expected_base = self.config.chain_id * 2 + 35;
            if (tx.v != expected_base and tx.v != expected_base + 1)
                return error.InvalidRecoveryId;
        }

        // 10. From address must not be zero (indicates failed recovery)
        const zero_addr = types.Address.zero();
        if (std.mem.eql(u8, &tx.from.bytes, &zero_addr.bytes))
            return error.ZeroSender;
    }
};

// ── Bloom Filter (Duplicate Detection) ──────────────────────────────────

/// Fast probabilistic duplicate detection using a counting bloom filter.
/// Used for O(1) TX hash deduplication in the mempool.
pub const TxBloomFilter = struct {
    bits: []u8,
    size: u32,
    count: u32,
    allocator: std.mem.Allocator,

    const NUM_HASHES = 4;

    pub fn init(allocator: std.mem.Allocator, size_bits: u32) !TxBloomFilter {
        const byte_size = (size_bits + 7) / 8;
        const bits = try allocator.alloc(u8, byte_size);
        @memset(bits, 0);
        return .{
            .bits = bits,
            .size = size_bits,
            .count = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TxBloomFilter) void {
        self.allocator.free(self.bits);
    }

    /// Add a TX hash to the bloom filter.
    pub fn add(self: *TxBloomFilter, hash: types.Hash) void {
        var positions: [NUM_HASHES]u32 = undefined;
        self.getPositions(hash, &positions);
        for (positions) |pos| {
            const byte_idx = pos / 8;
            const bit_idx: u3 = @intCast(pos % 8);
            self.bits[byte_idx] |= (@as(u8, 1) << bit_idx);
        }
        self.count += 1;
    }

    /// Check if a TX hash might be in the filter.
    /// False positives possible; false negatives impossible.
    pub fn mightContain(self: *const TxBloomFilter, hash: types.Hash) bool {
        var positions: [NUM_HASHES]u32 = undefined;
        self.getPositions(hash, &positions);
        for (positions) |pos| {
            const byte_idx = pos / 8;
            const bit_idx: u3 = @intCast(pos % 8);
            if ((self.bits[byte_idx] & (@as(u8, 1) << bit_idx)) == 0)
                return false;
        }
        return true;
    }

    /// Reset the bloom filter (e.g., on new epoch).
    pub fn reset(self: *TxBloomFilter) void {
        @memset(self.bits, 0);
        self.count = 0;
    }

    fn getPositions(self: *const TxBloomFilter, hash: types.Hash, out: *[NUM_HASHES]u32) void {
        // Use different 8-byte slices of the hash for each position
        for (0..NUM_HASHES) |i| {
            const offset = i * 8;
            const val = std.mem.readInt(u64, hash.bytes[offset..][0..8], .big);
            out[i] = @intCast(val % self.size);
        }
    }
};

// ── Reentrancy Guard ────────────────────────────────────────────────────

/// Execution-context reentrancy guard.
/// Prevents recursive state mutations during contract execution.
pub const ReentrancyGuard = struct {
    depth: u32 = 0,
    max_depth: u32 = 256,

    /// Enter a new execution context. Returns error if max depth exceeded.
    pub fn enter(self: *ReentrancyGuard) !void {
        if (self.depth >= self.max_depth) return error.MaxCallDepthExceeded;
        self.depth += 1;
    }

    /// Exit the current execution context.
    pub fn exit(self: *ReentrancyGuard) void {
        self.depth -|= 1;
    }

    /// Get current call depth.
    pub fn getDepth(self: *const ReentrancyGuard) u32 {
        return self.depth;
    }

    /// Reset to zero (between transactions).
    pub fn reset(self: *ReentrancyGuard) void {
        self.depth = 0;
    }
};

// ── Execution Timeout ───────────────────────────────────────────────────

/// Track execution time and enforce timeout.
pub const ExecutionTimer = struct {
    start_ns: i128,
    timeout_ns: i128,

    pub fn start(timeout_ms: u64) ExecutionTimer {
        return .{
            .start_ns = std.time.nanoTimestamp(),
            .timeout_ns = @as(i128, timeout_ms) * 1_000_000,
        };
    }

    /// Check if execution has exceeded the timeout.
    pub fn isExpired(self: *const ExecutionTimer) bool {
        const elapsed = std.time.nanoTimestamp() - self.start_ns;
        return elapsed > self.timeout_ns;
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsedMs(self: *const ExecutionTimer) u64 {
        const elapsed = std.time.nanoTimestamp() - self.start_ns;
        return @intCast(@divFloor(elapsed, 1_000_000));
    }
};

// ── Gas Metering ────────────────────────────────────────────────────────

/// Per-TX gas metering with overflow protection.
pub const GasMeter = struct {
    limit: u64,
    used: u64,

    pub fn init(limit: u64) GasMeter {
        return .{ .limit = limit, .used = 0 };
    }

    /// Consume gas. Returns error if limit exceeded.
    pub fn consume(self: *GasMeter, amount: u64) !void {
        const new_used = @addWithOverflow(self.used, amount);
        if (new_used[1] != 0) return error.GasOverflow;
        if (new_used[0] > self.limit) return error.OutOfGas;
        self.used = new_used[0];
    }

    /// Refund gas (e.g., SSTORE refund). Capped at used/5 per EIP-3529.
    pub fn refund(self: *GasMeter, amount: u64) void {
        const max_refund = self.used / 5;
        const actual = @min(amount, max_refund);
        self.used -|= actual;
    }

    pub fn remaining(self: *const GasMeter) u64 {
        return self.limit -| self.used;
    }
};

// ── Security Config (Aggregate) ─────────────────────────────────────────

/// Combined security configuration for the node.
pub const SecurityConfig = struct {
    rate_limit: RateLimiter.RateLimitConfig = .{},
    sanitizer: TxSanitizer.SanitizerConfig = .{},
    /// Maximum pending TXs in the pool
    max_pool_size: u32 = 50_000,
    /// Maximum pending TXs per account
    max_per_account: u32 = 64,
    /// Bloom filter size (bits) for dedup
    bloom_size: u32 = 1_048_576, // 1M bits = 128KB
    /// Execution timeout in milliseconds
    execution_timeout_ms: u64 = 5_000, // 5 seconds
    /// Maximum call depth
    max_call_depth: u32 = 256,
};

// ── DAG Security Configuration ──────────────────────────────────────────

/// Security parameters specific to the DAG-based mempool.
/// These protect against DAG-specific attack vectors:
///   • Lane depth bombs (filling one sender's lane)
///   • Hot-shard attacks (concentrating TXs on one shard)
///   • Nonce gap attacks (reserving lane slots with future nonces)
///   • Orphan lane memory exhaustion
///   • Malicious dependency injection
pub const DAGSecurityConfig = struct {
    /// Maximum pending TXs per sender lane.
    /// Prevents lane depth bomb attack where attacker fills a lane with
    /// max_nonce_gap sequential TXs each requiring separate validation.
    max_txs_per_lane: u32 = 256,

    /// Maximum total DAG vertices across all 256 shards.
    /// At 500K vertices with 21K gas each = 10.5B gas capacity.
    max_total_vertices: u32 = 500_000,

    /// Maximum gas budget per sender lane.
    /// Prevents a single sender from consuming entire block gas limit.
    max_lane_gas: u64 = 100_000_000, // 100M gas (10% of 1B block limit)

    /// Orphan lane timeout in seconds.
    /// Lanes with no new TXs after this period are garbage collected.
    /// Prevents memory exhaustion from abandoned accounts.
    orphan_timeout_s: u64 = 60,

    /// Maximum nonce gap from confirmed state nonce.
    /// Prevents attacker from creating placeholder entries in lanes
    /// by submitting TX with nonce = state_nonce + 64.
    max_nonce_gap: u64 = 64,

    /// Hot-shard detection multiplier.
    /// If any shard has > (mean × multiplier) vertices, gas price premium applies.
    /// This naturally distributes load across shards via economic pressure.
    hot_shard_multiplier: u32 = 2,

    /// Hot-shard gas price premium percentage (150 = 1.5× minimum gas price).
    /// Applied only when hot-shard threshold is exceeded.
    hot_shard_premium_pct: u32 = 150,

    /// Bloom filter size for DAG mempool (bits).
    /// 2M bits = 256KB, supports ~100K entries with <1% false positive rate.
    bloom_size_bits: u32 = 2_097_152,

    /// Maximum number of write keys per DAG vertex.
    /// Limits the cost of conflict detection per TX.
    max_write_keys_per_vertex: u8 = 8,

    /// Enable cross-lane conflict verification during block validation.
    /// Defense-in-depth: should never trigger in Zephyria's isolated model,
    /// but catches bugs or malicious block proposals.
    enable_cross_lane_verification: bool = true,

    /// Rate at which bloom filter is reset (every N blocks).
    /// Prevents bloom filter saturation over time.
    bloom_reset_interval_blocks: u32 = 1000,
};
