// ============================================================================
// Zephyria — Transaction Pool (Hardened)
// ============================================================================
//
// Production-grade mempool with:
//   • Deep TX sanitization via security module
//   • Bloom filter O(1) duplicate detection
//   • Per-account TX limits (max 64 pending per sender)
//   • Global pool cap (50K) with gas-price eviction
//   • Rate limiting integration
//   • Thread-safe concurrent access

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const TxList = @import("tx_list.zig").TxList;
const security = @import("security.zig");
const log = @import("logger.zig");

pub const PoolConfig = struct {
    max_pool_size: u32 = 50_000,
    max_per_account: u32 = 64,
    bloom_size: u32 = 1_048_576, // 1M bits
    enable_rate_limit: bool = true,
    enable_sanitization: bool = true,
    /// Minimum gas price to accept into pool (anti-spam floor)
    min_gas_price: u256 = 1_000_000_000, // 1 Gwei
    /// Gas price bump required for replacement (10%)
    replacement_bump_pct: u32 = 10,
};

pub const TxPool = struct {
    allocator: std.mem.Allocator,
    state: *state_mod.State,
    config: PoolConfig,
    // Per-account transaction lists (address → TxList)
    accounts: std.AutoHashMap(types.Address, *TxList),
    // Global hash index for O(1) lookup
    by_hash: std.AutoHashMap(types.Hash, *types.Transaction),
    // Bloom filter for fast duplicate detection
    bloom: security.TxBloomFilter,
    // TX sanitizer
    sanitizer: security.TxSanitizer,
    // Rate limiter
    rate_limiter: security.RateLimiter,
    // Total count
    count: u32,
    // Stats
    rejected_count: u64,
    evicted_count: u64,
    lock: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, state: *state_mod.State) TxPool {
        return TxPool{
            .allocator = allocator,
            .state = state,
            .config = PoolConfig{},
            .accounts = std.AutoHashMap(types.Address, *TxList).init(allocator),
            .by_hash = std.AutoHashMap(types.Hash, *types.Transaction).init(allocator),
            .bloom = security.TxBloomFilter.init(allocator, 1_048_576) catch @panic("bloom init"),
            .sanitizer = security.TxSanitizer.init(.{}),
            .rate_limiter = security.RateLimiter.init(allocator, .{}),
            .count = 0,
            .rejected_count = 0,
            .evicted_count = 0,
            .lock = .{},
        };
    }

    pub fn deinit(self: *TxPool) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.accounts.deinit();
        self.by_hash.deinit();
        self.bloom.deinit();
        self.rate_limiter.deinit();
    }

    /// Add a transaction to the pool after full security validation.
    pub fn add(self: *TxPool, tx: *types.Transaction) !void {
        const tx_hash = tx.hash();

        // 1. Rate limiting (RateLimiter has its own internal lock)
        if (self.config.enable_rate_limit) {
            self.rate_limiter.checkAndConsume(tx.from) catch {
                self.lock.lock();
                self.rejected_count += 1;
                self.lock.unlock();
                return error.RateLimited;
            };
        }

        // All remaining operations share the pool lock to avoid data races
        // on bloom, by_hash, counters, and account maps.
        self.lock.lock();
        defer self.lock.unlock();

        // 2. Bloom filter fast-path duplicate check
        if (self.bloom.mightContain(tx_hash)) {
            if (self.by_hash.contains(tx_hash)) {
                self.rejected_count += 1;
                return error.AlreadyKnown;
            }
        }

        // 3. Pool capacity check (evict if full)
        if (self.count >= self.config.max_pool_size) {
            if (!self.evictLowestGas(tx.gas_price)) {
                self.rejected_count += 1;
                return error.PoolFull;
            }
        }

        // 4. Minimum gas price floor
        if (tx.gas_price < self.config.min_gas_price) {
            self.rejected_count += 1;
            return error.GasPriceTooLow;
        }

        // 5. Deep TX sanitization
        if (self.config.enable_sanitization) {
            const sender_nonce = self.state.get_nonce(tx.from);
            const sender_balance = self.state.get_balance(tx.from);
            self.sanitizer.validate(tx, sender_nonce, sender_balance) catch |err| {
                self.rejected_count += 1;
                return err;
            };
        } else {
            if (tx.gas_limit < 21000) return error.GasLimitTooLow;
            const sender_balance = self.state.get_balance(tx.from);
            const max_cost = tx.gas_price * @as(u256, tx.gas_limit) + tx.value;
            if (sender_balance < max_cost) return error.InsufficientBalance;
        }

        // 6. Per-account limit check
        const gop = try self.accounts.getOrPut(tx.from);
        if (!gop.found_existing) {
            const nonce = self.state.get_nonce(tx.from);
            const list = try self.allocator.create(TxList);
            list.* = TxList.init(self.allocator, nonce);
            gop.value_ptr.* = list;
        }

        const list = gop.value_ptr.*;
        if (list.len() >= self.config.max_per_account) {
            self.rejected_count += 1;
            return error.AccountTxLimit;
        }

        // 7. Add to per-account list
        _ = try list.add(tx);

        // 8. Add to hash index and bloom filter
        try self.by_hash.put(tx_hash, tx);
        self.bloom.add(tx_hash);
        self.count += 1;
    }

    /// Evict the lowest gas-price TX to make room for a new one.
    /// Returns true if eviction succeeded (new TX has higher gas price).
    fn evictLowestGas(self: *TxPool, incoming_gas_price: u256) bool {
        var lowest_price: u256 = std.math.maxInt(u256);
        var lowest_hash: ?types.Hash = null;
        var lowest_from: ?types.Address = null;
        var lowest_nonce: u64 = 0;

        // Find the lowest gas-price TX in the pool
        var it = self.by_hash.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.gas_price < lowest_price) {
                lowest_price = entry.value_ptr.*.gas_price;
                lowest_hash = entry.key_ptr.*;
                lowest_from = entry.value_ptr.*.from;
                lowest_nonce = entry.value_ptr.*.nonce;
            }
        }

        // Only evict if incoming TX has higher gas price
        if (lowest_hash == null or incoming_gas_price <= lowest_price) return false;

        // Evict
        _ = self.by_hash.remove(lowest_hash.?);
        if (lowest_from) |from| {
            if (self.accounts.get(from)) |list| {
                list.forward(lowest_nonce + 1);
                if (list.empty()) {
                    _ = self.accounts.remove(from);
                    list.deinit();
                    self.allocator.destroy(list);
                }
            }
        }
        if (self.count > 0) self.count -= 1;
        self.evicted_count += 1;
        return true;
    }

    /// Get executable (ready) transactions for block building.
    pub fn pending(self: *TxPool, allocator: std.mem.Allocator) ![]types.Transaction {
        self.lock.lock();
        defer self.lock.unlock();

        var result = std.ArrayListUnmanaged(types.Transaction){};
        errdefer result.deinit(allocator);

        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            const ready = entry.value_ptr.*.ready();
            for (ready) |tx_ptr| {
                try result.append(allocator, tx_ptr.*);
            }
        }

        std.mem.sortUnstable(types.Transaction, result.items, {}, struct {
            pub fn lessThan(_: void, a: types.Transaction, b: types.Transaction) bool {
                return a.gas_price > b.gas_price;
            }
        }.lessThan);

        return result.toOwnedSlice(allocator);
    }

    /// Get a transaction by hash.
    pub fn get(self: *TxPool, hash: types.Hash) ?*types.Transaction {
        self.lock.lock();
        defer self.lock.unlock();
        return self.by_hash.get(hash);
    }

    /// Remove transactions that were included in a block.
    pub fn remove_executed(self: *TxPool, transactions: []const types.Transaction) void {
        self.lock.lock();
        defer self.lock.unlock();

        for (transactions) |tx| {
            _ = self.by_hash.remove(tx.hash());

            if (self.accounts.get(tx.from)) |list| {
                list.forward(tx.nonce + 1);
                if (list.empty()) {
                    _ = self.accounts.remove(tx.from);
                    list.deinit();
                    self.allocator.destroy(list);
                }
            }
            if (self.count > 0) self.count -= 1;
        }
    }

    /// Sync pool with current state (prune invalid transactions).
    pub fn sync_with_state(self: *TxPool) void {
        self.lock.lock();
        defer self.lock.unlock();

        var remove_addrs = std.ArrayListUnmanaged(types.Address){};
        defer remove_addrs.deinit(self.allocator);

        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            const addr = entry.key_ptr.*;
            const list = entry.value_ptr.*;
            const current_nonce = self.state.get_nonce(addr);
            list.forward(current_nonce);
            if (list.empty()) {
                remove_addrs.append(self.allocator, addr) catch continue;
            }
        }

        for (remove_addrs.items) |addr| {
            if (self.accounts.fetchRemove(addr)) |kv| {
                kv.value.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }

    pub fn pool_count(self: *const TxPool) u32 {
        return self.count;
    }

    /// Get up to max_count executable transactions.
    pub fn get_transactions(self: *TxPool, max_count: u32) []types.Transaction {
        self.lock.lock();
        defer self.lock.unlock();

        var result = std.ArrayListUnmanaged(types.Transaction){};
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            const ready = entry.value_ptr.*.ready();
            for (ready) |tx_ptr| {
                if (result.items.len >= max_count) break;
                result.append(self.allocator, tx_ptr.*) catch break;
            }
            if (result.items.len >= max_count) break;
        }

        std.mem.sortUnstable(types.Transaction, result.items, {}, struct {
            pub fn lessThan(_: void, a: types.Transaction, b: types.Transaction) bool {
                return a.gas_price > b.gas_price;
            }
        }.lessThan);

        return result.toOwnedSlice(self.allocator) catch &[_]types.Transaction{};
    }

    /// Get the next executable nonce for an address.
    pub fn get_executable_nonce(self: *TxPool, addr: types.Address) u64 {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.accounts.get(addr)) |list| {
            return list.nonce + list.ready_txs.items.len;
        }
        return self.state.get_nonce(addr);
    }

    /// Get pool statistics.
    pub fn getStats(self: *const TxPool) struct { total: u32, rejected: u64, evicted: u64, bloom_count: u32 } {
        return .{
            .total = self.count,
            .rejected = self.rejected_count,
            .evicted = self.evicted_count,
            .bloom_count = self.bloom.count,
        };
    }
};
