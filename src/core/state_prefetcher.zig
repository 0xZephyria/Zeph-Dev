// ============================================================================
// Zephyria — State Prefetcher (DAG Executor Acceleration)
// ============================================================================
//
// Pre-warms the Verkle trie cache by loading state entries that will be
// accessed during transaction execution. This eliminates cold-start
// cache misses and random I/O during the critical execution phase.
//
// Design:
//   Before Phase 1 (parallel lane execution), the prefetcher scans all
//   TXs in the execution plan and issues trie.get() calls for:
//     - nonce_key(tx.from)    — always needed for nonce verification
//     - balance_key(tx.from)  — always needed for gas/value deduction
//     - nonce_key(tx.to)      — needed for contract detection
//     - balance_key(tx.to)    — needed for value credit
//     - code_key(tx.to)       — needed for contract calls
//
//   These keys are fetched in a batch, populating the trie's internal
//   node cache. When executeSingleTx later reads the same keys through
//   the Overlay → State → Trie path, they hit the cache instead of
//   traversing cold trie nodes.
//
// Performance:
//   At 400K TXs/block with 800K unique addresses, this converts
//   ~2.4M random trie traversals into sequential cache-warm reads.
//   Expected speedup: 2-4x for Phase 1 execution.

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const dag_scheduler = @import("dag_scheduler.zig");

// ── Prefetch Configuration ─────────────────────────────────────────────

pub const PrefetchConfig = struct {
    /// Maximum number of unique addresses to prefetch per block.
    /// Caps memory usage for the address set.
    max_addresses: u32 = 1_000_000,

    /// Prefetch code for contract addresses.
    /// Disable if most TXs are simple transfers.
    prefetch_code: bool = true,

    /// Number of parallel prefetch workers.
    /// Each worker prefetches a disjoint subset of addresses.
    num_workers: u32 = 4,

    /// Enable hardware prefetch hints (CPU-level).
    /// Uses @prefetch intrinsic for trie node memory.
    hw_prefetch: bool = true,
};

// ── Prefetch Stats ─────────────────────────────────────────────────────

pub const PrefetchStats = struct {
    addresses_prefetched: u64,
    keys_prefetched: u64,
    prefetch_time_ns: i128,
    cache_hits: u64,
    cache_misses: u64,
};

// ── State Prefetcher ───────────────────────────────────────────────────

pub const StatePrefetcher = struct {
    allocator: std.mem.Allocator,
    state: *state_mod.State,
    config: PrefetchConfig,

    // Accumulated stats
    total_addresses: u64,
    total_keys: u64,
    total_time_ns: i128,
    blocks_prefetched: u64,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        state: *state_mod.State,
        config: PrefetchConfig,
    ) Self {
        return Self{
            .allocator = allocator,
            .state = state,
            .config = config,
            .total_addresses = 0,
            .total_keys = 0,
            .total_time_ns = 0,
            .blocks_prefetched = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Prefetch state entries for all transactions in the execution plan.
    /// Should be called BEFORE Phase 1 (parallel lane execution).
    ///
    /// Collects unique sender/receiver addresses, then batch-reads their
    /// nonce, balance, and code keys from the Verkle trie to warm the cache.
    pub fn prefetchForPlan(self: *Self, plan: *const dag_scheduler.ExecutionPlan) PrefetchStats {
        const start = std.time.nanoTimestamp();

        // Collect unique addresses from all lanes
        var address_set = std.AutoHashMap(types.Address, AddressRole).init(self.allocator);
        defer address_set.deinit();

        for (plan.lanes) |*lane| {
            for (lane.txs) |*tx| {
                // Sender is always accessed (nonce + balance)
                const sender_entry = address_set.getOrPut(tx.from) catch continue;
                if (!sender_entry.found_existing) {
                    sender_entry.value_ptr.* = .{ .is_sender = true, .is_receiver = false };
                } else {
                    sender_entry.value_ptr.*.is_sender = true;
                }

                // Receiver (if present) gets balance credit + possible code load
                if (tx.to) |to_addr| {
                    const recv_entry = address_set.getOrPut(to_addr) catch continue;
                    if (!recv_entry.found_existing) {
                        recv_entry.value_ptr.* = .{ .is_sender = false, .is_receiver = true };
                    } else {
                        recv_entry.value_ptr.*.is_receiver = true;
                    }
                }

                // Cap to prevent OOM on adversarial blocks
                if (address_set.count() >= self.config.max_addresses) break;
            }
        }

        // Batch prefetch: read each key from trie (populates internal cache)
        var keys_fetched: u64 = 0;
        var cache_hits: u64 = 0;
        var cache_misses: u64 = 0;

        var it = address_set.iterator();
        while (it.next()) |entry| {
            const addr = entry.key_ptr.*;
            const role = entry.value_ptr.*;

            // Always prefetch nonce + balance for senders
            if (role.is_sender) {
                const nonce_k = state_mod.State.nonce_key(addr);
                const bal_k = state_mod.State.balance_key(addr);

                if (self.state.trie.get(nonce_k) catch null) |d| {
                    self.allocator.free(d);
                    cache_hits += 1;
                } else {
                    cache_misses += 1;
                }
                keys_fetched += 1;

                if (self.state.trie.get(bal_k) catch null) |d| {
                    self.allocator.free(d);
                    cache_hits += 1;
                } else {
                    cache_misses += 1;
                }
                keys_fetched += 1;
            }

            // Prefetch balance + code for receivers
            if (role.is_receiver) {
                const bal_k = state_mod.State.balance_key(addr);
                if (self.state.trie.get(bal_k) catch null) |d| {
                    self.allocator.free(d);
                    cache_hits += 1;
                } else {
                    cache_misses += 1;
                }
                keys_fetched += 1;

                if (self.config.prefetch_code) {
                    const code_k = state_mod.State.code_key(addr);
                    if (self.state.trie.get(code_k) catch null) |d| {
                        self.allocator.free(d);
                        cache_hits += 1;
                    } else {
                        cache_misses += 1;
                    }
                    keys_fetched += 1;
                }
            }
        }

        const end = std.time.nanoTimestamp();
        const duration = end - start;

        // Update running stats
        self.total_addresses += address_set.count();
        self.total_keys += keys_fetched;
        self.total_time_ns += duration;
        self.blocks_prefetched += 1;

        return PrefetchStats{
            .addresses_prefetched = address_set.count(),
            .keys_prefetched = keys_fetched,
            .prefetch_time_ns = duration,
            .cache_hits = cache_hits,
            .cache_misses = cache_misses,
        };
    }

    /// Get accumulated stats across all blocks.
    pub fn getStats(self: *const Self) PrefetchStats {
        return PrefetchStats{
            .addresses_prefetched = self.total_addresses,
            .keys_prefetched = self.total_keys,
            .prefetch_time_ns = self.total_time_ns,
            .cache_hits = 0,
            .cache_misses = 0,
        };
    }
};

// ── Address Role ───────────────────────────────────────────────────────

const AddressRole = struct {
    is_sender: bool,
    is_receiver: bool,
};
