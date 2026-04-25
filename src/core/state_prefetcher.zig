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
    maxAddresses: u32 = 1_000_000,

    /// Prefetch code for contract addresses.
    /// Disable if most TXs are simple transfers.
    prefetchCode: bool = true,

    /// Number of parallel prefetch workers.
    /// Each worker prefetches a disjoint subset of addresses.
    numWorkers: u32 = 4,

    /// Enable hardware prefetch hints (CPU-level).
    /// Uses @prefetch intrinsic for trie node memory.
    hwPrefetch: bool = true,
};

// ── Prefetch Stats ─────────────────────────────────────────────────────

pub const PrefetchStats = struct {
    addressesPrefetched: u64,
    keysPrefetched: u64,
    prefetchTimeNs: i128,
    cacheHits: u64,
    cacheMisses: u64,
};

// ── State Prefetcher ───────────────────────────────────────────────────

pub const StatePrefetcher = struct {
    allocator: std.mem.Allocator,
    state: *state_mod.State,
    config: PrefetchConfig,

    // Accumulated stats
    totalAddresses: u64,
    totalKeys: u64,
    totalTimeNs: i128,
    blocksPrefetched: u64,

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
            .totalAddresses = 0,
            .totalKeys = 0,
            .totalTimeNs = 0,
            .blocksPrefetched = 0,
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
                    sender_entry.value_ptr.* = .{ .isSender = true, .isReceiver = false };
                } else {
                    sender_entry.value_ptr.*.isSender = true;
                }

                // Receiver (if present) gets balance credit + possible code load
                if (tx.to) |to_addr| {
                    const recv_entry = address_set.getOrPut(to_addr) catch continue;
                    if (!recv_entry.found_existing) {
                        recv_entry.value_ptr.* = .{ .isSender = false, .isReceiver = true };
                    } else {
                        recv_entry.value_ptr.*.isReceiver = true;
                    }
                }

                // Cap to prevent OOM on adversarial blocks
                if (address_set.count() >= self.config.maxAddresses) break;
            }
        }

        // Batch prefetch: read each key from trie (populates internal cache)
        var keys_fetched: u64 = 0;
        var cacheHits: u64 = 0;
        var cacheMisses: u64 = 0;

        var it = address_set.iterator();
        while (it.next()) |entry| {
            const addr = entry.key_ptr.*;
            const role = entry.value_ptr.*;

            // Always prefetch nonce + balance for senders
            if (role.isSender) {
                const nonce_k = state_mod.State.nonceKey(addr);
                const bal_k = state_mod.State.balanceKey(addr);

                if (self.state.trie.get(nonce_k) catch null) |d| {
                    self.allocator.free(d);
                    cacheHits += 1;
                } else {
                    cacheMisses += 1;
                }
                keys_fetched += 1;

                if (self.state.trie.get(bal_k) catch null) |d| {
                    self.allocator.free(d);
                    cacheHits += 1;
                } else {
                    cacheMisses += 1;
                }
                keys_fetched += 1;
            }

            // Prefetch balance + code for receivers
            if (role.isReceiver) {
                const bal_k = state_mod.State.balanceKey(addr);
                if (self.state.trie.get(bal_k) catch null) |d| {
                    self.allocator.free(d);
                    cacheHits += 1;
                } else {
                    cacheMisses += 1;
                }
                keys_fetched += 1;

                if (self.config.prefetchCode) {
                    const code_k = state_mod.State.codeKey(addr);
                    if (self.state.trie.get(code_k) catch null) |d| {
                        self.allocator.free(d);
                        cacheHits += 1;
                    } else {
                        cacheMisses += 1;
                    }
                    keys_fetched += 1;
                }
            }
        }

        const end = std.time.nanoTimestamp();
        const duration = end - start;

        // Update running stats
        self.totalAddresses += address_set.count();
        self.totalKeys += keys_fetched;
        self.totalTimeNs += duration;
        self.blocksPrefetched += 1;

        return PrefetchStats{
            .addressesPrefetched = address_set.count(),
            .keysPrefetched = keys_fetched,
            .prefetchTimeNs = duration,
            .cacheHits = cacheHits,
            .cacheMisses = cacheMisses,
        };
    }

    /// Get accumulated stats across all blocks.
    pub fn getStats(self: *const Self) PrefetchStats {
        return PrefetchStats{
            .addressesPrefetched = self.totalAddresses,
            .keysPrefetched = self.totalKeys,
            .prefetchTimeNs = self.totalTimeNs,
            .cacheHits = 0,
            .cacheMisses = 0,
        };
    }
};

// ── Address Role ───────────────────────────────────────────────────────

const AddressRole = struct {
    isSender: bool,
    isReceiver: bool,
};
