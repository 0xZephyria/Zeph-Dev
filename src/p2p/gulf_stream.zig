// ============================================================================
// Zephyria — Gulf Stream Transaction Forwarding (Loom Genesis Adaptive)
// ============================================================================
//
// Speculative transaction forwarding to predicted block producers.
// Reads pending transactions from DAG Mempool — no internal queuing.
//
// Features:
//   • DAG Mempool integration — reads pending TXs directly from the shared pool
//   • VRF-based leader prediction (adaptive: deterministic at Tier 1, VRF at Tier 2-3)
//   • Per-slot throttling to prevent flood
//   • Statistics: forwarded, bytes, latency

const std = @import("std");
const core = @import("core");
const consensus = @import("consensus");
const types = @import("types.zig");
const rlp = @import("encoding").rlp;
const log = core.logger;

// ── Constants ───────────────────────────────────────────────────────────

const MAX_BATCH_SIZE: usize = 4096;
const LEADER_LOOKAHEAD: usize = 2; // current + next slot only
const MAX_FORWARD_BYTES_PER_SLOT: u64 = 50 * 1024 * 1024; // 50 MB per slot
const MAX_FORWARD_BATCHES_PER_TARGET: u32 = 10; // Firewall 3: per-peer rate limit

// ── Forward Target ────────────────────────────────────────────────────

pub const ForwardTarget = struct {
    slot: u64,
    validatorAddress: core.types.Address,
};

// ── Gulf Stream Engine ──────────────────────────────────────────────────

pub const GulfStream = struct {
    allocator: std.mem.Allocator,
    engine: ?*consensus.ZeliusEngine,
    dagPool: *core.dag_mempool.DAGMempool,
    mutex: std.Thread.Mutex,

    // Current slot tracking
    current_slot: u64,

    // Per-slot throttling
    slotBytesForwarded: u64,
    throttleSlot: u64,

    // Track transactions forwarded during the current slot to prevent duplicate sends
    forwardedTxs: std.AutoHashMap(core.types.Hash, void),

    // Firewall 3: Per-target rate limiting
    peerForwardCount: std.AutoHashMap(core.types.Address, u32),

    // Stats
    stats: GulfStreamStats,

    const Self = @This();

    pub const GulfStreamStats = struct {
        batchesForwarded: u64,
        txsForwarded: u64,
        txsDropped: u64,
        bytesForwarded: u64,
        forwardLatencySumMs: u64,
        forwardCount: u64,

        pub fn avgLatencyMs(self: *const GulfStreamStats) f64 {
            if (self.forwardCount == 0) return 0;
            return @as(f64, @floatFromInt(self.forwardLatencySumMs)) /
                @as(f64, @floatFromInt(self.forwardCount));
        }
    };

    pub fn init(allocator: std.mem.Allocator, engine: ?*consensus.ZeliusEngine, dagPool: *core.dag_mempool.DAGMempool) Self {
        return Self{
            .allocator = allocator,
            .engine = engine,
            .dagPool = dagPool,
            .mutex = .{},
            .current_slot = 0,
            .slotBytesForwarded = 0,
            .throttleSlot = 0,
            .forwardedTxs = std.AutoHashMap(core.types.Hash, void).init(allocator),
            .peerForwardCount = std.AutoHashMap(core.types.Address, u32).init(allocator),
            .stats = std.mem.zeroes(GulfStreamStats),
        };
    }

    pub fn deinit(self: *Self) void {
        self.forwardedTxs.deinit();
        self.peerForwardCount.deinit();
    }

    /// Update slot — called by the consensus layer on each new block.
    pub fn advanceSlot(self: *Self, slot: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.current_slot = slot;

        // Reset per-slot throttle, already-forwarded set, and per-target counters on slot change
        if (slot != self.throttleSlot) {
            self.slotBytesForwarded = 0;
            self.throttleSlot = slot;
            self.forwardedTxs.clearRetainingCapacity();
            self.peerForwardCount.clearRetainingCapacity();
        }
    }

    /// Get current forward targets (predicted leaders via consensus VRF-based proposer selection).
    /// Firewall 1 + 2: Only returns targets verified as eligible proposers within valid slot range.
    pub fn getForwardTargets(self: *Self) [LEADER_LOOKAHEAD]?ForwardTarget {
        self.mutex.lock();
        defer self.mutex.unlock();

        const eng = self.engine orelse return [_]?ForwardTarget{null} ** LEADER_LOOKAHEAD;
        var targets: [LEADER_LOOKAHEAD]?ForwardTarget = [_]?ForwardTarget{null} ** LEADER_LOOKAHEAD;
        for (0..LEADER_LOOKAHEAD) |i| {
            const target_slot = self.current_slot + @as(u64, @intCast(i));
            // Firewall 2: Only forward for current (i=0) and next (i=1) slot
            if (i > 1) break;
            const proposer_idx = eng.getExpectedProposer(target_slot);
            if (proposer_idx < eng.activeValidators.len) {
                const addr = eng.activeValidators[proposer_idx].address;
                // Firewall 1: Verify target is the eligible proposer
                if (!eng.isEligibleProposer(target_slot, addr)) continue;
                targets[i] = .{
                    .slot = target_slot,
                    .validatorAddress = addr,
                };
            }
        }
        return targets;
    }

    /// Record a forward latency measurement.
    pub fn recordForwardLatency(self: *Self, latency_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.forwardLatencySumMs += latency_ms;
        self.stats.forwardCount += 1;
    }

    pub fn getStats(self: *const Self) GulfStreamStats {
        return self.stats;
    }

    // ── Drain API ────────────────────────────────────────────────────────
    //
    // drainBatch() reads pending transactions from the DAG Mempool and
    // returns them as an owned slice of RLP-encoded TX data, ready for
    // wire transmission to the predicted proposer.

    pub const DrainResult = struct {
        txData: [][]const u8,
        target: ?ForwardTarget,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *DrainResult) void {
            for (self.txData) |data| self.allocator.free(data);
            self.allocator.free(self.txData);
        }
    };

    /// Drain all pending transactions from DAG Mempool for forwarding.
    /// Returns null if no transactions or no leader predicted.
    /// Caller is responsible for calling DrainResult.deinit().
    pub fn drainBatch(self: *Self) !?DrainResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Get target for current slot
        const target: ?ForwardTarget = if (self.engine) |eng| blk: {
            const proposer_idx = eng.getExpectedProposer(self.current_slot);
            if (proposer_idx >= eng.activeValidators.len) break :blk null;

            const addr = eng.activeValidators[proposer_idx].address;

            // ── Firewall 1: Verify target is eligible proposer for this slot
            if (!eng.isEligibleProposer(self.current_slot, addr)) break :blk null;

            break :blk ForwardTarget{
                .slot = self.current_slot,
                .validatorAddress = addr,
            };
        } else null;
        const target_val = target orelse return null;

        // ── Firewall 3: Per-target rate limit ─────────────────────────────
        {
            const count = self.peerForwardCount.get(target_val.validatorAddress) orelse 0;
            if (count >= MAX_FORWARD_BATCHES_PER_TARGET) return null;
        }

        // Read pending TXs from DAG Mempool
        const pending_txs = try self.dagPool.pending(self.allocator);
        if (pending_txs.len == 0) return null;

        // Encode up to MAX_BATCH_SIZE TXs, respecting per-slot throttle and 55KB packet limit
        var encoded_list = std.ArrayList([]const u8).empty;
        errdefer {
            for (encoded_list.items) |d| self.allocator.free(d);
            encoded_list.deinit(self.allocator);
        }

        var current_batch_size: usize = 0;
        for (pending_txs) |*tx| {
            if (encoded_list.items.len >= MAX_BATCH_SIZE) break;

            const txId = tx.id();
            if (self.forwardedTxs.contains(txId)) continue;

            const encoded = rlp.encode(self.allocator, tx.*) catch |err| {
                log.warn("Failed to encode TX for forwarding: {}\n", .{err});
                continue;
            };

            // Limit single batch payload size to 55 KB to fit cleanly under UDP MTU and Packet.DATA_SIZE
            if (current_batch_size + encoded.len > 55_000) {
                self.allocator.free(encoded);
                break;
            }

            if (self.slotBytesForwarded + encoded.len > MAX_FORWARD_BYTES_PER_SLOT) {
                self.allocator.free(encoded);
                break;
            }

            self.forwardedTxs.put(txId, {}) catch |err| {
                log.warn("Failed to record forwarded TX hash: {}\n", .{err});
            };

            current_batch_size += encoded.len;
            self.slotBytesForwarded += encoded.len;
            try encoded_list.append(self.allocator, encoded);
        }
        self.allocator.free(pending_txs);

        if (encoded_list.items.len == 0) {
            encoded_list.deinit(self.allocator);
            return null;
        }

        self.stats.batchesForwarded += 1;
        self.stats.txsForwarded += @intCast(encoded_list.items.len);
        self.stats.bytesForwarded += current_batch_size;

        // Firewall 3: Increment per-target batch counter
        const prev_count = self.peerForwardCount.get(target_val.validatorAddress) orelse 0;
        self.peerForwardCount.put(target_val.validatorAddress, prev_count + 1) catch {
            log.warn("Failed to update per-target forward count\n", .{});
        };

        return DrainResult{
            .txData = try encoded_list.toOwnedSlice(self.allocator),
            .target = target_val,
            .allocator = self.allocator,
        };
    }

    /// Check if forwarding to a given target is within per-slot rate limit (Firewall 3).
    pub fn canForwardToTarget(self: *Self, address: core.types.Address) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const count = self.peerForwardCount.get(address) orelse 0;
        return count < MAX_FORWARD_BATCHES_PER_TARGET;
    }

    /// Drop any pending state (used on leader change or shutdown).
    pub fn drainAll(self: *Self) void {
        _ = self;
    }

    /// Current queue depth (always 0 — no internal queue).
    pub fn queueDepth(self: *Self) usize {
        _ = self;
        return 0;
    }
};
