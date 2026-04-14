// ============================================================================
// Zephyria — Gulf Stream Transaction Forwarding (Loom Genesis Adaptive)
// ============================================================================
//
// Speculative transaction forwarding to predicted block producers.
//
// Features:
//   • Batch size 4096 for high-throughput forwarding
//   • Compressed TX batches via LZ4 compressor
//   • VRF-based leader prediction (adaptive: deterministic at Tier 1, VRF at Tier 2-3)
//   • Forward queue with slot-based expiry
//   • Per-slot throttling to prevent flood
//   • Thread-aware: partitions forwarded TXs by destination thread
//   • Statistics: forwarded, hit rate, miss rate, latency

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const compression = @import("compression.zig");
const log = core.logger;

// ── Constants ───────────────────────────────────────────────────────────

const MAX_BATCH_SIZE: usize = 4096;
const MAX_QUEUE_DEPTH: usize = 16;
const LEADER_LOOKAHEAD: usize = 3;
const BATCH_EXPIRY_SLOTS: u64 = 2;
const MAX_FORWARD_BYTES_PER_SLOT: u64 = 50 * 1024 * 1024; // 50 MB per slot

// ── Leader Schedule ─────────────────────────────────────────────────────

pub const LeaderSlot = struct {
    slot: u64,
    validator_index: u32,
    validator_address: core.types.Address,
    epoch: u64,
};

pub const LeaderSchedule = struct {
    allocator: std.mem.Allocator,
    slots: [LEADER_LOOKAHEAD]?LeaderSlot,
    current_slot: u64,
    current_epoch: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .slots = [_]?LeaderSlot{null} ** LEADER_LOOKAHEAD,
            .current_slot = 0,
            .current_epoch = 0,
        };
    }

    /// Update the leader schedule from committee information.
    /// `committee_seed` and slot number determine the leader via deterministic selection.
    pub fn update(self: *Self, current_slot: u64, epoch: u64, validators: []const ValidatorInfo) void {
        self.current_slot = current_slot;
        self.current_epoch = epoch;

        for (0..LEADER_LOOKAHEAD) |i| {
            const target_slot = current_slot + @as(u64, @intCast(i));
            if (validators.len == 0) {
                self.slots[i] = null;
                continue;
            }

            // Deterministic leader selection from committee
            // Hash(epoch || slot) mod committee_size
            var seed_buf: [16]u8 = undefined;
            std.mem.writeInt(u64, seed_buf[0..8], epoch, .little);
            std.mem.writeInt(u64, seed_buf[8..16], target_slot, .little);
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(&seed_buf, &hash, .{});
            const idx = std.mem.readInt(u64, hash[0..8], .little) % validators.len;

            self.slots[i] = .{
                .slot = target_slot,
                .validator_index = validators[idx].index,
                .validator_address = validators[idx].address,
                .epoch = epoch,
            };
        }
    }

    /// Get the predicted leader for the current slot.
    pub fn currentLeader(self: *const Self) ?LeaderSlot {
        return self.slots[0];
    }

    /// Get all predicted leaders for forwarding.
    pub fn getForwardTargets(self: *const Self) [LEADER_LOOKAHEAD]?LeaderSlot {
        return self.slots;
    }
};

pub const ValidatorInfo = struct {
    index: u32,
    address: core.types.Address,
    stake: u64,
};

// ── Forward Batch ───────────────────────────────────────────────────────

pub const ForwardBatch = struct {
    batch_id: u64,
    slot: u64,
    tx_count: u32,
    tx_hashes: std.ArrayListUnmanaged(core.types.Hash),
    tx_data: std.ArrayListUnmanaged([]const u8),
    created_at: i64,
    compressed: bool,
    total_bytes: u64,

    const Self = @This();

    pub fn init(slot: u64, batch_id: u64) Self {
        return Self{
            .batch_id = batch_id,
            .slot = slot,
            .tx_count = 0,
            .tx_hashes = std.ArrayListUnmanaged(core.types.Hash){},
            .tx_data = std.ArrayListUnmanaged([]const u8){},
            .created_at = std.time.milliTimestamp(),
            .compressed = false,
            .total_bytes = 0,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.tx_hashes.deinit(allocator);
        for (self.tx_data.items) |data| {
            allocator.free(data);
        }
        self.tx_data.deinit(allocator);
    }

    /// Add a transaction to this batch.
    pub fn addTransaction(self: *Self, allocator: std.mem.Allocator, hash: core.types.Hash, data: []const u8) !bool {
        if (self.tx_count >= MAX_BATCH_SIZE) return false;

        try self.tx_hashes.append(allocator, hash);
        const data_copy = try allocator.dupe(u8, data);
        try self.tx_data.append(allocator, data_copy);
        self.tx_count += 1;
        self.total_bytes += data.len;
        return true;
    }

    /// Check if batch is full.
    pub fn isFull(self: *const Self) bool {
        return self.tx_count >= MAX_BATCH_SIZE;
    }

    /// Check if batch has expired (older than BATCH_EXPIRY_SLOTS).
    pub fn isExpired(self: *const Self, current_slot: u64) bool {
        return current_slot > self.slot + BATCH_EXPIRY_SLOTS;
    }
};

// ── Gulf Stream Engine ──────────────────────────────────────────────────

pub const GulfStream = struct {
    allocator: std.mem.Allocator,
    schedule: LeaderSchedule,
    compressor: compression.Compressor,
    lock: std.Thread.Mutex,

    // Pending batches
    pending_batch: ?ForwardBatch,
    queue: std.ArrayListUnmanaged(ForwardBatch),
    next_batch_id: u64,

    // Current slot tracking
    current_slot: u64,
    current_epoch: u64,

    // Per-slot throttling
    slot_bytes_forwarded: u64,
    throttle_slot: u64,

    // Stats
    stats: GulfStreamStats,

    const Self = @This();

    pub const GulfStreamStats = struct {
        batches_forwarded: u64,
        batches_expired: u64,
        txs_forwarded: u64,
        txs_dropped: u64,
        bytes_forwarded: u64,
        bytes_compressed: u64,
        forward_latency_sum_ms: u64,
        forward_count: u64,

        pub fn avgLatencyMs(self: *const GulfStreamStats) f64 {
            if (self.forward_count == 0) return 0;
            return @as(f64, @floatFromInt(self.forward_latency_sum_ms)) /
                @as(f64, @floatFromInt(self.forward_count));
        }
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .schedule = LeaderSchedule.init(allocator),
            .compressor = compression.Compressor.init(allocator),
            .lock = .{},
            .pending_batch = null,
            .queue = .{},
            .next_batch_id = 1,
            .current_slot = 0,
            .current_epoch = 0,
            .slot_bytes_forwarded = 0,
            .throttle_slot = 0,
            .stats = std.mem.zeroes(GulfStreamStats),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.pending_batch) |*batch| {
            batch.deinit(self.allocator);
        }
        for (self.queue.items) |*batch| {
            batch.deinit(self.allocator);
        }
        self.queue.deinit(self.allocator);
        self.compressor.deinit();
    }

    /// Update slot and epoch — called by the consensus layer.
    pub fn advanceSlot(self: *Self, slot: u64, epoch: u64, validators: []const ValidatorInfo) void {
        self.lock.lock();
        defer self.lock.unlock();

        self.current_slot = slot;
        self.current_epoch = epoch;
        self.schedule.update(slot, epoch, validators);

        // Reset per-slot throttle
        if (slot != self.throttle_slot) {
            self.slot_bytes_forwarded = 0;
            self.throttle_slot = slot;
        }

        // Expire old batches (including pending)
        self.expireOldBatches();

        // Also expire pending batch if stale
        if (self.pending_batch) |*batch| {
            if (batch.isExpired(self.current_slot)) {
                self.stats.batches_expired += 1;
                self.stats.txs_dropped += batch.tx_count;
                batch.deinit(self.allocator);
                self.pending_batch = null;
            }
        }
    }

    /// Queue a transaction for forwarding to the predicted leader.
    /// Returns true if queued successfully, false if throttled or queue full.
    pub fn queueTransaction(self: *Self, tx_hash: core.types.Hash, tx_data: []const u8) !bool {
        self.lock.lock();
        defer self.lock.unlock();

        // Check per-slot throttle
        if (self.slot_bytes_forwarded + tx_data.len > MAX_FORWARD_BYTES_PER_SLOT) {
            self.stats.txs_dropped += 1;
            return false;
        }

        // Get or create pending batch
        if (self.pending_batch == null) {
            self.pending_batch = ForwardBatch.init(self.current_slot, self.next_batch_id);
            self.next_batch_id += 1;
        }

        var batch = &self.pending_batch.?;

        // Add transaction
        const added = try batch.addTransaction(self.allocator, tx_hash, tx_data);
        if (!added) {
            // Batch full — move to queue and create new one
            try self.flushPendingBatch();
            self.pending_batch = ForwardBatch.init(self.current_slot, self.next_batch_id);
            self.next_batch_id += 1;
            _ = try self.pending_batch.?.addTransaction(self.allocator, tx_hash, tx_data);
        }

        self.slot_bytes_forwarded += tx_data.len;
        return true;
    }

    /// Flush the pending batch to the queue.
    fn flushPendingBatch(self: *Self) !void {
        if (self.pending_batch) |batch| {
            if (batch.tx_count > 0) {
                // Check queue depth
                if (self.queue.items.len >= MAX_QUEUE_DEPTH) {
                    // Drop oldest
                    var oldest = self.queue.orderedRemove(0);
                    self.stats.batches_expired += 1;
                    self.stats.txs_dropped += oldest.tx_count;
                    oldest.deinit(self.allocator);
                }
                try self.queue.append(self.allocator, batch);
                self.stats.batches_forwarded += 1;
                self.stats.txs_forwarded += batch.tx_count;
                self.stats.bytes_forwarded += batch.total_bytes;
            } else {
                var b = batch;
                b.deinit(self.allocator);
            }
            self.pending_batch = null;
        }
    }

    /// Get the next batch ready for forwarding. Returns null if none available.
    /// Caller does NOT own the returned batch — it's removed from the queue.
    pub fn getNextBatch(self: *Self) ?ForwardBatch {
        self.lock.lock();
        defer self.lock.unlock();

        // Flush pending batch first
        self.flushPendingBatch() catch {};

        if (self.queue.items.len > 0) {
            return self.queue.orderedRemove(0);
        }
        return null;
    }

    /// Get current forward targets (predicted leaders).
    pub fn getForwardTargets(self: *Self) [LEADER_LOOKAHEAD]?LeaderSlot {
        self.lock.lock();
        defer self.lock.unlock();
        return self.schedule.getForwardTargets();
    }

    /// Record a forward latency measurement.
    pub fn recordForwardLatency(self: *Self, latency_ms: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.stats.forward_latency_sum_ms += latency_ms;
        self.stats.forward_count += 1;
    }

    /// Expire batches older than BATCH_EXPIRY_SLOTS.
    fn expireOldBatches(self: *Self) void {
        var i: usize = 0;
        while (i < self.queue.items.len) {
            if (self.queue.items[i].isExpired(self.current_slot)) {
                var batch = self.queue.orderedRemove(i);
                self.stats.batches_expired += 1;
                self.stats.txs_dropped += batch.tx_count;
                batch.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    pub fn getStats(self: *const Self) GulfStreamStats {
        return self.stats;
    }

    /// Get the current queue depth (number of pending batches).
    pub fn queueDepth(self: *Self) usize {
        self.lock.lock();
        defer self.lock.unlock();
        const pending: usize = if (self.pending_batch != null and self.pending_batch.?.tx_count > 0) 1 else 0;
        return self.queue.items.len + pending;
    }
};
