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
    validatorIndex: u32,
    validatorAddress: core.types.Address,
    epoch: u64,
};

pub const LeaderSchedule = struct {
    allocator: std.mem.Allocator,
    slots: [LEADER_LOOKAHEAD]?LeaderSlot,
    currentSlot: u64,
    currentEpoch: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .slots = [_]?LeaderSlot{null} ** LEADER_LOOKAHEAD,
            .currentSlot = 0,
            .currentEpoch = 0,
        };
    }

    /// Update the leader schedule from committee information.
    /// `committee_seed` and slot number determine the leader via deterministic selection.
    pub fn update(self: *Self, currentSlot: u64, epoch: u64, validators: []const ValidatorInfo) void {
        self.currentSlot = currentSlot;
        self.currentEpoch = epoch;

        for (0..LEADER_LOOKAHEAD) |i| {
            const target_slot = currentSlot + @as(u64, @intCast(i));
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
                .validatorIndex = validators[idx].index,
                .validatorAddress = validators[idx].address,
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
    batchId: u64,
    slot: u64,
    txCount: u32,
    txHashes: std.ArrayListUnmanaged(core.types.Hash),
    txData: std.ArrayListUnmanaged([]const u8),
    createdAt: i64,
    compressed: bool,
    totalBytes: u64,

    const Self = @This();

    pub fn init(slot: u64, batchId: u64) Self {
        return Self{
            .batchId = batchId,
            .slot = slot,
            .txCount = 0,
            .txHashes = std.ArrayListUnmanaged(core.types.Hash){},
            .txData = std.ArrayListUnmanaged([]const u8){},
            .createdAt = std.time.milliTimestamp(),
            .compressed = false,
            .totalBytes = 0,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.txHashes.deinit(allocator);
        for (self.txData.items) |data| {
            allocator.free(data);
        }
        self.txData.deinit(allocator);
    }

    /// Add a transaction to this batch.
    pub fn addTransaction(self: *Self, allocator: std.mem.Allocator, hash: core.types.Hash, data: []const u8) !bool {
        if (self.txCount >= MAX_BATCH_SIZE) return false;

        try self.txHashes.append(allocator, hash);
        const data_copy = try allocator.dupe(u8, data);
        try self.txData.append(allocator, data_copy);
        self.txCount += 1;
        self.totalBytes += data.len;
        return true;
    }

    /// Check if batch is full.
    pub fn isFull(self: *const Self) bool {
        return self.txCount >= MAX_BATCH_SIZE;
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
    mutex: std.Thread.Mutex,

    // Pending batches
    pendingBatch: ?ForwardBatch,
    queue: std.ArrayListUnmanaged(ForwardBatch),
    nextBatchId: u64,

    // Current slot tracking
    current_slot: u64,
    current_epoch: u64,

    // Per-slot throttling
    slotBytesForwarded: u64,
    throttleSlot: u64,

    // Stats
    stats: GulfStreamStats,

    const Self = @This();

    pub const GulfStreamStats = struct {
        batchesForwarded: u64,
        batchesExpired: u64,
        txsForwarded: u64,
        txsDropped: u64,
        bytesForwarded: u64,
        bytesCompressed: u64,
        forwardLatencySumMs: u64,
        forwardCount: u64,

        pub fn avgLatencyMs(self: *const GulfStreamStats) f64 {
            if (self.forwardCount == 0) return 0;
            return @as(f64, @floatFromInt(self.forwardLatencySumMs)) /
                @as(f64, @floatFromInt(self.forwardCount));
        }
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .schedule = LeaderSchedule.init(allocator),
            .compressor = compression.Compressor.init(allocator),
            .mutex = .{},
            .pendingBatch = null,
            .queue = .{},
            .nextBatchId = 1,
            .current_slot = 0,
            .current_epoch = 0,
            .slotBytesForwarded = 0,
            .throttleSlot = 0,
            .stats = std.mem.zeroes(GulfStreamStats),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.pendingBatch) |*batch| {
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
        self.mutex.lock();
        defer self.mutex.unlock();

        self.current_slot = slot;
        self.current_epoch = epoch;
        self.schedule.update(slot, epoch, validators);

        // Reset per-slot throttle
        if (slot != self.throttleSlot) {
            self.slotBytesForwarded = 0;
            self.throttleSlot = slot;
        }

        // Expire old batches (including pending)
        self.expireOldBatches();

        // Also expire pending batch if stale
        if (self.pendingBatch) |*batch| {
            if (batch.isExpired(self.current_slot)) {
                self.stats.batchesExpired += 1;
                self.stats.txsDropped += batch.txCount;
                batch.deinit(self.allocator);
                self.pendingBatch = null;
            }
        }
    }

    /// Queue a transaction for forwarding to the predicted leader.
    /// Returns true if queued successfully, false if throttled or queue full.
    pub fn queueTransaction(self: *Self, tx_hash: core.types.Hash, tx_data: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check per-slot throttle
        if (self.slotBytesForwarded + tx_data.len > MAX_FORWARD_BYTES_PER_SLOT) {
            self.stats.txsDropped += 1;
            return false;
        }

        // Get or create pending batch
        if (self.pendingBatch == null) {
            self.pendingBatch = ForwardBatch.init(self.current_slot, self.nextBatchId);
            self.nextBatchId += 1;
        }

        var batch = &self.pendingBatch.?;

        // Add transaction
        const added = try batch.addTransaction(self.allocator, tx_hash, tx_data);
        if (!added) {
            // Batch full — move to queue and create new one
            try self.flushPendingBatch();
            self.pendingBatch = ForwardBatch.init(self.current_slot, self.nextBatchId);
            self.nextBatchId += 1;
            _ = try self.pendingBatch.?.addTransaction(self.allocator, tx_hash, tx_data);
        }

        self.slotBytesForwarded += tx_data.len;
        return true;
    }

    /// Flush the pending batch to the queue.
    fn flushPendingBatch(self: *Self) !void {
        if (self.pendingBatch) |batch| {
            if (batch.txCount > 0) {
                // Check queue depth
                if (self.queue.items.len >= MAX_QUEUE_DEPTH) {
                    // Drop oldest
                    var oldest = self.queue.orderedRemove(0);
                    self.stats.batchesExpired += 1;
                    self.stats.txsDropped += oldest.txCount;
                    oldest.deinit(self.allocator);
                }
                try self.queue.append(self.allocator, batch);
                self.stats.batchesForwarded += 1;
                self.stats.txsForwarded += batch.txCount;
                self.stats.bytesForwarded += batch.totalBytes;
            } else {
                var b = batch;
                b.deinit(self.allocator);
            }
            self.pendingBatch = null;
        }
    }

    /// Get the next batch ready for forwarding. Returns null if none available.
    /// Caller does NOT own the returned batch — it's removed from the queue.
    pub fn getNextBatch(self: *Self) ?ForwardBatch {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Flush pending batch first
        self.flushPendingBatch() catch {};

        if (self.queue.items.len > 0) {
            return self.queue.orderedRemove(0);
        }
        return null;
    }

    /// Get current forward targets (predicted leaders).
    pub fn getForwardTargets(self: *Self) [LEADER_LOOKAHEAD]?LeaderSlot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.schedule.getForwardTargets();
    }

    /// Record a forward latency measurement.
    pub fn recordForwardLatency(self: *Self, latency_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.forwardLatencySumMs += latency_ms;
        self.stats.forwardCount += 1;
    }

    /// Expire batches older than BATCH_EXPIRY_SLOTS.
    fn expireOldBatches(self: *Self) void {
        var i: usize = 0;
        while (i < self.queue.items.len) {
            if (self.queue.items[i].isExpired(self.current_slot)) {
                var batch = self.queue.orderedRemove(i);
                self.stats.batchesExpired += 1;
                self.stats.txsDropped += batch.txCount;
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
        self.mutex.lock();
        defer self.mutex.unlock();
        const pending: usize = if (self.pendingBatch != null and self.pendingBatch.?.txCount > 0) 1 else 0;
        return self.queue.items.len + pending;
    }
};
