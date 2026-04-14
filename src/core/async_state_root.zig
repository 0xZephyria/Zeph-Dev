// ============================================================================
// Zephyria — Async State Root Computer (Pipeline-Safe)
// ============================================================================
//
// Moves Verkle trie commitment computation off the block production
// critical path. State roots are computed on a dedicated background thread
// and delivered to the consensus pipeline with a configurable block lag.
//
// Architecture:
//   Block N production:
//     1. Execute TXs, merge deltas, commit overlays (Phase 1-2)
//     2. Queue dirty trie snapshot for background commitment (Phase 3)
//     3. Return immediately — block header uses root from Block N-lag
//
//   Background thread:
//     1. Receives queued commit requests (block_number + dirty_count)
//     2. Calls trie.commit() + trie.rootHash()
//     3. Stores result in completed ring buffer
//     4. Signals completion via atomic flag
//
// Safety:
//   - Mutex protects queue push/pop. Background thread holds mutex only
//     during queue pop (nanoseconds), not during commitment (seconds).
//   - Completed results are stored in a lock-free ring buffer.
//   - Trie access is NOT concurrent: background thread is the ONLY
//     writer to trie.commit()/rootHash() once async mode is active.
//     The executor writes to overlays/state, which are committed before
//     queuing the root computation. This serialization is guaranteed by
//     the queue ordering.
//
// Fraud-proof compatible:
//   - Each completed root includes its block_number for verification.
//   - The consensus DeferredExecutor can verify N-lag roots retroactively.

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const Atomic = std.atomic.Value;

// ── Configuration ───────────────────────────────────────────────────────

pub const AsyncRootConfig = struct {
    /// How many blocks behind the state root trails consensus.
    /// Block N's header contains the state root of Block N - root_lag.
    /// Default 2 for safety margin (Monad-inspired deferred execution).
    root_lag: u32 = 2,

    /// Maximum queued commit requests before blocking the producer.
    /// Acts as backpressure — if the background trie commitment can't
    /// keep up, the producer stalls rather than accumulating unbounded debt.
    max_queue_depth: u32 = 8,

    /// Enable verification mode: store all computed roots for retroactive
    /// fraud-proof checks by the consensus layer.
    enable_verification: bool = true,
};

// ── Commit Request ──────────────────────────────────────────────────────

/// A request to compute the state root for a given block.
/// Queued by the executor after Phase 2 (delta merge + overlay commit).
const CommitRequest = struct {
    block_number: u64,
    dirty_count: usize,
    queued_at_ns: i128,
};

// ── Completed Root ──────────────────────────────────────────────────────

/// A completed state root computation result.
pub const CompletedRoot = struct {
    block_number: u64,
    state_root: types.Hash,
    dirty_count: usize,
    computation_time_ns: i128,
    completed_at_ns: i128,
};

// ── Ring Buffer for Completed Roots ─────────────────────────────────────

const RING_SIZE: usize = 64;

// ── Async State Root Computer ───────────────────────────────────────────

pub const AsyncStateRootComputer = struct {
    allocator: std.mem.Allocator,
    config: AsyncRootConfig,
    state: *state_mod.State,

    // ── Queue (producer → background thread) ────────────────────────
    queue: [16]?CommitRequest,
    queue_head: usize,
    queue_tail: usize,
    queue_count: Atomic(u32),
    queue_mutex: std.Thread.Mutex,
    queue_cond: std.Thread.Condition,

    // ── Completed roots (background thread → consumer) ──────────────
    completed: [RING_SIZE]?CompletedRoot,
    completed_head: Atomic(u64),

    // ── Background thread ───────────────────────────────────────────
    bg_thread: ?std.Thread,
    shutdown: Atomic(bool),

    // ── Stats ───────────────────────────────────────────────────────
    roots_computed: Atomic(u64),
    total_computation_ns: Atomic(u64),
    max_computation_ns: Atomic(u64),
    queue_full_stalls: Atomic(u64),
    last_computed_block: Atomic(u64),

    const Self = @This();

    /// Initialize the async state root computer.
    /// Does NOT start the background thread — call start() explicitly.
    pub fn init(
        allocator: std.mem.Allocator,
        state: *state_mod.State,
        config: AsyncRootConfig,
    ) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .state = state,
            // Queue
            .queue = [_]?CommitRequest{null} ** 16,
            .queue_head = 0,
            .queue_tail = 0,
            .queue_count = Atomic(u32).init(0),
            .queue_mutex = .{},
            .queue_cond = .{},
            // Completed
            .completed = [_]?CompletedRoot{null} ** RING_SIZE,
            .completed_head = Atomic(u64).init(0),
            // Thread
            .bg_thread = null,
            .shutdown = Atomic(bool).init(false),
            // Stats
            .roots_computed = Atomic(u64).init(0),
            .total_computation_ns = Atomic(u64).init(0),
            .max_computation_ns = Atomic(u64).init(0),
            .queue_full_stalls = Atomic(u64).init(0),
            .last_computed_block = Atomic(u64).init(0),
        };
    }

    /// Start the background commitment thread.
    /// Must be called before queueCommit().
    pub fn start(self: *Self) !void {
        if (self.bg_thread != null) return; // Already running
        self.shutdown.store(false, .release);
        self.bg_thread = try std.Thread.spawn(.{}, backgroundLoop, .{self});
    }

    /// Shutdown the background thread and wait for completion.
    /// Safe to call multiple times.
    pub fn stop(self: *Self) void {
        self.shutdown.store(true, .release);

        // Wake the background thread if it's waiting on the condition
        self.queue_mutex.lock();
        self.queue_cond.signal();
        self.queue_mutex.unlock();

        if (self.bg_thread) |thread| {
            thread.join();
            self.bg_thread = null;
        }
    }

    pub fn deinit(self: *Self) void {
        self.stop();
    }

    // ── Producer API (called by DAGExecutor after Phase 2) ──────────

    /// Queue a state root computation for the given block.
    /// After calling this, the background thread will eventually call
    /// trie.commit() + trie.rootHash() and store the result.
    ///
    /// IMPORTANT: The caller must have already committed all overlays
    /// and deltas to the state trie BEFORE calling this. The background
    /// thread will compute commitments on the trie's current state.
    ///
    /// If the queue is full, this blocks until space is available
    /// (backpressure to prevent unbounded debt accumulation).
    pub fn queueCommit(self: *Self, block_number: u64, dirty_count: usize) void {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        // Backpressure: wait if queue is full
        while (self.queue_count.load(.acquire) >= self.config.max_queue_depth) {
            if (self.shutdown.load(.acquire)) return;
            _ = self.queue_full_stalls.fetchAdd(1, .monotonic);
            self.queue_cond.wait(&self.queue_mutex);
        }

        // Push to queue
        self.queue[self.queue_tail] = CommitRequest{
            .block_number = block_number,
            .dirty_count = dirty_count,
            .queued_at_ns = std.time.nanoTimestamp(),
        };
        self.queue_tail = (self.queue_tail + 1) % 16;
        _ = self.queue_count.fetchAdd(1, .monotonic);

        // Wake background thread
        self.queue_cond.signal();
    }

    /// Get the completed state root for a specific block number.
    /// Returns null if the root hasn't been computed yet.
    /// This is lock-free — safe to call from any thread.
    pub fn getRoot(self: *const Self, block_number: u64) ?CompletedRoot {
        const slot = @as(usize, @intCast(block_number % RING_SIZE));
        if (self.completed[slot]) |result| {
            if (result.block_number == block_number) {
                return result;
            }
        }
        return null;
    }

    /// Get the state root for the current block, accounting for the
    /// configured root lag. For Block N, returns the root of Block N-lag.
    /// Returns Hash.zero() if the lagged root isn't available yet
    /// (e.g., during the first `root_lag` blocks after genesis).
    pub fn getLaggedRoot(self: *const Self, current_block: u64) types.Hash {
        if (current_block < self.config.root_lag) {
            // During the first few blocks, no lagged root available
            return types.Hash.zero();
        }
        const target = current_block - self.config.root_lag;
        if (self.getRoot(target)) |result| {
            return result.state_root;
        }
        return types.Hash.zero();
    }

    /// Wait for a specific block's state root to become available.
    /// Times out after the specified duration. Returns null on timeout.
    pub fn waitForRoot(self: *Self, block_number: u64, timeout_ms: u64) ?CompletedRoot {
        const deadline_ns = std.time.nanoTimestamp() + @as(i128, timeout_ms) * 1_000_000;

        while (std.time.nanoTimestamp() < deadline_ns) {
            if (self.getRoot(block_number)) |result| {
                return result;
            }
            // Brief spin wait — the background thread should complete soon
            std.time.sleep(100_000); // 100 us
        }
        return null;
    }

    // ── Background Thread ───────────────────────────────────────────

    fn backgroundLoop(self: *Self) void {
        while (!self.shutdown.load(.acquire)) {
            // Pop next request from queue
            const request = blk: {
                self.queue_mutex.lock();
                defer self.queue_mutex.unlock();

                while (self.queue_count.load(.acquire) == 0) {
                    if (self.shutdown.load(.acquire)) return;
                    self.queue_cond.timedWait(&self.queue_mutex, 50_000_000) catch {}; // 50ms timeout
                    if (self.shutdown.load(.acquire)) return;
                }

                const req = self.queue[self.queue_head] orelse {
                    // Spurious: slot is null despite count > 0. Reset and retry.
                    continue;
                };
                self.queue[self.queue_head] = null;
                self.queue_head = (self.queue_head + 1) % 16;
                _ = self.queue_count.fetchSub(1, .monotonic);

                // Signal any producer waiting for queue space
                self.queue_cond.signal();

                break :blk req;
            };

            // Compute commitment (this is the expensive part — can take seconds)
            const compute_start = std.time.nanoTimestamp();

            // Use incremental commit (only recomputes dirty subtrees)
            // This is significantly faster than full commit() when only a
            // fraction of the trie is modified per block.
            self.state.trie.commitDirtyOnly() catch |err| {
                std.log.err("AsyncStateRoot: trie.commitDirtyOnly() failed for block {d}: {}", .{ request.block_number, err });
                // Fallback to full commit
                self.state.trie.commit() catch |err2| {
                    std.log.err("AsyncStateRoot: trie.commit() fallback also failed for block {d}: {}", .{ request.block_number, err2 });
                    continue;
                };
            };

            const root_bytes = self.state.trie.rootHash();
            const compute_end = std.time.nanoTimestamp();
            const duration_ns = compute_end - compute_start;

            // Store completed result
            const slot = @as(usize, @intCast(request.block_number % RING_SIZE));
            self.completed[slot] = CompletedRoot{
                .block_number = request.block_number,
                .state_root = types.Hash{ .bytes = root_bytes },
                .dirty_count = request.dirty_count,
                .computation_time_ns = duration_ns,
                .completed_at_ns = compute_end,
            };
            self.completed_head.store(request.block_number, .release);

            // Update stats
            _ = self.roots_computed.fetchAdd(1, .monotonic);
            self.last_computed_block.store(request.block_number, .release);
            const dur_u64: u64 = @intCast(@max(0, duration_ns));
            _ = self.total_computation_ns.fetchAdd(dur_u64, .monotonic);

            // Track max computation time
            var current_max = self.max_computation_ns.load(.acquire);
            while (dur_u64 > current_max) {
                const result = self.max_computation_ns.cmpxchgWeak(current_max, dur_u64, .acq_rel, .acquire);
                if (result) |val| {
                    current_max = val;
                } else {
                    break;
                }
            }

            std.log.info("AsyncStateRoot: block {d} root computed in {d}ms, dirty={d}", .{
                request.block_number,
                @as(u64, @intCast(@divFloor(duration_ns, 1_000_000))),
                request.dirty_count,
            });
        }
    }

    // ── Stats ───────────────────────────────────────────────────────

    pub const AsyncRootStats = struct {
        roots_computed: u64,
        avg_computation_ms: u64,
        max_computation_ms: u64,
        queue_depth: u32,
        queue_full_stalls: u64,
        last_computed_block: u64,
    };

    pub fn getStats(self: *const Self) AsyncRootStats {
        const computed = self.roots_computed.load(.acquire);
        const total_ns = self.total_computation_ns.load(.acquire);
        return .{
            .roots_computed = computed,
            .avg_computation_ms = if (computed > 0) total_ns / computed / 1_000_000 else 0,
            .max_computation_ms = self.max_computation_ns.load(.acquire) / 1_000_000,
            .queue_depth = self.queue_count.load(.acquire),
            .queue_full_stalls = self.queue_full_stalls.load(.acquire),
            .last_computed_block = self.last_computed_block.load(.acquire),
        };
    }
};
