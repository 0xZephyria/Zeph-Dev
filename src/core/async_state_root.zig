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
//     1. Receives queued commit requests (blockNumber + dirtyCount)
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
//   - Each completed root includes its blockNumber for verification.
//   - The consensus DeferredExecutor can verify N-lag roots retroactively.

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const Atomic = std.atomic.Value;

// ── Configuration ───────────────────────────────────────────────────────

pub const AsyncRootConfig = struct {
    /// How many blocks behind the state root trails consensus.
    /// Block N's header contains the state root of Block N - rootLag.
    /// Default 2 for safety margin (Monad-inspired deferred execution).
    rootLag: u32 = 2,

    /// Maximum queued commit requests before blocking the producer.
    /// Acts as backpressure — if the background trie commitment can't
    /// keep up, the producer stalls rather than accumulating unbounded debt.
    maxQueueDepth: u32 = 8,

    /// Enable verification mode: store all computed roots for retroactive
    /// fraud-proof checks by the consensus layer.
    enableVerification: bool = true,
};

// ── Commit Request ──────────────────────────────────────────────────────

/// A request to compute the state root for a given block.
/// Queued by the executor after Phase 2 (delta merge + overlay commit).
const CommitRequest = struct {
    blockNumber: u64,
    dirtyCount: usize,
    queuedAtNs: i128,
};

// ── Completed Root ──────────────────────────────────────────────────────

/// A completed state root computation result.
pub const CompletedRoot = struct {
    blockNumber: u64,
    stateRoot: types.Hash,
    dirtyCount: usize,
    computationTimeNs: i128,
    completedAtNs: i128,
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
    queueHead: usize,
    queueTail: usize,
    queueCount: Atomic(u32),
    queueMutex: std.Thread.Mutex,
    queueCond: std.Thread.Condition,

    // ── Completed roots (background thread → consumer) ──────────────
    completed: [RING_SIZE]?CompletedRoot,
    completedHead: Atomic(u64),

    // ── Background thread ───────────────────────────────────────────
    bgThread: ?std.Thread,
    shutdown: Atomic(bool),

    // ── Stats ───────────────────────────────────────────────────────
    rootsComputed: Atomic(u64),
    totalComputationNs: Atomic(u64),
    maxComputationNs: Atomic(u64),
    queueFullStalls: Atomic(u64),
    lastComputedBlock: Atomic(u64),

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
            .queueHead = 0,
            .queueTail = 0,
            .queueCount = Atomic(u32).init(0),
            .queueMutex = .{},
            .queueCond = .{},
            // Completed
            .completed = [_]?CompletedRoot{null} ** RING_SIZE,
            .completedHead = Atomic(u64).init(0),
            // Thread
            .bgThread = null,
            .shutdown = Atomic(bool).init(false),
            // Stats
            .rootsComputed = Atomic(u64).init(0),
            .totalComputationNs = Atomic(u64).init(0),
            .maxComputationNs = Atomic(u64).init(0),
            .queueFullStalls = Atomic(u64).init(0),
            .lastComputedBlock = Atomic(u64).init(0),
        };
    }

    /// Start the background commitment thread.
    /// Must be called before queueCommit().
    pub fn start(self: *Self) !void {
        if (self.bgThread != null) return; // Already running
        self.shutdown.store(false, .release);
        self.bgThread = try std.Thread.spawn(.{}, backgroundLoop, .{self});
    }

    /// Shutdown the background thread and wait for completion.
    /// Safe to call multiple times.
    pub fn stop(self: *Self) void {
        self.shutdown.store(true, .release);

        // Wake the background thread if it's waiting on the condition
        self.queueMutex.lock();
        self.queueCond.signal();
        self.queueMutex.unlock();

        if (self.bgThread) |thread| {
            thread.join();
            self.bgThread = null;
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
    pub fn queueCommit(self: *Self, blockNumber: u64, dirtyCount: usize) void {
        self.queueMutex.lock();
        defer self.queueMutex.unlock();

        // Backpressure: wait if queue is full
        while (self.queueCount.load(.acquire) >= self.config.maxQueueDepth) {
            if (self.shutdown.load(.acquire)) return;
            _ = self.queueFullStalls.fetchAdd(1, .monotonic);
            self.queueCond.wait(&self.queueMutex);
        }

        // Push to queue
        self.queue[self.queueTail] = CommitRequest{
            .blockNumber = blockNumber,
            .dirtyCount = dirtyCount,
            .queuedAtNs = std.time.nanoTimestamp(),
        };
        self.queueTail = (self.queueTail + 1) % 16;
        _ = self.queueCount.fetchAdd(1, .monotonic);

        // Wake background thread
        self.queueCond.signal();
    }

    /// Get the completed state root for a specific block number.
    /// Returns null if the root hasn't been computed yet.
    /// This is lock-free — safe to call from any thread.
    pub fn getRoot(self: *const Self, blockNumber: u64) ?CompletedRoot {
        const slot = @as(usize, @intCast(blockNumber % RING_SIZE));
        if (self.completed[slot]) |result| {
            if (result.blockNumber == blockNumber) {
                return result;
            }
        }
        return null;
    }

    /// Get the state root for the current block, accounting for the
    /// configured root lag. For Block N, returns the root of Block N-lag.
    /// Returns Hash.zero() if the lagged root isn't available yet
    /// (e.g., during the first `rootLag` blocks after genesis).
    pub fn getLaggedRoot(self: *const Self, current_block: u64) types.Hash {
        if (current_block < self.config.rootLag) {
            // During the first few blocks, no lagged root available
            return types.Hash.zero();
        }
        const target = current_block - self.config.rootLag;
        if (self.getRoot(target)) |result| {
            return result.stateRoot;
        }
        return types.Hash.zero();
    }

    /// Wait for a specific block's state root to become available.
    /// Times out after the specified duration. Returns null on timeout.
    pub fn waitForRoot(self: *Self, blockNumber: u64, timeout_ms: u64) ?CompletedRoot {
        const deadline_ns = std.time.nanoTimestamp() + @as(i128, timeout_ms) * 1_000_000;

        while (std.time.nanoTimestamp() < deadline_ns) {
            if (self.getRoot(blockNumber)) |result| {
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
                self.queueMutex.lock();
                defer self.queueMutex.unlock();

                while (self.queueCount.load(.acquire) == 0) {
                    if (self.shutdown.load(.acquire)) return;
                    self.queueCond.timedWait(&self.queueMutex, 50_000_000) catch {}; // 50ms timeout
                    if (self.shutdown.load(.acquire)) return;
                }

                const req = self.queue[self.queueHead] orelse {
                    // Spurious: slot is null despite count > 0. Reset and retry.
                    continue;
                };
                self.queue[self.queueHead] = null;
                self.queueHead = (self.queueHead + 1) % 16;
                _ = self.queueCount.fetchSub(1, .monotonic);

                // Signal any producer waiting for queue space
                self.queueCond.signal();

                break :blk req;
            };

            // Compute commitment (this is the expensive part — can take seconds)
            const compute_start = std.time.nanoTimestamp();

            // Use incremental commit (only recomputes dirty subtrees)
            // This is significantly faster than full commit() when only a
            // fraction of the trie is modified per block.
            self.state.trie.commitDirtyOnly() catch |err| {
                std.log.err("AsyncStateRoot: trie.commitDirtyOnly() failed for block {d}: {}", .{ request.blockNumber, err });
                // Fallback to full commit
                self.state.trie.commit() catch |err2| {
                    std.log.err("AsyncStateRoot: trie.commit() fallback also failed for block {d}: {}", .{ request.blockNumber, err2 });
                    continue;
                };
            };

            const root_bytes = self.state.trie.rootHash();
            const compute_end = std.time.nanoTimestamp();
            const duration_ns = compute_end - compute_start;

            // Store completed result
            const slot = @as(usize, @intCast(request.blockNumber % RING_SIZE));
            self.completed[slot] = CompletedRoot{
                .blockNumber = request.blockNumber,
                .stateRoot = types.Hash{ .bytes = root_bytes },
                .dirtyCount = request.dirtyCount,
                .computationTimeNs = duration_ns,
                .completedAtNs = compute_end,
            };
            self.completedHead.store(request.blockNumber, .release);

            // Update stats
            _ = self.rootsComputed.fetchAdd(1, .monotonic);
            self.lastComputedBlock.store(request.blockNumber, .release);
            const dur_u64: u64 = @intCast(@max(0, duration_ns));
            _ = self.totalComputationNs.fetchAdd(dur_u64, .monotonic);

            // Track max computation time
            var current_max = self.maxComputationNs.load(.acquire);
            while (dur_u64 > current_max) {
                const result = self.maxComputationNs.cmpxchgWeak(current_max, dur_u64, .acq_rel, .acquire);
                if (result) |val| {
                    current_max = val;
                } else {
                    break;
                }
            }

            std.log.info("AsyncStateRoot: block {d} root computed in {d}ms, dirty={d}", .{
                request.blockNumber,
                @as(u64, @intCast(@divFloor(duration_ns, 1_000_000))),
                request.dirtyCount,
            });
        }
    }

    // ── Stats ───────────────────────────────────────────────────────

    pub const AsyncRootStats = struct {
        rootsComputed: u64,
        avgComputationMs: u64,
        maxComputationMs: u64,
        queueDepth: u32,
        queueFullStalls: u64,
        lastComputedBlock: u64,
    };

    pub fn getStats(self: *const Self) AsyncRootStats {
        const computed = self.rootsComputed.load(.acquire);
        const total_ns = self.totalComputationNs.load(.acquire);
        return .{
            .rootsComputed = computed,
            .avgComputationMs = if (computed > 0) total_ns / computed / 1_000_000 else 0,
            .maxComputationMs = self.maxComputationNs.load(.acquire) / 1_000_000,
            .queueDepth = self.queueCount.load(.acquire),
            .queueFullStalls = self.queueFullStalls.load(.acquire),
            .lastComputedBlock = self.lastComputedBlock.load(.acquire),
        };
    }
};
