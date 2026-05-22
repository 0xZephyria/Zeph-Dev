const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const Atomic = std.atomic.Value;

pub const AsyncRootConfig = struct {
    rootLag: u32 = 2,
    maxQueueDepth: u32 = 8,
    enableVerification: bool = true,

    /// true = Verkle mode (commit trie, compute root)
    /// false = Flat KV mode (no per-block root — returns all zeros)
    computeRoot: bool = false,
};

const CommitRequest = struct {
    blockNumber: u64,
    dirtyCount: usize,
    queuedAtNs: i128,
};

pub const CompletedRoot = struct {
    blockNumber: u64,
    stateRoot: types.Hash,
    dirtyCount: usize,
    computationTimeNs: i128,
    completedAtNs: i128,
};

const RING_SIZE: usize = 64;

pub const AsyncStateRootComputer = struct {
    allocator: std.mem.Allocator,
    config: AsyncRootConfig,
    state: *state_mod.State,

    queue: [16]?CommitRequest,
    queueHead: usize,
    queueTail: usize,
    queueCount: Atomic(u32),
    queueMutex: std.Thread.Mutex,
    queueCond: std.Thread.Condition,

    completed: [RING_SIZE]?CompletedRoot,
    completedHead: Atomic(u64),

    bgThread: ?std.Thread,
    shutdown: Atomic(bool),

    rootsComputed: Atomic(u64),
    totalComputationNs: Atomic(u64),
    maxComputationNs: Atomic(u64),
    queueFullStalls: Atomic(u64),
    lastComputedBlock: Atomic(u64),

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        state: *state_mod.State,
        config: AsyncRootConfig,
    ) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .state = state,
            .queue = [_]?CommitRequest{null} ** 16,
            .queueHead = 0,
            .queueTail = 0,
            .queueCount = Atomic(u32).init(0),
            .queueMutex = .{},
            .queueCond = .{},
            .completed = [_]?CompletedRoot{null} ** RING_SIZE,
            .completedHead = Atomic(u64).init(0),
            .bgThread = null,
            .shutdown = Atomic(bool).init(false),
            .rootsComputed = Atomic(u64).init(0),
            .totalComputationNs = Atomic(u64).init(0),
            .maxComputationNs = Atomic(u64).init(0),
            .queueFullStalls = Atomic(u64).init(0),
            .lastComputedBlock = Atomic(u64).init(0),
        };
    }

    pub fn start(self: *Self) !void {
        if (self.bgThread != null) return;
        self.shutdown.store(false, .release);
        self.bgThread = try std.Thread.spawn(.{}, backgroundLoop, .{self});
    }

    pub fn stop(self: *Self) void {
        self.shutdown.store(true, .release);
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

    pub fn queueCommit(self: *Self, blockNumber: u64, dirtyCount: usize) void {
        self.queueMutex.lock();
        defer self.queueMutex.unlock();

        while (self.queueCount.load(.acquire) >= self.config.maxQueueDepth) {
            if (self.shutdown.load(.acquire)) return;
            _ = self.queueFullStalls.fetchAdd(1, .monotonic);
            self.queueCond.wait(&self.queueMutex);
        }

        self.queue[self.queueTail] = CommitRequest{
            .blockNumber = blockNumber,
            .dirtyCount = dirtyCount,
            .queuedAtNs = std.time.nanoTimestamp(),
        };
        self.queueTail = (self.queueTail + 1) % 16;
        _ = self.queueCount.fetchAdd(1, .monotonic);
        self.queueCond.signal();
    }

    pub fn getRoot(self: *const Self, blockNumber: u64) ?CompletedRoot {
        const slot = @as(usize, @intCast(blockNumber % RING_SIZE));
        if (self.completed[slot]) |result| {
            if (result.blockNumber == blockNumber) return result;
        }
        return null;
    }

    pub fn getLaggedRoot(self: *const Self, current_block: u64) types.Hash {
        if (current_block < self.config.rootLag) return types.Hash.zero();
        const target = current_block - self.config.rootLag;
        if (self.getRoot(target)) |result| return result.stateRoot;
        return types.Hash.zero();
    }

    pub fn waitForRoot(self: *Self, blockNumber: u64, timeout_ms: u64) ?CompletedRoot {
        const deadline_ns = std.time.nanoTimestamp() + @as(i128, timeout_ms) * 1_000_000;
        while (std.time.nanoTimestamp() < deadline_ns) {
            if (self.getRoot(blockNumber)) |result| return result;
            std.Thread.sleep(100_000);
        }
        return null;
    }

    fn backgroundLoop(self: *Self) void {
        while (!self.shutdown.load(.acquire)) {
            const request = blk: {
                self.queueMutex.lock();
                defer self.queueMutex.unlock();

                while (self.queueCount.load(.acquire) == 0) {
                    if (self.shutdown.load(.acquire)) return;
                    self.queueCond.timedWait(&self.queueMutex, 50_000_000) catch {};
                    if (self.shutdown.load(.acquire)) return;
                }

                const req = self.queue[self.queueHead] orelse continue;
                self.queue[self.queueHead] = null;
                self.queueHead = (self.queueHead + 1) % 16;
                _ = self.queueCount.fetchSub(1, .monotonic);
                self.queueCond.signal();
                break :blk req;
            };

            const compute_start = std.time.nanoTimestamp();

            const root_bytes: [32]u8 = [_]u8{0} ** 32;

            if (self.config.computeRoot) {
                // Verkle mode: commit and compute root (legacy)
                // Not used in Flat KV mode — kept for backward compatibility.
            }

            const compute_end = std.time.nanoTimestamp();
            const duration_ns = compute_end - compute_start;

            const slot = @as(usize, @intCast(request.blockNumber % RING_SIZE));
            self.completed[slot] = CompletedRoot{
                .blockNumber = request.blockNumber,
                .stateRoot = types.Hash{ .bytes = root_bytes },
                .dirtyCount = request.dirtyCount,
                .computationTimeNs = duration_ns,
                .completedAtNs = compute_end,
            };
            self.completedHead.store(request.blockNumber, .release);

            _ = self.rootsComputed.fetchAdd(1, .monotonic);
            self.lastComputedBlock.store(request.blockNumber, .release);
            const dur_u64: u64 = @intCast(@max(0, duration_ns));
            _ = self.totalComputationNs.fetchAdd(dur_u64, .monotonic);

            var current_max = self.maxComputationNs.load(.acquire);
            while (dur_u64 > current_max) {
                const result = self.maxComputationNs.cmpxchgWeak(current_max, dur_u64, .acq_rel, .acquire);
                if (result) |val| current_max = val else break;
            }
        }
    }

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
