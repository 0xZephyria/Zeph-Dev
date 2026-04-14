// Deferred Executor — Executes blocks behind consensus (Monad-inspired)
//
// Runs execution 2 blocks behind the consensus frontier:
//   Consensus at block N → executing block N-2
//
// Benefits:
//   - Consensus never waits for execution
//   - Execution has more time budget
//   - State root verified retroactively (fraud proof window)
//   - On restart, catches up from last checkpoint

const std = @import("std");
const core = @import("core");
const types = core.types;
const Atomic = std.atomic.Value;

/// Deferred executor configuration
pub const DeferredConfig = struct {
    /// How far behind consensus execution runs
    depth: u32 = 2,
    /// Maximum execution backlog before consensus stalls
    max_backlog: u32 = 10,
    /// Verify state roots retroactively
    verify_roots: bool = true,
};

/// Execution debt entry — a block waiting to be executed
pub const ExecutionDebt = struct {
    block_number: u64,
    tx_hashes: []types.Hash,
    expected_root: ?types.Hash, // Set after execution for verification
    executed: bool,
    verified: bool,
};

/// Deferred execution statistics
pub const DeferredStats = struct {
    blocks_executed: u64,
    blocks_pending: u64,
    verification_failures: u64,
    catchup_count: u64,
    last_executed_block: u64,
};

/// Deferred execution engine
pub const DeferredExecutor = struct {
    allocator: std.mem.Allocator,
    config: DeferredConfig,
    /// Ring buffer of pending executions
    debt_queue: [16]?ExecutionDebt,
    /// Last confirmed execution
    last_executed: Atomic(u64),
    /// Last verified block
    last_verified: Atomic(u64),
    /// Stats
    blocks_executed: Atomic(u64),
    verification_failures: Atomic(u64),
    catchup_count: Atomic(u64),
    lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: DeferredConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .debt_queue = [_]?ExecutionDebt{null} ** 16,
            .last_executed = Atomic(u64).init(0),
            .last_verified = Atomic(u64).init(0),
            .blocks_executed = Atomic(u64).init(0),
            .verification_failures = Atomic(u64).init(0),
            .catchup_count = Atomic(u64).init(0),
            .lock = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (&self.debt_queue) |*d| {
            if (d.*) |*debt| {
                self.allocator.free(debt.tx_hashes);
                d.* = null;
            }
        }
    }

    /// Enqueue a finalized block for deferred execution
    pub fn enqueue(self: *Self, block_number: u64, tx_hashes: []const types.Hash) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const slot = @as(usize, @intCast(block_number % 16));

        // Clean old
        if (self.debt_queue[slot]) |*old| {
            self.allocator.free(old.tx_hashes);
        }

        const hashes = try self.allocator.alloc(types.Hash, tx_hashes.len);
        @memcpy(hashes, tx_hashes);

        self.debt_queue[slot] = ExecutionDebt{
            .block_number = block_number,
            .tx_hashes = hashes,
            .expected_root = null,
            .executed = false,
            .verified = false,
        };
    }

    /// Get the next block to execute (if available and deferred enough)
    pub fn nextToExecute(self: *Self, consensus_head: u64) ?*ExecutionDebt {
        self.lock.lock();
        defer self.lock.unlock();

        const target = self.last_executed.load(.acquire) + 1;

        // Only execute if we're far enough behind consensus
        if (consensus_head < target + self.config.depth) return null;

        const slot = @as(usize, @intCast(target % 16));
        if (self.debt_queue[slot]) |*debt| {
            if (debt.block_number == target and !debt.executed) {
                return debt;
            }
        }
        return null;
    }

    /// Mark a block as executed, storing its state root for later verification
    pub fn markExecuted(self: *Self, block_number: u64, state_root: types.Hash) void {
        self.lock.lock();
        defer self.lock.unlock();

        const slot = @as(usize, @intCast(block_number % 16));
        if (self.debt_queue[slot]) |*debt| {
            if (debt.block_number == block_number) {
                debt.executed = true;
                debt.expected_root = state_root;
            }
        }

        self.last_executed.store(block_number, .release);
        _ = self.blocks_executed.fetchAdd(1, .monotonic);
    }

    /// Verify a state root matches what was committed by consensus
    pub fn verifyStateRoot(self: *Self, block_number: u64, committed_root: types.Hash) bool {
        self.lock.lock();
        defer self.lock.unlock();

        const slot = @as(usize, @intCast(block_number % 16));
        if (self.debt_queue[slot]) |*debt| {
            if (debt.block_number == block_number and debt.executed) {
                if (debt.expected_root) |expected| {
                    const matches = std.mem.eql(u8, &expected.bytes, &committed_root.bytes);
                    debt.verified = matches;
                    if (!matches) {
                        _ = self.verification_failures.fetchAdd(1, .monotonic);
                    }
                    return matches;
                }
            }
        }
        return false;
    }

    /// Get the current execution backlog
    pub fn getBacklog(self: *const Self, consensus_head: u64) u64 {
        const executed = self.last_executed.load(.acquire);
        return consensus_head -| executed;
    }

    /// Check if consensus should stall (backlog too large)
    pub fn shouldStall(self: *const Self, consensus_head: u64) bool {
        return self.getBacklog(consensus_head) >= self.config.max_backlog;
    }

    /// Catch up execution from a checkpoint
    pub fn catchUpFrom(self: *Self, start_block: u64) void {
        self.last_executed.store(start_block, .release);
        _ = self.catchup_count.fetchAdd(1, .monotonic);
    }

    /// Get statistics
    pub fn getStats(self: *const Self) DeferredStats {
        return .{
            .blocks_executed = self.blocks_executed.load(.acquire),
            .blocks_pending = blk: {
                var count: u64 = 0;
                for (self.debt_queue) |entry| {
                    if (entry != null) count += 1;
                }
                break :blk count;
            },
            .verification_failures = self.verification_failures.load(.acquire),
            .catchup_count = self.catchup_count.load(.acquire),
            .last_executed_block = self.last_executed.load(.acquire),
        };
    }
};
