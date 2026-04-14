// ============================================================================
// Zephyria — Committee Formation (Tier 2: Committee Loom)
// ============================================================================
//
// Epoch-shuffled committee management for 100–2000 validators.
// At each epoch boundary, validators are deterministically assigned to
// thread committees using Fisher-Yates shuffle seeded by the epoch seed.
//
// Properties:
//   • Deterministic — all validators compute the same assignments
//   • Minimum committee size enforced (20 validators per thread)
//   • Committees rotate every epoch (~7 minutes)
//   • Publicly verifiable from on-chain epoch seed

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

// ── Committee Manager ───────────────────────────────────────────────────

pub const CommitteeManager = struct {
    allocator: std.mem.Allocator,

    /// Epoch this assignment is valid for
    epoch: u64,
    /// Number of threads
    thread_count: u8,
    /// Number of validators
    validator_count: u32,

    /// Thread → list of validator indices assigned to it
    thread_committees: [types.MAX_THREADS]std.ArrayListUnmanaged(u32),
    /// Thread → total stake of committee members
    thread_stakes: [types.MAX_THREADS]u64,

    /// Validator index → thread assignment (for fast lookup)
    validator_thread: std.AutoHashMap(u32, u8),

    /// The shuffle seed used for this assignment
    shuffle_seed: [32]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        var committees: [types.MAX_THREADS]std.ArrayListUnmanaged(u32) = undefined;
        for (&committees) |*c| {
            c.* = .{};
        }
        return Self{
            .allocator = allocator,
            .epoch = 0,
            .thread_count = 0,
            .validator_count = 0,
            .thread_committees = committees,
            .thread_stakes = [_]u64{0} ** types.MAX_THREADS,
            .validator_thread = std.AutoHashMap(u32, u8).init(allocator),
            .shuffle_seed = [_]u8{0} ** 32,
        };
    }

    pub fn deinit(self: *Self) void {
        for (&self.thread_committees) |*c| {
            c.deinit(self.allocator);
        }
        self.validator_thread.deinit();
    }

    /// Recompute committee assignments for a new epoch.
    /// Uses Fisher-Yates shuffle with the epoch seed as PRNG.
    pub fn recompute(
        self: *Self,
        committee_seed: [32]u8,
        validator_count: u32,
        thread_count: u8,
        validator_stakes: []const u64,
    ) void {
        // Clear previous assignments
        for (&self.thread_committees) |*committee| {
            committee.clearRetainingCapacity();
        }
        self.thread_stakes = [_]u64{0} ** types.MAX_THREADS;
        self.validator_thread.clearRetainingCapacity();

        self.shuffle_seed = committee_seed;
        self.thread_count = thread_count;
        self.validator_count = validator_count;

        if (validator_count == 0 or thread_count == 0) return;

        // Build shuffled index array using deterministic PRNG
        // Fisher-Yates shuffle with Keccak256-based PRNG
        const n: usize = @intCast(validator_count);
        var indices = self.allocator.alloc(u32, n) catch return;
        defer self.allocator.free(indices);
        for (0..n) |i| {
            indices[i] = @intCast(i);
        }

        // PRNG: chain Keccak256 hashes from the seed
        var prng_state: [32]u8 = committee_seed;

        var i: usize = n;
        while (i > 1) {
            i -= 1;
            // Generate random index in [0, i]
            var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            hasher.update(&prng_state);
            var idx_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &idx_buf, @intCast(i), .big);
            hasher.update(&idx_buf);
            hasher.final(&prng_state);

            const rand_val = std.mem.readInt(u64, prng_state[0..8], .big);
            const j = rand_val % (i + 1);

            // Swap
            const tmp = indices[i];
            indices[i] = indices[j];
            indices[j] = tmp;
        }

        // Distribute shuffled validators across threads (round-robin)
        for (indices, 0..) |validator_idx, pos| {
            const thread_id: u8 = @intCast(pos % thread_count);

            self.thread_committees[thread_id].append(self.allocator, validator_idx) catch continue;
            self.validator_thread.put(validator_idx, thread_id) catch continue;

            // Track stake
            if (validator_idx < validator_stakes.len) {
                self.thread_stakes[thread_id] += validator_stakes[validator_idx];
            }
        }
    }

    /// Get the committee (list of validator indices) for a thread.
    pub fn getThreadCommittee(self: *const Self, thread_id: u8) []const u32 {
        if (thread_id >= types.MAX_THREADS) return &.{};
        return self.thread_committees[thread_id].items;
    }

    /// Get the total stake for a thread's committee.
    pub fn getThreadStake(self: *const Self, thread_id: u8) u64 {
        if (thread_id >= types.MAX_THREADS) return 0;
        return self.thread_stakes[thread_id];
    }

    /// Check if a validator is in a specific thread's committee.
    pub fn isInCommittee(self: *const Self, validator_index: u32, thread_id: u8) bool {
        if (self.validator_thread.get(validator_index)) |assigned_thread| {
            return assigned_thread == thread_id;
        }
        return false;
    }

    /// Get the thread assigned to a validator.
    pub fn getValidatorThread(self: *const Self, validator_index: u32) ?u8 {
        return self.validator_thread.get(validator_index);
    }

    /// Get the committee size for a thread.
    pub fn getCommitteeSize(self: *const Self, thread_id: u8) u32 {
        if (thread_id >= types.MAX_THREADS) return 0;
        return @intCast(self.thread_committees[thread_id].items.len);
    }

    /// Get the minimum committee size across all threads.
    pub fn getMinCommitteeSize(self: *const Self) u32 {
        if (self.thread_count == 0) return 0;
        var min_size: u32 = std.math.maxInt(u32);
        for (0..self.thread_count) |t| {
            const size: u32 = @intCast(self.thread_committees[t].items.len);
            if (size < min_size) min_size = size;
        }
        return min_size;
    }

    /// Verify that all committees meet the minimum size requirement.
    pub fn allCommitteesMeetMinimum(self: *const Self) bool {
        return self.getMinCommitteeSize() >= types.MIN_COMMITTEE_SIZE;
    }
};
