const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const vrf_mod = @import("vrf.zig");
const committees_mod = @import("committees.zig");
const slot_mod = @import("slot.zig");

/// Configuration for epoch management.
pub const EpochConfig = struct {
    slotsPerEpoch: u64 = types.SLOTS_PER_EPOCH,
    slotDurationMs: u64 = types.SLOT_DURATION_MS,
};

/// Manages epoch lifecycle: transitions, tier detection, proposer schedule,
/// committee assignment, and epoch seed.
pub const EpochManager = struct {
    allocator: std.mem.Allocator,
    config: EpochConfig,

    currentEpoch: u64,
    currentTier: types.ConsensusTier,
    currentThreadCount: u8,
    epochSeed: [32]u8,
    validatorCount: u32,

    /// Pre-computed proposer schedule (slot → proposer index).
    proposerSchedule: std.AutoHashMap(u64, types.ProposerScheduleEntry),

    /// Committee manager for Tier 2.
    committeeManager: committees_mod.CommitteeManager,

    /// Track tier transitions for stats.
    epochsCompleted: u64,
    tierTransitions: u64,

    lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: EpochConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .currentEpoch = 0,
            .currentTier = .FullBFT,
            .currentThreadCount = 1,
            .epochSeed = [_]u8{0} ** 32,
            .validatorCount = 0,
            .proposerSchedule = std.AutoHashMap(u64, types.ProposerScheduleEntry).init(allocator),
            .committeeManager = committees_mod.CommitteeManager.init(allocator),
            .epochsCompleted = 0,
            .tierTransitions = 0,
            .lock = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.proposerSchedule.deinit();
        self.committeeManager.deinit();
    }

    /// Transition to a new epoch. Recomputes tier, thread count, committees,
    /// and proposer schedule for the entire epoch.
    pub fn transition(
        self: *Self,
        newEpoch: u64,
        validatorCount: u32,
        newSeed: [32]u8,
        validatorStakes: []const u256,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const oldTier = self.currentTier;
        const newTier = slot_mod.computeTier(validatorCount);
        const newThreadCount = slot_mod.computeThreadCount(validatorCount);

        self.currentEpoch = newEpoch;
        self.currentTier = newTier;
        self.currentThreadCount = newThreadCount;
        self.epochSeed = newSeed;
        self.validatorCount = validatorCount;

        if (oldTier != newTier) {
            self.tierTransitions += 1;
        }

        // Recompute committees for Tier 2
        if (newTier == .CommitteeLoom) {
            const committeeSeed = vrf_mod.VRF.committee_seed(newSeed, newEpoch);
            try self.committeeManager.recompute(
                committeeSeed,
                validatorCount,
                newThreadCount,
                validatorStakes,
            );
        }

        // Pre-compute proposer schedule for the entire epoch.
        self.proposerSchedule.clearRetainingCapacity();
        {
            const epochStart = newEpoch * self.config.slotsPerEpoch;
            const epochEnd = epochStart + self.config.slotsPerEpoch;
            var s = epochStart;
            while (s < epochEnd) : (s += 1) {
                if (s == 0) continue;
                const idx = slot_mod.deterministicProposer(newSeed, s, validatorCount);
                try self.proposerSchedule.put(s, types.ProposerScheduleEntry{
                    .slot = s,
                    .primaryProposer = idx,
                    .backupProposer = (idx + 1) % validatorCount,
                    .vrfHash = [_]u8{0} ** 32,
                });
            }
        }

        self.epochsCompleted += 1;
    }

    /// Look up the deterministic proposer for a slot from the pre-computed schedule.
    /// Falls back to on-the-fly computation if schedule is empty (solo mode).
    pub fn proposerForSlot(self: *const Self, slot: u64) u32 {
        if (self.proposerSchedule.get(slot)) |entry| {
            return entry.primaryProposer;
        }
        return slot_mod.deterministicProposer(self.epochSeed, slot, self.validatorCount);
    }

    /// Compute proposer eligibility via VRF sortition for Tier 2-3.
    pub fn computeProposerVrf(
        self: *Self,
        slot: u64,
        skBytes: [32]u8,
        myStake: u256,
        totalStake: u256,
    ) !?struct { proposer_index: u32, proof: [96]u8, vrf_hash: [32]u8 } {
        const result = try vrf_mod.VRF.sortition_proposer(
            skBytes,
            self.epochSeed,
            slot,
            myStake,
            totalStake,
            types.EXPECTED_PROPOSERS,
        );
        if (result.eligible) {
            return .{
                .proposer_index = 0,
                .proof = result.proof,
                .vrf_hash = result.vrf_hash,
            };
        }
        return null;
    }

    /// Commit the epoch seed for the current epoch.
    pub fn getEpochSeed(self: *const Self) [32]u8 {
        return self.epochSeed;
    }

    /// Getters.
    pub fn getTier(self: *const Self) types.ConsensusTier { return self.currentTier; }
    pub fn getThreadCount(self: *const Self) u8 { return self.currentThreadCount; }
    pub fn getEpochNumber(self: *const Self) u64 { return self.currentEpoch; }
    pub fn getProposerSchedule(self: *const Self) *const std.AutoHashMap(u64, types.ProposerScheduleEntry) {
        return &self.proposerSchedule;
    }
    pub fn getCommitteeManager(self: *Self) *committees_mod.CommitteeManager {
        return &self.committeeManager;
    }

    pub const Stats = struct {
        epoch: u64,
        tier: types.ConsensusTier,
        threadCount: u8,
        validatorCount: u32,
        epochsCompleted: u64,
        tierTransitions: u64,
    };

    pub fn getStats(self: *const Self) Stats {
        return .{
            .epoch = self.currentEpoch,
            .tier = self.currentTier,
            .threadCount = self.currentThreadCount,
            .validatorCount = self.validatorCount,
            .epochsCompleted = self.epochsCompleted,
            .tierTransitions = self.tierTransitions,
        };
    }
};
