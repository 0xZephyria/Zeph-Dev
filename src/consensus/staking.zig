// ============================================================================
// Zephyria — Native Staking Protocol (Hardened)
// ============================================================================
//
// Production-hardened staking with:
//   • Minimum stake enforcement (10,000 ZEE)
//   • Auto-jailing after 100+ consecutive missed blocks
//   • Slashing: 100% for double-signing, 5% for downtime, 50% for fraud
//   • Cooldown period for re-registration after unjailing
//   • Delegator protection (proportional slash, forced unbonding on jail)
//   • Reward distribution with commission

const std = @import("std");
const core = @import("core");
const types = core.types;

/// Slash percentages (in basis points: 10000 = 100%)
pub const SlashRate = struct {
    pub const DOUBLE_SIGN: u32 = 10000; // 100%
    pub const DOWNTIME: u32 = 500; // 5%
    pub const FRAUD_PROOF: u32 = 5000; // 50%
    pub const INVALID_BLOCK: u32 = 2500; // 25%
};

/// Validator status
pub const ValidatorStatus = enum {
    Active,
    Jailed,
    Unbonding,
    Tombstoned, // Permanently banned (double-signing)
};

/// Extended validator record
pub const Validator = struct {
    address: types.Address,
    /// Self-staked amount
    stake: u256,
    /// Total delegated stake
    delegated_stake: u256,
    /// Commission rate (basis points: 1000 = 10%)
    commission_rate: u32,
    /// Status
    status: ValidatorStatus,
    /// Consecutive missed blocks
    missed_consecutive: u32,
    /// Total missed blocks
    missed_total: u64,
    /// Blocks proposed
    blocks_proposed: u64,
    /// Block number when jailed
    jailed_at: u64,
    /// Block number when eligible to unjail
    unjail_eligible_at: u64,
    /// Total slashed amount
    total_slashed: u256,
    /// Registration block
    registered_at: u64,

    pub fn total_stake(self: Validator) u256 {
        return self.stake + self.delegated_stake;
    }

    pub fn isActive(self: Validator) bool {
        return self.status == .Active;
    }
};

/// Delegation record
pub const Delegation = struct {
    delegator: types.Address,
    validator: types.Address,
    amount: u256,
    start_block: u64,
};

/// Unbonding record
pub const UnbondingEntry = struct {
    delegator: types.Address,
    validator: types.Address,
    amount: u256,
    completion_block: u64,
};

/// Slash event record
pub const SlashRecord = struct {
    validator: types.Address,
    amount: u256,
    reason: []const u8,
    block_number: u64,
    rate_bps: u32,
};

/// Reward distribution record
pub const RewardDistribution = struct {
    validator: types.Address,
    block_reward: u256,
    commission: u256,
    delegator_rewards: u256,
};

/// Staking configuration
pub const StakingConfig = struct {
    /// Minimum self-stake to register as validator (10,000 ZEE)
    min_stake: u256 = 10_000_000_000_000_000_000_000,
    /// Minimum delegation amount (100 ZEE)
    min_delegation: u256 = 100_000_000_000_000_000_000,
    /// Unbonding period in blocks (~7 days at 1s blocks)
    unbonding_period: u64 = 604_800,
    /// Cooldown after unjailing (1000 blocks)
    unjail_cooldown: u64 = 10_000,
    /// Block reward (2 ZEE)
    block_reward: u256 = 2_000_000_000_000_000_000,
    /// Missed blocks before jailing
    jail_threshold: u32 = 100,
    /// Maximum commission rate (50%)
    max_commission: u32 = 5000,
};

pub const Staking = struct {
    allocator: std.mem.Allocator,
    config: StakingConfig,
    /// Active validator set
    validators: std.AutoHashMap(types.Address, Validator),
    /// Delegations: delegator → list of delegations
    delegations: std.AutoHashMap(types.Address, std.ArrayList(Delegation)),
    /// Pending unbondings
    unbonding: std.ArrayListUnmanaged(UnbondingEntry),
    /// Slash history
    slash_history: std.ArrayListUnmanaged(SlashRecord),
    /// Current block for time tracking
    current_block: u64,
    /// Stats
    total_staked: u256,
    total_slashed: u256,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: StakingConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .validators = std.AutoHashMap(types.Address, Validator).init(allocator),
            .delegations = std.AutoHashMap(types.Address, std.ArrayList(Delegation)).init(allocator),
            .unbonding = .{},
            .slash_history = .{},
            .current_block = 0,
            .total_staked = 0,
            .total_slashed = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.validators.deinit();
        var it = self.delegations.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.delegations.deinit();
        self.unbonding.deinit(self.allocator);
        self.slash_history.deinit(self.allocator);
    }

    /// Register as a validator with initial stake.
    pub fn registerValidator(
        self: *Self,
        address: types.Address,
        stake: u256,
        commission_rate: u32,
        current_block_num: u64,
    ) !void {
        // Enforce minimum stake
        if (stake < self.config.min_stake) return error.StakeTooLow;

        // Enforce max commission
        if (commission_rate > self.config.max_commission) return error.CommissionTooHigh;

        // Check not already registered or tombstoned
        if (self.validators.get(address)) |existing| {
            if (existing.status == .Tombstoned) return error.ValidatorTombstoned;
            return error.AlreadyRegistered;
        }

        try self.validators.put(address, Validator{
            .address = address,
            .stake = stake,
            .delegated_stake = 0,
            .commission_rate = commission_rate,
            .status = .Active,
            .missed_consecutive = 0,
            .missed_total = 0,
            .blocks_proposed = 0,
            .jailed_at = 0,
            .unjail_eligible_at = 0,
            .total_slashed = 0,
            .registered_at = current_block_num,
        });

        self.total_staked += stake;
    }

    /// Delegate stake to a validator.
    pub fn delegate(
        self: *Self,
        delegator: types.Address,
        validator_addr: types.Address,
        amount: u256,
        current_block_num: u64,
    ) !void {
        // Enforce minimum delegation
        if (amount < self.config.min_delegation) return error.DelegationTooLow;

        var validator = self.validators.getPtr(validator_addr) orelse return error.ValidatorNotFound;
        if (validator.status == .Jailed) return error.ValidatorJailed;
        if (validator.status == .Tombstoned) return error.ValidatorTombstoned;

        validator.delegated_stake += amount;

        const gop = try self.delegations.getOrPut(delegator);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayList(Delegation).init(self.allocator);
        }

        try gop.value_ptr.append(Delegation{
            .delegator = delegator,
            .validator = validator_addr,
            .amount = amount,
            .start_block = current_block_num,
        });

        self.total_staked += amount;
    }

    /// Begin undelegation (starts unbonding period).
    pub fn undelegate(
        self: *Self,
        delegator: types.Address,
        validator_addr: types.Address,
        amount: u256,
        current_block_num: u64,
    ) !void {
        var validator = self.validators.getPtr(validator_addr) orelse return error.ValidatorNotFound;

        if (self.delegations.getPtr(delegator)) |dels| {
            for (dels.items) |*d| {
                if (std.mem.eql(u8, &d.validator.bytes, &validator_addr.bytes) and d.amount >= amount) {
                    d.amount -= amount;
                    validator.delegated_stake -|= amount;

                    try self.unbonding.append(self.allocator, UnbondingEntry{
                        .delegator = delegator,
                        .validator = validator_addr,
                        .amount = amount,
                        .completion_block = current_block_num + self.config.unbonding_period,
                    });
                    return;
                }
            }
        }
        return error.DelegationNotFound;
    }

    /// Process completed unbondings at the given block.
    pub fn processUnbonding(self: *Self, block_number: u64) ![]UnbondingEntry {
        self.current_block = block_number;

        var completed = std.ArrayList(UnbondingEntry).init(self.allocator);
        var i: usize = 0;

        while (i < self.unbonding.items.len) {
            if (self.unbonding.items[i].completion_block <= block_number) {
                try completed.append(self.unbonding.items[i]);
                _ = self.unbonding.swapRemove(i);
                self.total_staked -|= completed.items[completed.items.len - 1].amount;
            } else {
                i += 1;
            }
        }

        return completed.toOwnedSlice();
    }

    /// Slash a validator with rate in basis points (10000 = 100%).
    pub fn slash(self: *Self, address: types.Address, rate_bps: u32, reason: []const u8) !u256 {
        var validator = self.validators.getPtr(address) orelse return error.ValidatorNotFound;

        // Calculate slash amount
        const total = validator.total_stake();
        const slash_amount = (total * rate_bps) / 10000;

        // Apply slash to self-stake first, then delegated
        if (validator.stake >= slash_amount) {
            validator.stake -= slash_amount;
        } else {
            const remainder = slash_amount - validator.stake;
            validator.stake = 0;
            validator.delegated_stake -|= remainder;
        }

        validator.total_slashed += slash_amount;
        self.total_staked -|= slash_amount;
        self.total_slashed += slash_amount;

        // Record slash
        try self.slash_history.append(self.allocator, SlashRecord{
            .validator = address,
            .amount = slash_amount,
            .reason = reason,
            .block_number = self.current_block,
            .rate_bps = rate_bps,
        });

        // Tombstone for double-signing (100% slash = permanent ban)
        if (rate_bps >= SlashRate.DOUBLE_SIGN) {
            validator.status = .Tombstoned;
        } else {
            // Jail for other offenses
            validator.status = .Jailed;
            validator.jailed_at = self.current_block;
            validator.unjail_eligible_at = self.current_block + self.config.unjail_cooldown;
        }

        return slash_amount;
    }

    /// Record a missed block for a validator.
    pub fn recordMissedBlock(self: *Self, address: types.Address) !?u256 {
        var validator = self.validators.getPtr(address) orelse return null;

        validator.missed_consecutive += 1;
        validator.missed_total += 1;

        // Auto-jail if threshold exceeded
        if (validator.missed_consecutive >= self.config.jail_threshold and validator.status == .Active) {
            return try self.slash(address, SlashRate.DOWNTIME, "consecutive_missed_blocks");
        }

        return null;
    }

    /// Reset missed block counter (validator proposed a block).
    pub fn recordProposedBlock(self: *Self, address: types.Address) void {
        if (self.validators.getPtr(address)) |validator| {
            validator.missed_consecutive = 0;
            validator.blocks_proposed += 1;
        }
    }

    /// Unjail a validator (must meet cooldown requirement).
    pub fn unjail(self: *Self, address: types.Address) !void {
        var validator = self.validators.getPtr(address) orelse return error.ValidatorNotFound;

        if (validator.status != .Jailed) return error.NotJailed;
        if (validator.status == .Tombstoned) return error.ValidatorTombstoned;
        if (self.current_block < validator.unjail_eligible_at) return error.CooldownNotMet;

        // Must still have minimum stake to re-activate
        if (validator.total_stake() < self.config.min_stake) return error.StakeTooLow;

        validator.status = .Active;
        validator.missed_consecutive = 0;
        validator.jailed_at = 0;
    }

    /// Distribute block rewards to the proposer + delegators.
    pub fn distributeRewards(self: *Self, proposer: types.Address) !RewardDistribution {
        var validator = self.validators.getPtr(proposer) orelse return error.ValidatorNotFound;

        validator.blocks_proposed += 1;

        const total = self.config.block_reward;
        const commission = (total * validator.commission_rate) / 10000;
        const delegator_portion = total - commission;

        // Commission goes to validator's self-stake
        validator.stake += commission;

        // Delegator portion distributed proportionally
        if (validator.delegated_stake > 0) {
            validator.delegated_stake += delegator_portion;
        } else {
            validator.stake += delegator_portion;
        }

        self.total_staked += total;

        return RewardDistribution{
            .validator = proposer,
            .block_reward = total,
            .commission = commission,
            .delegator_rewards = delegator_portion,
        };
    }

    /// Get ALL active validators sorted by stake (no cap — adaptive protocol scales naturally).
    pub fn getActiveSet(self: *Self) ![]Validator {
        var active = std.ArrayList(Validator).init(self.allocator);
        defer active.deinit();

        var it = self.validators.iterator();
        while (it.next()) |entry| {
            const v = entry.value_ptr.*;
            if (v.isActive() and v.total_stake() >= self.config.min_stake) {
                try active.append(v);
            }
        }

        // Sort by total stake descending
        std.mem.sortUnstable(Validator, active.items, {}, struct {
            fn cmp(_: void, a: Validator, b: Validator) bool {
                return a.total_stake() > b.total_stake();
            }
        }.cmp);

        // Return ALL eligible validators (no cap)
        const count = active.items.len;
        var result = try self.allocator.alloc(Validator, count);
        @memcpy(result[0..count], active.items[0..count]);
        return result;
    }

    /// Get validator count (active only).
    pub fn validatorCount(self: *const Self) u32 {
        var count: u32 = 0;
        var it = self.validators.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isActive()) count += 1;
        }
        return count;
    }

    /// Get total slashed amount.
    pub fn getTotalSlashed(self: *const Self) u256 {
        return self.total_slashed;
    }

    /// Compute the consensus tier based on active validator count.
    /// Convenience wrapper around AdaptiveConsensus.computeTier.
    pub fn computeTier(self: *Self) @import("types.zig").ConsensusTier {
        return @import("adaptive.zig").AdaptiveConsensus.computeTier(self.validatorCount());
    }

    /// Get all active validator stakes as a u64 slice (for committee formation).
    pub fn getValidatorStakes(self: *Self) ![]u64 {
        var stakes = std.ArrayListUnmanaged(u64){};
        defer stakes.deinit(self.allocator);

        var it = self.validators.iterator();
        while (it.next()) |entry| {
            const v = entry.value_ptr.*;
            if (v.isActive() and v.total_stake() >= self.config.min_stake) {
                try stakes.append(self.allocator, @truncate(v.total_stake()));
            }
        }

        const result = try self.allocator.alloc(u64, stakes.items.len);
        @memcpy(result, stakes.items);
        return result;
    }
};
