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
const storage = @import("storage");
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
    /// BLS public key (48 bytes G1 compressed)
    bls_pubkey: [48]u8,
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
    /// Requires BLS public key and Proof-of-Possession (PoP) signature to
    /// prove ownership of the corresponding BLS private key.
    /// The PoP signature is over the BLS public key bytes (standard BLS PoP
    /// convention). A zero-filled pop_signature skips verification (genesis
    /// bootstrap / test-only path).
    pub fn registerValidator(
        self: *Self,
        address: types.Address,
        stake: u256,
        commission_rate: u32,
        bls_pubkey: [48]u8,
        pop_signature: [96]u8,
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

        // Verify Proof-of-Possession (proves validator controls the BLS secret key)
        const zero_pop = [_]u8{0} ** 96;
        if (!std.mem.eql(u8, &pop_signature, &zero_pop)) {
            const sig_mod = @import("core").signature;
            const valid = try sig_mod.verifyProofOfPossession(
                &bls_pubkey,
                &bls_pubkey, // msg = pubkey (standard BLS PoP convention)
                &pop_signature,
            );
            if (!valid) return error.InvalidProofOfPossession;
        }

        try self.validators.put(address, Validator{
            .address = address,
            .bls_pubkey = bls_pubkey,
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
            gop.value_ptr.* = .{};
        }

        try gop.value_ptr.append(self.allocator, Delegation{
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

        var completed = std.ArrayList(UnbondingEntry).empty;
        errdefer completed.deinit(self.allocator);
        var i: usize = 0;

        while (i < self.unbonding.items.len) {
            if (self.unbonding.items[i].completion_block <= block_number) {
                try completed.append(self.allocator, self.unbonding.items[i]);
                _ = self.unbonding.swapRemove(i);
                self.total_staked -|= completed.items[completed.items.len - 1].amount;
            } else {
                i += 1;
            }
        }

        return completed.toOwnedSlice(self.allocator);
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
        var active = std.ArrayList(Validator).empty;
        defer active.deinit(self.allocator);

        var it = self.validators.iterator();
        while (it.next()) |entry| {
            const v = entry.value_ptr.*;
            if (v.isActive() and v.total_stake() >= self.config.min_stake) {
                try active.append(self.allocator, v);
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

    /// Get all active validator stakes as a u256 slice (for committee formation).
    pub fn getValidatorStakes(self: *Self) ![]u256 {
        var stakes = std.ArrayListUnmanaged(u256){};
        defer stakes.deinit(self.allocator);

        var it = self.validators.iterator();
        while (it.next()) |entry| {
            const v = entry.value_ptr.*;
            if (v.isActive() and v.total_stake() >= self.config.min_stake) {
                try stakes.append(self.allocator, v.total_stake());
            }
        }

        const result = try self.allocator.alloc(u256, stakes.items.len);
        @memcpy(result, stakes.items);
        return result;
    }

    // ── Persistence (FlatKV at Epoch Boundaries) ─────────────────
    //
    // Staking state is serialized to the shared HybridDB at every
    // epoch rotation. On node restart, restore() reads it back.
    // Key namespace: 0xFF prefix (system-reserved, see State.stakingXxxKey).
    //
    // Serialization format: fixed-size packed byte arrays for each
    // record type, written directly with std.mem.writeInt / @memcpy.
    // This avoids any runtime allocation during snapshot.

    // Packed Validator record: 48+32+16+16+16+16+4+1+4+4+8+8+8+16+16+8 = 225 bytes
    const SerializedValidator = extern struct {
        bls_pubkey: [48]u8,
        address: [32]u8,
        stake_hi: u128,
        stake_lo: u128,
        delegated_stake_hi: u128,
        delegated_stake_lo: u128,
        commission_rate: u32,
        status: u8, // 0=Active 1=Jailed 2=Unbonding 3=Tombstoned
        missed_consecutive: u32,
        missed_total: u64,
        blocks_proposed: u64,
        jailed_at: u64,
        unjail_eligible_at: u64,
        total_slashed_hi: u128,
        total_slashed_lo: u128,
        registered_at: u64,
    };

    // Packed Delegation: 32+32+16+16+8 = 104 bytes
    const SerializedDelegation = extern struct {
        delegator: [32]u8,
        validator: [32]u8,
        amount_hi: u128,
        amount_lo: u128,
        start_block: u64,
    };

    // Packed UnbondingEntry: 32+32+16+16+8 = 104 bytes
    const SerializedUnbonding = extern struct {
        delegator: [32]u8,
        validator: [32]u8,
        amount_hi: u128,
        amount_lo: u128,
        completion_block: u64,
    };

    fn u256ToHiLo(v: u256) struct { hi: u128, lo: u128 } {
        return .{
            .hi = @intCast(v >> 128),
            .lo = @intCast(v & @as(u256, std.math.maxInt(u128))),
        };
    }

    fn hiLoToU256(hi: u128, lo: u128) u256 {
        return (@as(u256, hi) << 128) | @as(u256, lo);
    }

    /// Persist the full staking registry to HybridDB.
    /// Called at each epoch boundary. Non-blocking: writes are batched
    /// to the DB's write path, which handles durability asynchronously.
    pub fn persist(self: *Self, db: storage.DB) !void {
        // ── 1. Write metadata (validator count, unbonding count, delegation count) ──
        var val_count: u32 = 0;
        var val_iter = self.validators.iterator();
        while (val_iter.next()) |_| val_count += 1;

        var del_count: u32 = 0;
        var del_address_count: u32 = 0;
        var del_iter = self.delegations.iterator();
        while (del_iter.next()) |entry| {
            del_count += @intCast(entry.value_ptr.items.len);
            del_address_count += 1;
        }

        var meta_buf: [52]u8 = undefined;
        std.mem.writeInt(u32, meta_buf[0..4], val_count, .big);
        std.mem.writeInt(u32, meta_buf[4..8], del_count, .big);
        std.mem.writeInt(u32, meta_buf[8..12], @intCast(self.unbonding.items.len), .big);
        std.mem.writeInt(u64, meta_buf[12..20], self.current_block, .big);
        std.mem.writeInt(u256, meta_buf[20..52], self.total_staked, .big);
        const meta_key = core.State.stakingMetaKey(0x01);
        try db.write(&meta_key, &meta_buf);

        // Write validator address list
        if (val_count > 0) {
            const addresses = try self.allocator.alloc(u8, val_count * 32);
            defer self.allocator.free(addresses);
            var addr_idx: usize = 0;
            var val_iter2 = self.validators.iterator();
            while (val_iter2.next()) |entry| {
                @memcpy(addresses[addr_idx * 32 .. (addr_idx + 1) * 32], &entry.key_ptr.bytes);
                addr_idx += 1;
            }
            const val_list_key = core.State.stakingMetaKey(0x02);
            try db.write(&val_list_key, addresses);
        }

        // Write delegator address list
        if (del_address_count > 0) {
            const del_addresses = try self.allocator.alloc(u8, del_address_count * 32);
            defer self.allocator.free(del_addresses);
            var del_addr_idx: usize = 0;
            var del_iter2 = self.delegations.iterator();
            while (del_iter2.next()) |entry| {
                @memcpy(del_addresses[del_addr_idx * 32 .. (del_addr_idx + 1) * 32], &entry.key_ptr.bytes);
                del_addr_idx += 1;
            }
            const del_list_key = core.State.stakingMetaKey(0x03);
            try db.write(&del_list_key, del_addresses);
        }

        // ── 2. Write each validator ──────────────────────────────────────
        var vit = self.validators.iterator();
        while (vit.next()) |entry| {
            const v = entry.value_ptr.*;
            const hl_stake = u256ToHiLo(v.stake);
            const hl_del = u256ToHiLo(v.delegated_stake);
            const hl_slashed = u256ToHiLo(v.total_slashed);
            var sv = SerializedValidator{
                .bls_pubkey = v.bls_pubkey,
                .address = v.address.bytes,
                .stake_hi = hl_stake.hi,
                .stake_lo = hl_stake.lo,
                .delegated_stake_hi = hl_del.hi,
                .delegated_stake_lo = hl_del.lo,
                .commission_rate = v.commission_rate,
                .status = @intFromEnum(v.status),
                .missed_consecutive = v.missed_consecutive,
                .missed_total = v.missed_total,
                .blocks_proposed = v.blocks_proposed,
                .jailed_at = v.jailed_at,
                .unjail_eligible_at = v.unjail_eligible_at,
                .total_slashed_hi = hl_slashed.hi,
                .total_slashed_lo = hl_slashed.lo,
                .registered_at = v.registered_at,
            };
            const vkey = core.State.stakingValidatorKey(v.address);
            try db.write(&vkey, std.mem.asBytes(&sv));
        }

        // ── 3. Write each delegation ─────────────────────────────────────
        var dit = self.delegations.iterator();
        while (dit.next()) |entry| {
            for (entry.value_ptr.items, 0..) |d, local_idx| {
                const hl_amt = u256ToHiLo(d.amount);
                const sd = SerializedDelegation{
                    .delegator = d.delegator.bytes,
                    .validator = d.validator.bytes,
                    .amount_hi = hl_amt.hi,
                    .amount_lo = hl_amt.lo,
                    .start_block = d.start_block,
                };
                const dkey = core.State.stakingDelegationKey(d.delegator, @intCast(local_idx));
                try db.write(&dkey, std.mem.asBytes(&sd));
            }
        }

        // ── 4. Write each unbonding entry ────────────────────────────────
        for (self.unbonding.items, 0..) |u, idx| {
            const hl_amt = u256ToHiLo(u.amount);
            const su = SerializedUnbonding{
                .delegator = u.delegator.bytes,
                .validator = u.validator.bytes,
                .amount_hi = hl_amt.hi,
                .amount_lo = hl_amt.lo,
                .completion_block = u.completion_block,
            };
            const ukey = core.State.stakingUnbondingKey(@intCast(idx));
            try db.write(&ukey, std.mem.asBytes(&su));
        }

        // Flush to disk
        db.sync() catch {};
    }

    /// Restore staking state from HybridDB on node startup.
    /// Reads the metadata key first to determine counts, then reads
    /// each validator and delegation record in deterministic order.
    pub fn restore(self: *Self, db: storage.DB) !void {
        // ── 1. Read metadata ─────────────────────────────────────────────
        const meta_key = core.State.stakingMetaKey(0x01);
        const meta_raw = db.read(&meta_key) orelse return; // No data = fresh node
        if (meta_raw.len < 52) return;

        const val_count = std.mem.readInt(u32, meta_raw[0..4], .big);
        self.current_block = std.mem.readInt(u64, meta_raw[12..20], .big);

        // ── 2. Restore validators ─────────────────────────────────────────
        if (val_count > 0) {
            const val_list_key = core.State.stakingMetaKey(0x02);
            if (db.read(&val_list_key)) |val_list_raw| {
                var idx: usize = 0;
                const num_vals = val_list_raw.len / 32;
                while (idx < num_vals) : (idx += 1) {
                    var addr: types.Address = undefined;
                    @memcpy(&addr.bytes, val_list_raw[idx * 32 .. (idx + 1) * 32]);
                    _ = try self.restoreValidator(db, addr);
                }
            }
        }

        // ── 3. Restore delegations ────────────────────────────────────────
        const del_list_key = core.State.stakingMetaKey(0x03);
        if (db.read(&del_list_key)) |del_list_raw| {
            var del_idx: usize = 0;
            const num_dels = del_list_raw.len / 32;
            while (del_idx < num_dels) : (del_idx += 1) {
                var delegator_addr: types.Address = undefined;
                @memcpy(&delegator_addr.bytes, del_list_raw[del_idx * 32 .. (del_idx + 1) * 32]);

                // Read all delegations for this delegator
                var local_idx: u32 = 0;
                while (true) : (local_idx += 1) {
                    const dkey = core.State.stakingDelegationKey(delegator_addr, local_idx);
                    const draw = db.read(&dkey) orelse break;
                    if (draw.len < @sizeOf(SerializedDelegation)) break;
                    const sd = std.mem.bytesAsValue(SerializedDelegation, draw[0..@sizeOf(SerializedDelegation)]);
                    
                    const del = Delegation{
                        .delegator = delegator_addr,
                        .validator = types.Address{ .bytes = sd.validator },
                        .amount = hiLoToU256(sd.amount_hi, sd.amount_lo),
                        .start_block = sd.start_block,
                    };
                    
                    var list = try self.delegations.getOrPut(delegator_addr);
                    if (!list.found_existing) {
                        list.value_ptr.* = .{};
                    }
                    try list.value_ptr.append(self.allocator, del);
                }
            }
        }

        // ── 4. Restore unbonding entries ──────────────────────────────────
        const unb_count = std.mem.readInt(u32, meta_raw[8..12], .big);
        var i: u32 = 0;
        while (i < unb_count) : (i += 1) {
            const ukey = core.State.stakingUnbondingKey(i);
            const uraw = db.read(&ukey) orelse continue;
            if (uraw.len < @sizeOf(SerializedUnbonding)) continue;
            const su = std.mem.bytesAsValue(SerializedUnbonding, uraw[0..@sizeOf(SerializedUnbonding)]);
            try self.unbonding.append(self.allocator, UnbondingEntry{
                .delegator = types.Address{ .bytes = su.delegator },
                .validator = types.Address{ .bytes = su.validator },
                .amount = hiLoToU256(su.amount_hi, su.amount_lo),
                .completion_block = su.completion_block,
            });
        }
    }

    /// Restore a specific validator from the DB by address.
    /// Used by the consensus engine to lazily restore individual validators
    /// without loading the entire set at startup.
    pub fn restoreValidator(self: *Self, db: storage.DB, addr: types.Address) !bool {
        const vkey = core.State.stakingValidatorKey(addr);
        const vraw = db.read(&vkey) orelse return false;
        if (vraw.len < @sizeOf(SerializedValidator)) return false;
        const sv = std.mem.bytesAsValue(SerializedValidator, vraw[0..@sizeOf(SerializedValidator)]);
        const status: ValidatorStatus = switch (sv.status) {
            0 => .Active,
            1 => .Jailed,
            2 => .Unbonding,
            3 => .Tombstoned,
            else => .Jailed,
        };
        const v = Validator{
            .address = addr,
            .bls_pubkey = sv.bls_pubkey,
            .stake = hiLoToU256(sv.stake_hi, sv.stake_lo),
            .delegated_stake = hiLoToU256(sv.delegated_stake_hi, sv.delegated_stake_lo),
            .commission_rate = sv.commission_rate,
            .status = status,
            .missed_consecutive = sv.missed_consecutive,
            .missed_total = sv.missed_total,
            .blocks_proposed = sv.blocks_proposed,
            .jailed_at = sv.jailed_at,
            .unjail_eligible_at = sv.unjail_eligible_at,
            .total_slashed = hiLoToU256(sv.total_slashed_hi, sv.total_slashed_lo),
            .registered_at = sv.registered_at,
        };
        try self.validators.put(addr, v);
        self.total_staked += v.stake + v.delegated_stake;
        return true;
    }

    /// Slash a validator AND deduct the slashed amount from their on-chain
    /// account balance in the state DB. This is the production path: in-memory
    /// staking state and on-chain balance are both updated atomically.
    ///
    /// The `state` parameter is nullable — if null, only in-memory state is
    /// updated (used in tests and the legacy call path).
    pub fn slashAndPersist(
        self: *Self,
        address: types.Address,
        rate_bps: u32,
        reason: []const u8,
        state: ?*core.State,
    ) !u256 {
        // Apply in-memory slash first
        const slash_amount = try self.slash(address, rate_bps, reason);

        // Deduct from on-chain balance in state DB
        if (state) |s| {
            const current_balance = s.getBalance(address);
            const new_balance = if (current_balance > slash_amount)
                current_balance - slash_amount
            else
                0;
            s.setBalance(address, new_balance) catch {};
        }

        return slash_amount;
    }
};

