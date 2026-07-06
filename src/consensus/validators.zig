const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const staking_mod = @import("staking.zig");

/// Owns the active validator set lifecycle: init, epoch rotation, slashing, index.
///
/// Ownership invariant: `active` is owned by this set (freed on deinit/rebuild).
/// The `all` slice (if set) is borrowed — used for genesis/historical reference.
pub const ValidatorSet = struct {
    allocator: std.mem.Allocator,

    /// Active validator info slice — owned
    active: []types.ValidatorInfo,

    /// Fast O(1) validator lookup by address → index into `active`
    indexByAddr: std.AutoHashMap(core.types.Address, usize),

    /// Cached total active stake — rebuilt on every mutation via rebuildIndex()
    totalActiveStake: u256,

    pub fn init(allocator: std.mem.Allocator, initial: []const types.ValidatorInfo) !ValidatorSet {
        const owned = try allocator.alloc(types.ValidatorInfo, initial.len);
        @memcpy(owned, initial);
        var set = ValidatorSet{
            .allocator = allocator,
            .active = owned,
            .indexByAddr = std.AutoHashMap(core.types.Address, usize).init(allocator),
            .totalActiveStake = 0,
        };
        set.rebuildIndex();
        return set;
    }

    pub fn deinit(self: *ValidatorSet) void {
        self.indexByAddr.deinit();
        self.allocator.free(self.active);
    }

    /// Rebuild the address→index map and recompute total stake cache.
    /// Call whenever `active` changes (e.g., init, epoch rotation).
    pub fn rebuildIndex(self: *ValidatorSet) void {
        self.indexByAddr.clearRetainingCapacity();
        var total: u256 = 0;
        for (self.active, 0..) |v, i| {
            self.indexByAddr.put(v.address, i) catch {};
            total += v.stake;
        }
        self.totalActiveStake = total;
    }

    /// Returns the cached total active stake (O(1), rebuilt on every mutation).
    pub fn totalStake(self: *const ValidatorSet) u256 {
        return self.totalActiveStake;
    }

    /// Rebuild the active set from staking state (called at epoch rotation).
    /// Frees the previous owned allocation.
    pub fn rebuildFromStaking(self: *ValidatorSet, staking: *staking_mod.Staking) !void {
        const staking_vals = try staking.getActiveSet();
        defer staking.allocator.free(staking_vals);

        self.allocator.free(self.active);
        self.active = try self.stakingValidatorsToInfo(staking_vals);
        self.rebuildIndex();
    }

    /// Convert a slice of staking Validator records to consensus ValidatorInfo.
    fn stakingValidatorsToInfo(self: *ValidatorSet, staking_vals: []const staking_mod.Validator) ![]types.ValidatorInfo {
        const infos = try self.allocator.alloc(types.ValidatorInfo, staking_vals.len);
        for (staking_vals, 0..) |sv, i| {
            infos[i] = .{
                .address = sv.address,
                .stake = sv.total_stake(),
                .status = switch (sv.status) {
                    .Active => .Active,
                    .Jailed, .Tombstoned => .Slashed,
                    .Unbonding => .Unbonding,
                },
                .blsPubKey = sv.bls_pubkey,
                .commission = @intCast(sv.commission_rate),
                .activationBlock = sv.registered_at,
                .slashCount = 0,
                .totalRewards = 0,
                .name = "",
                .website = "",
            };
        }
        return infos;
    }

    /// Return the number of active validators.
    pub fn len(self: *const ValidatorSet) usize {
        return self.active.len;
    }

    /// Get validator info by index. Returns null if out of bounds.
    pub fn get(self: *const ValidatorSet, index: usize) ?types.ValidatorInfo {
        if (index >= self.active.len) return null;
        return self.active[index];
    }

    /// Look up validator address → index. Returns null if not found.
    pub fn indexOf(self: *const ValidatorSet, address: core.types.Address) ?usize {
        return self.indexByAddr.get(address);
    }

    /// Look up validator by address. Returns null if not found.
    pub fn getByAddress(self: *const ValidatorSet, address: core.types.Address) ?types.ValidatorInfo {
        const idx = self.indexOf(address) orelse return null;
        return self.active[idx];
    }
};

/// Compute total stake across a validator set.
pub fn totalStake(validators: []const types.ValidatorInfo) u256 {
    var total: u256 = 0;
    for (validators) |v| {
        total += v.stake;
    }
    return total;
}

/// Find a validator's index by address. Returns null if not found.
pub fn indexByAddress(validators: []const types.ValidatorInfo, address: core.types.Address) ?u32 {
    for (validators, 0..) |v, i| {
        if (std.mem.eql(u8, &v.address.bytes, &address.bytes)) {
            return @intCast(i);
        }
    }
    return null;
}

/// Build an address-to-index lookup map.
pub fn buildAddressIndexMap(allocator: std.mem.Allocator, validators: []const types.ValidatorInfo) !std.AutoHashMap(core.types.Address, usize) {
    var map = std.AutoHashMap(core.types.Address, usize).init(allocator);
    for (validators, 0..) |v, i| {
        try map.put(v.address, i);
    }
    return map;
}
