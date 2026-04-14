const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

const State = core.State;

pub const ValidatorRegistry = struct {
    staking_addr: core.types.Address,
    validator_addr: core.types.Address,

    pub fn init(staking_addr: core.types.Address, validator_addr: core.types.Address) ValidatorRegistry {
        return ValidatorRegistry{
            .staking_addr = staking_addr,
            .validator_addr = validator_addr,
        };
    }

    /// Compute validator info storage key using Keccak256(address || "INFO")
    fn validator_info_key(self: *const ValidatorRegistry, addr: core.types.Address) core.types.Hash {
        _ = self;
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&addr.bytes);
        hasher.update("INFO");
        var result: core.types.Hash = undefined;
        hasher.final(&result.bytes);
        return result;
    }

    pub fn get_validator_info(self: *const ValidatorRegistry, world_state: *State, addr: core.types.Address) ?types.ValidatorInfo {
        const key = self.validator_info_key(addr);
        const data = world_state.get_verkle_value(key);
        if (data) |d| {
            defer world_state.allocator.free(d);
            if (d.len == 0) return null;
            // Decode ValidatorInfo from RLP
            const decoded = core.rlp.decode(world_state.allocator, types.ValidatorInfo, d) catch return null;
            return decoded;
        }
        return null;
    }

    pub fn register_validator(
        self: *ValidatorRegistry,
        world_state: *State,
        addr: core.types.Address,
        stake: u256,
        bls_pub_key: [48]u8,
        commission: u16,
        block_num: u64,
    ) !void {
        if (commission > 10000) return error.CommissionTooHigh;

        if (self.get_validator_info(world_state, addr) != null) return error.ValidatorAlreadyRegistered;

        const info = types.ValidatorInfo{
            .address = addr,
            .stake = stake,
            .status = .Active,
            .bls_pub_key = bls_pub_key,
            .commission = commission,
            .activation_block = block_num,
            .slash_count = 0,
            .total_rewards = 0,
            .name = "",
            .website = "",
        };

        // RLP encode and store in state
        const encoded = try core.rlp.encode(world_state.allocator, info);
        defer world_state.allocator.free(encoded);
        const key = self.validator_info_key(addr);
        try world_state.set_verkle_value(key, encoded);
    }
};
