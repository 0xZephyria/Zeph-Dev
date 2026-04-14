// ============================================================================
// Zephyria — System Account (Type 7)
// ============================================================================
//
// Protocol-level accounts with restricted access. These are initialized at
// genesis and can only be mutated by the protocol itself (consensus, staking).
//
// System Contract Addresses:
//   0x1000 — Staking:    Validator deposits, delegations, slashing
//   0x2000 — Rewards:    Block reward distribution
//   0x3000 — Validator:  Validator registry, active set management
//   0x4000 — Randomness: VRF-based on-chain randomness beacon

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;

pub const SystemAccount = struct {
    header: AccountHeader,
    /// Human-readable identifier for this system account
    name: []const u8,

    pub fn init(address: types.Address, name: []const u8) SystemAccount {
        return .{
            .header = .{
                .account_type = .System,
                .owner_program = address,
                .flags = 0x02, // System flag
            },
            .name = name,
        };
    }
};

// ── Well-Known System Addresses ─────────────────────────────────────────

pub const STAKING_ADDRESS = parseSystemAddress(0x1000);
pub const REWARDS_ADDRESS = parseSystemAddress(0x2000);
pub const VALIDATOR_ADDRESS = parseSystemAddress(0x3000);
pub const RANDOMNESS_ADDRESS = parseSystemAddress(0x4000);

fn parseSystemAddress(comptime suffix: u16) types.Address {
    var addr = types.Address.zero();
    addr.bytes[18] = @intCast((suffix >> 8) & 0xFF);
    addr.bytes[19] = @intCast(suffix & 0xFF);
    return addr;
}

/// Check if an address is a system account
pub fn isSystemAddress(addr: types.Address) bool {
    // System addresses are in the range 0x0000...0000XXXX (last 2 bytes non-zero, rest zero)
    for (addr.bytes[0..18]) |b| {
        if (b != 0) return false;
    }
    const suffix = @as(u16, addr.bytes[18]) << 8 | addr.bytes[19];
    return suffix >= 0x1000 and suffix <= 0x4000;
}

/// Get the system account name for a given address
pub fn getSystemName(addr: types.Address) ?[]const u8 {
    if (addr.eql(STAKING_ADDRESS)) return "staking";
    if (addr.eql(REWARDS_ADDRESS)) return "rewards";
    if (addr.eql(VALIDATOR_ADDRESS)) return "validator";
    if (addr.eql(RANDOMNESS_ADDRESS)) return "randomness";
    return null;
}

/// All system addresses for genesis initialization
pub fn allSystemAddresses() [4]types.Address {
    return .{
        STAKING_ADDRESS,
        REWARDS_ADDRESS,
        VALIDATOR_ADDRESS,
        RANDOMNESS_ADDRESS,
    };
}
