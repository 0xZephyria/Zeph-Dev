const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;

/// System Account (Type 7).
/// Protocol-level accounts with restricted access. Initialized at genesis.
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

    /// Serialize to bytes: header(60) + name_len(2) + name(variable)
    pub fn serialize(self: *const SystemAccount, buf: []u8) []u8 {
        const hdr = std.mem.asBytes(&self.header);
        @memcpy(buf[0..60], hdr);
        std.mem.writeInt(u16, buf[60..62], @intCast(self.name.len), .big);
        if (self.name.len > 0) {
            @memcpy(buf[62..][0..self.name.len], self.name);
        }
        return buf[0..62 + self.name.len];
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: []const u8) ?SystemAccount {
        if (data.len < 62) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .System) return null;
        const name_len = std.mem.readInt(u16, data[60..62], .big);
        if (data.len < 62 + name_len) return null;
        return .{ .header = header, .name = data[62..62 + name_len] };
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
