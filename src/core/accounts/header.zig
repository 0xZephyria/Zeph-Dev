// ============================================================================
// Zephyria — Universal Account Header
// ============================================================================
//
// Fixed-size header shared by all account types.
// Guarantees:
//   • Predictable hashing (fixed layout, no dynamic fields)
//   • SIMD-friendly batch processing
//   • Zero dynamic allocation for header operations
//   • Efficient Verkle trie leaf encoding

const std = @import("std");
const types = @import("../types.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

/// Universal Account Header.
/// Every account in the Verkle trie starts with this header.
pub const AccountHeader = struct {
    /// Schema version for future upgrades
    version: u8 = 1,
    /// Account type discriminator (see types.AccountType)
    account_type: types.AccountType = .EOA,
    /// Bit flags: 0x01 = frozen, 0x02 = system, 0x04 = proxy
    flags: u16 = 0,
    /// Program that owns this account (zero for EOAs)
    owner_program: types.Address = types.Address.zero(),
    /// Transaction count (EOA) or update counter (contract)
    nonce: u64 = 0,
    /// Native token balance (in wei)
    balance: u128 = 0,
    /// Hash of the account's data payload
    data_hash: types.Hash = types.Hash.zero(),

    pub fn computeHash(self: AccountHeader) types.Hash {
        var buf: [128]u8 = [_]u8{0} ** 128;
        buf[0] = self.version;
        buf[1] = @intFromEnum(self.account_type);
        std.mem.writeInt(u16, buf[2..4], self.flags, .big);
        @memcpy(buf[4..24], &self.owner_program.bytes);
        std.mem.writeInt(u64, buf[24..32], self.nonce, .big);
        std.mem.writeInt(u128, buf[32..48], self.balance, .big);
        @memcpy(buf[48..80], &self.data_hash.bytes);
        var h: types.Hash = undefined;
        Keccak256.hash(&buf, &h.bytes, .{});
        return h;
    }

    /// Check if this account is a system account
    pub fn isSystem(self: AccountHeader) bool {
        return (self.flags & 0x02) != 0;
    }

    /// Check if this account is frozen (read-only)
    pub fn isFrozen(self: AccountHeader) bool {
        return (self.flags & 0x01) != 0;
    }
};
