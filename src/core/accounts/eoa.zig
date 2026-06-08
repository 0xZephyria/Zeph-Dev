const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const common = @import("common.zig");

/// Externally Owned Account (Type 0).
/// User wallet. Header stores sequence + balance directly.
pub const EOA = struct {
    header: AccountHeader,

    pub fn init(address: types.Address) EOA {
        return .{
            .header = .{
                .account_type = .EOA,
                .owner_program = address,
            },
        };
    }

    pub fn withBalance(address: types.Address, balance: u128, sequence: u64) EOA {
        return .{
            .header = .{
                .account_type = .EOA,
                .owner_program = address,
                .balance = balance,
                .sequence = sequence,
            },
        };
    }

    pub fn getAddress(self: *const EOA) types.Address {
        return self.header.owner_program;
    }

    pub fn getBalance(self: *const EOA) u128 {
        return self.header.balance;
    }

    pub fn getSequence(self: *const EOA) u64 {
        return self.header.sequence;
    }

    /// Serialize this EOA account to a byte buffer.
    /// EOA has no payload beyond the header — all state is in header fields.
    pub fn serialize(self: *const EOA, buf: []u8) []u8 {
        @memcpy(buf[0..60], std.mem.asBytes(&self.header));
        return buf[0..60];
    }

    /// Deserialize an EOA account from a byte buffer.
    pub fn deserialize(data: []const u8) ?EOA {
        if (data.len < 60) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .EOA) return null;
        return .{ .header = header };
    }

    /// Verify the sequence matches an expected value.
    pub fn verifySequence(self: *const EOA, expected: u64) bool {
        return self.header.sequence == expected;
    }

    /// Verify the balance covers a required amount.
    pub fn hasSufficientBalance(self: *const EOA, required: u128) bool {
        return self.header.balance >= required;
    }

    /// Subtract from balance (returns new balance or error if insufficient).
    pub fn debit(self: *EOA, amount: u128) !void {
        if (self.header.balance < amount) return error.InsufficientBalance;
        self.header.balance -= amount;
    }

    /// Add to balance.
    pub fn credit(self: *EOA, amount: u128) void {
        self.header.balance += amount;
    }

    /// Increment sequence.
    pub fn incrementSequence(self: *EOA) void {
        self.header.sequence += 1;
    }
};

/// Sequence key: stem || 0x00
pub fn sequenceKey(addr: types.Address) [32]u8 {
    return common.sequenceKey(addr);
}

/// Balance key: stem || 0x01
pub fn balanceKey(addr: types.Address) [32]u8 {
    return common.balanceKey(addr);
}

/// Derive address from private key bytes (Ed25519 seed)
pub fn addressFromPrivKey(priv_key: [32]u8) !types.Address {
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(priv_key);
    var addr: types.Address = undefined;
    std.crypto.hash.Blake3.hash(&key_pair.public_key.toBytes(), &addr.bytes, .{});
    return addr;
}

/// Derive address from public key (32 bytes)
pub fn addressFromPubKey(pub_key: []const u8) !types.Address {
    if (pub_key.len != 32) return error.InvalidKey;
    var addr: types.Address = undefined;
    std.crypto.hash.Blake3.hash(pub_key, &addr.bytes, .{});
    return addr;
}

/// Verify an Ed25519 signature
pub fn verifySignature(msg: []const u8, sig: [64]u8, pub_key_bytes: [32]u8) !bool {
    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(sig);
    const public_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(pub_key_bytes);
    signature.verify(msg, public_key) catch return false;
    return true;
}

/// Backward-compatible alias: verify_signature
pub fn verify_signature(challenge: []const u8, sig: [64]u8, pub_key: [32]u8) !bool {
    return verifySignature(challenge, sig, pub_key);
}
