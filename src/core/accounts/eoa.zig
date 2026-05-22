// ============================================================================
// Zephyria — Externally Owned Account (Type 0)
// ============================================================================
//
// User wallet account. Each EOA is its own isolated state object.
// Parallel transactions from the same sender conflict ONLY on nonce,
// matching Ethereum semantics. No global nonce lock.

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

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

    pub fn withBalance(address: types.Address, balance: u128, nonce: u64) EOA {
        return .{
            .header = .{
                .account_type = .EOA,
                .owner_program = address,
                .balance = balance,
                .nonce = nonce,
            },
        };
    }

    pub fn getAddress(self: *const EOA) types.Address {
        return self.header.owner_program;
    }

    pub fn getBalance(self: *const EOA) u128 {
        return self.header.balance;
    }

    pub fn getNonce(self: *const EOA) u64 {
        return self.header.nonce;
    }
};

// ── Key Derivation ──────────────────────────────────────────────────────

/// Derive the Verkle stem/hash for an EOA address using BLAKE3.
/// stem = blake3(address)[0..31]
pub fn accountStem(addr: types.Address) [31]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&addr.bytes, &h, .{});
    var stem: [31]u8 = undefined;
    @memcpy(&stem, h[0..31]);
    return stem;
}

/// Nonce key: stem || 0x00
pub fn nonceKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x00;
    return key;
}

/// Balance key: stem || 0x01
pub fn balanceKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x01;
    return key;
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
