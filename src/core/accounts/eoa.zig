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

/// Derive the Verkle stem for an EOA address.
/// stem = keccak256(address)[0..31]
pub fn accountStem(addr: types.Address) [31]u8 {
    var h: [32]u8 = undefined;
    Keccak256.hash(&addr.bytes, &h, .{});
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

/// Derive address from private key bytes (secp256k1)
pub fn addressFromPrivKey(priv_key: [32]u8) !types.Address {
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    const scalar = try Secp256k1.scalar.Scalar.fromBytes(priv_key, .big);
    const public_key = try Secp256k1.basePoint.mul(scalar.toBytes(.big), .big);
    const uncompressed = public_key.toUncompressedSec1();
    var hasher = Keccak256.init(.{});
    hasher.update(uncompressed[1..]);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, hash[12..32]);
    return addr;
}

/// Derive address from uncompressed public key (65 bytes, 0x04 prefix)
pub fn addressFromPubKey(pub_key: []const u8) !types.Address {
    if (pub_key.len != 65 or pub_key[0] != 0x04) return error.InvalidKey;
    var hasher = Keccak256.init(.{});
    hasher.update(pub_key[1..]);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, hash[12..32]);
    return addr;
}

/// Verify an ECDSA signature
pub fn verifySignature(msg_hash: [32]u8, sig: [64]u8, pub_key_bytes: [65]u8) !bool {
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, std.crypto.hash.sha3.Keccak256);
    const signature = Ecdsa.Signature.fromBytes(sig);
    const public_key = try Ecdsa.PublicKey.fromSec1(pub_key_bytes[0..]);
    signature.verifyPrehashed(msg_hash, public_key) catch return false;
    return true;
}

/// Recover public key from ECDSA signature (r, s, recovery_id)
pub fn recoverPublicKey(msg_hash: [32]u8, r: [32]u8, s: [32]u8, recovery_id: u8) ![65]u8 {
    const Secp256k1 = std.crypto.ecc.Secp256k1;

    const prefix: u8 = 0x02 + (recovery_id % 2);
    var compressed_R: [33]u8 = undefined;
    compressed_R[0] = prefix;
    @memcpy(compressed_R[1..], &r);

    const R = try Secp256k1.fromSec1(&compressed_R);

    const e = try Secp256k1.scalar.Scalar.fromBytes(msg_hash, .big);
    const s_scalar = try Secp256k1.scalar.Scalar.fromBytes(s, .big);
    const r_scalar = try Secp256k1.scalar.Scalar.fromBytes(r, .big);

    const r_inv = r_scalar.invert();
    const e_neg = e.neg();

    const sR = try R.mul(s_scalar.toBytes(.big), .big);
    const neg_eG = try Secp256k1.basePoint.mul(e_neg.toBytes(.big), .big);
    const sum = sR.add(neg_eG);
    const Q = try sum.mul(r_inv.toBytes(.big), .big);

    return Q.toUncompressedSec1();
}

/// Backward-compatible alias: verify_signature(msg_hash, sig, pub_key)
pub fn verify_signature(challenge: [32]u8, sig: [64]u8, pub_key: [65]u8) !bool {
    return verifySignature(challenge, sig, pub_key);
}

/// Backward-compatible alias: recover_public_key
pub fn recover_public_key(msg_hash: [32]u8, r: [32]u8, s: [32]u8, recovery_id: u8) ![65]u8 {
    return recoverPublicKey(msg_hash, r, s, recovery_id);
}
