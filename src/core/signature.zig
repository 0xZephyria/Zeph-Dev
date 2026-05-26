// ============================================================================
// Zephyria — Pluggable Cryptographic Signature Schemes
// ============================================================================
//
// Generic interface for transaction and consensus signature verification.
// Facilitates upgrading from Ed25519 to post-quantum signature schemes
// (such as ML-DSA/Dilithium or SPHINCS+) before production launch.

const std = @import("std");

pub const SignatureScheme = enum(u8) {
    ed25519 = 0,
    bls12_381 = 1,
    quantum_resistant = 2,
};

/// Verify a message signature using the specified scheme.
pub fn verify(scheme: SignatureScheme, msg: []const u8, sig: []const u8, pubkey: []const u8) !bool {
    switch (scheme) {
        .ed25519 => {
            if (sig.len != 64 or pubkey.len != 32) return false;
            const signature = std.crypto.sign.Ed25519.Signature.fromBytes(sig[0..64].*);
            const public_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(pubkey[0..32].*);
            signature.verify(msg, public_key) catch return false;
            return true;
        },
        .bls12_381 => {
            const crypto = @import("crypto");
            const PublicKey = crypto.blst.PublicKey;
            const Signature = crypto.blst.Signature;
            const DST = crypto.blst.DST;

            if (sig.len != 96 or pubkey.len != 48) return false;

            const pk = PublicKey.uncompress(pubkey) catch return false;
            const signature = Signature.uncompress(sig) catch return false;

            signature.verify(true, msg, DST, null, &pk, true) catch return false;
            return true;
        },
        .quantum_resistant => {
            // Placeholder for future post-quantum migration.
            return error.UnsupportedScheme;
        },
    }
}

/// Verify an aggregate signature against a slice of messages and public keys.
/// 'msgs' must have the same length as 'pks_bytes'.
pub fn verifyAggregate(sig_bytes: []const u8, msgs: []const [32]u8, pks_bytes: []const []const u8) !bool {
    const crypto = @import("crypto");
    const PublicKey = crypto.blst.PublicKey;
    const Signature = crypto.blst.Signature;
    const Pairing = crypto.blst.Pairing;
    const DST = crypto.blst.DST;

    if (sig_bytes.len != 96) return false;
    if (msgs.len != pks_bytes.len or msgs.len == 0) return false;

    const signature = Signature.uncompress(sig_bytes) catch return false;

    var buffer: [Pairing.sizeOf()]u8 = undefined;

    // Use stack allocation for up to 128 public keys to avoid heap allocation overhead in hot paths
    var inline_pks: [128]PublicKey = undefined;
    var pks: []PublicKey = undefined;
    var allocated_pks: ?[]PublicKey = null;
    if (pks_bytes.len <= 128) {
        pks = inline_pks[0..pks_bytes.len];
    } else {
        allocated_pks = std.heap.page_allocator.alloc(PublicKey, pks_bytes.len) catch return false;
        pks = allocated_pks.?;
    }
    defer if (allocated_pks) |ap| std.heap.page_allocator.free(ap);

    for (pks_bytes, 0..) |pk_b, i| {
        pks[i] = PublicKey.uncompress(pk_b) catch return false;
    }

    return signature.aggregateVerify(true, &buffer, msgs, DST, pks, true) catch |err| {
        std.log.err("verifyAggregate failed: {}", .{err});
        return false;
    };
}

/// Fast-verify an aggregate signature against a single message and a slice of public keys.
pub fn verifyFastAggregate(sig_bytes: []const u8, msg: *const [32]u8, pks_bytes: []const []const u8) !bool {
    const crypto = @import("crypto");
    const PublicKey = crypto.blst.PublicKey;
    const Signature = crypto.blst.Signature;
    const Pairing = crypto.blst.Pairing;
    const DST = crypto.blst.DST;

    if (sig_bytes.len != 96) return false;
    if (pks_bytes.len == 0) return false;

    const signature = Signature.uncompress(sig_bytes) catch return false;

    var buffer: [Pairing.sizeOf()]u8 = undefined;

    // Use stack allocation for up to 128 public keys to avoid heap allocation overhead in hot paths
    var inline_pks: [128]PublicKey = undefined;
    var pks: []PublicKey = undefined;
    var allocated_pks: ?[]PublicKey = null;
    if (pks_bytes.len <= 128) {
        pks = inline_pks[0..pks_bytes.len];
    } else {
        allocated_pks = std.heap.page_allocator.alloc(PublicKey, pks_bytes.len) catch return false;
        pks = allocated_pks.?;
    }
    defer if (allocated_pks) |ap| std.heap.page_allocator.free(ap);

    for (pks_bytes, 0..) |pk_b, i| {
        pks[i] = PublicKey.uncompress(pk_b) catch return false;
    }

    return signature.fastAggregateVerify(true, &buffer, msg, DST, pks, true) catch |err| {
        std.log.err("verifyFastAggregate failed: {}", .{err});
        return false;
    };
}

/// Verify a Proof-of-Possession signature against a public key and the validator's identity address/msg.
/// The POP_DST is used to prevent reuse/signature replay of regular consensus messages as PoP messages.
pub fn verifyProofOfPossession(pubkey_bytes: []const u8, msg: []const u8, sig_bytes: []const u8) !bool {
    const crypto = @import("crypto");
    const PublicKey = crypto.blst.PublicKey;
    const Signature = crypto.blst.Signature;
    const POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    if (sig_bytes.len != 96 or pubkey_bytes.len != 48) return false;

    const pk = PublicKey.uncompress(pubkey_bytes) catch return false;
    const signature = Signature.uncompress(sig_bytes) catch return false;

    signature.verify(true, msg, POP_DST, null, &pk, true) catch return false;
    return true;
}
