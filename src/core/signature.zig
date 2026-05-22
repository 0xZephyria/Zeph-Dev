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
            // Stubbed for validator signatures.
            return error.UnsupportedScheme;
        },
        .quantum_resistant => {
            // Placeholder for future post-quantum migration.
            return error.UnsupportedScheme;
        },
    }
}
