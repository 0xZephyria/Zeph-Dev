const std = @import("std");
const core = @import("core");
const types = @import("types.zig");

const blst_mod = core.crypto.blst;
const secureZero = @import("utils").secureZero;
const c = blst_mod.c;

pub const BLS_DST = "ZEPHYRIA_BLS_DST_V01";
pub const VRF_KEY_DST = "ZEPHYRIA_VRF_KEY_V01";
pub const REGISTRATION_DST = "ZEPHYRIA_REGISTRATION_V01";

/// Derive a BLS signing key (32 bytes) from a seed via blst_keygen (HKDF).
pub fn deriveBlsPrivKey(seed: [32]u8) [32]u8 {
    var mutable = seed;
    defer secureZero(&mutable);
    var sk: c.blst_scalar = undefined;
    defer secureZero(std.mem.asBytes(&sk));
    c.blst_keygen(&sk, &mutable, mutable.len, null, 0);
    var sk_bytes: [32]u8 = undefined;
    defer secureZero(&sk_bytes);
    c.blst_bendian_from_scalar(&sk_bytes, &sk);
    return sk_bytes;
}

/// Derive a VRF signing key (32 bytes) from a seed with a different domain tag.
pub fn deriveVrfPrivKey(seed: [32]u8) [32]u8 {
    var mutable = seed;
    defer secureZero(&mutable);
    var sk: c.blst_scalar = undefined;
    defer secureZero(std.mem.asBytes(&sk));
    c.blst_keygen(&sk, &mutable, mutable.len, VRF_KEY_DST, VRF_KEY_DST.len);
    var sk_bytes: [32]u8 = undefined;
    defer secureZero(&sk_bytes);
    c.blst_bendian_from_scalar(&sk_bytes, &sk);
    return sk_bytes;
}

/// Derive BLS public key (48 bytes compressed G1) from a BLS private key.
pub fn deriveBlsPubKey(priv_key: [32]u8) [48]u8 {
    var mutable = priv_key;
    defer secureZero(&mutable);
    var sk: c.blst_scalar = undefined;
    defer secureZero(std.mem.asBytes(&sk));
    c.blst_scalar_from_bendian(&sk, &mutable);
    var pk: c.blst_p1 = undefined;
    c.blst_sk_to_pk_in_g1(&pk, &sk);
    var pk_compressed: [48]u8 = undefined;
    c.blst_p1_compress(&pk_compressed, &pk);
    return pk_compressed;
}

/// Generate a BLS proof-of-possession: signs the registration message
/// "ZEPHYRIA_REGISTRATION_V01" ‖ validator_address with the BLS private key.
pub fn generatePop(priv_key: [32]u8, address: core.types.Address) [96]u8 {
    var mutable_key = priv_key;
    defer secureZero(&mutable_key);
    var msg: [32 + 20]u8 = undefined;
    @memcpy(msg[0..REGISTRATION_DST.len], REGISTRATION_DST);
    @memcpy(msg[REGISTRATION_DST.len..][0..20], &address.bytes);
    var p2: c.blst_p2 = undefined;
    c.blst_hash_to_g2(&p2, &msg, msg.len, BLS_DST.ptr, BLS_DST.len, null, 0);
    var sk: c.blst_scalar = undefined;
    defer secureZero(std.mem.asBytes(&sk));
    c.blst_scalar_from_bendian(&sk, &mutable_key);
    var sig: c.blst_p2 = undefined;
    c.blst_sign_pk_in_g1(&sig, &p2, &sk);
    var sig_bytes: [96]u8 = undefined;
    c.blst_p2_compress(&sig_bytes, &sig);
    return sig_bytes;
}

/// Verify a proof-of-possession against a BLS public key.
pub fn verifyPop(pk_bytes: [48]u8, address: core.types.Address, signature: [96]u8) bool {
    const zero_pk = [_]u8{0} ** 48;
    if (std.mem.eql(u8, &pk_bytes, &zero_pk)) return false;
    var msg: [32 + 20]u8 = undefined;
    @memcpy(msg[0..REGISTRATION_DST.len], REGISTRATION_DST);
    @memcpy(msg[REGISTRATION_DST.len..][0..20], &address.bytes);
    var pk_affine: c.blst_p1_affine = undefined;
    const pk_rc = c.blst_p1_uncompress(&pk_affine, &pk_bytes);
    if (pk_rc != c.BLST_SUCCESS) return false;
    if (!c.blst_p1_affine_in_g1(&pk_affine)) return false;
    var sig_affine: c.blst_p2_affine = undefined;
    const sig_rc = c.blst_p2_uncompress(&sig_affine, &signature);
    if (sig_rc != c.BLST_SUCCESS) return false;
    if (!c.blst_p2_affine_in_g2(&sig_affine)) return false;
    const result = c.blst_core_verify_pk_in_g1(
        &pk_affine,
        &sig_affine,
        true,
        &msg,
        msg.len,
        BLS_DST.ptr,
        BLS_DST.len,
        null,
        0,
    );
    return result == c.BLST_SUCCESS;
}

/// Verify a BLS signature over a raw message payload, given a public key.
/// DST is the domain separation tag used during signing.
pub fn verifyBlsSignature(pk_bytes: [48]u8, message: []const u8, dst: []const u8, sig_bytes: [96]u8) bool {
    const zero_pk = [_]u8{0} ** 48;
    if (std.mem.eql(u8, &pk_bytes, &zero_pk)) return false;
    var pk_affine: c.blst_p1_affine = undefined;
    const pk_rc = c.blst_p1_uncompress(&pk_affine, &pk_bytes);
    if (pk_rc != c.BLST_SUCCESS) return false;
    if (!c.blst_p1_affine_in_g1(&pk_affine)) return false;
    var sig_affine: c.blst_p2_affine = undefined;
    const sig_rc = c.blst_p2_uncompress(&sig_affine, &sig_bytes);
    if (sig_rc != c.BLST_SUCCESS) return false;
    if (!c.blst_p2_affine_in_g2(&sig_affine)) return false;
    const result = c.blst_core_verify_pk_in_g1(
        &pk_affine,
        &sig_affine,
        true,
        message.ptr,
        message.len,
        dst.ptr,
        dst.len,
        null,
        0,
    );
    return result == c.BLST_SUCCESS;
}

/// Verify a BLS vote signature on message = blockId(32) ‖ view(8,BE).
pub fn verifyVoteSignature(pk_bytes: [48]u8, block_id: core.types.Hash, view: u64, sig_bytes: [96]u8) bool {
    var msg: [40]u8 = undefined;
    @memcpy(msg[0..32], &block_id.bytes);
    std.mem.writeInt(u64, msg[32..40], view, .big);
    return verifyBlsSignature(pk_bytes, &msg, BLS_DST, sig_bytes);
}

/// Aggregate multiple BLS signatures (G2 points) into one.
pub fn aggregateBlsSignatures(signatures: []const [96]u8) [96]u8 {
    var acc = std.mem.zeroes(c.blst_p2);
    var first = true;
    for (signatures) |sig_bytes| {
        var sig_affine: c.blst_p2_affine = undefined;
        const rc = c.blst_p2_uncompress(&sig_affine, &sig_bytes);
        if (rc != c.BLST_SUCCESS) continue;
        if (!c.blst_p2_affine_in_g2(&sig_affine)) continue;
        var sig_jac = std.mem.zeroes(c.blst_p2);
        c.blst_p2_from_affine(&sig_jac, &sig_affine);
        if (first) {
            acc = sig_jac;
            first = false;
        } else {
            c.blst_p2_add_or_double(&acc, &acc, &sig_jac);
        }
    }
    var result: [96]u8 = undefined;
    c.blst_p2_compress(&result, &acc);
    return result;
}
