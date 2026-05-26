const std = @import("std");
const signature_mod = @import("signature.zig");
const crypto = @import("crypto");
const SecretKey = crypto.blst.SecretKey;
const PublicKey = crypto.blst.PublicKey;
const Signature = crypto.blst.Signature;
const AggregateSignature = crypto.blst.AggregateSignature;
const DST = crypto.blst.DST;

test "BLS12-381 single signature verify" {
    const ikm = [_]u8{0x42} ** 32;
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();
    const pk_bytes = pk.compress();

    const msg = "zephyria consensus verification test message";
    const sig = sk.sign(msg, DST, null);
    const sig_bytes = sig.compress();

    // Verify via public signature module API
    const verified = try signature_mod.verify(.bls12_381, msg, &sig_bytes, &pk_bytes);
    try std.testing.expect(verified);

    // Invalid message should fail verification
    const verified_bad_msg = try signature_mod.verify(.bls12_381, "wrong message", &sig_bytes, &pk_bytes);
    try std.testing.expect(!verified_bad_msg);

    // Invalid signature length should fail verification
    const verified_bad_sig_len = try signature_mod.verify(.bls12_381, msg, sig_bytes[0..90], &pk_bytes);
    try std.testing.expect(!verified_bad_sig_len);

    // Invalid pk length should fail verification
    const verified_bad_pk_len = try signature_mod.verify(.bls12_381, msg, &sig_bytes, pk_bytes[0..40]);
    try std.testing.expect(!verified_bad_pk_len);
}

test "BLS12-381 proof of possession verify" {
    const ikm = [_]u8{0x55} ** 32;
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();
    const pk_bytes = pk.compress();

    const POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const identity_msg = "validator_address_or_identifier_string";

    // Create Proof of Possession signature
    const pop_sig = sk.sign(identity_msg, POP_DST, null);
    const pop_sig_bytes = pop_sig.compress();

    // Verify via public signature module API
    const verified = try signature_mod.verifyProofOfPossession(&pk_bytes, identity_msg, &pop_sig_bytes);
    try std.testing.expect(verified);

    // Wrong identity should fail
    const verified_bad = try signature_mod.verifyProofOfPossession(&pk_bytes, "wrong_identity", &pop_sig_bytes);
    try std.testing.expect(!verified_bad);
}

test "BLS12-381 aggregate verify" {
    const num_validators = 5;
    const dst = DST;

    const ikm_base = [_]u8{0xaa} ** 32;
    var msgs: [num_validators][32]u8 = undefined;
    var pks_list: [num_validators][48]u8 = undefined;
    var sigs: [num_validators]Signature = undefined;

    for (0..num_validators) |i| {
        var ikm = ikm_base;
        ikm[0] = @intCast(i);
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        pks_list[i] = pk.compress();

        // Each validator signs a unique message
        var msg = [_]u8{0} ** 32;
        std.mem.writeInt(u64, msg[0..8], i, .little);
        msgs[i] = msg;

        sigs[i] = sk.sign(&msg, dst, null);
    }

    // Aggregate signatures
    const agg_sig = try AggregateSignature.aggregate(&sigs, false);
    const sig = Signature.fromAggregate(&agg_sig);
    const sig_bytes = sig.compress();

    // Construct slice of slices for public keys
    var pks_slices: [num_validators][]const u8 = undefined;
    for (0..num_validators) |i| {
        pks_slices[i] = &pks_list[i];
    }

    const verified = try signature_mod.verifyAggregate(&sig_bytes, &msgs, &pks_slices);
    try std.testing.expect(verified);

    // Fast aggregate verification (single message, multiple public keys)
    const fast_msg = [_]u8{0x77} ** 32;
    var fast_sigs: [num_validators]Signature = undefined;
    for (0..num_validators) |i| {
        var ikm = ikm_base;
        ikm[0] = @intCast(i);
        const sk = try SecretKey.keyGen(&ikm, null);
        fast_sigs[i] = sk.sign(&fast_msg, dst, null);
    }
    const fast_agg_sig = try AggregateSignature.aggregate(&fast_sigs, false);
    const fast_sig = Signature.fromAggregate(&fast_agg_sig);
    const fast_sig_bytes = fast_sig.compress();

    const fast_verified = try signature_mod.verifyFastAggregate(&fast_sig_bytes, &fast_msg, &pks_slices);
    try std.testing.expect(fast_verified);
}

test "BLS12-381 verify methods handling of invalid/malformed decompression inputs" {
    const bad_sig = [_]u8{0xff} ** 96;
    const bad_pk = [_]u8{0xff} ** 48;
    const msg = "test msg";
    const msg32 = [_]u8{42} ** 32;

    // verify (bls12_381 case)
    const verified1 = try signature_mod.verify(.bls12_381, msg, &bad_sig, &bad_pk);
    try std.testing.expect(!verified1);

    // verifyProofOfPossession
    const verified2 = try signature_mod.verifyProofOfPossession(&bad_pk, msg, &bad_sig);
    try std.testing.expect(!verified2);

    // verifyAggregate
    var bad_pk_slices = [_][]const u8{&bad_pk};
    var msgs32 = [_][32]u8{msg32};
    const verified3 = try signature_mod.verifyAggregate(&bad_sig, &msgs32, &bad_pk_slices);
    try std.testing.expect(!verified3);

    // verifyFastAggregate
    const verified4 = try signature_mod.verifyFastAggregate(&bad_sig, &msg32, &bad_pk_slices);
    try std.testing.expect(!verified4);
}
