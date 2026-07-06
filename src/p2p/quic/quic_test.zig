// ============================================================================
// Zephyria — QUIC Integration Test Suite (RFC 9001 Test Vectors)
// ============================================================================
//
// Standalone QUIC tests using RFC 9001 Appendix A hardcoded test vectors.
// These are deterministic and don't require network access.
//
// RFC 9001 Appendix A: https://www.rfc-editor.org/rfc/rfc9001#appendix-A

const std = @import("std");
const testing = std.testing;

const tls = @import("tls.zig");
const pkt = @import("transport/packet.zig");
const frm = @import("frames.zig");
const conn_mod = @import("conn.zig");
const stream_mod = @import("stream.zig");

// ── RFC 9001 Appendix A Test Vectors ────────────────────────────────────

test "RFC 9001 A.1: Client Initial secrets" {
    // dcid = 8394c8f03e515708
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = tls.deriveInitialSecrets(&dcid);

    // Client key = 1f369613dd76d5467730efcbe3b1a22d
    const expected_key = [_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    };
    try testing.expectEqualSlices(u8, &expected_key, &secrets.client_initial.key);

    // Client IV = fa044b2f42a3fd3b46fb255c
    const expected_iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    };
    try testing.expectEqualSlices(u8, &expected_iv, &secrets.client_initial.iv);

    // Client HP = 9f50449e04a0e810283a1e9933adedd2
    const expected_hp = [_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    };
    try testing.expectEqualSlices(u8, &expected_hp, &secrets.client_hp);
}

test "RFC 9001 A.1: Server Initial secrets" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = tls.deriveInitialSecrets(&dcid);

    // Server key = cf3a5331653c364c88f0f379b6067e37
    const expected_key = [_]u8{
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
        0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    };
    try testing.expectEqualSlices(u8, &expected_key, &secrets.server_initial.key);

    // Server IV = 0ac1493ca1905853b0bba03e
    const expected_iv = [_]u8{
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
        0xb0, 0xbb, 0xa0, 0x3e,
    };
    try testing.expectEqualSlices(u8, &expected_iv, &secrets.server_initial.iv);

    // Server HP = c206b8d9b9f0f37644430b490eeaa314
    const expected_hp = [_]u8{
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
    };
    try testing.expectEqualSlices(u8, &expected_hp, &secrets.server_hp);
}

test "VarInt: complete RFC 9000 test vectors" {
    // From RFC 9000 Appendix A: Table of variable-length integer encodings
    const cases = [_]struct { bytes: []const u8, expected: u64 }{
        .{ .bytes = &[_]u8{0x00}, .expected = 0 },
        .{ .bytes = &[_]u8{0x01}, .expected = 1 },
        .{ .bytes = &[_]u8{0x3f}, .expected = 63 },
        .{ .bytes = &[_]u8{ 0x40, 0x00 }, .expected = 0 },
        .{ .bytes = &[_]u8{ 0x7f, 0xff }, .expected = 16383 },
        .{ .bytes = &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, .expected = 151288809941952652 },
        .{ .bytes = &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }, .expected = 494878333 },
        .{ .bytes = &[_]u8{ 0x7b, 0xbd }, .expected = 15293 },
    };

    for (cases) |tc| {
        const r = try pkt.varIntDecode(tc.bytes);
        try testing.expectEqual(tc.expected, r.value);
    }
}

test "AES-128-GCM: QUIC packet protection round-trip" {
    // Use the RFC 9001 client Initial key for this test
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = tls.deriveInitialSecrets(&dcid);

    const plaintext = "hello from zephyria blockchain!"; // 31 bytes
    const nonce = tls.buildNonce(secrets.client_initial.iv, 0);

    var ciphertext: [31 + tls.TAG_LEN]u8 = undefined;
    try tls.aesGcmEncrypt(secrets.client_initial.key, nonce, &[_]u8{}, plaintext, &ciphertext);

    var recovered: [31]u8 = undefined;
    try tls.aesGcmDecrypt(secrets.client_initial.key, nonce, &[_]u8{}, &ciphertext, &recovered);
    try testing.expectEqualSlices(u8, plaintext, &recovered);
}

test "Header protection mask: AES-ECB" {
    // From RFC 9001 Appendix A.2: Client Initial header protection
    // hp_key = 9f50449e04a0e810283a1e9933adedd2
    const hp_key = [_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    };
    // sample = d1b1c98dd7689fb8ec11d242b123dc9b (from RFC 9001 A.2)
    const sample = [_]u8{
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
    };
    const mask = tls.aesHeaderProtectionMask(hp_key, sample);
    // Expected mask[0] = 43 (first byte of AES-ECB output)
    try testing.expectEqual(@as(u8, 0x43), mask[0]);
}

test "Packet number encoding/decoding round-trip" {
    // Test pn_decode(encode(pn)) == pn for various values
    const cases = [_]u64{ 0, 1, 127, 128, 16383, 16384, 100000, 1000000 };
    for (cases) |pn| {
        const enc = pkt.encodePacketNumber(pn, if (pn > 0) pn - 1 else 0);
        const decoded = pkt.decodePacketNumber(enc.truncated, if (pn > 0) pn - 1 else 0, enc.pn_len);
        try testing.expectEqual(pn, decoded);
    }
}

test "Long header: Initial packet encode/decode" {
    var buf: [1500]u8 = undefined;
    const dst = try pkt.ConnectionId.fromSlice(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const src = try pkt.ConnectionId.fromSlice(&[_]u8{ 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04 });
    const fake_payload = [_]u8{0xAA} ** 32;

    const written = try pkt.encodeLongHeader(
        &buf, .Initial, pkt.QUIC_V1,
        dst, src, &[_]u8{}, // empty token
        42, 2, &fake_payload,
    );
    try testing.expect(written > 0);

    const kind = try pkt.detectHeaderKind(buf[0..written]);
    try testing.expectEqual(pkt.HeaderKind.Long, kind);

    const parsed = try pkt.parseLongHeader(buf[0..written]);
    try testing.expectEqual(pkt.QUIC_V1, parsed.hdr.version);
    try testing.expect(pkt.ConnectionId.eql(dst, parsed.hdr.dst_conn_id));
    try testing.expectEqual(pkt.QuicPacketType.Initial, parsed.hdr.packetType());
}

test "STREAM frame: Zephyria Gulf Stream stream ID" {
    const allocator = testing.allocator;
    const data = "tx-batch-0001";
    const original = frm.Frame{ .Stream = frm.StreamFrame{
        .stream_id = frm.StreamIds.GULF_STREAM,
        .offset = 0,
        .data = data,
        .fin = false,
    } };

    var buf: [128]u8 = undefined;
    const written = try original.encode(&buf);
    const decoded = try frm.Frame.decode(buf[0..written], allocator);
    try testing.expectEqual(frm.StreamIds.GULF_STREAM, decoded.frame.Stream.stream_id);
    try testing.expectEqualSlices(u8, data, decoded.frame.Stream.data);
}

test "ACK frame encode/decode" {
    const allocator = testing.allocator;
    const original = frm.Frame{ .Ack = frm.AckFrame{
        .largest_acknowledged = 100,
        .ack_delay = 250,
        .first_ack_range = 4, // packets 96-100 acked
        .ack_ranges = &[_]frm.AckRange{},
    } };

    var buf: [64]u8 = undefined;
    const written = try original.encode(&buf);
    const decoded = try frm.Frame.decode(buf[0..written], allocator);
    defer if (decoded.frame.Ack.ack_ranges.len > 0) allocator.free(decoded.frame.Ack.ack_ranges);
    try testing.expectEqual(@as(u64, 100), decoded.frame.Ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 4), decoded.frame.Ack.first_ack_range);
}

test "Stream reassembly: overlapping segments" {
    const allocator = testing.allocator;
    var s = stream_mod.QuicStream.init(allocator, 0, 65535);
    defer s.deinit();

    // Deliver three overlapping segments
    try s.receiveStreamFrame(frm.StreamFrame{ .stream_id = 0, .offset = 0, .data = "Hello", .fin = false });
    try s.receiveStreamFrame(frm.StreamFrame{ .stream_id = 0, .offset = 3, .data = "lo World", .fin = false }); // overlaps
    try s.receiveStreamFrame(frm.StreamFrame{ .stream_id = 0, .offset = 11, .data = "!", .fin = true });

    var buf: [32]u8 = undefined;
    const n = s.read(&buf);
    // Should deliver at least "Hello" (5 bytes)
    try testing.expect(n >= 5);
    try testing.expectEqualSlices(u8, "Hello", buf[0..5]);
}

test "Connection: full lifecycle with TLS key installation" {
    const allocator = testing.allocator;
    const addr = std.net.Address.initIp4([_]u8{127, 0, 0, 1}, 8009);

    const conn = try conn_mod.QuicConn.init(allocator, false, addr, null, null);
    defer conn.deinit();

    // Initial state
    try testing.expectEqual(conn_mod.ConnState.Initial, conn.state);
    try testing.expect(conn.pn_spaces[0].keys_available);

    // Install Handshake keys (simulating ServerHello processing)
    const kiv = tls.KeyIv{
        .key = [_]u8{0x42} ** 16,
        .iv = [_]u8{0x13} ** 12,
    };
    const hp = [_]u8{0x99} ** 16;
    conn.installHandshakeKeys(kiv, kiv, hp, hp);
    try testing.expectEqual(conn_mod.ConnState.Handshake, conn.state);

    // Install 1-RTT keys and establish
    conn.install1RttKeys(kiv, kiv, hp, hp);
    conn.establishConnection();
    try testing.expectEqual(conn_mod.ConnState.Established, conn.state);
    try testing.expectEqual(conn_mod.TlsState.Complete, conn.tls_state);
}

test "Nonce: packet number XOR" {
    const iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
    // Packet number = 2 (from RFC 9001 A.2 client packet number = 2)
    const nonce = tls.buildNonce(iv, 2);
    // Last byte: 0x5c XOR 0x02 = 0x5e
    try testing.expectEqual(@as(u8, 0x5e), nonce[11]);
}

test "HKDF-Expand-Label: quic key label" {
    // From RFC 9001 A.1:
    // HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = tls.deriveInitialSecrets(&dcid);

    // Re-derive client_initial_secret manually
    var initial_secret: [32]u8 = undefined;
    tls.hkdfExtract(&tls.QUIC_V1_INITIAL_SALT, &dcid, &initial_secret);
    var client_initial_secret: [32]u8 = undefined;
    tls.hkdfExpandLabel(&initial_secret, "client in", "", &client_initial_secret);

    var derived_key: [16]u8 = undefined;
    tls.hkdfExpandLabel(&client_initial_secret, "quic key", "", &derived_key);

    try testing.expectEqualSlices(u8, &secrets.client_initial.key, &derived_key);
}
