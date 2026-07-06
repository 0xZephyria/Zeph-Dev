// ============================================================================
// Zephyria — QUIC TLS 1.3 Crypto Layer (RFC 9001)
// ============================================================================
//
// Implements the cryptographic primitives required by QUIC's TLS 1.3 integration:
//
//   • HKDF-SHA256 — key derivation (RFC 5869 via std.crypto.auth.hmac)
//   • QUIC Initial secret derivation (RFC 9001 §5.2)
//     - Client/Server initial keys from connection ID
//   • Header protection mask generation (RFC 9001 §5.4)
//     - AES-ECB-based for AES_128_GCM_SHA256 suites
//   • AEAD encryption/decryption (RFC 9001 §5.3)
//     - AES-128-GCM for Initial and Handshake packets
//     - ChaCha20-Poly1305 for application data (optional)
//   • TLS 1.3 Transcript Hash (SHA-256 rolling digest)
//   • Minimal TLS 1.3 handshake message construction:
//     - ClientHello / ServerHello (for QUIC CRYPTO frames)
//     - Certificate (validator's Ed25519 public key as SubjectPublicKeyInfo)
//     - CertificateVerify (Ed25519 signature over transcript)
//     - Finished (HMAC-SHA256 over transcript)
//
// Memory model: All buffers are stack or caller-allocated. Zero heap usage.

const std = @import("std");

// ── HKDF-SHA256 ───────────────────────────────────────────────────────────

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
pub fn hkdfExtract(salt: []const u8, ikm: []const u8, out: *[32]u8) void {
    HmacSha256.create(out, ikm, salt);
}

/// HKDF-Expand: T(i) expansion per RFC 5869 §2.3
/// Produces `out_len` bytes from `prk` and `info`.
pub fn hkdfExpand(prk: []const u8, info: []const u8, out: []u8) void {
    std.debug.assert(out.len <= 255 * 32);
    var prev: [32]u8 = undefined;
    var counter: u8 = 1;
    var pos: usize = 0;

    while (pos < out.len) {
        var mac = HmacSha256.init(prk);
        if (counter > 1) mac.update(&prev);
        mac.update(info);
        mac.update(&[_]u8{counter});
        mac.final(&prev);
        const take = @min(32, out.len - pos);
        @memcpy(out[pos .. pos + take], prev[0..take]);
        pos += take;
        counter += 1;
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1 / RFC 9001):
/// OKM = HKDF-Expand(secret, HkdfLabel, length)
/// where HkdfLabel = length(2) || "tls13 " + label || context_len || context
pub fn hkdfExpandLabel(
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) void {
    // Build HkdfLabel
    var label_buf: [512]u8 = undefined;
    var lpos: usize = 0;

    // length (2 bytes, big-endian)
    label_buf[lpos] = @intCast((out.len >> 8) & 0xFF);
    lpos += 1;
    label_buf[lpos] = @intCast(out.len & 0xFF);
    lpos += 1;

    // label = "tls13 " + label_str
    const prefix = "tls13 ";
    const full_label_len: u8 = @intCast(prefix.len + label.len);
    label_buf[lpos] = full_label_len;
    lpos += 1;
    @memcpy(label_buf[lpos .. lpos + prefix.len], prefix);
    lpos += prefix.len;
    @memcpy(label_buf[lpos .. lpos + label.len], label);
    lpos += label.len;

    // context
    label_buf[lpos] = @intCast(context.len);
    lpos += 1;
    @memcpy(label_buf[lpos .. lpos + context.len], context);
    lpos += context.len;

    hkdfExpand(secret, label_buf[0..lpos], out);
}

// ── QUIC v1 Initial Secrets (RFC 9001 §5.2) ──────────────────────────────

/// QUIC v1 salt (from RFC 9001 §5.2)
pub const QUIC_V1_INITIAL_SALT = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

pub const InitialSecrets = struct {
    client_initial: KeyIv,
    server_initial: KeyIv,
    client_hp: [16]u8, // header protection key
    server_hp: [16]u8,
};

pub const KeyIv = struct {
    key: [16]u8, // AES-128-GCM key
    iv: [12]u8,  // 12-byte nonce base
};

/// Derive Initial packet protection keys from the Destination Connection ID.
/// These keys are publicly known (not secret) and protect Initial packets.
pub fn deriveInitialSecrets(dst_conn_id: []const u8) InitialSecrets {
    // Step 1: HKDF-Extract with QUIC v1 salt
    var initial_secret: [32]u8 = undefined;
    hkdfExtract(&QUIC_V1_INITIAL_SALT, dst_conn_id, &initial_secret);

    // Step 2: Derive client/server secrets
    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;
    hkdfExpandLabel(&initial_secret, "client in", "", &client_secret);
    hkdfExpandLabel(&initial_secret, "server in", "", &server_secret);

    // Step 3: Derive key, iv, hp for each side
    var client_key: [16]u8 = undefined;
    var client_iv: [12]u8 = undefined;
    var client_hp: [16]u8 = undefined;
    hkdfExpandLabel(&client_secret, "quic key", "", &client_key);
    hkdfExpandLabel(&client_secret, "quic iv", "", &client_iv);
    hkdfExpandLabel(&client_secret, "quic hp", "", &client_hp);

    var server_key: [16]u8 = undefined;
    var server_iv: [12]u8 = undefined;
    var server_hp: [16]u8 = undefined;
    hkdfExpandLabel(&server_secret, "quic key", "", &server_key);
    hkdfExpandLabel(&server_secret, "quic iv", "", &server_iv);
    hkdfExpandLabel(&server_secret, "quic hp", "", &server_hp);

    return InitialSecrets{
        .client_initial = .{ .key = client_key, .iv = client_iv },
        .server_initial = .{ .key = server_key, .iv = server_iv },
        .client_hp = client_hp,
        .server_hp = server_hp,
    };
}

/// Derive application-level (1-RTT) secrets from the master secret and transcript.
pub fn derive1RttSecrets(
    master_secret: [32]u8,
    transcript_hash: [32]u8,
    client_out: *KeyIv,
    server_out: *KeyIv,
    client_hp_out: *[16]u8,
    server_hp_out: *[16]u8,
) void {
    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;

    hkdfExpandLabel(&master_secret, "c ap traffic", &transcript_hash, &client_secret);
    hkdfExpandLabel(&master_secret, "s ap traffic", &transcript_hash, &server_secret);

    hkdfExpandLabel(&client_secret, "quic key", "", &client_out.key);
    hkdfExpandLabel(&client_secret, "quic iv", "", &client_out.iv);
    hkdfExpandLabel(&client_secret, "quic hp", "", client_hp_out);

    hkdfExpandLabel(&server_secret, "quic key", "", &server_out.key);
    hkdfExpandLabel(&server_secret, "quic iv", "", &server_out.iv);
    hkdfExpandLabel(&server_secret, "quic hp", "", server_hp_out);
}

// ── Nonce Construction (RFC 9001 §5.3) ───────────────────────────────────

/// Compute the per-packet nonce by XOR-ing the IV base with the packet number.
/// Packet number is left-padded to 12 bytes (big-endian).
pub fn buildNonce(iv: [12]u8, packet_number: u64) [12]u8 {
    var nonce = iv;
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
    // XOR last 8 bytes of nonce with packet number
    for (0..8) |i| {
        nonce[4 + i] ^= pn_bytes[i];
    }
    return nonce;
}

// ── AES-128-GCM AEAD (RFC 9001 §5.3) ─────────────────────────────────────

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` in-place and append 16-byte authentication tag.
/// `ciphertext` must have capacity for `plaintext.len + TAG_LEN`.
/// `aad` = additional authenticated data (the QUIC packet header bytes).
pub fn aesGcmEncrypt(
    key: [16]u8,
    nonce: [12]u8,
    aad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8, // must be plaintext.len + TAG_LEN
) !void {
    if (ciphertext.len < plaintext.len + TAG_LEN) return error.BufferTooSmall;
    var tag: [TAG_LEN]u8 = undefined;
    Aes128Gcm.encrypt(
        ciphertext[0..plaintext.len],
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );
    @memcpy(ciphertext[plaintext.len .. plaintext.len + TAG_LEN], &tag);
}

/// Decrypt and authenticate `ciphertext` (which includes the 16-byte tag).
/// `plaintext` must have capacity for `ciphertext.len - TAG_LEN`.
pub fn aesGcmDecrypt(
    key: [16]u8,
    nonce: [12]u8,
    aad: []const u8,
    ciphertext: []const u8, // includes 16-byte tag at end
    plaintext: []u8,
) !void {
    if (ciphertext.len < TAG_LEN) return error.InvalidTag;
    const ct_len = ciphertext.len - TAG_LEN;
    if (plaintext.len < ct_len) return error.BufferTooSmall;
    const tag = ciphertext[ct_len..][0..TAG_LEN];
    try Aes128Gcm.decrypt(
        plaintext[0..ct_len],
        ciphertext[0..ct_len],
        tag.*,
        aad,
        nonce,
        key,
    );
}

// ── ChaCha20-Poly1305 AEAD (alternate suite) ──────────────────────────────

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// Encrypt with ChaCha20-Poly1305 (key must be 32 bytes).
pub fn chachaEncrypt(
    key: [32]u8,
    nonce: [12]u8,
    aad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
) !void {
    if (ciphertext.len < plaintext.len + 16) return error.BufferTooSmall;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(
        ciphertext[0..plaintext.len],
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );
    @memcpy(ciphertext[plaintext.len .. plaintext.len + 16], &tag);
}

pub fn chachaDecrypt(
    key: [32]u8,
    nonce: [12]u8,
    aad: []const u8,
    ciphertext: []const u8,
    plaintext: []u8,
) !void {
    if (ciphertext.len < 16) return error.InvalidTag;
    const ct_len = ciphertext.len - 16;
    const tag = ciphertext[ct_len..][0..16];
    try ChaCha20Poly1305.decrypt(
        plaintext[0..ct_len],
        ciphertext[0..ct_len],
        tag.*,
        aad,
        nonce,
        key,
    );
}

// ── Header Protection (RFC 9001 §5.4.3 — AES-ECB mask) ──────────────────

const Aes128 = std.crypto.core.aes.Aes128;

/// Generate the 5-byte header protection mask using AES-ECB.
/// `hp_key`: 16-byte header protection key.
/// `sample`: 16-byte sample from the encrypted payload (bytes 4..20 after pn).
pub fn aesHeaderProtectionMask(hp_key: [16]u8, sample: [16]u8) [5]u8 {
    var ctx = Aes128.initEnc(hp_key);
    var encrypted: [16]u8 = undefined;
    ctx.encrypt(&encrypted, &sample);
    return encrypted[0..5].*;
}

/// Generate header protection mask using ChaCha20 (for ChaCha20-Poly1305 suites).
/// `hp_key`: 32-byte header protection key.
/// `sample`: first 16 bytes of encrypted payload.
pub fn chachaHeaderProtectionMask(hp_key: [32]u8, sample: [16]u8) [5]u8 {
    // counter = first 4 bytes of sample (little-endian u32)
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    // nonce = last 12 bytes of sample
    const nonce = sample[4..16].*;
    var mask: [5]u8 = undefined;
    // ChaCha20 keystream at byte 0
    const zeros = [_]u8{0} ** 5;
    std.crypto.stream.chacha.ChaCha20IETF.xor(&mask, &zeros, counter, hp_key, nonce);
    return mask;
}

// ── TLS 1.3 Transcript Hash ───────────────────────────────────────────────

/// Rolling SHA-256 transcript hash for TLS 1.3.
pub const TranscriptHash = struct {
    state: std.crypto.hash.sha2.Sha256,

    pub fn init() TranscriptHash {
        return .{ .state = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *TranscriptHash, data: []const u8) void {
        self.state.update(data);
    }

    /// Get current hash without finalizing (peek).
    pub fn peek(self: *const TranscriptHash) [32]u8 {
        var copy = self.state;
        var out: [32]u8 = undefined;
        copy.final(&out);
        return out;
    }

    pub fn final(self: *TranscriptHash, out: *[32]u8) void {
        self.state.final(out);
    }
};

// ── TLS Handshake Message Builders ───────────────────────────────────────

/// Minimal TLS 1.3 ClientHello for QUIC (RFC 8446).
/// Used inside QUIC CRYPTO frames during the Initial handshake.
pub const ClientHello = struct {
    random: [32]u8,
    legacy_session_id: [32]u8,
    // We advertise TLS_AES_128_GCM_SHA256 (0x1301) only
    // + key_share with X25519 ECDH
    ecdh_public: [32]u8, // X25519 ephemeral public key

    pub fn encode(self: ClientHello, buf: []u8) !usize {
        var pos: usize = 0;

        // Handshake record: type=ClientHello(1), length TBD
        buf[pos] = 0x01; // ClientHello
        pos += 1;
        const len_pos = pos;
        pos += 3; // placeholder for 3-byte length

        // legacy_version = TLS 1.2 (0x0303)
        buf[pos] = 0x03; buf[pos+1] = 0x03; pos += 2;

        // random (32 bytes)
        @memcpy(buf[pos..pos+32], &self.random); pos += 32;

        // legacy_session_id (32 bytes, non-empty for middlebox compat)
        buf[pos] = 32; pos += 1;
        @memcpy(buf[pos..pos+32], &self.legacy_session_id); pos += 32;

        // cipher_suites: TLS_AES_128_GCM_SHA256
        buf[pos] = 0x00; buf[pos+1] = 0x02; pos += 2; // length = 2
        buf[pos] = 0x13; buf[pos+1] = 0x01; pos += 2; // TLS_AES_128_GCM_SHA256

        // legacy_compression_methods: null only
        buf[pos] = 0x01; buf[pos+1] = 0x00; pos += 2;

        // Extensions
        const ext_len_pos = pos; pos += 2;
        const ext_start = pos;

        // supported_versions (0x002B): TLS 1.3
        buf[pos] = 0x00; buf[pos+1] = 0x2B; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x03; pos += 2; // ext length
        buf[pos] = 0x02; pos += 1;
        buf[pos] = 0x03; buf[pos+1] = 0x04; pos += 2;

        // supported_groups (0x000A): X25519 only
        buf[pos] = 0x00; buf[pos+1] = 0x0A; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x04; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x02; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x1D; pos += 2; // x25519

        // signature_algorithms (0x000D): ed25519 (0x0807)
        buf[pos] = 0x00; buf[pos+1] = 0x0D; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x04; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x02; pos += 2;
        buf[pos] = 0x08; buf[pos+1] = 0x07; pos += 2;

        // key_share (0x0033): X25519 ephemeral key
        buf[pos] = 0x00; buf[pos+1] = 0x33; pos += 2;
        buf[pos] = 0x00; buf[pos+1] = 0x26; pos += 2; // ext length = 38
        buf[pos] = 0x00; buf[pos+1] = 0x24; pos += 2; // list length = 36
        buf[pos] = 0x00; buf[pos+1] = 0x1D; pos += 2; // x25519 group
        buf[pos] = 0x00; buf[pos+1] = 0x20; pos += 2; // key_exchange length = 32
        @memcpy(buf[pos..pos+32], &self.ecdh_public); pos += 32;

        // QUIC transport parameters (0x0039)
        // Minimal: max_udp_payload_size=1350, initial_max_data=1MB,
        //          initial_max_streams_bidi=128, initial_max_streams_uni=128
        const quic_params = buildMinimalTransportParams();
        buf[pos] = 0x00; buf[pos+1] = 0x39; pos += 2;
        const qp_len_pos = pos; pos += 2;
        const qp_start = pos;
        @memcpy(buf[pos..pos+quic_params.len], &quic_params);
        pos += quic_params.len;
        const qp_len: u16 = @intCast(pos - qp_start);
        buf[qp_len_pos] = @intCast(qp_len >> 8);
        buf[qp_len_pos+1] = @intCast(qp_len & 0xFF);

        // Fill in extensions length
        const ext_len: u16 = @intCast(pos - ext_start);
        buf[ext_len_pos] = @intCast(ext_len >> 8);
        buf[ext_len_pos+1] = @intCast(ext_len & 0xFF);

        // Fill in handshake message length (3 bytes)
        const msg_len = pos - len_pos - 3;
        buf[len_pos] = @intCast((msg_len >> 16) & 0xFF);
        buf[len_pos+1] = @intCast((msg_len >> 8) & 0xFF);
        buf[len_pos+2] = @intCast(msg_len & 0xFF);

        return pos;
    }
};

/// Build minimal QUIC transport parameters for inclusion in TLS extension.
fn buildMinimalTransportParams() [32]u8 {
    var params: [32]u8 = std.mem.zeroes([32]u8);
    var pos: usize = 0;
    // max_udp_payload_size (0x03) = 1350
    params[pos] = 0x03; pos += 1; // param id
    params[pos] = 0x02; pos += 1; // length = 2
    params[pos] = 0x05; params[pos+1] = 0x46; pos += 2; // 1350
    // initial_max_data (0x04) = 1048576 (1MB)
    params[pos] = 0x04; pos += 1;
    params[pos] = 0x04; pos += 1;
    params[pos] = 0x80; params[pos+1] = 0x10; params[pos+2] = 0x00; params[pos+3] = 0x00; pos += 4;
    return params;
}

/// Build a Finished message: HMAC-SHA256(finished_key, transcript_hash).
pub fn buildFinished(finished_key: [32]u8, transcript_hash: [32]u8, out: *[36]u8) void {
    // Handshake type = Finished (20), length = 32
    out[0] = 20;
    out[1] = 0; out[2] = 0; out[3] = 32;
    // HMAC-SHA256 verify data
    HmacSha256.create(out[4..36], &transcript_hash, &finished_key);
}

/// Verify a received Finished message.
pub fn verifyFinished(
    finished_key: [32]u8,
    transcript_hash: [32]u8,
    received_verify_data: [32]u8,
) bool {
    var expected: [32]u8 = undefined;
    HmacSha256.create(&expected, &transcript_hash, &finished_key);
    return std.crypto.timing_safe.eql([32]u8, expected, received_verify_data);
}

// ── Ed25519 Certificate Builder ───────────────────────────────────────────
//
// Solana-style: the validator's Ed25519 identity keypair is used directly
// as the TLS certificate. We construct a minimal X.509-like DER structure
// containing only the SubjectPublicKeyInfo.

const Ed25519 = std.crypto.sign.Ed25519;

pub const TlsConfig = struct {
    private_key: [64]u8,  // Ed25519 seed + public key (64 bytes)
    public_key: [32]u8,
    certificate_der: [256]u8,
    certificate_len: usize,

    pub fn init(private_key_seed: [32]u8) !TlsConfig {
        const kp = try Ed25519.KeyPair.generateDeterministic(private_key_seed);
        var cfg = TlsConfig{
            .private_key = kp.secret_key.bytes,
            .public_key = kp.public_key.bytes,
            .certificate_der = undefined,
            .certificate_len = 0,
        };
        cfg.certificate_len = buildSelfCert(kp.public_key.bytes, &cfg.certificate_der);
        return cfg;
    }

    /// Sign data with our Ed25519 key (for CertificateVerify)
    pub fn sign(self: *const TlsConfig, data: []const u8, out: *[64]u8) !void {
        const kp = Ed25519.KeyPair{
            .public_key = try Ed25519.PublicKey.fromBytes(self.public_key),
            .secret_key = try Ed25519.SecretKey.fromBytes(self.private_key),
        };
        const sig = try kp.sign(data, null);
        out.* = sig.toBytes();
    }
};

// ── X25519 ECDH (RFC 9001 key exchange) ────────────────────────────────
//
// QUIC uses X25519 (Curve25519) as the default key exchange mechanism.
// Both sides generate ephemeral keypairs and exchange public keys in the
// key_share TLS extension. The shared secret is used to derive Handshake
// and 1-RTT secrets per RFC 9001 §5.1.

/// Generate an ephemeral X25519 keypair for the TLS handshake.
pub fn generateEcdhKeypair() struct { private: [32]u8, public: [32]u8 } {
    const kp = std.crypto.dh.X25519.KeyPair.generate();
    return .{ .private = kp.secret_key, .public = kp.public_key };
}

/// Compute X25519 shared secret from our private key and peer's public key.
pub fn ecdhSharedSecret(private: [32]u8, public: [32]u8) [32]u8 {
    return std.crypto.dh.X25519.scalarmult(private, public) catch unreachable;
}

/// Derive Handshake-level keys from the ECDH shared secret.
/// Follows RFC 9001 §5.1 key schedule.
pub fn deriveHandshakeSecrets(
    shared_secret: [32]u8,
    transcript_hash: [32]u8,
    client_out: *KeyIv,
    server_out: *KeyIv,
    client_hp_out: *[16]u8,
    server_hp_out: *[16]u8,
) void {
    // handshake_secret = HKDF-Extract(salt=0, ikm=shared_secret)
    var handshake_secret: [32]u8 = undefined;
    hkdfExtract(&[_]u8{0} ** 32, &shared_secret, &handshake_secret);

    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;
    hkdfExpandLabel(&handshake_secret, "c hs traffic", &transcript_hash, &client_secret);
    hkdfExpandLabel(&handshake_secret, "s hs traffic", &transcript_hash, &server_secret);

    hkdfExpandLabel(&client_secret, "quic key", "", &client_out.key);
    hkdfExpandLabel(&client_secret, "quic iv", "", &client_out.iv);
    hkdfExpandLabel(&client_secret, "quic hp", "", client_hp_out);

    hkdfExpandLabel(&server_secret, "quic key", "", &server_out.key);
    hkdfExpandLabel(&server_secret, "quic iv", "", &server_out.iv);
    hkdfExpandLabel(&server_secret, "quic hp", "", server_hp_out);
}

/// Derive 1-RTT application-level keys from the ECDH shared secret.
pub fn derive1RttFromShared(
    shared_secret: [32]u8,
    transcript_hash: [32]u8,
    client_out: *KeyIv,
    server_out: *KeyIv,
    client_hp_out: *[16]u8,
    server_hp_out: *[16]u8,
) void {
    // Derive handshake_secret first
    var handshake_secret: [32]u8 = undefined;
    hkdfExtract(&[_]u8{0} ** 32, &shared_secret, &handshake_secret);

    // Derive master_secret = HKDF-Extract(salt=0, ikm=handshake_secret)
    var master_secret: [32]u8 = undefined;
    hkdfExtract(&[_]u8{0} ** 32, &handshake_secret, &master_secret);

    // Derive 1-RTT traffic secrets keyed with transcript hash
    derive1RttSecrets(master_secret, transcript_hash, client_out, server_out, client_hp_out, server_hp_out);
}

/// Build a minimal DER-encoded certificate containing the Ed25519 public key.
/// This is a simplified SubjectPublicKeyInfo embedded in a stub X.509 structure.
fn buildSelfCert(pub_key: [32]u8, out: *[256]u8) usize {
    // OID for Ed25519: 1.3.101.112 → DER = 06 03 2B 65 70
    // SubjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING }
    var pos: usize = 0;
    out[pos] = 0x30; pos += 1; // SEQUENCE
    const seq_len_pos = pos; pos += 1;
    const seq_start = pos;

    // AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 }
    out[pos] = 0x30; pos += 1; // inner SEQUENCE
    out[pos] = 0x05; pos += 1; // length = 5
    out[pos] = 0x06; pos += 1; // OID
    out[pos] = 0x03; pos += 1; // OID length = 3
    out[pos] = 0x2B; out[pos+1] = 0x65; out[pos+2] = 0x70; pos += 3;

    // BIT STRING containing the 32-byte Ed25519 public key
    out[pos] = 0x03; pos += 1; // BIT STRING
    out[pos] = 33;   pos += 1; // length = 33 (1 unused bits byte + 32 key bytes)
    out[pos] = 0x00; pos += 1; // 0 unused bits
    @memcpy(out[pos..pos+32], &pub_key);
    pos += 32;

    out[seq_len_pos] = @intCast(pos - seq_start);
    return pos;
}

/// Extract the Ed25519 public key from a minimal DER-encoded certificate
/// produced by buildSelfCert (or compatible format).
/// Returns null if parsing fails.
pub fn extractEd25519PublicKey(cert_der: []const u8) ?[32]u8 {
    // Expected structure: SEQUENCE { SEQUENCE { OID }, BIT STRING { 0x00 + 32 bytes } }
    if (cert_der.len < 8) return null;
    var off: usize = 0;

    // Outer SEQUENCE
    if (cert_der[off] != 0x30) return null;
    off += 1;
    const seq_len = readDerLength(cert_der, &off) orelse return null;
    _ = seq_len;
    if (off + 5 > cert_der.len) return null;

    // Skip AlgorithmIdentifier SEQUENCE
    if (cert_der[off] != 0x30) return null;
    off += 1;
    const alg_len = readDerLength(cert_der, &off) orelse return null;
    off += alg_len;
    if (off >= cert_der.len) return null;

    // BIT STRING
    if (cert_der[off] != 0x03) return null;
    off += 1;
    const bit_len = readDerLength(cert_der, &off) orelse return null;
    // bit_len = 33: 1 unused bits byte + 32 key bytes
    if (bit_len != 33) return null;
    if (off + 33 > cert_der.len) return null;
    // Skip unused bits byte
    off += 1;
    var pubkey: [32]u8 = undefined;
    @memcpy(&pubkey, cert_der[off..off+32]);
    return pubkey;
}

fn readDerLength(data: []const u8, off: *usize) ?usize {
    if (off.* >= data.len) return null;
    const first = data[off.*];
    off.* += 1;
    if (first < 0x80) return first;
    const num_bytes = first & 0x7F;
    if (num_bytes == 0 or num_bytes > 4) return null;
    if (off.* + num_bytes > data.len) return null;
    var len: usize = 0;
    for (0..num_bytes) |_| {
        len = (len << 8) | data[off.*];
        off.* += 1;
    }
    return len;
}

// ── Unit Tests (RFC 9001 Appendix A Test Vectors) ────────────────────────

test "QUIC Initial secrets — RFC 9001 Appendix A" {
    // Test vector from RFC 9001 Appendix A.1
    // client_dst_connection_id = 0x8394c8f03e515708
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = deriveInitialSecrets(&dcid);

    // Expected client key (from RFC 9001 Appendix A)
    const expected_client_key = [_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    };
    try std.testing.expectEqualSlices(u8, &expected_client_key, &secrets.client_initial.key);

    // Expected client IV
    const expected_client_iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    };
    try std.testing.expectEqualSlices(u8, &expected_client_iv, &secrets.client_initial.iv);

    // Expected client HP key
    const expected_client_hp = [_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    };
    try std.testing.expectEqualSlices(u8, &expected_client_hp, &secrets.client_hp);
}

test "Nonce construction" {
    const iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const nonce = buildNonce(iv, 1);
    // Last byte of IV should be XOR'd with 1
    try std.testing.expectEqual(@as(u8, 10), nonce[11]);
}

test "AES-128-GCM encrypt/decrypt round-trip" {
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 12;
    const plaintext = "hello zephyria quic";
    var ciphertext: [plaintext.len + TAG_LEN]u8 = undefined;
    try aesGcmEncrypt(key, nonce, &[_]u8{}, plaintext, &ciphertext);
    var decrypted: [plaintext.len]u8 = undefined;
    try aesGcmDecrypt(key, nonce, &[_]u8{}, &ciphertext, &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "TLS transcript hash — deterministic" {
    var t = TranscriptHash.init();
    t.update("hello");
    t.update(" world");
    const h1 = t.peek();
    const h2 = t.peek(); // peek should be idempotent
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "TlsConfig — Ed25519 cert generation" {
    const seed = [_]u8{0x42} ** 32;
    const cfg = try TlsConfig.init(seed);
    try std.testing.expect(cfg.certificate_len > 0);
    try std.testing.expect(cfg.certificate_len < 256);
}
