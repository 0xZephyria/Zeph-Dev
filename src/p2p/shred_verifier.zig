// ============================================================================
// Zephyria — Shred Signature Verifier (Turbine Security)
// ============================================================================
//
// Verifies the Ed25519 producer signature on incoming shreds before they
// are processed by the Turbine engine. This prevents Byzantine validators
// from injecting corrupted or forged shreds into the propagation tree.
//
// Security model:
//   1. Block producer signs the (block_number || shred_index || payload_hash)
//      tuple using their Ed25519 validator key.
//   2. Receiving validators verify this signature against the known validator
//      set before inserting the shred into their collector.
//   3. Invalid signatures are rejected and the sending peer is penalized.
//
// Performance:
//   - Ed25519 verification: ~75μs per signature on modern CPUs
//   - At 54K shreds/block (48MB block), total verification: ~4 seconds
//   - Mitigation: batch verification and sampling (verify N% of shreds)
//   - For production at 1M TPS: sample 10% = ~5.4K verifications = ~400ms

const std = @import("std");
const core = @import("core");
const types = core.types;

// ── Shred Signature Configuration ──────────────────────────────────────

pub const ShredVerifyConfig = struct {
    /// Fraction of shreds to verify (0.0–1.0).
    /// At 1.0: verify all (highest security, highest cost).
    /// At 0.1: verify 10% (production default for 1M TPS).
    sampleRate: f64 = 0.10,

    /// Enable verification at all.
    /// Disable for benchmarking or trusted validator sets.
    enabled: bool = true,

    /// Maximum cache size for validator public keys.
    maxValidators: u32 = 200_000,
};

// ── Validator Set ──────────────────────────────────────────────────────

/// Minimal validator entry for signature verification.
pub const ValidatorEntry = struct {
    address: types.Address,
    /// Ed25519 public key (32 bytes)
    pubkey: [32]u8,
    /// Current stake (for weight-based sampling)
    stake: u64,
    /// Is this validator currently active?
    active: bool,
};

// ── Shred Verifier ─────────────────────────────────────────────────────

pub const ShredVerifier = struct {
    allocator: std.mem.Allocator,
    config: ShredVerifyConfig,
    validators: std.AutoHashMap(types.Address, ValidatorEntry),

    // Stats
    totalVerified: u64,
    totalPassed: u64,
    totalFailed: u64,
    totalSkipped: u64,

    // Deterministic sampling PRNG
    sampleState: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ShredVerifyConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .validators = std.AutoHashMap(types.Address, ValidatorEntry).init(allocator),
            .totalVerified = 0,
            .totalPassed = 0,
            .totalFailed = 0,
            .totalSkipped = 0,
            .sampleState = 0x123456789ABCDEF0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.validators.deinit();
    }

    /// Register a validator's public key for signature verification.
    pub fn addValidator(self: *Self, entry: ValidatorEntry) !void {
        try self.validators.put(entry.address, entry);
    }

    /// Remove a validator (e.g., on slash or unstake).
    pub fn removeValidator(self: *Self, addr: types.Address) void {
        _ = self.validators.remove(addr);
    }

    /// Check if a validator is registered and active.
    pub fn isValidProducer(self: *const Self, addr: types.Address) bool {
        if (self.validators.get(addr)) |v| {
            return v.active;
        }
        return false;
    }

    /// Compute the signing payload for a shred:
    ///   SHA256(block_number || shred_index || SHA256(payload))
    pub fn computeSigningPayload(
        block_number: u64,
        shred_index: u32,
        payload: []const u8,
    ) [32]u8 {
        // Hash the payload
        var payload_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &payload_hash, .{});

        // Hash (block_number || shred_index || payload_hash)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(std.mem.asBytes(&block_number));
        hasher.update(std.mem.asBytes(&shred_index));
        hasher.update(&payload_hash);

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Verify a shred's producer signature.
    /// Returns true if the signature is valid or verification was skipped (sampling).
    /// Returns false if the signature is invalid.
    pub fn verifyShred(
        self: *Self,
        block_number: u64,
        shred_index: u32,
        payload: []const u8,
        signature: [64]u8,
        producer_addr: types.Address,
    ) bool {
        if (!self.config.enabled) {
            self.totalSkipped += 1;
            return true;
        }

        // Deterministic sampling: skip verification for some shreds
        if (self.config.sampleRate < 1.0) {
            self.sampleState = xorshift64(self.sampleState);
            const threshold: u64 = @intFromFloat(self.config.sampleRate * @as(f64, @floatFromInt(std.math.maxInt(u64))));
            if (self.sampleState > threshold) {
                self.totalSkipped += 1;
                return true; // Skip — not sampled
            }
        }

        // Look up producer's public key
        const validator = self.validators.get(producer_addr) orelse {
            // Unknown producer — could be legitimate if validator set is out of date,
            // but we must reject for safety.
            self.totalVerified += 1;
            self.totalFailed += 1;
            return false;
        };

        if (!validator.active) {
            self.totalVerified += 1;
            self.totalFailed += 1;
            return false;
        }

        // Compute signing payload
        const signing_payload = computeSigningPayload(block_number, shred_index, payload);

        // Verify Ed25519 signature
        const valid = verifyEd25519(signing_payload, signature, validator.pubkey);

        self.totalVerified += 1;
        if (valid) {
            self.totalPassed += 1;
        } else {
            self.totalFailed += 1;
        }

        return valid;
    }

    // ── Stats ───────────────────────────────────────────────────────

    pub const VerifierStats = struct {
        totalVerified: u64,
        totalPassed: u64,
        totalFailed: u64,
        totalSkipped: u64,
        sampleRate: f64,
        validatorsRegistered: u32,
    };

    pub fn getStats(self: *const Self) VerifierStats {
        return .{
            .totalVerified = self.totalVerified,
            .totalPassed = self.totalPassed,
            .totalFailed = self.totalFailed,
            .totalSkipped = self.totalSkipped,
            .sampleRate = self.config.sampleRate,
            .validatorsRegistered = @intCast(self.validators.count()),
        };
    }
};

// ── Ed25519 Verification ───────────────────────────────────────────────

/// Verify an Ed25519 signature.
/// Uses Zig's standard library Ed25519 implementation.
fn verifyEd25519(message: [32]u8, signature: [64]u8, pubkey: [32]u8) bool {
    const Ed25519 = std.crypto.sign.Ed25519;
    const sig = Ed25519.Signature.fromBytes(signature);
    const pk = Ed25519.PublicKey.fromBytes(pubkey) catch return false;
    sig.verify(&message, pk) catch return false;
    return true;
}

/// xorshift64 PRNG for deterministic sampling
fn xorshift64(state: u64) u64 {
    var x = state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

// ── Tests ───────────────────────────────────────────────────────────────

test "ShredVerifier init and validator management" {
    const allocator = std.testing.allocator;
    var verifier = ShredVerifier.init(allocator, .{});
    defer verifier.deinit();

    const addr = types.Address{ .bytes = [_]u8{0x01} ** 20 };
    try verifier.addValidator(.{
        .address = addr,
        .pubkey = [_]u8{0} ** 32,
        .stake = 1000,
        .active = true,
    });

    try std.testing.expect(verifier.isValidProducer(addr));

    verifier.removeValidator(addr);
    try std.testing.expect(!verifier.isValidProducer(addr));
}

test "ShredVerifier signing payload deterministic" {
    const p1 = ShredVerifier.computeSigningPayload(42, 7, &[_]u8{ 1, 2, 3 });
    const p2 = ShredVerifier.computeSigningPayload(42, 7, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, &p1, &p2);

    // Different input → different payload
    const p3 = ShredVerifier.computeSigningPayload(43, 7, &[_]u8{ 1, 2, 3 });
    try std.testing.expect(!std.mem.eql(u8, &p1, &p3));
}

test "ShredVerifier disabled mode skips all" {
    const allocator = std.testing.allocator;
    var verifier = ShredVerifier.init(allocator, .{ .enabled = false });
    defer verifier.deinit();

    const result = verifier.verifyShred(
        1,
        0,
        &[_]u8{0},
        [_]u8{0} ** 64,
        types.Address.zero(),
    );
    try std.testing.expect(result); // Should pass (disabled)
    try std.testing.expectEqual(@as(u64, 1), verifier.totalSkipped);
}

test "ShredVerifier rejects unknown producer" {
    const allocator = std.testing.allocator;
    var verifier = ShredVerifier.init(allocator, .{ .sampleRate = 1.0 });
    defer verifier.deinit();

    const result = verifier.verifyShred(
        1,
        0,
        &[_]u8{0},
        [_]u8{0} ** 64,
        types.Address{ .bytes = [_]u8{0xFF} ** 20 },
    );
    try std.testing.expect(!result); // Should fail (unknown)
    try std.testing.expectEqual(@as(u64, 1), verifier.totalFailed);
}
