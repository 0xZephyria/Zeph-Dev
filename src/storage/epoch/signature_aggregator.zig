// BLS Signature Aggregator - Wrapper around blst for epoch aggregation
// Achieves constant-size proof: 100 sigs × 64 bytes → single 96-byte aggregated sig

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("crypto");
const blst = crypto.blst;

pub const BLS_DST = "FORGEYRIA_EPOCH_SIG_V01";

/// Aggregated BLS signature result
pub const AggregatedSignature = struct {
    signature: [96]u8, // Compressed G2 point
    signers_bitmap: []u8, // Which validators signed
    signer_count: u32,

    pub fn deinit(self: *AggregatedSignature, allocator: Allocator) void {
        if (self.signers_bitmap.len > 0) {
            allocator.free(self.signers_bitmap);
        }
    }
};

/// BLS Signature Aggregator for epoch-level aggregation
pub const SignatureAggregator = struct {
    const Self = @This();

    allocator: Allocator,
    signatures: std.ArrayListUnmanaged(blst.Signature),
    public_keys: std.ArrayListUnmanaged(blst.PublicKey),
    messages: std.ArrayListUnmanaged([]const u8),
    signers_bitmap: std.DynamicBitSet,
    validator_count: usize,

    pub fn init(allocator: Allocator, validator_count: usize) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.signatures = .{};
        self.public_keys = .{};
        self.messages = .{};
        self.signers_bitmap = try std.DynamicBitSet.initEmpty(allocator, validator_count);
        self.validator_count = validator_count;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.signatures.deinit(self.allocator);
        self.public_keys.deinit(self.allocator);
        for (self.messages.items) |msg| {
            self.allocator.free(msg);
        }
        self.messages.deinit(self.allocator);
        self.signers_bitmap.deinit();
        self.allocator.destroy(self);
    }

    /// Add a signature from a validator
    /// Verifies the signature before adding
    pub fn addSignature(
        self: *Self,
        validator_index: usize,
        signature_bytes: [96]u8,
        public_key_bytes: [48]u8,
        message: []const u8,
    ) !void {
        // Deserialize public key
        var pk = try blst.PublicKey.fromBytes(&public_key_bytes);
        try pk.validate();

        // Deserialize signature
        var sig = try blst.Signature.uncompress(&signature_bytes);
        try sig.validate(true);

        // Verify signature
        try sig.verify(true, message, BLS_DST, null, &pk, true);

        // Store valid signature and details
        try self.signatures.append(self.allocator, sig);
        try self.public_keys.append(self.allocator, pk);
        try self.messages.append(self.allocator, try self.allocator.dupe(u8, message));

        if (validator_index < self.validator_count) {
            self.signers_bitmap.set(validator_index);
        }
    }

    /// Aggregate all collected signatures into one
    pub fn aggregate(self: *Self) !AggregatedSignature {
        if (self.signatures.items.len == 0) {
            return error.NoSignatures;
        }

        // Aggregate signatures
        // sigs_groupcheck is false because we already validated on add
        const agg_sig_obj = try blst.AggregateSignature.aggregate(self.signatures.items, false);
        const agg_sig = agg_sig_obj.toSignature();
        const compressed_sig = agg_sig.compress();

        // Export bitmap
        const bitmap_bytes = (self.validator_count + 7) / 8;
        const signers_bitmap = try self.allocator.alloc(u8, bitmap_bytes);
        @memset(signers_bitmap, 0);

        var iter = self.signers_bitmap.iterator(.{});
        while (iter.next()) |idx| {
            signers_bitmap[idx / 8] |= @as(u8, 1) << @intCast(idx % 8);
        }

        return AggregatedSignature{
            .signature = compressed_sig,
            .signers_bitmap = signers_bitmap,
            .signer_count = @intCast(self.signatures.items.len),
        };
    }

    /// Verify aggregated signature against all signers
    pub fn verifyAggregated(
        aggregated_sig_bytes: [96]u8,
        public_keys_bytes: []const [48]u8,
        messages: []const []const u8,
    ) !bool {
        if (public_keys_bytes.len != messages.len or public_keys_bytes.len == 0) {
            return false;
        }

        const sig = try blst.Signature.uncompress(&aggregated_sig_bytes);

        // We need to construct Pk and Msg arrays for batch verification
        // This is expensive so we should use fastAggregateVerify if message is same
        // But here messages might be different (e.g. state roots? usually same for epoch block?)
        // If messages are different, we use aggregateVerify

        // For Zephyria constant-size, the message signed is the state root.
        // All validators sign the SAME message (the epoch metadata/roots).
        // So we can check if all messages are identical.

        const first_msg = messages[0];
        var all_msgs_same = true;
        for (messages[1..]) |msg| {
            if (!std.mem.eql(u8, msg, first_msg)) {
                all_msgs_same = false;
                break;
            }
        }

        if (all_msgs_same) {
            // Fast path: multiple PKs, single message
            // Use stack-allocated buffer for PKs (max 1024 validators per committee)
            const MAX_VALIDATORS = 1024;
            if (public_keys_bytes.len > MAX_VALIDATORS) return error.TooManyValidators;

            var pk_buf: [MAX_VALIDATORS]blst.PublicKey = undefined;
            for (public_keys_bytes, 0..) |pk_bytes, i| {
                pk_buf[i] = try blst.PublicKey.fromBytes(&pk_bytes);
            }
            const pks = pk_buf[0..public_keys_bytes.len];

            if (first_msg.len != 32) return error.InvalidMessageLength;

            // Stack-allocated pairing buffer (avoids heap allocation on hot path)
            var pairing_buf: [blst.Pairing.sizeOf()]u8 = undefined;
            return sig.fastAggregateVerify(true, &pairing_buf, first_msg[0..32], BLS_DST, pks, false) catch false;
        } else {
            // Slow path: distinct messages
            return error.DistinctMessagesNotSupported;
        }
    }
};

/// Verify a single BLS signature
pub fn verifySignature(signature: [96]u8, public_key: [48]u8, message: []const u8) !bool {
    const sig = blst.Signature.uncompress(&signature) catch return false;
    const pk = blst.PublicKey.fromBytes(&public_key) catch return false;

    sig.verify(true, message, BLS_DST, null, &pk, true) catch return false;
    return true;
}

/// Sign a message with a secret key (Helper for tests/dev)
pub fn sign(secret_key: [32]u8, message: []const u8) [96]u8 {
    // Reconstruct SecretKey from bytes
    // Note: blst SecretKey.fromBytes might strict check IKM/serialization.
    // For now assuming secret_key is IKM.
    const sk = blst.SecretKey.keyGen(&secret_key, null) catch unreachable;
    const sig = sk.sign(message, BLS_DST, null);
    return sig.compress();
}

/// Derive public key from secret key (Helper for tests/dev)
pub fn derivePublicKey(secret_key: [32]u8) [48]u8 {
    const sk = blst.SecretKey.keyGen(&secret_key, null) catch unreachable;
    const pk = sk.toPublicKey();
    return pk.compress();
}

// Tests
test "SignatureAggregator with real BLS" {
    const allocator = std.testing.allocator;

    var aggregator = try SignatureAggregator.init(allocator, 10);
    defer aggregator.deinit();

    const message = [_]u8{0xaa} ** 32;

    // Generate 5 validators
    for (0..5) |i| {
        var secret_key: [32]u8 = undefined;
        // Use deterministic keys for tests
        @memset(&secret_key, @intCast(i + 1));

        const public_key = derivePublicKey(secret_key);
        const signature = sign(secret_key, &message);

        try aggregator.addSignature(i, signature, public_key, &message);
    }

    var agg_result = try aggregator.aggregate();
    defer agg_result.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 5), agg_result.signer_count);
}
