// ============================================================================
// Zephyria — Transaction Decode / Sender Recovery
// ============================================================================
//
// Recovers the sender address from a signed transaction's public key
// and supports binary transaction deserialization.

const std = @import("std");
const types = @import("types.zig");

/// Recover the sender address from a signed transaction.
/// For Ed25519 transactions, the sender address is derived as blake3(pub_key).
pub fn recoverFromTx(allocator: std.mem.Allocator, tx: types.Transaction) !types.Address {
    _ = allocator;
    var addr: types.Address = undefined;
    std.crypto.hash.Blake3.hash(&tx.pub_key, &addr.bytes, .{});
    return addr;
}

/// Decode a raw binary transaction and recover the sender.
/// Backward-compatible API for rpc/methods.zig.
pub fn decodeTransaction(allocator: std.mem.Allocator, raw: []const u8) !types.Transaction {
    var tx: types.Transaction = undefined;
    try tx.decodeBinary(allocator, raw);
    return tx;
}
