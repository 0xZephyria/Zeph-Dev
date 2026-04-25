// ============================================================================
// Zephyria — Transaction Decode / Sender Recovery
// ============================================================================
//
// Recovers the sender address from a signed transaction using ECDSA
// signature recovery (v, r, s values).

const std = @import("std");
const types = @import("types.zig");

/// Recover the sender address from a signed transaction.
/// Uses ECDSA recovery from the v, r, s signature values.
pub fn recoverFromTx(allocator: std.mem.Allocator, tx: types.Transaction) !types.Address {
    // Calculate recovery ID from v
    // Legacy: v = 27 or 28  →  recoveryId = v - 27
    // EIP-155: v = chainId * 2 + 35 or 36  →  recoveryId = v - chainId * 2 - 35
    var recoveryId: u8 = 0;
    const v_u256 = tx.v;
    if (v_u256 >= 35) {
        // EIP-155
        recoveryId = @intCast((v_u256 - 35) % 2);
    } else if (v_u256 >= 27) {
        // Legacy
        recoveryId = @intCast(v_u256 - 27);
    }

    // Encode r and s as big-endian 32-byte arrays
    var rBytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &rBytes, tx.r, .big);
    var sBytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &sBytes, tx.s, .big);

    // Compute signing hash (RLP without v, r, s)
    const msgHash = try txSigningHash(allocator, tx);

    // Recover public key
    const eoa = @import("accounts/eoa.zig");
    const pubKey = eoa.recoverPublicKey(msgHash, rBytes, sBytes, recoveryId) catch
        return types.Address.zero();

    // Derive address from public key
    var addrHash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(pubKey[1..], &addrHash, .{});
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, addrHash[12..32]);
    return addr;
}

/// Compute the signing hash for a transaction (hash of RLP without signature fields).
fn txSigningHash(allocator: std.mem.Allocator, tx: types.Transaction) ![32]u8 {
    const rlp = @import("encoding").rlp;
    var listData = std.ArrayListUnmanaged(u8){};
    defer listData.deinit(allocator);

    var inner = std.ArrayListUnmanaged(u8){};
    defer inner.deinit(allocator);

    const v_u64 = @as(u64, @intCast(tx.v & 0xFF));
    const isEip155 = v_u64 >= 35;
    const chainId: u64 = if (isEip155) (v_u64 - 35) / 2 else 0;

    try rlp.serialize(u64, allocator, tx.nonce, &inner);
    try rlp.serialize(u256, allocator, tx.gasPrice, &inner);
    try rlp.serialize(u64, allocator, tx.gasLimit, &inner);

    if (tx.to) |toAddr| {
        try toAddr.encodeToRLP(allocator, &inner);
    } else {
        try rlp.serialize([]const u8, allocator, &[_]u8{}, &inner);
    }

    try rlp.serialize(u256, allocator, tx.value, &inner);
    try rlp.serialize([]const u8, allocator, tx.data, &inner);

    if (isEip155) {
        try rlp.serialize(u64, allocator, chainId, &inner);
        try rlp.serialize(u64, allocator, 0, &inner);
        try rlp.serialize(u64, allocator, 0, &inner);
    }

    try rlp.encodeListHeader(allocator, inner.items.len, &listData);
    try listData.appendSlice(allocator, inner.items);

    var h: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(listData.items, &h, .{});
    return h;
}

/// Decode a raw RLP-encoded transaction and recover the sender.
/// Backward-compatible API for rpc/methods.zig.
pub fn decodeTransaction(allocator: std.mem.Allocator, raw: []const u8) !types.Transaction {
    const rlp = @import("rlp");
    var tx = try rlp.decode(allocator, types.Transaction, raw);
    tx.from = try recoverFromTx(allocator, tx);
    return tx;
}
