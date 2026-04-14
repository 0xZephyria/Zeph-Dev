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
    // Legacy: v = 27 or 28  →  recovery_id = v - 27
    // EIP-155: v = chain_id * 2 + 35 or 36  →  recovery_id = v - chain_id * 2 - 35
    var recovery_id: u8 = 0;
    const v_u256 = tx.v;
    if (v_u256 >= 35) {
        // EIP-155
        recovery_id = @intCast((v_u256 - 35) % 2);
    } else if (v_u256 >= 27) {
        // Legacy
        recovery_id = @intCast(v_u256 - 27);
    }

    // Encode r and s as big-endian 32-byte arrays
    var r_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &r_bytes, tx.r, .big);
    var s_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &s_bytes, tx.s, .big);

    // Compute signing hash (RLP without v, r, s)
    const msg_hash = try txSigningHash(allocator, tx);

    // Recover public key
    const eoa = @import("accounts/eoa.zig");
    const pub_key = eoa.recoverPublicKey(msg_hash, r_bytes, s_bytes, recovery_id) catch
        return types.Address.zero();

    // Derive address from public key
    var addr_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(pub_key[1..], &addr_hash, .{});
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, addr_hash[12..32]);
    return addr;
}

/// Compute the signing hash for a transaction (hash of RLP without signature fields).
fn txSigningHash(allocator: std.mem.Allocator, tx: types.Transaction) ![32]u8 {
    const rlp = @import("encoding").rlp;
    var list_data = std.ArrayListUnmanaged(u8){};
    defer list_data.deinit(allocator);

    var inner = std.ArrayListUnmanaged(u8){};
    defer inner.deinit(allocator);

    const v_u64 = @as(u64, @intCast(tx.v & 0xFF));
    const is_eip155 = v_u64 >= 35;
    const chain_id: u64 = if (is_eip155) (v_u64 - 35) / 2 else 0;

    try rlp.serialize(u64, allocator, tx.nonce, &inner);
    try rlp.serialize(u256, allocator, tx.gas_price, &inner);
    try rlp.serialize(u64, allocator, tx.gas_limit, &inner);

    if (tx.to) |to_addr| {
        try to_addr.encodeToRLP(allocator, &inner);
    } else {
        try rlp.serialize([]const u8, allocator, &[_]u8{}, &inner);
    }

    try rlp.serialize(u256, allocator, tx.value, &inner);
    try rlp.serialize([]const u8, allocator, tx.data, &inner);

    if (is_eip155) {
        try rlp.serialize(u64, allocator, chain_id, &inner);
        try rlp.serialize(u64, allocator, 0, &inner);
        try rlp.serialize(u64, allocator, 0, &inner);
    }

    try rlp.encodeListHeader(allocator, inner.items.len, &list_data);
    try list_data.appendSlice(allocator, inner.items);

    var h: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(list_data.items, &h, .{});
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
