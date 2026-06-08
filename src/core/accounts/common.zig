const std = @import("std");
const types = @import("../types.zig");

threadlocal var last_addr_bytes: ?[32]u8 = null;
threadlocal var last_stem: [31]u8 = undefined;

/// Derive the Verkle stem for any account address using BLAKE3.
/// stem = blake3(address)[0..31]
/// TLS-cached: repeated calls with same address skip the hash.
pub fn accountStem(addr: types.Address) [31]u8 {
    if (last_addr_bytes) |lab| {
        if (std.mem.eql(u8, &lab, &addr.bytes)) {
            return last_stem;
        }
    }
    var h: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&addr.bytes, &h, .{});
    var stem: [31]u8 = undefined;
    @memcpy(&stem, h[0..31]);
    last_addr_bytes = addr.bytes;
    last_stem = stem;
    return stem;
}

/// Sequence key: stem || 0x00
pub fn sequenceKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x00;
    return key;
}

/// Balance key: stem || 0x01
pub fn balanceKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x01;
    return key;
}

/// Code hash key: stem || 0x02
pub fn codeHashKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x02;
    return key;
}

/// Code body key: stem || 0x03
pub fn codeKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x03;
    return key;
}

/// Type discriminator key: stem || 0x04
/// Stores 1 byte — the AccountType enum value for this address.
/// Written at account creation, read at dispatch to know which module to use.
pub fn typeKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &accountStem(addr));
    key[31] = 0x04;
    return key;
}

/// Write the account type discriminator for an address.
pub fn writeAccountType(db: anytype, addr: types.Address, account_type: types.AccountType) !void {
    const key = typeKey(addr);
    const byte = [_]u8{@intFromEnum(account_type)};
    try db.write(&key, &byte);
}

/// Read the account type discriminator for an address.
/// Returns null if no account exists at this address.
pub fn readAccountType(db: anytype, addr: types.Address) ?types.AccountType {
    const key = typeKey(addr);
    const data = db.read(&key);
    if (data) |d| {
        if (d.len < 1) return null;
        return std.meta.intToEnum(types.AccountType, d[0]) catch null;
    }
    return null;
}

/// Check if an account exists at this address (has a type discriminator).
pub fn accountExists(db: anytype, addr: types.Address) bool {
    return readAccountType(db, addr) != null;
}
