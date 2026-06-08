const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;

/// Storage Cell Account (Type 4).
/// Each Ethereum storage slot maps to an independent account.
/// Zero conflicts by construction — different slots = different keys.
pub const StorageCellAccount = struct {
    header: AccountHeader,
    slot_key: types.Hash,
    value: [32]u8,

    pub fn init(contract: types.Address, slot: [32]u8) StorageCellAccount {
        var slot_hash: types.Hash = undefined;
        @memcpy(&slot_hash.bytes, &slot);
        return .{
            .header = .{
                .account_type = .StorageCell,
                .owner_program = contract,
            },
            .slot_key = slot_hash,
            .value = [_]u8{0} ** 32,
        };
    }

    pub fn withValue(contract: types.Address, slot: [32]u8, value: [32]u8) StorageCellAccount {
        var slot_hash: types.Hash = undefined;
        @memcpy(&slot_hash.bytes, &slot);
        return .{
            .header = .{
                .account_type = .StorageCell,
                .owner_program = contract,
            },
            .slot_key = slot_hash,
            .value = value,
        };
    }

    pub fn isZero(self: *const StorageCellAccount) bool {
        return std.mem.eql(u8, &self.value, &([_]u8{0} ** 32));
    }

    /// Serialize to bytes: header(60) + slot_key(32) + value(32) = 124 bytes
    pub fn serialize(self: *const StorageCellAccount, buf: []u8) []u8 {
        const hdr = std.mem.asBytes(&self.header);
        @memcpy(buf[0..60], hdr);
        @memcpy(buf[60..92], &self.slot_key.bytes);
        @memcpy(buf[92..124], &self.value);
        return buf[0..124];
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: []const u8) ?StorageCellAccount {
        if (data.len < 124) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .StorageCell) return null;
        var slot_key: types.Hash = undefined;
        @memcpy(&slot_key.bytes, data[60..92]);
        var value: [32]u8 = undefined;
        @memcpy(&value, data[92..124]);
        return .{ .header = header, .slot_key = slot_key, .value = value };
    }
};

/// Derive the storage cell key: blake3(contract_address || storage_slot)
pub fn storageKey(contract: types.Address, slot: [32]u8) [32]u8 {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &contract.bytes);
    @memcpy(input[32..64], &slot);
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&input, &hash, .{});
    return hash;
}

/// Derive the storage cell address (for scheduling conflict detection).
pub fn storageCellAddress(contract: types.Address, slot: [32]u8) types.Address {
    const full_key = storageKey(contract, slot);
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, &full_key);
    return addr;
}
