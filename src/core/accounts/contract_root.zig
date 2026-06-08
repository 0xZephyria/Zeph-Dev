const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const common = @import("common.zig");

/// Contract Root Account (Type 1).
/// Metadata for a deployed contract.
pub const ContractRoot = struct {
    header: AccountHeader,
    code_hash: types.Hash,
    /// Virtual — for eth_getProof RPC compatibility only.
    /// Actual commitment uses the global trie.
    storage_root: types.Hash,

    pub fn init(address: types.Address, code_hash: types.Hash) ContractRoot {
        return .{
            .header = .{
                .account_type = .ContractRoot,
                .owner_program = address,
                .data_hash = code_hash,
            },
            .code_hash = code_hash,
            .storage_root = types.Hash.zero(),
        };
    }

    pub fn getAddress(self: *const ContractRoot) types.Address {
        return self.header.owner_program;
    }

    pub fn isDeployed(self: *const ContractRoot) bool {
        return !self.code_hash.eql(types.Hash.zero());
    }

    /// Serialize to bytes: header(60) + code_hash(32) + storage_root(32) = 124 bytes
    pub fn serialize(self: *const ContractRoot, buf: []u8) []u8 {
        const hdr = std.mem.asBytes(&self.header);
        @memcpy(buf[0..60], hdr);
        @memcpy(buf[60..92], &self.code_hash.bytes);
        @memcpy(buf[92..124], &self.storage_root.bytes);
        return buf[0..124];
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: []const u8) ?ContractRoot {
        if (data.len < 124) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .ContractRoot) return null;
        var code_hash: types.Hash = undefined;
        @memcpy(&code_hash.bytes, data[60..92]);
        var storage_root: types.Hash = undefined;
        @memcpy(&storage_root.bytes, data[92..124]);
        return .{ .header = header, .code_hash = code_hash, .storage_root = storage_root };
    }
};

/// Code hash key: stem || 0x02
pub fn codeHashKey(addr: types.Address) [32]u8 {
    return common.codeHashKey(addr);
}

/// Code body key: stem || 0x03
pub fn codeKey(addr: types.Address) [32]u8 {
    return common.codeKey(addr);
}

/// Derive contract address from deployer + sequence (CREATE opcode)
pub fn deriveAddress(deployer: types.Address, sequence: u64) types.Address {
    var sequenceBytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequenceBytes, sequence, .big);
    var createInput: [40]u8 = undefined;
    @memcpy(createInput[0..32], &deployer.bytes);
    @memcpy(createInput[32..40], &sequenceBytes);
    var addr: types.Address = undefined;
    std.crypto.hash.Blake3.hash(&createInput, &addr.bytes, .{});
    return addr;
}

/// Derive contract address from CREATE2 (deployer + salt + init_code_hash)
pub fn deriveCreate2Address(deployer: types.Address, salt: [32]u8, init_code_hash: [32]u8) types.Address {
    var create2Input: [97]u8 = undefined;
    create2Input[0] = 0x02;
    @memcpy(create2Input[1..33], &deployer.bytes);
    @memcpy(create2Input[33..65], &salt);
    @memcpy(create2Input[65..97], &init_code_hash);
    var addr: types.Address = undefined;
    std.crypto.hash.Blake3.hash(&create2Input, &addr.bytes, .{});
    return addr;
}
