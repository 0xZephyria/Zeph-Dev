const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const common = @import("common.zig");

/// Code Account (Type 2).
/// Immutable RISC-V bytecode storage. Write-once at deployment.
pub const CodeAccount = struct {
    header: AccountHeader,
    code_hash: types.Hash,
    code_size: u64,

    pub fn init(contract_addr: types.Address, code: []const u8) CodeAccount {
        var code_hash: types.Hash = undefined;
        std.crypto.hash.Blake3.hash(code, &code_hash.bytes, .{});
        return .{
            .header = .{
                .account_type = .Code,
                .owner_program = contract_addr,
                .flags = 0x01, // Frozen — immutable
                .data_hash = code_hash,
            },
            .code_hash = code_hash,
            .code_size = @intCast(code.len),
        };
    }

    pub const EMPTY_CODE_HASH = types.Hash{
        .bytes = .{
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
            0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
            0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
            0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
        },
    };

    pub fn isEmpty(self: *const CodeAccount) bool {
        return self.code_hash.eql(EMPTY_CODE_HASH) or self.code_size == 0;
    }

    pub fn hasCode(hash: types.Hash) bool {
        return !std.mem.eql(u8, &hash.bytes, &EMPTY_CODE_HASH.bytes);
    }

    /// Serialize to bytes: header(60) + code_hash(32) + code_size(8) + code_body(variable)
    pub fn serialize(self: *const CodeAccount, buf: []u8, code_body: []const u8) []u8 {
        const hdr = std.mem.asBytes(&self.header);
        @memcpy(buf[0..60], hdr);
        @memcpy(buf[60..92], &self.code_hash.bytes);
        std.mem.writeInt(u64, buf[92..100], self.code_size, .big);
        if (code_body.len > 0) {
            @memcpy(buf[100..][0..code_body.len], code_body);
        }
        return buf[0..100 + code_body.len];
    }

    /// Deserialize from bytes (without code body).
    pub fn deserialize(data: []const u8) ?CodeAccount {
        if (data.len < 100) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .Code) return null;
        var code_hash: types.Hash = undefined;
        @memcpy(&code_hash.bytes, data[60..92]);
        const code_size = std.mem.readInt(u64, data[92..100], .big);
        return .{ .header = header, .code_hash = code_hash, .code_size = code_size };
    }
};

/// Compute blake3 hash of code bytes
pub fn hashCode(code: []const u8) types.Hash {
    var h: types.Hash = undefined;
    std.crypto.hash.Blake3.hash(code, &h.bytes, .{});
    return h;
}

/// Code body key: stem || 0x03
pub fn codeKey(addr: types.Address) [32]u8 {
    return common.codeKey(addr);
}

/// Code hash key: stem || 0x02
pub fn codeHashKey(addr: types.Address) [32]u8 {
    return common.codeHashKey(addr);
}
