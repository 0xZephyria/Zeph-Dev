// ============================================================================
// Zephyria — Code Account (Type 2)
// ============================================================================
//
// Immutable storage for compiled RISC-V bytecode.
// Zero conflict scope — code is write-once at deployment.
// After deployment, only READ operations are allowed.

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const Blake3 = std.crypto.hash.Blake3;

pub const CodeAccount = struct {
    header: AccountHeader,
    code_hash: types.Hash,
    code_size: u64,

    pub fn init(contract_addr: types.Address, code: []const u8) CodeAccount {
        var code_hash: types.Hash = undefined;
        Blake3.hash(code, &code_hash.bytes, .{});
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

    /// Empty code hash (blake3 of empty bytes)
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
};

/// Compute blake3 hash of code bytes
pub fn hashCode(code: []const u8) types.Hash {
    var h: types.Hash = undefined;
    Blake3.hash(code, &h.bytes, .{});
    return h;
}
