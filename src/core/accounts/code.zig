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
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const CodeAccount = struct {
    header: AccountHeader,
    code_hash: types.Hash,
    code_size: u64,

    pub fn init(contract_addr: types.Address, code: []const u8) CodeAccount {
        var code_hash: types.Hash = undefined;
        Keccak256.hash(code, &code_hash.bytes, .{});
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

    /// Empty code hash (keccak256 of empty bytes)
    pub const EMPTY_CODE_HASH = types.Hash{
        .bytes = .{
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
            0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
            0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
            0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
        },
    };

    pub fn isEmpty(self: *const CodeAccount) bool {
        return self.code_hash.eql(EMPTY_CODE_HASH) or self.code_size == 0;
    }

    pub fn hasCode(hash: types.Hash) bool {
        return !std.mem.eql(u8, &hash.bytes, &EMPTY_CODE_HASH.bytes);
    }
};

/// Compute keccak256 hash of code bytes
pub fn hashCode(code: []const u8) types.Hash {
    var h: types.Hash = undefined;
    Keccak256.hash(code, &h.bytes, .{});
    return h;
}
