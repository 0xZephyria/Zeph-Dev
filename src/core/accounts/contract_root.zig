// ============================================================================
// Zephyria — Contract Root Account (Type 1)
// ============================================================================
//
// Metadata account for a deployed contract. Externally, this presents as
// a single Ethereum-style address. Internally, it maps to:
//   ContractRoot → CodeAccount (immutable)
//                → ConfigAccount (rare-write)
//                → VaultAccount (balance)
//                → StorageCellAccount[] (N per-slot accounts)
//
// The storage_root field is virtual — used ONLY for ETH JSON-RPC
// compatibility (eth_getProof). Actual commitment uses the global Verkle trie.

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const Blake3 = std.crypto.hash.Blake3;

pub const ContractRoot = struct {
    header: AccountHeader,
    code_hash: types.Hash,
    storage_root: types.Hash, // Virtual — for RPC compatibility only

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
};

// ── Key Derivation ──────────────────────────────────────────────────────

/// Code hash key for Verkle trie: stem || 0x02
pub fn codeHashKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &contractStem(addr));
    key[31] = 0x02;
    return key;
}

/// Code body key: stem || 0x03
pub fn codeKey(addr: types.Address) [32]u8 {
    var key: [32]u8 = undefined;
    @memcpy(key[0..31], &contractStem(addr));
    key[31] = 0x03;
    return key;
}

/// Contract stem: blake3(address)[0..31]
pub fn contractStem(addr: types.Address) [31]u8 {
    var h: [32]u8 = undefined;
    Blake3.hash(&addr.bytes, &h, .{});
    var stem: [31]u8 = undefined;
    @memcpy(&stem, h[0..31]);
    return stem;
}

/// Derive contract address from deployer + nonce (CREATE opcode)
pub fn deriveAddress(deployer: types.Address, nonce: u64) types.Address {
    var nonceBytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonceBytes, nonce, .big);
    var createInput: [40]u8 = undefined;
    @memcpy(createInput[0..32], &deployer.bytes);
    @memcpy(createInput[32..40], &nonceBytes);
    var addr: types.Address = undefined;
    Blake3.hash(&createInput, &addr.bytes, .{});
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
    Blake3.hash(&create2Input, &addr.bytes, .{});
    return addr;
}
