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
const Keccak256 = std.crypto.hash.sha3.Keccak256;

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

/// Contract stem: keccak256(address)[0..31]
pub fn contractStem(addr: types.Address) [31]u8 {
    var h: [32]u8 = undefined;
    Keccak256.hash(&addr.bytes, &h, .{});
    var stem: [31]u8 = undefined;
    @memcpy(&stem, h[0..31]);
    return stem;
}

/// Derive contract address from deployer + nonce (CREATE opcode)
pub fn deriveAddress(deployer: types.Address, nonce: u64) types.Address {
    const ally = std.heap.page_allocator;
    const rlp_mod = @import("encoding").rlp;
    const Derivation = struct { from: types.Address, nonce: u64 };
    const d = Derivation{ .from = deployer, .nonce = nonce };
    const encoded = rlp_mod.encode(ally, d) catch return types.Address.zero();
    defer ally.free(encoded);
    var h: [32]u8 = undefined;
    Keccak256.hash(encoded, &h, .{});
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, h[12..32]);
    return addr;
}

/// Derive contract address from CREATE2 (deployer + salt + init_code_hash)
pub fn deriveCreate2Address(deployer: types.Address, salt: [32]u8, init_code_hash: [32]u8) types.Address {
    var input: [85]u8 = undefined;
    input[0] = 0xff;
    @memcpy(input[1..21], &deployer.bytes);
    @memcpy(input[21..53], &salt);
    @memcpy(input[53..85], &init_code_hash);
    var h: [32]u8 = undefined;
    Keccak256.hash(&input, &h, .{});
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, h[12..32]);
    return addr;
}
