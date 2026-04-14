// ============================================================================
// Zephyria — Storage Cell Account (Type 4)
// ============================================================================
//
// THE KEY TO ZERO CONFLICTS.
//
// Each Ethereum storage slot becomes an independent account in the Verkle trie.
// Address derivation:
//   StorageAccountKey = keccak256(contract_root_address || slot_hash)
//
// One slot = one account. No shared storage blob.
// Parallel transactions touching different slots have ZERO overlap.
// Conflict detection becomes trivial set intersection of write-set keys.
//
// This preserves full Ethereum storage compatibility:
//   • ABI identical
//   • Storage slot hashing identical (Solidity keccak256(key || base_slot))
//   • Tools see same storage layout via eth_getStorageAt RPC translation
//   • No changes to MetaMask, Hardhat, Foundry, Ethers.js

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

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
};

// ── Key Derivation ──────────────────────────────────────────────────────

/// Derive the storage cell key in the global Verkle trie.
/// Key = keccak256(contract_address || storage_slot)
///
/// This is the CORE of the zero-conflict model: each slot maps to a
/// unique trie key, so two transactions writing different slots NEVER
/// touch the same trie node.
pub fn storageKey(contract: types.Address, slot: [32]u8) [32]u8 {
    var input: [52]u8 = undefined;
    @memcpy(input[0..20], &contract.bytes);
    @memcpy(input[20..52], &slot);
    var hash: [32]u8 = undefined;
    Keccak256.hash(&input, &hash, .{});
    return hash;
}

/// Derive the storage cell address (for scheduling conflict detection).
/// This returns an Address (20 bytes) from the full storage key.
pub fn storageCellAddress(contract: types.Address, slot: [32]u8) types.Address {
    const full_key = storageKey(contract, slot);
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, full_key[12..32]);
    return addr;
}
