// ============================================================================
// Zephyria — Vault Account (Type 6)
// ============================================================================
//
// Isolated contract balance holder. Separates a contract's native token
// balance from its storage cells, so balance transfers (receive ZEE) don't
// conflict with storage mutations (contract logic).
//
// This means a simple "send ZEE to contract" can execute in parallel
// with any contract call that doesn't touch the vault.

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const Blake3 = std.crypto.hash.Blake3;

pub const VaultAccount = struct {
    header: AccountHeader,

    pub fn init(contract: types.Address) VaultAccount {
        return .{
            .header = .{
                .account_type = .Vault,
                .owner_program = contract,
            },
        };
    }

    pub fn withBalance(contract: types.Address, balance: u128) VaultAccount {
        return .{
            .header = .{
                .account_type = .Vault,
                .owner_program = contract,
                .balance = balance,
            },
        };
    }

    pub fn getBalance(self: *const VaultAccount) u128 {
        return self.header.balance;
    }

    pub fn getContract(self: *const VaultAccount) types.Address {
        return self.header.owner_program;
    }
};

// ── Key Derivation ──────────────────────────────────────────────────────

/// Vault key for a contract: blake3("vault" || contract_address)
pub fn vaultKey(contract: types.Address) [32]u8 {
    var hasher = Blake3.init(.{});
    hasher.update("vault");
    hasher.update(&contract.bytes);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash;
}
