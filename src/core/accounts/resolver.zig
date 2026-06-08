const std = @import("std");
const types = @import("../types.zig");
const common = @import("common.zig");

/// Account Type Resolver.
///
/// The blockchain's central type-dispatch system. Every account in Zephyria
/// has a type discriminator byte stored at `stem || 0x04` in the KV store.
/// This module reads that byte and routes to the correct account module.
///
/// Lifecycle:
///   1. CREATE — context determines the type (sender→EOA, deploy→ContractRoot, etc.)
///   2. STORE — type discriminator written alongside account fields
///   3. READ/DISPATCH — type discriminator read, operation dispatched to correct module
///
/// Rules:
///   • EOA: created by TX sender; can hold balance, has sequence; no calldata execution
///   • ContractRoot: created by deploy; contains code_hash; calldata triggers execution
///   • System: created at genesis; dispatch to system contract handlers
///   • Code/Config/Vault/StorageCell/DerivedState: created as side-effects; never called directly

/// Result of resolving an address — tells the caller what kind of account lives here
/// and what operations are valid.
pub const Resolution = struct {
    account_type: types.AccountType,
    exists: bool,
    is_callable: bool,
    is_fungible: bool, // Can hold native token balance
};

/// Resolve an address: read its type discriminator and return classification.
pub fn resolve(db: anytype, addr: types.Address) Resolution {
    const acct_type = common.readAccountType(db, addr) orelse return Resolution{
        .account_type = .EOA,
        .exists = false,
        .is_callable = false,
        .is_fungible = false,
    };

    return Resolution{
        .account_type = acct_type,
        .exists = true,
        .is_callable = acct_type == .ContractRoot or acct_type == .System,
        .is_fungible = acct_type == .EOA or acct_type == .Vault or acct_type == .System,
    };
}

/// Determine what type to create for a new address based on context.
pub fn resolveCreateType(context: CreateContext) types.AccountType {
    return switch (context) {
        .sender => .EOA,
        .deploy => .ContractRoot,
        .system_init => .System,
        .lazy_storage => .StorageCell,
        .lazy_derived => .DerivedState,
        .lazy_vault => .Vault,
    };
}

/// Context for account creation — tells the system WHAT type to create.
pub const CreateContext = enum(u8) {
    /// Incoming TX from a new address — create EOA
    sender,
    /// Contract deployment (CREATE/CREATE2) — create ContractRoot + Code + Config + Vault
    deploy,
    /// Genesis initialization — create System
    system_init,
    /// First write to a storage slot — create StorageCell
    lazy_storage,
    /// First write to derived state — create DerivedState
    lazy_derived,
    /// First ZEE received by a contract — create Vault
    lazy_vault,
};

/// Assert that an address has the expected type. Returns error.UnexpectedAccountType if not.
pub fn expectType(db: anytype, addr: types.Address, expected: types.AccountType) !void {
    const actual = common.readAccountType(db, addr);
    if (actual) |t| {
        if (t != expected) return error.UnexpectedAccountType;
    } else {
        return error.AccountNotFound;
    }
}
