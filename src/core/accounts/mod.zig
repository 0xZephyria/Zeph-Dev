// ============================================================================
// Zephyria — Accounts Module (Banking Module System)
// ============================================================================
//
// Each account type is a self-contained module (like a banking module system):
//   • Owns its key derivation (single source of truth)
//   • Owns its serialization/deserialization format
//   • Owns its typed operations (CRUD, validation, access control)
//   • Imported by need — only the modules you use
//
// Account Types:
//   0 — EOA:          User wallet (balance + sequence)
//   1 — ContractRoot: Contract metadata (code_hash, storage_root)
//   2 — Code:         Immutable RISC-V bytecode
//   3 — Config:       Slot classification metadata
//   4 — StorageCell:  Per-slot isolated storage
//   5 — DerivedState: Per-user contract state (DEX parallelism)
//   6 — Vault:        Contract balance holder (type discriminator only)
//   7 — System:       Protocol-level accounts

pub const header = @import("header.zig");
pub const common = @import("common.zig");
pub const eoa = @import("eoa.zig");
pub const contract_root = @import("contract_root.zig");
pub const code = @import("code.zig");
pub const storage_cell = @import("storage_cell.zig");
pub const derived = @import("derived.zig");
pub const system = @import("system.zig");
pub const config = @import("config.zig");
pub const resolver = @import("resolver.zig");

// Re-exports for convenience
pub const AccountHeader = header.AccountHeader;
pub const EOA = eoa.EOA;
pub const ContractRoot = contract_root.ContractRoot;
pub const CodeAccount = code.CodeAccount;
pub const StorageCellAccount = storage_cell.StorageCellAccount;
pub const DerivedStateAccount = derived.DerivedStateAccount;
pub const SystemAccount = system.SystemAccount;
pub const ConfigAccount = config.ConfigAccount;
pub const ContractMetadata = config.ContractMetadata;
pub const MetadataRegistry = config.MetadataRegistry;
pub const ReceiptQueue = derived.ReceiptQueue;
pub const DeltaQueue = derived.DeltaQueue;
