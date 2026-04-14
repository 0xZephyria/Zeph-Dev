// ============================================================================
// Zephyria — Config Account (Type 3) & Metadata Registry
// ============================================================================
//
// Contract slot classification metadata. The transpiler (Solidity → Zig)
// populates this at deployment time, classifying each storage slot as:
//   • PerUser — mapping(address => X) keyed by msg.sender → isolated per-user
//   • Global — scalar variables, counters → use accumulator deltas
//   • Immutable — constants, set once at deploy → zero conflict
//
// At runtime, the executor queries slot classification to determine
// which key derivation function to use for conflict-free execution.
// Default: unknown slots are classified as PerUser (safe — never conflicts).

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;

pub const ConfigAccount = struct {
    header: AccountHeader,

    pub fn init(contract: types.Address) ConfigAccount {
        return .{
            .header = .{
                .account_type = .Config,
                .owner_program = contract,
            },
        };
    }
};

// ── Contract Metadata ───────────────────────────────────────────────────

pub const ContractMetadata = struct {
    contract: types.Address,
    per_user_slots: std.AutoHashMap([32]u8, void),
    global_slots: std.AutoHashMap([32]u8, void),
    immutable_slots: std.AutoHashMap([32]u8, void),

    pub fn init(allocator: std.mem.Allocator, contract: types.Address) ContractMetadata {
        return .{
            .contract = contract,
            .per_user_slots = std.AutoHashMap([32]u8, void).init(allocator),
            .global_slots = std.AutoHashMap([32]u8, void).init(allocator),
            .immutable_slots = std.AutoHashMap([32]u8, void).init(allocator),
        };
    }

    pub fn deinit(self: *ContractMetadata) void {
        self.per_user_slots.deinit();
        self.global_slots.deinit();
        self.immutable_slots.deinit();
    }

    /// Classify a storage slot. Returns PerUser if unknown (safe default).
    pub fn classify(self: *const ContractMetadata, slot: [32]u8) types.SlotClassification {
        if (self.global_slots.contains(slot)) return .Global;
        if (self.immutable_slots.contains(slot)) return .Immutable;
        return .PerUser;
    }

    pub fn markPerUser(self: *ContractMetadata, slot: [32]u8) !void {
        try self.per_user_slots.put(slot, {});
    }

    pub fn markGlobal(self: *ContractMetadata, slot: [32]u8) !void {
        try self.global_slots.put(slot, {});
    }

    pub fn markImmutable(self: *ContractMetadata, slot: [32]u8) !void {
        try self.immutable_slots.put(slot, {});
    }
};

// ── Metadata Registry ───────────────────────────────────────────────────

/// Centralized registry of all deployed contract metadata.
/// The executor queries this to determine slot classification.
pub const MetadataRegistry = struct {
    allocator: std.mem.Allocator,
    contracts: std.AutoHashMap(types.Address, ContractMetadata),

    pub fn init(allocator: std.mem.Allocator) MetadataRegistry {
        return .{
            .allocator = allocator,
            .contracts = std.AutoHashMap(types.Address, ContractMetadata).init(allocator),
        };
    }

    pub fn deinit(self: *MetadataRegistry) void {
        var it = self.contracts.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.contracts.deinit();
    }

    pub fn register(self: *MetadataRegistry, meta: ContractMetadata) !void {
        try self.contracts.put(meta.contract, meta);
    }

    pub fn get(self: *const MetadataRegistry, contract: types.Address) ?*const ContractMetadata {
        if (self.contracts.getPtr(contract)) |ptr| return ptr;
        return null;
    }

    /// Classify a slot for a contract. Returns PerUser if unregistered.
    pub fn classifySlot(self: *const MetadataRegistry, contract: types.Address, slot: [32]u8) types.SlotClassification {
        if (self.get(contract)) |meta| return meta.classify(slot);
        return .PerUser;
    }
};
