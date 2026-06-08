const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;

/// Config Account (Type 3).
/// Contract slot classification metadata for the transpiler.
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

    /// Serialize to bytes: header only (60 bytes).
    pub fn serialize(self: *const ConfigAccount, buf: []u8) []u8 {
        const hdr = std.mem.asBytes(&self.header);
        @memcpy(buf[0..60], hdr);
        return buf[0..60];
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: []const u8) ?ConfigAccount {
        if (data.len < 60) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .Config) return null;
        return .{ .header = header };
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

    pub fn classifySlot(self: *const MetadataRegistry, contract: types.Address, slot: [32]u8) types.SlotClassification {
        if (self.get(contract)) |meta| return meta.classify(slot);
        return .PerUser;
    }
};
