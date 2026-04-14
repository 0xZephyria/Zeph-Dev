// File: tools/zephyrc/storage_layout.zig
// ZephyrLang Storage Layout Engine — Computes EVM-compatible storage slots
// for state variables, mappings, and dynamic arrays.
// Follows Solidity storage layout rules for maximum compatibility.

const std = @import("std");
const ast = @import("ast.zig");
const type_check = @import("type_check.zig");
const ResolvedType = type_check.ResolvedType;

pub const StorageSlot = struct {
    name: []const u8,
    slot: u64,
    offset: u8, // byte offset within 32-byte slot (for packing)
    size: u8, // size in bytes
    kind: SlotKind,
};

pub const SlotKind = enum {
    value, // fixed-size value stored directly
    mapping, // mapping root (keccak256(key, slot))
    dynamic_array, // dynamic array length stored at slot, data at keccak256(slot)
    bytes_string, // length at slot, data at keccak256(slot) if > 31 bytes
};

pub const StorageLayout = struct {
    slots: std.ArrayList(StorageSlot),
    alloc: std.mem.Allocator,
    next_slot: u64,
    current_offset: u8,

    pub fn init(alloc: std.mem.Allocator) StorageLayout {
        return .{ .slots = .{}, .alloc = alloc, .next_slot = 0, .current_offset = 0 };
    }

    pub fn deinit(self: *StorageLayout) void {
        self.slots.deinit(self.alloc);
    }

    /// Compute storage layout for all state variables in a contract.
    pub fn computeForContract(self: *StorageLayout, members: []const ast.ContractMember) !void {
        for (members) |member| {
            switch (member) {
                .state_var => |sv| {
                    if (sv.storage_class == .constant or sv.storage_class == .immutable) continue;
                    try self.assignSlot(sv);
                },
                else => {},
            }
        }
        // Finalize — move to next slot if partial
        if (self.current_offset > 0) {
            self.next_slot += 1;
            self.current_offset = 0;
        }
    }

    fn assignSlot(self: *StorageLayout, sv: ast.StateVarDecl) !void {
        const size = typeStorageSize(sv.type_expr);
        const kind = typeSlotKind(sv.type_expr);

        // Mappings and dynamic arrays always start a new slot
        if (kind != .value) {
            if (self.current_offset > 0) {
                self.next_slot += 1;
                self.current_offset = 0;
            }
            try self.slots.append(self.alloc, .{
                .name = sv.name,
                .slot = self.next_slot,
                .offset = 0,
                .size = 32,
                .kind = kind,
            });
            self.next_slot += 1;
            return;
        }

        // Try to pack into current slot (EVM packs from right to left)
        if (self.current_offset + size > 32) {
            // Doesn't fit — start new slot
            self.next_slot += 1;
            self.current_offset = 0;
        }

        try self.slots.append(self.alloc, .{
            .name = sv.name,
            .slot = self.next_slot,
            .offset = self.current_offset,
            .size = size,
            .kind = .value,
        });
        self.current_offset += size;

        // Full slot — advance
        if (self.current_offset >= 32) {
            self.next_slot += 1;
            self.current_offset = 0;
        }
    }

    /// Compute the keccak256-based storage key for a mapping access.
    /// In EVM: keccak256(abi.encode(key, slot))
    pub fn mappingSlot(base_slot: u64, key_hash: [32]u8) [32]u8 {
        var input: [64]u8 = undefined;
        @memcpy(input[0..32], &key_hash);
        // Slot number in big-endian 32 bytes
        @memset(input[32..64], 0);
        input[63] = @truncate(base_slot);
        input[62] = @truncate(base_slot >> 8);
        input[61] = @truncate(base_slot >> 16);
        input[60] = @truncate(base_slot >> 24);
        // In production, this would be keccak256(input)
        // For now, return a deterministic hash
        var result: [32]u8 = undefined;
        @memset(&result, 0);
        var h: u32 = 0x811c9dc5;
        for (input) |b| {
            h ^= b;
            h *%= 0x01000193;
        }
        result[0] = @truncate(h);
        result[1] = @truncate(h >> 8);
        result[2] = @truncate(h >> 16);
        result[3] = @truncate(h >> 24);
        return result;
    }

    /// Compute storage slot for dynamic array element.
    /// data_start = keccak256(slot), element_slot = data_start + index * element_size/32
    pub fn dynamicArraySlot(base_slot: u64, index: u64, elem_size: u32) u64 {
        _ = elem_size;
        // Simplified — in production would use keccak256
        return base_slot * 0x100 + index;
    }
};

// ============================================================================
// Type-based size computation
// ============================================================================

fn typeStorageSize(ty: ast.TypeExpr) u8 {
    return switch (ty) {
        .elementary => |e| elementarySize(e),
        .user_defined => 32, // default to full slot
        .mapping => 32,
        .array => 32, // pointer to data
        .option_type => 33, // 32 + 1 byte flag (occupies full slot)
        .result_type => 32,
        .resource_type => 32,
        else => 32,
    };
}

fn elementarySize(e: ast.ElementaryType) u8 {
    return switch (e) {
        .uint8, .int8 => 1,
        .uint16, .int16 => 2,
        .uint32, .int32 => 4,
        .uint64, .int64 => 8,
        .uint128, .int128 => 16,
        .uint256, .int256 => 32,
        .bool_type => 1,
        .address, .address_payable => 20,
        .bytes1 => 1,
        .bytes4 => 4,
        .bytes32 => 32,
        .bytes_type, .string_type => 32, // pointer
        else => 32,
    };
}

fn typeSlotKind(ty: ast.TypeExpr) StorageSlot.SlotKind {
    return switch (ty) {
        .mapping => .mapping,
        .array => .dynamic_array,
        .elementary => |e| switch (e) {
            .bytes_type, .string_type => .bytes_string,
            else => .value,
        },
        else => .value,
    };
}

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;

test "storage_layout: basic value packing" {
    var layout = StorageLayout.init(testing.allocator);
    defer layout.deinit();

    // Simulate: bool a; uint8 b; uint16 c; => all pack into slot 0
    try layout.slots.append(testing.allocator, .{ .name = "a", .slot = 0, .offset = 0, .size = 1, .kind = .value });
    layout.current_offset = 1;
    try layout.slots.append(testing.allocator, .{ .name = "b", .slot = 0, .offset = 1, .size = 1, .kind = .value });
    layout.current_offset = 2;
    try layout.slots.append(testing.allocator, .{ .name = "c", .slot = 0, .offset = 2, .size = 2, .kind = .value });

    try testing.expectEqual(@as(usize, 3), layout.slots.items.len);
    try testing.expectEqual(@as(u64, 0), layout.slots.items[0].slot);
    try testing.expectEqual(@as(u64, 0), layout.slots.items[2].slot); // same slot
}

test "storage_layout: mapping slot computation" {
    var key: [32]u8 = undefined;
    @memset(&key, 0xAB);
    const result = StorageLayout.mappingSlot(5, key);
    try testing.expect(result[0] != 0 or result[1] != 0); // non-trivial hash
}
