const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;

/// Derived State Account (Type 5).
/// Per-user contract state for conflict-free DEX parallelism.
pub const DerivedStateAccount = struct {
    header: AccountHeader,
    user: types.Address,
    contract: types.Address,

    pub fn init(user: types.Address, contract: types.Address) DerivedStateAccount {
        return .{
            .header = .{
                .account_type = .DerivedState,
                .owner_program = contract,
            },
            .user = user,
            .contract = contract,
        };
    }

    /// Serialize to bytes: header(60) + user(32) + contract(32) = 124 bytes
    pub fn serialize(self: *const DerivedStateAccount, buf: []u8) []u8 {
        const hdr = std.mem.asBytes(&self.header);
        @memcpy(buf[0..60], hdr);
        @memcpy(buf[60..92], &self.user.bytes);
        @memcpy(buf[92..124], &self.contract.bytes);
        return buf[0..124];
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: []const u8) ?DerivedStateAccount {
        if (data.len < 124) return null;
        var header: AccountHeader = undefined;
        @memcpy(std.mem.asBytes(&header), data[0..60]);
        if (header.account_type != .DerivedState) return null;
        var user: types.Address = undefined;
        @memcpy(&user.bytes, data[60..92]);
        var contract: types.Address = undefined;
        @memcpy(&contract.bytes, data[92..124]);
        return .{ .header = header, .user = user, .contract = contract };
    }
};

/// Derive deterministic account address for a user's state within a contract.
/// Address = blake3(user || contract)
pub fn deriveAddress(user: types.Address, contract: types.Address) types.Address {
    var createInput: [64]u8 = undefined;
    @memcpy(createInput[0..32], &user.bytes);
    @memcpy(createInput[32..64], &contract.bytes);
    var addr: types.Address = undefined;
    std.crypto.hash.Blake3.hash(&createInput, &addr.bytes, .{});
    return addr;
}

/// Per-user storage key: blake3(user || contract || slot)
pub fn derivedStorageKey(user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
    var createInput: [96]u8 = undefined;
    @memcpy(createInput[0..32], &user.bytes);
    @memcpy(createInput[32..64], &contract.bytes);
    @memcpy(createInput[64..96], &slot);
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&createInput, &hash, .{});
    return hash;
}

/// Global accumulator storage key: blake3(contract || "global" || slot)
pub fn globalStorageKey(contract: types.Address, slot: [32]u8) [32]u8 {
    var createInput: [70]u8 = undefined;
    @memcpy(createInput[0..32], &contract.bytes);
    @memcpy(createInput[32..38], "global");
    @memcpy(createInput[38..70], &slot);
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&createInput, &hash, .{});
    return hash;
}

/// Legacy-compatible storage key: blake3(contract || slot)
pub fn legacyStorageKey(addr: types.Address, slot: [32]u8) [32]u8 {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &addr.bytes);
    @memcpy(input[32..64], &slot);
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&input, &hash, .{});
    return hash;
}

// ── Credit Receipt Queue ────────────────────────────────────────────────

/// Queue of credit receipts produced during parallel execution.
pub const ReceiptQueue = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayListUnmanaged(types.CreditReceipt),

    pub fn init(allocator: std.mem.Allocator) ReceiptQueue {
        return .{ .allocator = allocator, .items = .{} };
    }

    pub fn deinit(self: *ReceiptQueue) void {
        self.items.deinit(self.allocator);
    }

    pub fn push(self: *ReceiptQueue, receipt: types.CreditReceipt) !void {
        try self.items.append(self.allocator, receipt);
    }

    pub fn sort(self: *ReceiptQueue) void {
        std.mem.sortUnstable(types.CreditReceipt, self.items.items, {}, struct {
            pub fn lessThan(_: void, a: types.CreditReceipt, b: types.CreditReceipt) bool {
                return a.txIndex < b.txIndex;
            }
        }.lessThan);
    }

    pub fn count(self: *const ReceiptQueue) usize {
        return self.items.items.len;
    }

    pub fn clear(self: *ReceiptQueue) void {
        self.items.clearRetainingCapacity();
    }
};

// ── Accumulator Delta Queue ─────────────────────────────────────────────

/// Queue of accumulator deltas for commutative global state.
pub const DeltaQueue = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayListUnmanaged(types.AccumulatorDelta),

    pub fn init(allocator: std.mem.Allocator) DeltaQueue {
        return .{ .allocator = allocator, .items = .{} };
    }

    pub fn deinit(self: *DeltaQueue) void {
        self.items.deinit(self.allocator);
    }

    pub fn push(self: *DeltaQueue, delta: types.AccumulatorDelta) !void {
        try self.items.append(self.allocator, delta);
    }

    pub fn count(self: *const DeltaQueue) usize {
        return self.items.items.len;
    }

    pub fn clear(self: *DeltaQueue) void {
        self.items.clearRetainingCapacity();
    }

    /// Merge all deltas for the same (contract, slot) into a single net value.
    pub fn merge(self: *DeltaQueue, allocator: std.mem.Allocator) !std.AutoHashMap([32]u8, i256) {
        var result = std.AutoHashMap([32]u8, i256).init(allocator);
        errdefer result.deinit();
        for (self.items.items) |delta| {
            const key = globalStorageKey(delta.contract, delta.slot);
            const val = std.mem.readInt(u256, &delta.deltaValue, .big);
            const signed: i256 = if (delta.isAddition) @intCast(val) else -@as(i256, @intCast(val));
            const gop = try result.getOrPut(key);
            if (gop.found_existing) {
                gop.value_ptr.* += signed;
            } else {
                gop.value_ptr.* = signed;
            }
        }
        return result;
    }
};
