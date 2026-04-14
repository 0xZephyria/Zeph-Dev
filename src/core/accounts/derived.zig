// ============================================================================
// Zephyria — Derived State Account (Type 5)
// ============================================================================
//
// THE KEY TO DEX PARALLELISM.
//
// For high-frequency contracts (AMMs, DEXes, token contracts), mappings
// like `balances[user]` are decomposed into per-user derived accounts:
//
//   DerivedKey = keccak256(user || contract || slot)
//
// This means Alice's token balance and Bob's token balance are DIFFERENT
// trie keys — swaps from different users NEVER conflict on balance storage.
//
// For global state (totalSupply, pool reserves), uses accumulator pattern:
//
//   GlobalKey = keccak256(contract || "global" || slot)
//
// Accumulators merge order-independently via credit receipts and delta queues.
// Each TX produces a delta (e.g., "+100 tokens"), and Phase 2 merges them
// deterministically in TX-index order.
//
// Result: Even DEX swaps that traditionally lock the entire pool can be
// fully parallelized — user balances go to isolated per-user accounts,
// reserve updates go through commutative accumulators.

const std = @import("std");
const types = @import("../types.zig");
const AccountHeader = @import("header.zig").AccountHeader;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

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
};

// ── Key Derivation ──────────────────────────────────────────────────────

/// Derive deterministic account address for a user's state within a contract.
/// Address = keccak256(user || contract)[12..32]
pub fn deriveAddress(user: types.Address, contract: types.Address) types.Address {
    var hasher = Keccak256.init(.{});
    hasher.update(&user.bytes);
    hasher.update(&contract.bytes);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    var addr: types.Address = undefined;
    @memcpy(&addr.bytes, hash[12..32]);
    return addr;
}

/// Per-user storage key: keccak256(user || contract || slot)
/// Replaces the legacy storage_key(contract, slot) for per-user slots.
/// Two different users writing the SAME logical slot get DIFFERENT trie keys.
pub fn derivedStorageKey(user: types.Address, contract: types.Address, slot: [32]u8) [32]u8 {
    var hasher = Keccak256.init(.{});
    hasher.update(&user.bytes);
    hasher.update(&contract.bytes);
    hasher.update(&slot);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash;
}

/// Global accumulator storage key: keccak256(contract || "global" || slot)
/// Used for commutative state like totalSupply, pool reserves.
/// All transactions writing this key produce AccumulatorDeltas that merge.
pub fn globalStorageKey(contract: types.Address, slot: [32]u8) [32]u8 {
    var hasher = Keccak256.init(.{});
    hasher.update(&contract.bytes);
    hasher.update("global");
    hasher.update(&slot);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hash;
}

/// Legacy-compatible storage key: keccak256(contract || slot)
/// Used for contracts that haven't been classified yet by the transpiler.
pub fn legacyStorageKey(addr: types.Address, slot: [32]u8) [32]u8 {
    var input: [52]u8 = undefined;
    @memcpy(input[0..20], &addr.bytes);
    @memcpy(input[20..52], &slot);
    var hash: [32]u8 = undefined;
    Keccak256.hash(&input, &hash, .{});
    return hash;
}

// ── Credit Receipt Queue ────────────────────────────────────────────────

/// Queue of credit receipts produced during parallel execution.
/// Receipts represent cross-user state changes (e.g., Bob gets +100 tokens
/// from Alice's transfer). Applied deterministically in TX-index order.
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
                return a.tx_index < b.tx_index;
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
/// Deltas merge order-independently — the final result is the same
/// regardless of which thread produced them first.
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
            const val = std.mem.readInt(u256, &delta.delta_value, .big);
            const signed: i256 = if (delta.is_addition) @intCast(val) else -@as(i256, @intCast(val));
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
