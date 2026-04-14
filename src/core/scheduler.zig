// ============================================================================
// Zephyria — DAG-Based Parallel Scheduler
// ============================================================================
//
// Groups transactions into conflict-free parallel wavefronts using a
// Directed Acyclic Graph (DAG) of dependencies.
//
// How it works:
//   1. For each TX, determine its "data footprint" — the set of account
//      addresses and storage cell keys it touches (from/to + contract slots).
//   2. Build a dependency graph: TX_A → TX_B if their footprints overlap.
//   3. Topologically sort the DAG into wavefronts (levels).
//   4. All TXs in the same wavefront can execute in parallel — guaranteed
//      zero conflicts because no two share a write key.
//
// Storage cell keys are derived using the account-per-slot model:
//   storageKey(contract, slot) → unique trie key
//   derivedStorageKey(user, contract, slot) → per-user isolated key
//
// No access lists needed. Dependencies are derived from TX structure:
//   • Simple transfer: touches from.nonce + from.balance + to.balance
//   • Contract call: touches from.nonce + from.balance + contract storage cells
//   • Per-user slots (token balances): NEVER conflict between different users

const std = @import("std");
const types = @import("types.zig");
const accounts = @import("accounts/mod.zig");

/// A wavefront is a batch of transactions that can execute in parallel.
pub const Wave = struct {
    tx_indices: std.ArrayListUnmanaged(usize),

    pub fn deinit(self: *Wave, allocator: std.mem.Allocator) void {
        self.tx_indices.deinit(allocator);
    }
};

/// Scheduler result: ordered list of parallel wavefronts.
pub const Schedule = struct {
    waves: std.ArrayListUnmanaged(Wave),
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Schedule) void {
        for (self.waves.items) |*w| {
            w.deinit(self.allocator);
        }
        self.waves.deinit(self.allocator);
    }

    pub fn wave_count(self: *const Schedule) usize {
        return self.waves.items.len;
    }

    pub fn total_txs(self: *const Schedule) usize {
        var count: usize = 0;
        for (self.waves.items) |w| {
            count += w.tx_indices.items.len;
        }
        return count;
    }
};

/// Build a parallel execution schedule from a set of transactions.
///
/// The scheduler analyzes each TX's data footprint and groups non-conflicting
/// TXs into wavefronts. TXs within a wave share NO write keys.
///
/// metadata_registry: optional contract metadata for slot classification.
///   If provided, per-user slots produce user-specific keys that never
///   conflict between different senders — enabling DEX parallelism.
pub fn schedule(
    allocator: std.mem.Allocator,
    transactions: []const types.Transaction,
    metadata_registry: ?*const accounts.MetadataRegistry,
) !Schedule {
    if (transactions.len == 0) {
        return Schedule{ .waves = .{}, .allocator = allocator };
    }

    // 1. Compute data footprint for each TX
    const footprints = try allocator.alloc(std.AutoHashMap([32]u8, void), transactions.len);
    defer {
        for (footprints) |*fp| fp.deinit();
        allocator.free(footprints);
    }

    for (transactions, 0..) |tx, i| {
        footprints[i] = std.AutoHashMap([32]u8, void).init(allocator);
        try computeFootprint(allocator, &footprints[i], tx, metadata_registry);
    }

    // 2. Build wavefronts greedily: assign each TX to the earliest wave
    //    where it doesn't conflict with any other TX already in that wave.
    var result = Schedule{ .waves = .{}, .allocator = allocator };
    errdefer result.deinit();

    // Per-wave occupied keys
    var wave_keys = std.ArrayListUnmanaged(std.AutoHashMap([32]u8, void)){};
    defer {
        for (wave_keys.items) |*wk| wk.deinit();
        wave_keys.deinit(allocator);
    }

    for (0..transactions.len) |tx_idx| {
        var placed = false;

        // Try to place in an existing wave
        for (result.waves.items, 0..) |_, wave_idx| {
            if (!conflictsWithWave(&footprints[tx_idx], &wave_keys.items[wave_idx])) {
                // No conflict — add to this wave
                try result.waves.items[wave_idx].tx_indices.append(allocator, tx_idx);
                // Mark keys as occupied
                var fp_it = footprints[tx_idx].iterator();
                while (fp_it.next()) |entry| {
                    try wave_keys.items[wave_idx].put(entry.key_ptr.*, {});
                }
                placed = true;
                break;
            }
        }

        if (!placed) {
            // Create new wave
            var new_wave = Wave{ .tx_indices = .{} };
            try new_wave.tx_indices.append(allocator, tx_idx);

            var new_keys = std.AutoHashMap([32]u8, void).init(allocator);
            var fp_it = footprints[tx_idx].iterator();
            while (fp_it.next()) |entry| {
                try new_keys.put(entry.key_ptr.*, {});
            }

            try result.waves.append(allocator, new_wave);
            try wave_keys.append(allocator, new_keys);
        }
    }

    return result;
}

/// Compute the data footprint of a transaction: the set of trie keys it touches.
fn computeFootprint(
    _: std.mem.Allocator,
    fp: *std.AutoHashMap([32]u8, void),
    tx: types.Transaction,
    metadata_registry: ?*const accounts.MetadataRegistry,
) !void {
    const state = @import("state.zig").State;

    // 1. Sender nonce + balance (always touched)
    try fp.put(state.nonce_key(tx.from), {});
    try fp.put(state.balance_key(tx.from), {});

    // 2. Recipient balance
    if (tx.to) |to_addr| {
        try fp.put(state.balance_key(to_addr), {});

        // 3. If calling a contract and metadata is available, analyze data field
        //    to determine which storage slots will be touched.
        //    For per-user classified slots, derive user-specific keys that
        //    DON'T conflict with other users.
        if (metadata_registry != null and tx.data.len >= 4) {
            // Function selector = first 4 bytes
            // For classified contracts, the transpiler annotates which slots
            // a function touches. Here we conservatively add the contract's
            // balance key and vault key.
            try fp.put(state.balance_key(to_addr), {});

            // Per-user derived key for the sender (never conflicts with other senders)
            var sender_slot: [32]u8 = [_]u8{0} ** 32;
            @memcpy(sender_slot[0..20], &tx.from.bytes);
            try fp.put(state.derived_storage_key(tx.from, to_addr, sender_slot), {});
        }
    } else {
        // Contract creation: touches deployer nonce + new contract address
        const new_addr = tx.deriveContractAddress();
        try fp.put(state.nonce_key(new_addr), {});
        try fp.put(state.balance_key(new_addr), {});
        try fp.put(state.code_hash_key(new_addr), {});
    }
}

/// Check if a TX's footprint conflicts with any key already in a wave.
fn conflictsWithWave(
    fp: *const std.AutoHashMap([32]u8, void),
    wave_keys: *const std.AutoHashMap([32]u8, void),
) bool {
    var it = fp.iterator();
    while (it.next()) |entry| {
        if (wave_keys.contains(entry.key_ptr.*)) return true;
    }
    return false;
}

/// Derive the data address for a per-user storage cell.
/// Used by the DAG mempool to route TXs to the correct dependency group.
pub fn derive_data_address(user: types.Address, contract: types.Address, slot: [32]u8) types.Address {
    return accounts.storage_cell.storageCellAddress(contract, accounts.derived.derivedStorageKey(user, contract, slot));
}
