// Code Store Module - Content-addressed bytecode deduplication
// Achieves ~70% storage reduction for contract code

const std = @import("std");

/// Code store implementation
pub const store = @import("store.zig");
pub const CodeStore = store.CodeStore;
pub const CodeStoreStats = store.CodeStoreStats;
pub const CodeHash = store.CodeHash;
pub const EMPTY_CODE_HASH = store.EMPTY_CODE_HASH;

/// Hash code to get content address
pub const hashCode = store.CodeStore.hashCode;

// Tests
test {
    std.testing.refAllDecls(@This());
}
