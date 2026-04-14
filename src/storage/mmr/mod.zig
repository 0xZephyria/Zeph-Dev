// MMR Module - Merkle Mountain Range for constant-size header storage
// Enables O(log n) proofs for any historical block header

const std = @import("std");

/// MMR tree implementation
pub const tree = @import("tree.zig");
pub const MMR = tree.MMR;
pub const MMRNode = tree.MMRNode;
pub const MMRProof = tree.MMRProof;
pub const Hash = tree.Hash;
pub const ZERO_HASH = tree.ZERO_HASH;

// Tests
test {
    std.testing.refAllDecls(@This());
}
