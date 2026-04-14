// Production Verkle Trie Node Implementation
// Uses Banderwagon curve for commitments and IPA for proofs

const std = @import("std");
const Allocator = std.mem.Allocator;

// Use real verkle-crypto library
const verkle_crypto = @import("lib/main.zig");
const banderwagon = verkle_crypto.banderwagon;
const crs_mod = verkle_crypto.crs;
const ipa_mod = verkle_crypto.ipa;

pub const Element = banderwagon.Element;
pub const ElementMSM = banderwagon.ElementMSM;
pub const Fr = banderwagon.Fr;
pub const CRS = crs_mod.CRS;
pub const DomainSize = crs_mod.DomainSize; // 256 children per node

/// Verkle Node Types
pub const NodeType = enum(u8) {
    Empty = 0x00,
    Internal = 0x01,
    Leaf = 0x02,
    HashedNode = 0x03, // Placeholder for pruned subtree
};

/// Verkle key constants
pub const KEY_LENGTH = 32;
pub const STEM_LENGTH = 31; // First 31 bytes form the stem
pub const SUFFIX_LENGTH = 1; // Last byte is the suffix (index into leaf values)

/// Internal Node: Commits to 256 children using Pedersen vector commitments
/// Each child is either Empty, another Internal node, or a Leaf node
pub const InternalNode = struct {
    /// Child commitments - each represents a subtree
    children: [256]?*Node,
    /// Commitment C = commit(C_0, C_1, ..., C_255) using CRS
    commitment: Element,
    /// Depth in tree (0 = root)
    depth: u8,
    /// Cached commitment values for children (for efficient updates)
    child_commitments: [256]Fr,
    /// Dirty flag for lazy commitment recalculation
    dirty: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, depth: u8) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .children = [_]?*Node{null} ** 256,
            .commitment = Element.identity(),
            .depth = depth,
            .child_commitments = [_]Fr{Fr.zero()} ** 256,
            .dirty = false,
        };
        return self;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (&self.children) |*child| {
            if (child.*) |node| {
                node.deinit(allocator);
                allocator.destroy(node);
                child.* = null;
            }
        }
        allocator.destroy(self);
    }

    /// Set a child and mark dirty for commitment recalculation
    pub fn setChild(self: *Self, index: u8, node: ?*Node) void {
        self.children[index] = node;
        self.dirty = true;
    }

    /// Get child at index
    pub fn getChild(self: *const Self, index: u8) ?*Node {
        return self.children[index];
    }

    /// Recalculate commitment from children
    /// C = sum(G_i * hash(C_i)) for all non-empty children
    pub fn updateCommitment(self: *Self, xcrs: *const CRS) !void {
        if (!self.dirty) return;

        // Collect child commitment scalars
        for (self.children, 0..) |child_opt, i| {
            if (child_opt) |child| {
                // Convert child commitment to scalar field element
                self.child_commitments[i] = child.getCommitment().mapToScalarField();
            } else {
                self.child_commitments[i] = Fr.zero();
            }
        }

        // Compute Pedersen commitment: C = sum(G_i * child_commitments[i])
        self.commitment = try xcrs.commit(&self.child_commitments);
        self.dirty = false;
    }

    /// Serialize for storage
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        // Format: [Type(1)][Depth(1)][Commitment(32)][ChildBitmap(32)][Children...]
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();

        try list.append(@intFromEnum(NodeType.Internal));
        try list.append(self.depth);
        try list.appendSlice(&self.commitment.toBytes());

        // Create bitmap of non-null children
        var bitmap: [32]u8 = [_]u8{0} ** 32;
        for (0..256) |i| {
            if (self.children[i] != null) {
                bitmap[i / 8] |= @as(u8, 1) << @intCast(i % 8);
            }
        }
        try list.appendSlice(&bitmap);

        // Serialize each child commitment (not full child data - that's stored separately)
        for (self.children) |child_opt| {
            if (child_opt) |child| {
                try list.appendSlice(&child.getCommitment().toBytes());
            }
        }

        return list.toOwnedSlice();
    }

    /// Deserialize from storage
    pub fn deserialize(allocator: Allocator, data: []const u8) !*Self {
        if (data.len < 66) return error.InvalidData; // 1 + 1 + 32 + 32

        if (data[0] != @intFromEnum(NodeType.Internal)) return error.WrongNodeType;

        const depth = data[1];
        const commitment = Element.fromBytes(data[2..34].*) catch return error.InvalidCommitment;
        const bitmap = data[34..66];

        const self = try allocator.create(Self);
        self.* = Self{
            .children = [_]?*Node{null} ** 256,
            .commitment = commitment,
            .depth = depth,
            .child_commitments = [_]Fr{Fr.zero()} ** 256,
            .dirty = false,
        };

        // Count children to deserialize their commitments
        var offset: usize = 66;
        for (0..256) |i| {
            if ((bitmap[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0) {
                if (offset + 32 > data.len) {
                    allocator.destroy(self);
                    return error.TruncatedData;
                }
                // Store commitment as HashedNode placeholder
                const child_commitment = Element.fromBytes(data[offset..][0..32].*) catch {
                    allocator.destroy(self);
                    return error.InvalidChildCommitment;
                };
                const hashed_node = try HashedNode.init(allocator, child_commitment);
                self.children[i] = &hashed_node.node;
                offset += 32;
            }
        }

        return self;
    }
};

/// Leaf Node: Stores up to 256 values at leaf level
/// Key structure: [stem (31 bytes)][suffix (1 byte)]
/// All keys with same stem share the same leaf node
pub const LeafNode = struct {
    /// The 31-byte stem (prefix of all keys in this leaf)
    stem: [STEM_LENGTH]u8,
    /// Values indexed by suffix (last byte of key)
    /// null means slot is empty
    values: [256]?[]u8,
    /// C1 commitment: first 128 values
    c1: Element,
    /// C2 commitment: last 128 values
    c2: Element,
    /// Overall commitment: hash(1, stem, C1, C2)
    commitment: Element,
    /// Dirty flag
    dirty: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, stem: [STEM_LENGTH]u8) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .stem = stem,
            .values = [_]?[]u8{null} ** 256,
            .c1 = Element.identity(),
            .c2 = Element.identity(),
            .commitment = Element.identity(),
            .dirty = true,
        };
        return self;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (&self.values) |*val| {
            if (val.*) |v| {
                allocator.free(v);
                val.* = null;
            }
        }
        allocator.destroy(self);
    }

    /// Set value at suffix index
    pub fn setValue(self: *Self, allocator: Allocator, suffix: u8, value: []const u8) !void {
        // Free old value if exists
        if (self.values[suffix]) |old| {
            allocator.free(old);
        }
        self.values[suffix] = try allocator.dupe(u8, value);
        self.dirty = true;
    }

    /// Get value at suffix index
    pub fn getValue(self: *const Self, suffix: u8) ?[]const u8 {
        return self.values[suffix];
    }

    /// Delete value at suffix index
    pub fn deleteValue(self: *Self, allocator: Allocator, suffix: u8) void {
        if (self.values[suffix]) |old| {
            allocator.free(old);
            self.values[suffix] = null;
            self.dirty = true;
        }
    }

    /// Update leaf commitment
    /// C1 = commit(v[0..128] as field elements)
    /// C2 = commit(v[128..256] as field elements)
    /// commitment = commit(1, stem_as_fr, C1_as_fr, C2_as_fr)
    pub fn updateCommitment(self: *Self, xcrs: *const CRS) !void {
        if (!self.dirty) return;

        // Convert first 128 values to field elements
        var c1_scalars: [256]Fr = [_]Fr{Fr.zero()} ** 256;
        var c2_scalars: [256]Fr = [_]Fr{Fr.zero()} ** 256;

        // Pack values into scalars (two field elements per value: low and high 128 bits)
        for (0..128) |i| {
            if (self.values[i]) |value| {
                c1_scalars[i * 2] = valueToFieldLow(value);
                c1_scalars[i * 2 + 1] = valueToFieldHigh(value);
            }
        }

        for (128..256) |i| {
            if (self.values[i]) |value| {
                const idx = i - 128;
                c2_scalars[idx * 2] = valueToFieldLow(value);
                c2_scalars[idx * 2 + 1] = valueToFieldHigh(value);
            }
        }

        self.c1 = try xcrs.commit(&c1_scalars);
        self.c2 = try xcrs.commit(&c2_scalars);

        // Final commitment includes stem and both sub-commitments
        var final_scalars: [256]Fr = [_]Fr{Fr.zero()} ** 256;
        final_scalars[0] = Fr.one(); // Marker for leaf
        final_scalars[1] = stemToField(self.stem);
        final_scalars[2] = self.c1.mapToScalarField();
        final_scalars[3] = self.c2.mapToScalarField();

        self.commitment = try xcrs.commit(&final_scalars);
        self.dirty = false;
    }

    /// Serialize for storage
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        // Format: [Type(1)][Stem(31)][C1(32)][C2(32)][ValueBitmap(32)][Values...]
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();

        try list.append(@intFromEnum(NodeType.Leaf));
        try list.appendSlice(&self.stem);
        try list.appendSlice(&self.c1.toBytes());
        try list.appendSlice(&self.c2.toBytes());

        // Bitmap of non-null values
        var bitmap: [32]u8 = [_]u8{0} ** 32;
        for (0..256) |i| {
            if (self.values[i] != null) {
                bitmap[i / 8] |= @as(u8, 1) << @intCast(i % 8);
            }
        }
        try list.appendSlice(&bitmap);

        // Serialize each value with length prefix
        for (self.values) |val_opt| {
            if (val_opt) |val| {
                const len: u32 = @intCast(val.len);
                try list.appendSlice(std.mem.asBytes(&len));
                try list.appendSlice(val);
            }
        }

        return list.toOwnedSlice();
    }

    /// Deserialize from storage
    pub fn deserialize(allocator: Allocator, data: []const u8) !*Self {
        if (data.len < 128) return error.InvalidData; // 1 + 31 + 32 + 32 + 32

        if (data[0] != @intFromEnum(NodeType.Leaf)) return error.WrongNodeType;

        var stem: [STEM_LENGTH]u8 = undefined;
        @memcpy(&stem, data[1..32]);

        const c1 = Element.fromBytes(data[32..64].*) catch return error.InvalidC1;
        const c2 = Element.fromBytes(data[64..96].*) catch return error.InvalidC2;
        const bitmap = data[96..128];

        const self = try allocator.create(Self);
        self.* = Self{
            .stem = stem,
            .values = [_]?[]u8{null} ** 256,
            .c1 = c1,
            .c2 = c2,
            .commitment = Element.identity(),
            .dirty = true, // Need to recalculate overall commitment
        };

        // Deserialize values
        var offset: usize = 128;
        for (0..256) |i| {
            if ((bitmap[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0) {
                if (offset + 4 > data.len) {
                    self.deinit(allocator);
                    return error.TruncatedData;
                }
                const len = std.mem.readInt(u32, data[offset..][0..4], .little);
                offset += 4;

                if (offset + len > data.len) {
                    self.deinit(allocator);
                    return error.TruncatedData;
                }
                self.values[i] = try allocator.dupe(u8, data[offset .. offset + len]);
                offset += len;
            }
        }

        return self;
    }
};

/// Hashed Node: Placeholder for pruned subtree with known commitment
pub const HashedNode = struct {
    commitment: Element,
    node: Node,

    const Self = @This();

    pub fn init(allocator: Allocator, commitment: Element) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .commitment = commitment,
            .node = Node{ .HashedNode = self },
        };
        return self;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.destroy(self);
    }
};

/// Union type for all node types
pub const Node = union(NodeType) {
    Empty: void,
    Internal: *InternalNode,
    Leaf: *LeafNode,
    HashedNode: *HashedNode,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        switch (self.*) {
            .Empty => {},
            .Internal => |node| node.deinit(allocator),
            .Leaf => |node| node.deinit(allocator),
            .HashedNode => |node| node.deinit(allocator),
        }
    }

    pub fn getCommitment(self: *const Self) Element {
        return switch (self.*) {
            .Empty => Element.identity(),
            .Internal => |node| node.commitment,
            .Leaf => |node| node.commitment,
            .HashedNode => |node| node.commitment,
        };
    }

    pub fn isLeaf(self: *const Self) bool {
        return self.* == .Leaf;
    }

    pub fn isInternal(self: *const Self) bool {
        return self.* == .Internal;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.* == .Empty;
    }
};

// Helper functions for field element conversions

/// Convert value bytes (up to 32) to low 16-byte field element
fn valueToFieldLow(value: []const u8) Fr {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    const len = @min(value.len, 16);
    @memcpy(bytes[0..len], value[0..len]);
    // Set top bit to 0 to ensure < field modulus
    bytes[31] = 0;
    return Fr.fromBytes(bytes);
}

/// Convert value bytes (up to 32) to high 16-byte field element
fn valueToFieldHigh(value: []const u8) Fr {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    if (value.len > 16) {
        const len = @min(value.len - 16, 16);
        @memcpy(bytes[0..len], value[16..][0..len]);
    }
    bytes[31] = 0;
    return Fr.fromBytes(bytes);
}

/// Convert stem to field element
fn stemToField(stem: [STEM_LENGTH]u8) Fr {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    @memcpy(bytes[0..STEM_LENGTH], &stem);
    bytes[31] = 0;
    return Fr.fromBytes(bytes);
}

/// Extract stem from full key
pub fn getStem(key: [KEY_LENGTH]u8) [STEM_LENGTH]u8 {
    var stem: [STEM_LENGTH]u8 = undefined;
    @memcpy(&stem, key[0..STEM_LENGTH]);
    return stem;
}

/// Extract suffix from full key
pub fn getSuffix(key: [KEY_LENGTH]u8) u8 {
    return key[KEY_LENGTH - 1];
}

// Tests

test "InternalNode init and deinit" {
    const allocator = std.testing.allocator;
    const node = try InternalNode.init(allocator, 0);
    defer node.deinit(allocator);

    try std.testing.expect(node.depth == 0);
    try std.testing.expect(!node.dirty);
    try std.testing.expect(node.commitment.equal(Element.identity()));
}

test "LeafNode set and get value" {
    const allocator = std.testing.allocator;
    const stem: [STEM_LENGTH]u8 = [_]u8{0xAA} ** STEM_LENGTH;
    const leaf = try LeafNode.init(allocator, stem);
    defer leaf.deinit(allocator);

    const value = "hello world";
    try leaf.setValue(allocator, 42, value);

    const got = leaf.getValue(42);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(value, got.?);
}

test "getStem and getSuffix" {
    var key: [KEY_LENGTH]u8 = undefined;
    for (0..KEY_LENGTH) |i| {
        key[i] = @intCast(i);
    }

    const stem = getStem(key);
    try std.testing.expect(stem.len == STEM_LENGTH);
    try std.testing.expect(stem[0] == 0);
    try std.testing.expect(stem[30] == 30);

    const suffix = getSuffix(key);
    try std.testing.expect(suffix == 31);
}
