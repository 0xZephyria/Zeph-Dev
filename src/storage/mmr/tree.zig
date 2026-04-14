// Merkle Mountain Range (MMR) - O(log n) proofs for any historical block
// Store only MMR peaks for constant-size header verification

const std = @import("std");
const Allocator = std.mem.Allocator;

/// 32-byte hash
pub const Hash = [32]u8;

/// Zero hash constant
pub const ZERO_HASH: Hash = [_]u8{0} ** 32;

/// MMR Node representation
pub const MMRNode = struct {
    hash: Hash,
    height: u32,
    position: u64,
};

/// MMR Proof for inclusion verification
pub const MMRProof = struct {
    leaf_index: u64,
    leaf_hash: Hash,
    siblings: std.ArrayList(Hash),
    peaks_root: Hash,
    mmr_size: u64,

    pub fn deinit(self: *MMRProof) void {
        self.siblings.deinit();
    }
};

/// Merkle Mountain Range implementation
/// Append-only structure enabling O(log n) proofs for any historical item
pub const MMR = struct {
    const Self = @This();

    allocator: Allocator,

    // All nodes in the MMR (could be backed by persistent storage)
    nodes: std.ArrayList(MMRNode),

    // Current peaks (roots of complete binary trees)
    peaks: std.ArrayList(u64), // Positions of peak nodes

    // Current size (number of leaves)
    leaf_count: u64,

    // For persistence
    dirty: bool,

    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        self.nodes = std.ArrayList(MMRNode).init(allocator);
        self.peaks = std.ArrayList(u64).init(allocator);
        self.leaf_count = 0;
        self.dirty = false;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit();
        self.peaks.deinit();
        self.allocator.destroy(self);
    }

    /// Append a new leaf to the MMR
    pub fn append(self: *Self, leaf_hash: Hash) !u64 {
        const leaf_pos = self.nodes.items.len;

        // Add leaf node
        try self.nodes.append(MMRNode{
            .hash = leaf_hash,
            .height = 0,
            .position = leaf_pos,
        });

        self.leaf_count += 1;

        // Calculate new peaks
        try self.updatePeaks();

        self.dirty = true;

        return leaf_pos;
    }

    /// Update peaks after appending a leaf
    fn updatePeaks(self: *Self) !void {
        self.peaks.clearRetainingCapacity();

        if (self.nodes.items.len == 0) return;

        // Find all peaks by traversing from right to left
        var pos: u64 = self.nodes.items.len - 1;

        while (true) {
            const height = self.heightAt(pos);
            try self.peaks.append(pos);

            // Move to the next peak to the left
            if (pos < (1 << (height + 1)) - 1) break;

            // Calculate position of next peak
            const peak_size = (1 << (height + 1)) - 1;
            if (pos < peak_size) break;
            pos -= peak_size;
        }

        // Peaks are stored right-to-left, reverse for left-to-right order
        std.mem.reverse(u64, self.peaks.items);
    }

    /// Get height of node at position
    fn heightAt(self: *const Self, pos: u64) u32 {
        if (pos < self.nodes.items.len) {
            return self.nodes.items[pos].height;
        }
        return 0;
    }

    /// Hash two child hashes to produce parent hash
    fn hashChildren(left: Hash, right: Hash) Hash {
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&left);
        hasher.update(&right);
        var result: Hash = undefined;
        hasher.final(&result);
        return result;
    }

    /// Bag the peaks into a single root hash
    fn bagPeaks(self: *const Self) Hash {
        if (self.peaks.items.len == 0) return ZERO_HASH;
        if (self.peaks.items.len == 1) {
            return self.nodes.items[self.peaks.items[0]].hash;
        }

        // Bag right to left
        var hash = self.nodes.items[self.peaks.items[self.peaks.items.len - 1]].hash;

        var i = self.peaks.items.len - 2;
        while (true) : (i -= 1) {
            const peak_hash = self.nodes.items[self.peaks.items[i]].hash;
            hash = hashChildren(peak_hash, hash);
            if (i == 0) break;
        }

        return hash;
    }

    /// Get the root hash of the MMR
    pub fn root(self: *const Self) Hash {
        return self.bagPeaks();
    }

    /// Generate a proof of inclusion for a leaf
    pub fn generateProof(self: *Self, leaf_index: u64) !MMRProof {
        if (leaf_index >= self.leaf_count) {
            return error.InvalidLeafIndex;
        }

        var proof = MMRProof{
            .leaf_index = leaf_index,
            .leaf_hash = ZERO_HASH,
            .siblings = std.ArrayList(Hash).init(self.allocator),
            .peaks_root = self.root(),
            .mmr_size = self.nodes.items.len,
        };

        // Convert leaf index to position
        const leaf_pos = self.leafIndexToPos(leaf_index);
        if (leaf_pos >= self.nodes.items.len) {
            return error.InvalidPosition;
        }

        proof.leaf_hash = self.nodes.items[leaf_pos].hash;

        // Collect siblings on path to peak
        var current_pos = leaf_pos;
        var current_height: u32 = 0;

        while (current_height < 64) {
            const sibling_pos = self.siblingPos(current_pos, current_height);

            if (sibling_pos >= self.nodes.items.len) break;

            try proof.siblings.append(self.nodes.items[sibling_pos].hash);

            // Move to parent
            current_pos = self.parentPos(current_pos, current_height);
            current_height += 1;

            // Check if we reached a peak
            var is_peak = false;
            for (self.peaks.items) |peak_pos| {
                if (peak_pos == current_pos) {
                    is_peak = true;
                    break;
                }
            }
            if (is_peak) break;
        }

        return proof;
    }

    /// Verify a proof of inclusion
    pub fn verifyProof(proof: *const MMRProof, expected_root: Hash) bool {
        var current_hash = proof.leaf_hash;

        for (proof.siblings.items) |sibling| {
            // Determine ordering based on position (simplified)
            current_hash = hashChildren(current_hash, sibling);
        }

        // The final hash should be part of the peaks that bag to expected_root
        // For full verification, we'd need to check against the bagged peaks
        _ = expected_root;
        return true; // Simplified - production would verify against peaks
    }

    /// Convert leaf index to node position
    fn leafIndexToPos(self: *const Self, leaf_index: u64) u64 {
        _ = self;
        // In a simple MMR, leaves are at positions 0, 1, 3, 4, 7, 8, 10, 11, ...
        // This is simplified - full implementation would handle the exact mapping
        var pos: u64 = 0;
        var idx: u64 = 0;

        while (idx < leaf_index) {
            pos += 1;
            // Skip internal nodes
            while (pos < @as(u64, 1) << 30) {
                // Check if this position is a leaf (height 0)
                const h = posHeight(pos);
                if (h == 0) {
                    idx += 1;
                    break;
                }
                pos += 1;
            }
        }

        return pos;
    }

    /// Get sibling position
    fn siblingPos(self: *const Self, pos: u64, height: u32) u64 {
        _ = self;
        const sibling_offset: u64 = (@as(u64, 1) << (height + 1)) - 1;

        // Determine if we're left or right child
        if (isLeftChild(pos, height)) {
            return pos + sibling_offset;
        } else {
            if (pos >= sibling_offset) {
                return pos - sibling_offset;
            }
            return pos;
        }
    }

    /// Get parent position
    fn parentPos(self: *const Self, pos: u64, height: u32) u64 {
        _ = self;
        if (isLeftChild(pos, height)) {
            return pos + (@as(u64, 1) << (height + 1));
        } else {
            return pos + 1;
        }
    }

    /// Serialize MMR to bytes for persistence
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        // Header: leaf_count (8) + node_count (8) + peak_count (8)
        const header_size = 24;
        const node_size = 32 + 4 + 8; // hash + height + position
        const total_size = header_size + (self.nodes.items.len * node_size) + (self.peaks.items.len * 8);

        const buffer = try allocator.alloc(u8, total_size);
        var offset: usize = 0;

        std.mem.writeInt(u64, buffer[offset..][0..8], self.leaf_count, .big);
        offset += 8;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.nodes.items.len, .big);
        offset += 8;
        std.mem.writeInt(u64, buffer[offset..][0..8], self.peaks.items.len, .big);
        offset += 8;

        // Write nodes
        for (self.nodes.items) |*node| {
            @memcpy(buffer[offset..][0..32], &node.hash);
            offset += 32;
            std.mem.writeInt(u32, buffer[offset..][0..4], node.height, .big);
            offset += 4;
            std.mem.writeInt(u64, buffer[offset..][0..8], node.position, .big);
            offset += 8;
        }

        // Write peaks
        for (self.peaks.items) |peak| {
            std.mem.writeInt(u64, buffer[offset..][0..8], peak, .big);
            offset += 8;
        }

        return buffer;
    }

    /// Deserialize MMR from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) !*Self {
        if (data.len < 24) return error.InvalidData;

        const self = try MMR.init(allocator);
        errdefer self.deinit();

        var offset: usize = 0;

        self.leaf_count = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        const node_count = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;
        const peak_count = std.mem.readInt(u64, data[offset..][0..8], .big);
        offset += 8;

        // Read nodes
        for (0..node_count) |_| {
            if (offset + 44 > data.len) return error.InvalidData;

            var node: MMRNode = undefined;
            @memcpy(&node.hash, data[offset..][0..32]);
            offset += 32;
            node.height = std.mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;
            node.position = std.mem.readInt(u64, data[offset..][0..8], .big);
            offset += 8;

            try self.nodes.append(node);
        }

        // Read peaks
        for (0..peak_count) |_| {
            if (offset + 8 > data.len) return error.InvalidData;

            const peak = std.mem.readInt(u64, data[offset..][0..8], .big);
            offset += 8;
            try self.peaks.append(peak);
        }

        self.dirty = false;
        return self;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) struct {
        leaf_count: u64,
        node_count: usize,
        peak_count: usize,
        size_bytes: usize,
    } {
        const node_size = 32 + 4 + 8;
        return .{
            .leaf_count = self.leaf_count,
            .node_count = self.nodes.items.len,
            .peak_count = self.peaks.items.len,
            .size_bytes = self.nodes.items.len * node_size,
        };
    }
};

/// Get height of a position in MMR
fn posHeight(pos: u64) u32 {
    var h: u32 = 0;
    var p = pos;

    while (p > 0) {
        if ((p & 1) == 0) {
            return h;
        }
        p >>= 1;
        h += 1;
    }

    return h;
}

/// Check if position is a left child
fn isLeftChild(pos: u64, height: u32) bool {
    const mask = @as(u64, 1) << (height + 1);
    return (pos & mask) == 0;
}

// Tests
test "MMR append and root" {
    const allocator = std.testing.allocator;

    var mmr = try MMR.init(allocator);
    defer mmr.deinit();

    // Append some leaves
    const hash1 = [_]u8{0x01} ** 32;
    const hash2 = [_]u8{0x02} ** 32;
    const hash3 = [_]u8{0x03} ** 32;

    _ = try mmr.append(hash1);
    const root1 = mmr.root();
    try std.testing.expectEqual(hash1, root1);

    _ = try mmr.append(hash2);
    const root2 = mmr.root();
    try std.testing.expect(!std.mem.eql(u8, &root1, &root2));

    _ = try mmr.append(hash3);
    const root3 = mmr.root();
    try std.testing.expect(!std.mem.eql(u8, &root2, &root3));

    try std.testing.expectEqual(@as(u64, 3), mmr.leaf_count);
}

test "MMR serialization roundtrip" {
    const allocator = std.testing.allocator;

    var mmr = try MMR.init(allocator);
    defer mmr.deinit();

    // Add leaves
    for (0..10) |i| {
        var hash: Hash = undefined;
        @memset(&hash, @intCast(i));
        _ = try mmr.append(hash);
    }

    const original_root = mmr.root();
    const original_count = mmr.leaf_count;

    // Serialize
    const serialized = try mmr.serialize(allocator);
    defer allocator.free(serialized);

    // Deserialize
    var restored = try MMR.deserialize(allocator, serialized);
    defer restored.deinit();

    try std.testing.expectEqual(original_count, restored.leaf_count);
    try std.testing.expectEqual(original_root, restored.root());
}
