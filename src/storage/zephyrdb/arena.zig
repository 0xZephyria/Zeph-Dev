// ZephyrDB Arena — Pre-allocated memory arena for zero-allocation hot state storage
//
// TigerBeetle-inspired: All memory is allocated at startup via mmap.
// No runtime heap allocation — eliminates GC pauses, fragmentation, and OOM.
//
// Design:
//   - Uses mmap(MAP_ANONYMOUS | MAP_PRIVATE) to reserve virtual address space
//   - Physical pages are committed on-demand by the OS (lazy allocation)
//   - Fixed-size block allocator with free-list for O(1) alloc/free
//   - Thread-safe via atomic bump pointer for allocations

const std = @import("std");
const Atomic = std.atomic.Value;

/// Default arena size: 4GB virtual address space
pub const DEFAULT_ARENA_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Block sizes for the fixed-size allocator
pub const BlockSize = enum(u32) {
    B64 = 64, // Account entries (cache-line aligned)
    B256 = 256, // Storage slot groups (8 slots inline)
    B1K = 1024, // Small buffers
    B4K = 4096, // Page-sized allocations
    B64K = 65536, // Large allocations (code, etc.)
};

/// Arena statistics
pub const ArenaStats = struct {
    total_capacity: usize,
    bytes_committed: usize,
    bytes_free: usize,
    alloc_count: u64,
    free_count: u64,
    peak_usage: usize,
};

/// A single free-list node (overlaid on free blocks)
const FreeNode = struct {
    next: ?*FreeNode,
};

/// Per-size-class allocator with free-list
const SizeClass = struct {
    block_size: u32,
    free_list: ?*FreeNode,
    alloc_count: Atomic(u64),
    free_count: Atomic(u64),
    lock: std.Thread.Mutex,

    fn init(block_size: u32) SizeClass {
        return .{
            .block_size = block_size,
            .free_list = null,
            .alloc_count = Atomic(u64).init(0),
            .free_count = Atomic(u64).init(0),
            .lock = .{},
        };
    }

    fn alloc(self: *SizeClass) ?[*]u8 {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.free_list) |node| {
            self.free_list = node.next;
            _ = self.alloc_count.fetchAdd(1, .monotonic);
            return @ptrCast(node);
        }
        return null;
    }

    fn free(self: *SizeClass, ptr: [*]u8) void {
        self.lock.lock();
        defer self.lock.unlock();

        const node: *FreeNode = @ptrCast(@alignCast(ptr));
        node.next = self.free_list;
        self.free_list = node;
        _ = self.free_count.fetchAdd(1, .monotonic);
    }
};

/// The main memory arena backed by a single mmap region.
/// Provides O(1) fixed-size block allocation with zero runtime heap usage.
pub const Arena = struct {
    /// Base address of the mmap'd region
    base: [*]align(4096) u8,
    /// Total capacity in bytes
    capacity: usize,
    /// Current bump pointer offset (for initial allocation before free-list recycling)
    bump_offset: Atomic(usize),
    /// Peak usage tracking
    peak_usage: Atomic(usize),
    /// Size-class allocators
    size_classes: [5]SizeClass,
    /// Whether the arena was mmap'd (vs. heap-allocated for testing)
    is_mmap: bool,
    /// Fallback allocator for non-arena needs
    fallback: std.mem.Allocator,

    const Self = @This();

    /// Initialize the arena by reserving virtual address space.
    /// Physical pages are committed lazily by the OS on first access.
    pub fn init(fallback_alloc: std.mem.Allocator, capacity: usize) !Self {
        const base = try mapMemory(capacity);

        return Self{
            .base = base,
            .capacity = capacity,
            .bump_offset = Atomic(usize).init(0),
            .peak_usage = Atomic(usize).init(0),
            .size_classes = .{
                SizeClass.init(@intFromEnum(BlockSize.B64)),
                SizeClass.init(@intFromEnum(BlockSize.B256)),
                SizeClass.init(@intFromEnum(BlockSize.B1K)),
                SizeClass.init(@intFromEnum(BlockSize.B4K)),
                SizeClass.init(@intFromEnum(BlockSize.B64K)),
            },
            .is_mmap = true,
            .fallback = fallback_alloc,
        };
    }

    /// Initialize with a smaller size for testing (uses heap instead of mmap)
    pub fn initForTesting(alloc: std.mem.Allocator, capacity: usize) !Self {
        const mem = try alloc.alignedAlloc(u8, 4096, capacity);
        @memset(mem, 0);

        return Self{
            .base = mem.ptr,
            .capacity = capacity,
            .bump_offset = Atomic(usize).init(0),
            .peak_usage = Atomic(usize).init(0),
            .size_classes = .{
                SizeClass.init(@intFromEnum(BlockSize.B64)),
                SizeClass.init(@intFromEnum(BlockSize.B256)),
                SizeClass.init(@intFromEnum(BlockSize.B1K)),
                SizeClass.init(@intFromEnum(BlockSize.B4K)),
                SizeClass.init(@intFromEnum(BlockSize.B64K)),
            },
            .is_mmap = false,
            .fallback = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.is_mmap) {
            unmapMemory(self.base, self.capacity);
        } else {
            const slice = self.base[0..self.capacity];
            self.fallback.free(@alignCast(slice));
        }
    }

    /// Allocate a fixed-size block. Tries free-list first, falls back to bump allocation.
    pub fn allocBlock(self: *Self, comptime size: BlockSize) ?*align(64) [size_val(size)]u8 {
        const idx = sizeClassIndex(size);

        // Try free-list first (O(1) recycled allocation)
        if (self.size_classes[idx].alloc()) |ptr| {
            return @ptrCast(@alignCast(ptr));
        }

        // Fall back to bump allocation
        return self.bumpAlloc(size_val(size));
    }

    /// Free a fixed-size block back to the free-list for reuse.
    pub fn freeBlock(self: *Self, comptime size: BlockSize, ptr: *align(64) [size_val(size)]u8) void {
        const idx = sizeClassIndex(size);
        self.size_classes[idx].free(@ptrCast(ptr));
    }

    /// Allocate raw bytes via bump pointer (no free-list).
    /// Used for initial allocation and variable-size data.
    pub fn allocRaw(self: *Self, size: usize) ?[]u8 {
        const aligned_size = alignUp(size, 64); // Always cache-line aligned
        const offset = self.bump_offset.fetchAdd(aligned_size, .monotonic);

        if (offset + aligned_size > self.capacity) {
            // Undo the bump
            _ = self.bump_offset.fetchSub(aligned_size, .monotonic);
            return null;
        }

        // Update peak usage
        const new_usage = offset + aligned_size;
        var peak = self.peak_usage.load(.monotonic);
        while (new_usage > peak) {
            const result = self.peak_usage.cmpxchgWeak(peak, new_usage, .monotonic, .monotonic);
            if (result) |current| {
                peak = current;
            } else {
                break;
            }
        }

        return self.base[offset .. offset + size];
    }

    /// Get current usage statistics
    pub fn getStats(self: *const Self) ArenaStats {
        const committed = self.bump_offset.load(.acquire);
        var total_freed: u64 = 0;
        for (&self.size_classes) |*sc| {
            total_freed += sc.free_count.load(.acquire) * sc.block_size;
        }

        return ArenaStats{
            .total_capacity = self.capacity,
            .bytes_committed = committed,
            .bytes_free = @intCast(total_freed),
            .alloc_count = blk: {
                var total: u64 = 0;
                for (&self.size_classes) |*sc| {
                    total += sc.alloc_count.load(.acquire);
                }
                break :blk total;
            },
            .free_count = blk: {
                var total: u64 = 0;
                for (&self.size_classes) |*sc| {
                    total += sc.free_count.load(.acquire);
                }
                break :blk total;
            },
            .peak_usage = self.peak_usage.load(.acquire),
        };
    }

    /// Reset the arena (invalidates all outstanding pointers!)
    /// Only safe to call when you know nothing references arena memory.
    pub fn reset(self: *Self) void {
        self.bump_offset.store(0, .release);
        for (&self.size_classes) |*sc| {
            sc.lock.lock();
            sc.free_list = null;
            sc.alloc_count.store(0, .release);
            sc.free_count.store(0, .release);
            sc.lock.unlock();
        }
    }

    /// Get a pointer to arena memory at a specific offset (for serialization/deserialization)
    pub fn ptrAt(self: *const Self, offset: usize, len: usize) ?[]const u8 {
        if (offset + len > self.capacity) return null;
        return self.base[offset .. offset + len];
    }

    /// Get a mutable pointer to arena memory at a specific offset
    pub fn ptrAtMut(self: *Self, offset: usize, len: usize) ?[]u8 {
        if (offset + len > self.capacity) return null;
        return self.base[offset .. offset + len];
    }

    // ---- Internal helpers ----

    fn bumpAlloc(self: *Self, size: usize) ?*align(64) anyopaque {
        const aligned_size = alignUp(size, 64);
        const offset = self.bump_offset.fetchAdd(aligned_size, .monotonic);

        if (offset + aligned_size > self.capacity) {
            _ = self.bump_offset.fetchSub(aligned_size, .monotonic);
            return null;
        }

        const new_usage = offset + aligned_size;
        var peak = self.peak_usage.load(.monotonic);
        while (new_usage > peak) {
            const result = self.peak_usage.cmpxchgWeak(peak, new_usage, .monotonic, .monotonic);
            if (result) |current| {
                peak = current;
            } else {
                break;
            }
        }

        const ptr: [*]u8 = self.base + offset;
        return @ptrCast(@alignCast(ptr));
    }

    fn sizeClassIndex(size: BlockSize) usize {
        return switch (size) {
            .B64 => 0,
            .B256 => 1,
            .B1K => 2,
            .B4K => 3,
            .B64K => 4,
        };
    }

    fn size_val(comptime size: BlockSize) usize {
        return @intFromEnum(size);
    }
};

// ---- Platform-specific memory mapping ----

fn mapMemory(size: usize) ![*]align(4096) u8 {
    if (@import("builtin").os.tag == .linux) {
        const result = std.posix.mmap(
            null,
            size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        return @alignCast(result.ptr);
    } else {
        // macOS and other POSIX systems
        const result = std.posix.mmap(
            null,
            size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        return @alignCast(result.ptr);
    }
}

fn unmapMemory(ptr: [*]align(4096) u8, size: usize) void {
    std.posix.munmap(@alignCast(ptr[0..size]));
}

fn alignUp(value: usize, alignment: usize) usize {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ---- Tests ----

test "Arena basic allocation" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024); // 1MB
    defer arena.deinit();

    // Allocate a 64-byte block
    const block = arena.allocBlock(.B64) orelse return error.OutOfMemory;
    @memset(block, 0xAA);
    try std.testing.expectEqual(@as(u8, 0xAA), block[0]);

    // Free and reallocate
    arena.freeBlock(.B64, block);
    const block2 = arena.allocBlock(.B64) orelse return error.OutOfMemory;
    // Should get the same pointer back from free-list
    try std.testing.expectEqual(@intFromPtr(block), @intFromPtr(block2));
}

test "Arena raw allocation" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    const data = arena.allocRaw(100) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@as(usize, 100), data.len);

    // Multiple allocations
    const data2 = arena.allocRaw(200) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@as(usize, 200), data2.len);

    // Check stats
    const stats = arena.getStats();
    try std.testing.expect(stats.bytes_committed > 0);
}

test "Arena capacity exhaustion" {
    var arena = try Arena.initForTesting(std.testing.allocator, 4096);
    defer arena.deinit();

    // Allocate most of the space
    _ = arena.allocRaw(3000) orelse return error.OutOfMemory;

    // This should fail (not enough space for 64-byte aligned 2000 bytes)
    const result = arena.allocRaw(2000);
    try std.testing.expect(result == null);
}

test "Arena reset" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    _ = arena.allocRaw(1000) orelse return error.OutOfMemory;
    try std.testing.expect(arena.bump_offset.load(.acquire) > 0);

    arena.reset();
    try std.testing.expectEqual(@as(usize, 0), arena.bump_offset.load(.acquire));
}

test "Arena stats tracking" {
    var arena = try Arena.initForTesting(std.testing.allocator, 1024 * 1024);
    defer arena.deinit();

    const b1 = arena.allocBlock(.B64) orelse return error.OutOfMemory;
    const b2 = arena.allocBlock(.B256) orelse return error.OutOfMemory;
    arena.freeBlock(.B64, b1);
    _ = b2;

    const stats = arena.getStats();
    try std.testing.expect(stats.alloc_count >= 1);
    try std.testing.expect(stats.free_count >= 1);
    try std.testing.expect(stats.peak_usage > 0);
}
