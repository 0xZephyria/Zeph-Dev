const std = @import("std");
const WAL = @import("wal.zig").WAL;
const io = @import("io.zig");

// Mock IO Engine (Stub for now as WAL uses std.fs directly for synchronous writes in this implementation)
// But wait, the WAL init takes an io.IoEngine. Let's see if we can pass a dummy one or if we need to modify WAL to not need it for this test.
// WAL struct: io_engine: io.IoEngine
// Let's create a dummy struct matching IoEngine if needed, or just use undefined if it's not used in the sync path we modified.
// WAL uses `self.file.pwriteAll` which is synchronous std.fs. It stores `io_engine` but doesn't seem to use it in `append` or `recover`.

test "WAL Recovery" {
    const allocator = std.testing.allocator;
    const test_path = "test_wal.log";

    // Clean up previous run
    std.fs.cwd().deleteFile(test_path) catch {};
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // 1. Write some data
    {
        // Need a dummy IoEngine?
        // Let's look at io.zig to see how to construct one easily, or just use undefined if unused.
        // Assuming undefined is safe for now as we don't call async methods.
        const io_engine: io.IoEngine = undefined;

        var wal = try WAL.init(allocator, io_engine, test_path);

        try wal.append("Entry 1", 100);
        try wal.append("Entry 2", 101);

        // Internal check: file size should be (Header + 7) + (Header + 7)
        // EntryHeader size is 4+4+8 = 16.
        // Total = 16+7 + 16+7 = 46 bytes.

        wal.deinit();
    }

    // 2. Reopen and Recover (Happy Path)
    {
        const io_engine: io.IoEngine = undefined;
        var wal = try WAL.init(allocator, io_engine, test_path);
        defer wal.deinit();

        try std.testing.expectEqual(@as(u64, 46), wal.current_offset);
    }

    // 3. Corrupt the file (Append garbage)
    {
        const file = try std.fs.cwd().openFile(test_path, .{ .mode = .read_write });
        try file.seekFromEnd(0);
        try file.writeAll("GARBAGE_CHUNK"); // 13 bytes
        file.close();
    }

    // 4. Reopen and Recover (Should Truncate)
    {
        const io_engine: io.IoEngine = undefined;
        var wal = try WAL.init(allocator, io_engine, test_path);
        defer wal.deinit();

        // Should have truncated back to 46
        try std.testing.expectEqual(@as(u64, 46), wal.current_offset);

        // Verify size
        const stat = try std.fs.cwd().statFile(test_path);
        try std.testing.expectEqual(@as(u64, 46), stat.size);
    }
}
