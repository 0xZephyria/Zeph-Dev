const std = @import("std");
const trie = @import("storage/verkle/trie.zig");
const db_lib = @import("storage/lsm/db.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var db = try db_lib.DB.init(allocator, "./isolate_data");
    defer db.deinit();

    var vt = try trie.VerkleTrie.init(allocator, db.asAbstractDB());
    defer vt.deinit();

    const key = [_]u8{5} ** 32;
    const value = [_]u8{7} ** 32;

    try vt.put(key, &value);

    // Attempt retrieve BEFORE commit
    const val1 = try vt.get(key);
    std.debug.print("BEFORE COMMIT get: {any}\n", .{val1 != null});

    try vt.commit();

    // Attempt retrieve AFTER commit
    const val2 = try vt.get(key);
    std.debug.print("AFTER COMMIT get: {any}\n", .{val2 != null});
}
