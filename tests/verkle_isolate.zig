const std = @import("std");
const trie = @import("../src/storage/verkle/trie.zig");
const storage = @import("../src/sdk/storage.zig");
const db_lib = @import("../src/storage/lsm/db.zig");

// To mock an AbstractDB locally
const AbstractDB = @import("../src/storage/abstract_db.zig").AbstractDB;

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
    std.debug.print("BEFORE COMMIT get: {any}\n", .{val1});

    try vt.commit();

    // Attempt retrieve AFTER commit
    const val2 = try vt.get(key);
    std.debug.print("AFTER COMMIT get: {any}\n", .{val2});
}
