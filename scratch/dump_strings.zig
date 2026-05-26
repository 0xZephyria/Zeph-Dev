const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const file_path = "vm/polkavm/revive-transfer-example.elf";
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(data);

    std.debug.print("=== ELF PRINTABLE STRINGS (len >= 4) ===\n", .{});
    var i: usize = 0;
    while (i < data.len) {
        if (std.ascii.isPrint(data[i])) {
            var len: usize = 0;
            while (i + len < data.len and std.ascii.isPrint(data[i + len])) : (len += 1) {}
            if (len >= 4) {
                const str = data[i .. i + len];
                // Only print if it looks like a code symbol, signature, or message
                std.debug.print("String at offset 0x{x}: {s}\n", .{i, str});
                i += len;
                continue;
            }
        }
        i += 1;
    }
}
