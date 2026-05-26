const std = @import("std");

pub fn main() !void {
    const signature = "sendEther(address)";
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(signature, &hash, .{});
    std.debug.print("Signature: {s}\n", .{signature});
    std.debug.print("Selector: 0x", .{});
    for (hash[0..4]) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
}
