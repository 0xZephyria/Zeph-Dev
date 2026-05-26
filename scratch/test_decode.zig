const std = @import("std");
const types = @import("../src/core/types.zig");
const tx_decode = @import("../src/core/tx_decode.zig");
const hex = @import("../src/utils/hex.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    std.debug.print("Testing transaction serialization...\n", .{});

    // Let's mock a transaction like in ethSendTransaction
    const pub_key = [_]u8{1} ** 32;
    var from = types.Address.zero();
    std.crypto.hash.Blake3.hash(&pub_key, &from.bytes, .{});

    const tx_inner = types.Transaction{
        .pub_key = pub_key,
        .from = from,
        .nonce = 42,
        .gasPrice = 20000000000,
        .gasLimit = 21000,
        .to = null,
        .value = 100,
        .data = "hello world",
    };

    var tx_buf = std.ArrayListUnmanaged(u8).empty;
    defer tx_buf.deinit(allocator);
    try tx_inner.encodeBinary(tx_buf.writer(allocator));

    std.debug.print("Encoded transaction bytes length: {d}\n", .{tx_buf.items.len});

    // Try decoding
    var decoded_tx = types.Transaction{};
    decoded_tx.decodeBinary(allocator, tx_buf.items) catch |err| {
        std.debug.print("decodeBinary failed: {}\n", .{err});
        return err;
    };

    std.debug.print("Decoded transaction successfully!\n", .{});
    std.debug.print("Data: {s}\n", .{decoded_tx.data});
    allocator.free(decoded_tx.data);
}
