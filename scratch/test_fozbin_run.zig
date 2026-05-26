const std = @import("std");
const contractLoader = @import("../vm/polkavm/loader/contract_loader.zig");
const syscallDispatch = @import("../vm/polkavm/syscall/dispatch.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // 1. Read TokenTest.fozbin
    const file = try std.fs.cwd().openFile("./TokenTest.fozbin", .{});
    defer file.close();
    const size = (try file.stat()).size;
    const binData = try allocator.alloc(u8, size);
    defer allocator.free(binData);
    _ = try file.readAll(binData);

    const selectors = [_]u32{
        0x6f91d85a,
        0xba4d2440,
        0x1ce900f6,
        0x25b04e4e,
        0x47779aaa,
        0x0dc9e26b,
        0xa0873bbc,
    };

    std.debug.print("Executing selectors on TokenTest.fozbin...\n", .{});
    for (selectors) |sel| {
        var env = syscallDispatch.HostEnv.init(allocator);
        defer env.deinit();
        env.gasLimit = 10_000_000;
        env.chainId = 99999;
        env.blockNumber = 1;
        env.timestamp = 1716422400;

        var calldata: [4]u8 = undefined;
        std.mem.writeInt(u32, &calldata, sel, .little);

        const res = try contractLoader.executeFromZephBin(
            allocator,
            binData,
            &calldata,
            10_000_000,
            &env,
        );
        defer allocator.free(res.returnData);

        std.debug.print("Selector 0x{x:0>8}: status={}, returnData.len={d}, hex={s}\n", .{
            sel,
            res.status,
            res.returnData.len,
            std.fmt.fmtSliceHexLower(res.returnData),
        });
    }
}
