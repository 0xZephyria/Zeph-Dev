const std = @import("std");
const builtin = @import("builtin");
const Packet = @import("packet.zig").Packet;

pub const PACKETS_PER_BATCH: usize = 64;

pub fn sendBatch(
    socket: std.posix.socket_t,
    packets: []const Packet,
) !usize {
    if (builtin.os.tag == .linux) {
        return sendBatchLinux(socket, packets);
    } else {
        return sendBatchFallback(socket, packets);
    }
}

fn sendBatchFallback(
    socket: std.posix.socket_t,
    packets: []const Packet,
) !usize {
    var sent: usize = 0;
    for (packets) |packet| {
        _ = std.posix.sendto(
            socket,
            packet.data(),
            0,
            &packet.addr.any,
            packet.addr.getOsSockLen(),
        ) catch |err| {
            // On error, we stop and return how many we sent successfully
            // or return error if 0 sent?
            // Sig implementation logs and continues or returns partial.
            // We'll log to stderr if possible or just return partial.
            if (sent > 0) return sent;
            return err;
        };
        sent += 1;
    }
    return sent;
}

fn sendBatchLinux(
    socket: std.posix.socket_t,
    packets: []const Packet,
) !usize {
    // Only compile this on Linux to avoid struct definition errors
    if (builtin.os.tag != .linux) unreachable;

    // We can't use variable length array for msgs on stack easily in Zig without comptime known upper bound?
    // But PACKETS_PER_BATCH is constant.
    var msgs: [PACKETS_PER_BATCH]std.os.linux.mmsghdr = undefined;
    var iovecs: [PACKETS_PER_BATCH]std.os.linux.iovec = undefined;
    // We need to store sockaddrs because mmsghdr takes pointers

    // usage of std.net.Address.any implies we should use storage capable of holding both.
    // std.os.linux.sockaddr is just the header. We need storage.
    var sockaddr_storage: [PACKETS_PER_BATCH]std.posix.sockaddr.storage = undefined;

    const count = @min(packets.len, PACKETS_PER_BATCH);

    for (0..count) |i| {
        const packet = &packets[i];

        iovecs[i] = .{
            .base = packet.data().ptr,
            .len = packet.size,
        };

        // Copy address to storage
        const addr_len = packet.addr.getOsSockLen();
        const src_ptr: *const std.posix.sockaddr = &packet.addr.any;
        const dst_ptr: *std.posix.sockaddr = @ptrCast(&sockaddr_storage[i]);
        // Raw copy bytes
        @memcpy(@as([*]u8, @ptrCast(dst_ptr))[0..addr_len], @as([*]const u8, @ptrCast(src_ptr))[0..addr_len]);

        msgs[i] = .{
            .msg_hdr = .{
                .name = @ptrCast(&sockaddr_storage[i]),
                .namelen = addr_len,
                .iov = @ptrCast(&iovecs[i]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .msg_len = 0,
        };
    }

    const rc = std.os.linux.sendmmsg(socket, &msgs, @intCast(count), 0);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |e| return std.posix.unexpectedErrno(e),
    };
}
