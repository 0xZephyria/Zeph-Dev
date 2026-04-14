const std = @import("std");

pub const Packet = struct {
    buffer: [DATA_SIZE]u8,
    size: usize,
    addr: std.net.Address,

    /// Maximum over-the-wire size of a Transaction
    ///   1280 is IPv6 minimum MTU
    ///   40 bytes is the size of the IPv6 header
    ///   8 bytes is the size of the fragment header
    pub const DATA_SIZE: usize = 1232;

    pub const ANY_EMPTY: Packet = .{
        .addr = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 0),
        .buffer = .{0} ** DATA_SIZE,
        .size = 0,
    };

    pub fn init(
        addr: std.net.Address,
        data_init: [DATA_SIZE]u8,
        size: usize,
    ) Packet {
        return .{
            .addr = addr,
            .buffer = data_init,
            .size = size,
        };
    }

    pub fn data(self: *const Packet) []const u8 {
        return self.buffer[0..self.size];
    }

    pub fn dataMut(self: *Packet) []u8 {
        return self.buffer[0..self.size];
    }
};
