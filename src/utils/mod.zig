pub const hex = @import("hex.zig");
pub const mux = @import("mux.zig");
pub const allocators = @import("allocators.zig");
pub const swiss_map = @import("swiss_map.zig");
pub const SwissMap = swiss_map.SwissMap;
pub const RwMux = mux.RwMux;
pub const Mux = mux.Mux;
pub const RecycleBuffer = allocators.RecycleBuffer;

/// Securely zero a buffer using volatile writes to prevent compiler from optimizing away the clear.
pub fn secureZero(buf: []u8) void {
    const ptr = @as([*]volatile u8, @ptrCast(buf.ptr));
    for (0..buf.len) |i| ptr[i] = 0;
}

/// Token bucket rate limiter.
pub const TokenBucket = struct {
    tokens: f64,
    last_refill: i64,
    capacity: f64,
    refill_rate: f64,

    pub fn init(capacity: f64, refill_rate: f64) TokenBucket {
        return .{
            .tokens = capacity,
            .last_refill = std.time.milliTimestamp(),
            .capacity = capacity,
            .refill_rate = refill_rate,
        };
    }

    pub fn refill(self: *Self, now: i64) void {
        const elapsed_sec = @as(f64, @floatFromInt(now - self.last_refill)) / 1000.0;
        if (elapsed_sec > 0) {
            self.tokens = @min(self.tokens + elapsed_sec * self.refill_rate, self.capacity);
            self.last_refill = now;
        }
    }

    pub fn tryConsume(self: *Self, amount: f64, now: i64) bool {
        self.refill(now);
        if (self.tokens >= amount) {
            self.tokens -= amount;
            return true;
        }
        return false;
    }

    const Self = @This();
};

// Need std for millisecond timestamp used in TokenBucket
const std = @import("std");
