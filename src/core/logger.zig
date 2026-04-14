// ============================================================================
// Zephyria — Production Logger
// ============================================================================
//
// Structured logging with compile-time level filtering.
// Levels: err, warn, info, debug, trace
//
// Usage:
//   const log = @import("logger.zig");
//   log.info("Block #{d} sealed", .{number});
//
// In production, set to .err or .warn for near-zero I/O overhead.

const std = @import("std");

pub const Level = enum(u3) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,
    trace = 4,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .err => "ERR",
            .warn => "WRN",
            .info => "INF",
            .debug => "DBG",
            .trace => "TRC",
        };
    }

    pub fn fromString(s: []const u8) ?Level {
        if (std.ascii.eqlIgnoreCase(s, "err") or std.ascii.eqlIgnoreCase(s, "error")) return .err;
        if (std.ascii.eqlIgnoreCase(s, "warn") or std.ascii.eqlIgnoreCase(s, "warning")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        if (std.ascii.eqlIgnoreCase(s, "trace")) return .trace;
        return null;
    }
};

var global_level: Level = .info;

pub fn setLevel(level: Level) void {
    global_level = level;
}

pub fn getLevel() Level {
    return global_level;
}

pub fn log(comptime level: Level, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(level) > @intFromEnum(global_level)) return;
    std.debug.print("[" ++ comptime level.toString() ++ "] " ++ fmt ++ "\n", args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

pub fn trace(comptime fmt: []const u8, args: anytype) void {
    log(.trace, fmt, args);
}
