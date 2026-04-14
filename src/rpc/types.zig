const std = @import("std");

pub const JSON_RPC_VERSION = "2.0";

pub const Request = struct {
    jsonrpc: []const u8,
    method: []const u8,
    params: std.json.Value,
    id: std.json.Value,
};

pub const Response = struct {
    jsonrpc: []const u8 = JSON_RPC_VERSION,
    result: ?std.json.Value = null,
    err: ?Error = null,
    id: std.json.Value,
};

pub const Error = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value = null,
};
