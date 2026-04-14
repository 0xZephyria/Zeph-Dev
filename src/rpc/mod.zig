const log = @import("core").logger;
const std = @import("std");
pub const types = @import("types.zig");
pub const grpc_server = @import("grpc.zig");

pub const GrpcServer = grpc_server.GrpcServer;
pub const http_server = @import("http_server.zig");
pub const HttpServer = http_server.Context;
// Defaulting Server to HttpServer now for gradual migration
pub const Server = HttpServer;

pub fn init() void {
    log.debug("RPC module initialized\n", .{});
}
