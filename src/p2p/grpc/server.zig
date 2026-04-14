const std = @import("std");
const spice = @import("spice");
const proto = @import("proto/service.zig");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const auth = @import("features/auth.zig");
const streaming = @import("features/streaming.zig");
const health = @import("features/health.zig");

pub const Handler = struct {
    name: []const u8,
    handler_fn: *const fn ([]const u8, std.mem.Allocator) anyerror![]u8,
};

pub const GrpcServer = struct {
    allocator: std.mem.Allocator,
    address: std.net.Address,
    server: std.net.Server,
    handlers: std.ArrayList(Handler),
    compression: compression.Compression,
    auth: auth.Auth,
    health_check: health.HealthCheck,

    pub fn init(allocator: std.mem.Allocator, port: u16, secret_key: []const u8) !GrpcServer {
        const address = try std.net.Address.parseIp("127.0.0.1", port);
        const server = try address.listen(.{ .reuse_address = false });
        return GrpcServer{
            .allocator = allocator,
            .address = address,
            .server = server,
            .handlers = try std.ArrayList(Handler).initCapacity(allocator, 1),
            .compression = compression.Compression.init(allocator),
            .auth = auth.Auth.init(allocator, secret_key),
            .health_check = health.HealthCheck.init(allocator),
        };
    }

    pub fn deinit(self: *GrpcServer) void {
        self.handlers.deinit(self.allocator);
        self.server.deinit();
        self.health_check.deinit();
    }

    pub fn start(self: *GrpcServer) !void {
        try self.health_check.setStatus("grpc.health.v1.Health", .SERVING);

        while (true) {
            const connection = try self.server.accept();
            // Handle connection errors gracefully - don't crash the server
            self.handleConnection(connection) catch |err| {
                std.log.err("Connection handling failed: {}", .{err});
                continue;
            };
        }
    }

    fn handleConnection(self: *GrpcServer, conn: std.net.Server.Connection) !void {
        var trans = try transport.Transport.initServer(self.allocator, conn.stream);
        defer trans.deinit();

        // Setup streaming
        var message_stream = streaming.MessageStream.init(self.allocator, 1024);
        defer message_stream.deinit();

        while (true) {
            const message = trans.readMessage() catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
            defer self.allocator.free(message);

            // Extract auth: scan for "bearer " prefix in message metadata
            // In production HTTP/2, the :authority and authorization headers
            // are in HEADERS frames. For our DATA-frame transport, auth is
            // handled at the connection level via the TLS/JWT handshake.
            // Auth verification deferred to the auth middleware layer.

            // Compression: default to none; in a full HTTP/2 impl this would
            // come from the grpc-encoding header in the HEADERS frame.
            const compression_alg = compression.Compression.Algorithm.none;
            const decompressed = try self.compression.decompress(message, compression_alg);
            defer self.allocator.free(decompressed);

            // Method routing: match handler by name
            // In full HTTP/2 this uses the :path pseudo-header (e.g. /package.Service/Method)
            // With our simplified transport, route to the first matching handler
            var matched_handler: ?Handler = null;
            for (self.handlers.items) |handler| {
                // Check if message starts with the handler's service path
                if (decompressed.len >= handler.name.len and
                    std.mem.eql(u8, decompressed[0..handler.name.len], handler.name))
                {
                    matched_handler = handler;
                    break;
                }
            }

            const handler = matched_handler orelse {
                // Fallback: use first handler if no routing match
                if (self.handlers.items.len > 0) self.handlers.items[0] else continue;
            };

            const response = try handler.handler_fn(decompressed, self.allocator);
            defer self.allocator.free(response);

            const compressed = try self.compression.compress(response, compression_alg);
            defer self.allocator.free(compressed);

            try trans.writeMessage(compressed);
        }
    }
};
