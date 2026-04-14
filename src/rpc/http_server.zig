const log = @import("core").logger;
const std = @import("std");
const core = @import("core");
const p2p = @import("p2p");
const methods = @import("methods.zig");

const MAX_HEADER_BUFFER_SIZE = 8 * 1024; // 8KB for MetaMask's large headers
const MAX_REQUEST_BODY_SIZE = 5 * 1024 * 1024; // 5MB
const KEEP_ALIVE_TIMEOUT_MS = 30_000; // 30 second idle timeout
const MAX_REQUESTS_PER_CONN = 1000; // Safety valve

pub const Context = struct {
    allocator: std.mem.Allocator,
    wait_group: std.Thread.WaitGroup,
    tcp: std.net.Server,
    read_buffer_size: usize,
    handler: methods.RpcHandler,
    running: std.atomic.Value(bool),
    thread: ?std.Thread,

    // Rate Limiting
    rate_limiter: std.AutoHashMap(u32, RateLimitEntry),
    rate_limit_lock: std.Thread.Mutex,

    const RateLimitEntry = struct {
        tokens: f64,
        last_update: i64,
    };
    const RATE_LIMIT_CAPACITY = 100.0; // Higher for MetaMask/Remix rapid polling
    const RATE_LIMIT_REFILL = 40.0; // Faster refill for RPC workloads

    /// Heap-allocate the Context so that its address is stable across
    /// spawned threads.  Returning by value caused the HashMap's internal
    /// metadata pointer to become misaligned once the stack frame moved.
    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        chain: *core.blockchain.Blockchain,
        pool: *core.tx_pool.TxPool,
        exec: *core.executor.Executor,
        state: *core.state.State,
    ) !*Context {
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        const tcp_server = try addr.listen(.{
            .force_nonblocking = false,
            .reuse_address = true,
        });

        const handler = methods.RpcHandler.init(allocator, chain, pool, exec, state);

        const self = try allocator.create(Context);
        self.* = .{
            .allocator = allocator,
            .wait_group = .{},
            .tcp = tcp_server,
            .read_buffer_size = MAX_HEADER_BUFFER_SIZE,
            .handler = handler,
            .running = std.atomic.Value(bool).init(true),
            .thread = null,
            .rate_limiter = std.AutoHashMap(u32, RateLimitEntry).init(allocator),
            .rate_limit_lock = .{},
        };
        return self;
    }

    pub fn set_p2p(self: *Context, p2p_server: *p2p.Server) void {
        self.handler.set_p2p(p2p_server);
    }

    /// Set historical state for time-travel RPC queries
    pub fn setHistoricalState(self: *Context, historical: *core.historical_state.HistoricalState) void {
        self.handler.setHistoricalState(historical);
    }

    /// Set DAG mempool for parallel TX routing from RPC
    pub fn setDAGPool(self: *Context, dag: *core.dag_mempool.DAGMempool) void {
        self.handler.setDAGPool(dag);
    }

    pub fn deinit(self: *Context) void {
        self.running.store(false, .seq_cst);
        // Close the TCP listener first to unblock accept() in serve_loop
        self.tcp.deinit();
        // Now join the serve thread so it finishes before we free memory
        if (self.thread) |t| t.join();
        self.rate_limiter.deinit();
        self.allocator.destroy(self);
    }

    pub fn check_rate_limit(self: *Context, addr: std.net.Address) bool {
        if (addr.any.family != std.posix.AF.INET) return true;

        const ip = addr.in.sa.addr;
        const now = std.time.milliTimestamp();

        self.rate_limit_lock.lock();
        defer self.rate_limit_lock.unlock();

        const entry = self.rate_limiter.getOrPut(ip) catch return true;
        if (!entry.found_existing) {
            entry.value_ptr.* = .{
                .tokens = RATE_LIMIT_CAPACITY - 1.0,
                .last_update = now,
            };
            return true;
        } else {
            const elapsed_sec = @as(f64, @floatFromInt(now - entry.value_ptr.last_update)) / 1000.0;
            const new_tokens = entry.value_ptr.tokens + (elapsed_sec * RATE_LIMIT_REFILL);
            entry.value_ptr.tokens = @min(new_tokens, RATE_LIMIT_CAPACITY);
            entry.value_ptr.last_update = now;

            if (entry.value_ptr.tokens >= 1.0) {
                entry.value_ptr.tokens -= 1.0;
                return true;
            }
            return false;
        }
    }

    pub fn start(self: *Context) !void {
        self.thread = try std.Thread.spawn(.{}, serve_loop, .{self});
    }
};

fn serve_loop(ctx: *Context) void {
    log.debug("RPC Server listening on port {}\n", .{ctx.tcp.listen_address.getPort()});
    while (ctx.running.load(.seq_cst)) {
        const conn = ctx.tcp.accept() catch |err| {
            if (!ctx.running.load(.seq_cst)) break;
            log.debug("RPC Accept error: {}\n", .{err});
            continue;
        };

        const thread = std.Thread.spawn(.{}, handle_connection, .{ ctx, conn }) catch |err| {
            log.debug("RPC Spawn error: {}\n", .{err});
            conn.stream.close();
            continue;
        };
        thread.detach();
    }
}

/// HTTP/1.1 persistent connection handler.
/// Loops to process multiple requests on the same TCP connection (keep-alive).
fn handle_connection(ctx: *Context, conn: std.net.Server.Connection) void {
    defer conn.stream.close();

    // Rate limit check on connection open
    if (!ctx.check_rate_limit(conn.address)) {
        _ = conn.stream.write("HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n") catch {};
        return;
    }

    var requests_served: usize = 0;

    // ── Keep-alive loop: process multiple HTTP requests on the same connection ──
    while (requests_served < MAX_REQUESTS_PER_CONN) {
        // Per-request rate limit check
        if (requests_served > 0 and !ctx.check_rate_limit(conn.address)) {
            _ = conn.stream.write("HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n") catch {};
            return;
        }

        // ── 1. Read HTTP headers with idle timeout ──
        var buf: [MAX_HEADER_BUFFER_SIZE]u8 = undefined;
        var total_read: usize = 0;
        var header_end: ?usize = null;

        while (header_end == null) {
            if (total_read >= buf.len) {
                // Header too large
                _ = conn.stream.write("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n") catch {};
                return;
            }
            const n = conn.stream.read(buf[total_read..]) catch |err| {
                // Connection closed or error — normal for keep-alive timeout
                if (requests_served > 0) return; // Clean close after serving at least one request
                log.debug("RPC read error on fresh conn: {}\n", .{err});
                return;
            };
            if (n == 0) return; // Client closed connection — clean exit

            total_read += n;

            if (std.mem.indexOf(u8, buf[0..total_read], "\r\n\r\n")) |idx| {
                header_end = idx;
            }
        }

        const end = header_end.?;
        const headers = buf[0..end];
        const body_start = end + 4;
        const remaining_body_in_buf = total_read - body_start;

        // ── 2. Handle CORS preflight ──
        if (std.mem.startsWith(u8, headers, "OPTIONS")) {
            const cors_response = "HTTP/1.1 204 No Content\r\n" ++
                "Access-Control-Allow-Origin: *\r\n" ++
                "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n" ++
                "Access-Control-Allow-Headers: Content-Type, Authorization\r\n" ++
                "Access-Control-Max-Age: 86400\r\n" ++
                "Connection: keep-alive\r\n" ++
                "Content-Length: 0\r\n\r\n";
            _ = conn.stream.write(cors_response) catch return;
            requests_served += 1;
            continue; // Stay alive for next request
        }

        // ── 3. Parse Content-Length and Connection header ──
        var content_length: usize = 0;
        var client_wants_close = false;
        var it = std.mem.splitSequence(u8, headers, "\r\n");
        _ = it.first(); // Skip request line

        while (it.next()) |line| {
            if (line.len > 15 and std.ascii.eqlIgnoreCase(line[0..15], "Content-Length:")) {
                const val_str = std.mem.trim(u8, line[15..], " ");
                content_length = std.fmt.parseInt(usize, val_str, 10) catch 0;
            }
            // Detect "Connection: close" from client
            if (line.len > 11 and std.ascii.eqlIgnoreCase(line[0..11], "Connection:")) {
                const val = std.mem.trim(u8, line[11..], " ");
                if (std.ascii.eqlIgnoreCase(val, "close")) {
                    client_wants_close = true;
                }
            }
        }

        if (content_length > MAX_REQUEST_BODY_SIZE) {
            _ = conn.stream.write("HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n") catch {};
            return;
        }

        // ── 4. Read request body ──
        const body = ctx.allocator.alloc(u8, content_length) catch return;
        defer ctx.allocator.free(body);

        if (remaining_body_in_buf > 0) {
            const avail = @min(remaining_body_in_buf, content_length);
            @memcpy(body[0..avail], buf[body_start .. body_start + avail]);
        }

        var body_read = @min(remaining_body_in_buf, content_length);
        while (body_read < content_length) {
            const n = conn.stream.read(body[body_read..content_length]) catch return;
            if (n == 0) break;
            body_read += n;
        }

        // ── 5. Process JSON-RPC request ──
        var arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer arena.deinit();

        const keep_alive = !client_wants_close;
        handle_request_raw(ctx, arena.allocator(), conn, body[0..body_read], keep_alive) catch |err| {
            log.debug("RPC Handle Error: {}\n", .{err});
            // Send error response so MetaMask doesn't hang
            _ = conn.stream.write("HTTP/1.1 500 Internal Server Error\r\n" ++
                "Content-Type: application/json\r\n" ++
                "Access-Control-Allow-Origin: *\r\n" ++
                "Connection: close\r\n" ++
                "Content-Length: 72\r\n\r\n" ++
                "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"},\"id\":null}") catch {};
            return;
        };

        requests_served += 1;

        // If client sent "Connection: close", honor it
        if (client_wants_close) return;
    }
}

fn handle_request_raw(ctx: *Context, allocator: std.mem.Allocator, conn: std.net.Server.Connection, body: []const u8, keep_alive: bool) !void {
    // Parse JSON-RPC
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch {
        try respond_raw(conn, 200, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}", keep_alive);
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;

    // Batch request support: if root is an array, process each element
    if (root == .array) {
        var batch_response = std.ArrayListUnmanaged(u8){};
        defer batch_response.deinit(allocator);
        const batch_writer = batch_response.writer(allocator);
        try batch_writer.writeByte('[');

        for (root.array.items, 0..) |item, idx| {
            if (idx > 0) try batch_writer.writeByte(',');
            try process_single_request(ctx, allocator, item, batch_writer);
        }

        try batch_writer.writeByte(']');
        try respond_raw(conn, 200, batch_response.items, keep_alive);
        return;
    }

    if (root != .object) {
        try respond_raw(conn, 200, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"},\"id\":null}", keep_alive);
        return;
    }

    // Single request
    var response_json = std.ArrayListUnmanaged(u8){};
    defer response_json.deinit(allocator);
    const writer = response_json.writer(allocator);
    try process_single_request(ctx, allocator, root, writer);
    try respond_raw(conn, 200, response_json.items, keep_alive);
}

fn process_single_request(ctx: *Context, allocator: std.mem.Allocator, root: std.json.Value, writer: anytype) !void {
    if (root != .object) {
        try writer.writeAll("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"},\"id\":null}");
        return;
    }

    const method = root.object.get("method");
    const id = root.object.get("id");
    const params = root.object.get("params");

    // Validate JSON-RPC 2.0
    if (root.object.get("jsonrpc")) |val| {
        if (val != .string or !std.mem.eql(u8, val.string, "2.0")) {
            try write_error_response(writer, id, -32600, "Invalid Request");
            return;
        }
    }

    if (method == null or method.? != .string) {
        try write_error_response(writer, id, -32600, "Invalid Request");
        return;
    }

    const method_str = method.?.string;

    const result = ctx.handler.handle_request(allocator, method_str, params orelse .null) catch |err| {
        if (err == error.MethodNotFound) {
            log.debug("[RPC] Method not found: '{s}'\n", .{method_str});
            try write_error_response(writer, id, -32601, "Method not found");
            return;
        }

        if (err == error.InvalidParams) {
            log.debug("[RPC] Invalid params for '{s}'\n", .{method_str});
            try write_error_response(writer, id, -32602, "Invalid params");
            return;
        }

        log.debug("[RPC] Internal error for '{s}': {}\n", .{ method_str, err });
        try write_error_response(writer, id, -32603, "Internal error");
        return;
    };

    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    if (id) |i| {
        try dumpJson(i, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"result\":");
    try dumpJson(result, writer);
    try writer.writeAll("}");
}

fn write_error_response(writer: anytype, id: ?std.json.Value, code: i32, msg: []const u8) !void {
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    if (id) |i| {
        try dumpJson(i, writer);
    } else {
        try writer.writeAll("null");
    }
    try std.fmt.format(writer, ",\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}", .{ code, msg });
}

fn dumpJson(val: std.json.Value, writer: anytype) !void {
    switch (val) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |i| try std.fmt.format(writer, "{}", .{i}),
        .float => |f| try std.fmt.format(writer, "{}", .{f}),
        .number_string => |s| try writer.writeAll(s),
        .string => |s| {
            try writer.writeByte('"');
            // Escape special JSON characters
            for (s) |c| {
                switch (c) {
                    '"' => try writer.writeAll("\\\""),
                    '\\' => try writer.writeAll("\\\\"),
                    '\n' => try writer.writeAll("\\n"),
                    '\r' => try writer.writeAll("\\r"),
                    '\t' => try writer.writeAll("\\t"),
                    else => try writer.writeByte(c),
                }
            }
            try writer.writeByte('"');
        },
        .array => |arr| {
            try writer.writeByte('[');
            for (arr.items, 0..) |item, i| {
                if (i > 0) try writer.writeByte(',');
                try dumpJson(item, writer);
            }
            try writer.writeByte(']');
        },
        .object => |obj| {
            try writer.writeByte('{');
            var it = obj.iterator();
            var i: usize = 0;
            while (it.next()) |entry| {
                if (i > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try writer.writeAll(entry.key_ptr.*);
                try writer.writeByte('"');
                try writer.writeByte(':');
                try dumpJson(entry.value_ptr.*, writer);
                i += 1;
            }
            try writer.writeByte('}');
        },
    }
}

fn respond_raw(conn: std.net.Server.Connection, status: usize, json_body: []const u8, keep_alive: bool) !void {
    var header_buf: [512]u8 = undefined;
    const conn_header = if (keep_alive) "keep-alive" else "close";
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 {d} OK\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Access-Control-Allow-Origin: *\r\n" ++
        "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n" ++
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n" ++
        "Connection: {s}\r\n" ++
        "Content-Length: {d}\r\n\r\n", .{ status, conn_header, json_body.len });
    _ = try conn.stream.write(header);
    _ = try conn.stream.write(json_body);
}
