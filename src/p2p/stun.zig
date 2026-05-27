// ============================================================================
// Zephyria — STUN client (NAT Traversal & Public IP Discovery)
// ============================================================================
//
// Implements an active STUN (RFC 5389 / RFC 8489) client over UDP to retrieve
// the node's external IPv4 address.
// This supports the "Solana-style" NAT traversal strategy:
//   1. Validator queries public STUN servers on startup to discover its external IP.
//   2. Dynamically updates ZnrRecord and local node address.
//   3. Advertises the discovered IP/listening port in the peer routing table.

const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.stun);

pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

pub const StunError = error{
    ResolveFailed,
    SocketError,
    SendError,
    Timeout,
    InvalidResponse,
    NoAddressFound,
};

/// Query a public STUN server to discover the external IPv4 address.
/// Ephemeral UDP socket is used to send a Binding Request and parse the Binding Response.
pub fn discoverExternalAddress(stun_host: []const u8, stun_port: u16) StunError!std.net.Address {
    // 1. Resolve STUN host
    const resolved_list = std.net.getAddressList(std.heap.page_allocator, stun_host, stun_port) catch {
        return error.ResolveFailed;
    };
    defer resolved_list.deinit();

    var ipv4_addr: ?std.net.Address = null;
    for (resolved_list.addrs) |addr| {
        if (addr.any.family == posix.AF.INET) {
            ipv4_addr = addr;
            break;
        }
    }
    const stun_addr = ipv4_addr orelse return error.ResolveFailed;

    // 2. Open ephemeral UDP socket
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch {
        return error.SocketError;
    };
    defer posix.close(sock);

    // 3. Set receive timeout (2 seconds)
    const Timeval = extern struct {
        tv_sec: c_long,
        tv_usec: c_int,
    };
    const timeout = Timeval{ .tv_sec = 2, .tv_usec = 0 };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout)) catch {
        return error.SocketError;
    };

    // 4. Construct STUN Binding Request Packet (20 bytes)
    var request_buf: [20]u8 = undefined;
    // Message Type: 0x0001 (Binding Request)
    std.mem.writeInt(u16, request_buf[0..2], 0x0001, .big);
    // Message Length: 0x0000 (no attributes)
    std.mem.writeInt(u16, request_buf[2..4], 0x0000, .big);
    // Magic Cookie: 0x2112A442
    std.mem.writeInt(u32, request_buf[4..8], STUN_MAGIC_COOKIE, .big);
    // Transaction ID: 12 random bytes
    var transaction_id: [12]u8 = undefined;
    std.crypto.random.bytes(&transaction_id);
    @memcpy(request_buf[8..20], &transaction_id);

    // 5. Send Binding Request
    _ = posix.sendto(sock, &request_buf, 0, &stun_addr.any, stun_addr.getOsSockLen()) catch {
        return error.SendError;
    };

    // 6. Receive Binding Response
    var response_buf: [512]u8 = undefined;
    var from_addr: posix.sockaddr.in = undefined;
    var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    const recv_len = posix.recvfrom(sock, &response_buf, 0, @ptrCast(&from_addr), &from_len) catch |err| {
        if (err == error.WouldBlock or err == error.Again) {
            return error.Timeout;
        }
        return error.SocketError;
    };

    return try parseStunResponse(response_buf[0..recv_len], transaction_id);
}

/// Parse a raw STUN Binding Response and validate/decrypt its attributes.
pub fn parseStunResponse(response_buf: []const u8, transaction_id: [12]u8) StunError!std.net.Address {
    if (response_buf.len < 20) return error.InvalidResponse;

    // Validate Response Header
    const msg_type = std.mem.readInt(u16, response_buf[0..2], .big);
    const msg_len = std.mem.readInt(u16, response_buf[2..4], .big);
    const magic = std.mem.readInt(u32, response_buf[4..8], .big);

    // Expected Message Type: 0x0101 (Binding Success Response)
    if (msg_type != 0x0101) return error.InvalidResponse;
    if (magic != STUN_MAGIC_COOKIE) return error.InvalidResponse;
    if (!std.mem.eql(u8, response_buf[8..20], &transaction_id)) return error.InvalidResponse;

    if (20 + msg_len > response_buf.len) return error.InvalidResponse;

    // Parse attributes
    var offset: usize = 20;
    const end = 20 + msg_len;

    while (offset + 4 <= end) {
        const attr_type = std.mem.readInt(u16, response_buf[offset..][0..2], .big);
        const attr_len = std.mem.readInt(u16, response_buf[offset + 2..][0..2], .big);

        offset += 4;
        if (offset + attr_len > end) return error.InvalidResponse;

        const attr_value = response_buf[offset .. offset + attr_len];

        // Pad to 32-bit boundary
        offset += attr_len;
        const padding = (4 - (attr_len % 4)) % 4;
        offset += padding;

        if (attr_type == 0x0001) { // MAPPED-ADDRESS
            if (attr_value.len < 8) continue;
            const family = attr_value[1];
            if (family == 0x01) { // IPv4
                const port = std.mem.readInt(u16, attr_value[2..4], .big);
                var ip_bytes: [4]u8 = undefined;
                @memcpy(&ip_bytes, attr_value[4..8]);
                return std.net.Address.initIp4(ip_bytes, port);
            }
        } else if (attr_type == 0x0020) { // XOR-MAPPED-ADDRESS
            if (attr_value.len < 8) continue;
            const family = attr_value[1];
            if (family == 0x01) { // IPv4
                // XOR Port
                const xor_port = std.mem.readInt(u16, attr_value[2..4], .big);
                const cookie_high = @as(u16, @intCast(STUN_MAGIC_COOKIE >> 16));
                const port = xor_port ^ cookie_high;

                // XOR IP
                const xor_ip = std.mem.readInt(u32, attr_value[4..8], .big);
                const ip_u32 = xor_ip ^ STUN_MAGIC_COOKIE;

                var ip_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &ip_bytes, ip_u32, .big);
                return std.net.Address.initIp4(ip_bytes, port);
            }
        }
    }

    return error.NoAddressFound;
}

/// Query a public HTTP endpoint to discover the external IPv4 address as a fallback to STUN.
/// Performs a plain HTTP GET request to public IP echo services.
pub fn discoverExternalAddressHttp(allocator: std.mem.Allocator) StunError!std.net.Address {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    // Use plain HTTP (port 80) endpoints to avoid requiring TLS library support.
    const urls = [_][]const u8{
        "http://api.ipify.org",
        "http://icanhazip.com",
        "http://ident.me",
    };

    for (urls) |url| {
        var body_buf: [256]u8 = undefined;
        var body_writer: std.Io.Writer = .fixed(&body_buf);

        const result = client.fetch(.{
            .location = .{ .url = url },
            .response_writer = &body_writer,
        }) catch {
            continue;
        };

        if (result.status == .ok) {
            const body = body_writer.buffered();
            const ip_str = std.mem.trim(u8, body, " \t\r\n");
            if (std.net.Address.parseIp4(ip_str, 0)) |addr| {
                return addr;
            } else |_| {}
        }
    }
    return error.NoAddressFound;
}
