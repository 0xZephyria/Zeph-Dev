// ============================================================================
// Zephyria — QUIC Module Root
// ============================================================================
//
// Re-exports all QUIC subsystems for clean module-level imports.
//
// Layer architecture:
//   transport/packet.zig  — RFC 9000 packet codec (VarInt, long/short headers)
//   frames.zig            — RFC 9000 frame types & codec
//   tls.zig               — RFC 9001 TLS 1.3 crypto (HKDF, AES-GCM, Ed25519)
//   stream.zig            — RFC 9000 stream multiplexer & reassembly
//   conn.zig              — Connection state machine (7-state FSM)
//   endpoint.zig          — Connection manager / QUIC tile (top-level handler)

const std = @import("std");

// ── Core packet codec
pub const transport = struct {
    pub const packet = @import("transport/packet.zig");
};
pub const pkt = transport.packet;

// ── Frame codec
pub const frames = @import("frames.zig");

// ── TLS 1.3 / QUIC crypto
pub const tls = @import("tls.zig");

// ── Stream multiplexer
pub const stream = @import("stream.zig");

// ── Connection state machine
pub const conn = @import("conn.zig");

// ── Endpoint (top-level connection manager)
pub const endpoint = @import("endpoint.zig");

// ── Top-level re-exports for ergonomic use
pub const QuicEndpoint = endpoint.QuicEndpoint;
pub const QuicConn = conn.QuicConn;
pub const QuicStream = stream.QuicStream;
pub const ConnState = conn.ConnState;
pub const EncryptionLevel = conn.EncryptionLevel;
pub const TlsConfig = tls.TlsConfig;
pub const StreamIds = frames.StreamIds;
pub const ConnectionId = pkt.ConnectionId;
pub const EndpointCallbacks = endpoint.EndpointCallbacks;
