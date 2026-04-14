// ============================================================================
// Zephyria — P2P Module (Root)
// ============================================================================
//
// Re-exports all P2P subsystems for clean module-level imports.

const log = @import("core").logger;
const std = @import("std");

pub const types = @import("types.zig");
pub const server = @import("server.zig");
pub const peer = @import("peer.zig");
pub const quic = @import("quic/root.zig");
pub const grpc = @import("grpc/server.zig");
pub const discovery = @import("discovery.zig");
pub const turbine = @import("turbine.zig");
pub const gulf_stream = @import("gulf_stream.zig");
pub const compression = @import("compression.zig");
pub const shred_verifier = @import("shred_verifier.zig");

// Export key structs
pub const Server = server.Server;
pub const ServerConfig = server.ServerConfig;
pub const Peer = peer.Peer;
pub const TurbineEngine = turbine.TurbineEngine;
pub const GulfStream = gulf_stream.GulfStream;
pub const Compressor = compression.Compressor;
pub const DiscoveryService = discovery.DiscoveryService;
pub const PropagationTree = turbine.PropagationTree;
pub const ReedSolomon = turbine.ReedSolomon;
pub const ShredCollector = turbine.ShredCollector;

pub fn init() void {
    log.debug("P2P module initialized (v{})\n", .{types.PROTOCOL_VERSION});
}
