const std = @import("std");
const node_runner = @import("node_runner.zig");
const load_generator = @import("load_generator.zig");

pub fn printDashboard(
    nodes: []const *node_runner.VirtualNode,
    load_gen: ?*load_generator.LoadGenerator,
    active_attack: ?[]const u8,
    elapsed_sec: u64,
) void {
    std.debug.print("\x1b[2J\x1b[H", .{});
    
    std.debug.print("========================================================================\n", .{});
    std.debug.print("  ⚡ ZEPHYRIA NETWORK SIMULATOR  │  Elapsed: {d}s\n", .{elapsed_sec});
    std.debug.print("========================================================================\n\n", .{});

    std.debug.print("◆ VIRTUAL NODES CONFIGURATION:\n", .{});
    std.debug.print("ID   PORT   HTTP   ROLE      HEIGHT   PEERS   DB TYPE        DOUBLE SIGS\n", .{});
    std.debug.print("------------------------------------------------------------------------\n", .{});
    for (nodes) |n| {
        const role_str = if (n.is_miner) "Miner   " else "SyncNode";
        const height = if (n.chain.getHead()) |h| h.header.number else 0;
        const peer_count = n.p2p_server.peers.items.len;
        const double_signs = n.engine.doubleSignsDetected;

        std.debug.print("v{d}   {d}  {d}   {s}  #{d: <6}  {d: <5}   ZephyrDB/LSM  {d}\n", .{
            n.node_index, n.p2p_port, n.http_port, role_str, height, peer_count, double_signs,
        });
    }
    std.debug.print("\n", .{});

    std.debug.print("◆ TRANSACTION LOAD GENERATOR:\n", .{});
    if (load_gen) |lg| {
        const sent = lg.tx_sent.load(.seq_cst);
        const failed = lg.tx_failed.load(.seq_cst);
        const tps = if (elapsed_sec > 0) sent / elapsed_sec else 0;

        std.debug.print("  Status:     \x1b[32mActive\x1b[0m\n", .{});
        std.debug.print("  Target rate: {d} TPS\n", .{lg.tx_rate});
        std.debug.print("  Sent:        {d} TXs\n", .{sent});
        std.debug.print("  Failed:      {d} TXs\n", .{failed});
        std.debug.print("  Effective:   {d} TPS (avg)\n", .{tps});
    } else {
        std.debug.print("  Status:     \x1b[33mInactive\x1b[0m\n", .{});
    }
    std.debug.print("\n", .{});

    std.debug.print("◆ NETWORK WORKFLOW & P2P METRICS:\n", .{});
    for (nodes) |n| {
        const stats = n.p2p_server.getStats();
        std.debug.print("  v{d} - Pkts Rx/Tx: {d}/{d} │ Bytes Rx: {d} KB │ Mempool: {d} TXs\n", .{
            n.node_index,
            stats.packetsReceived,
            stats.packetsSent,
            stats.bytesReceived / 1024,
            n.dag_pool.count(),
        });
    }
    std.debug.print("\n", .{});

    std.debug.print("◆ SECURITY ATTACK SIMULATOR:\n", .{});
    if (active_attack) |attack| {
        std.debug.print("  Active Attack: \x1b[31m{s}\x1b[0m\n", .{attack});
    } else {
        std.debug.print("  Active Attack: \x1b[32mNone\x1b[0m\n", .{});
    }
    std.debug.print("\n", .{});

    std.debug.print("========================================================================\n", .{});
    std.debug.print("  [1] Double-Sign  [2] Replay  [3] Spam  [4] Downtime  [5] Stop Load  [Q] Quit\n", .{});
    std.debug.print("========================================================================\n", .{});
}
