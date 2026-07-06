const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const Peer = @import("peer.zig").Peer;
const turbine_mod = @import("turbine.zig");
const Server = @import("server.zig").Server;
const log = core.logger;

/// Broadcast a block using Turbine shredding (primary propagation).
/// Shreds the block data, then sends each shred through the Turbine tree.
pub fn broadcastBlockViaTurbine(server: *Server, blockData: []const u8, blockNumber: u64, blockId: core.types.Hash) !void {
    var total_rtt: u64 = 0;
    var val_count: u64 = 0;

    server.mutex.lock();
    for (server.peers.items) |peer| {
        if (peer.handshakeComplete and peer.peerRole == .Validator) {
            total_rtt += peer.rtt_ms;
            val_count += 1;
        }
    }
    server.mutex.unlock();

    const avg_rtt = if (val_count > 0) total_rtt / val_count else 100;
    var ratio: f64 = 0.25;
    if (avg_rtt <= 50) {
        ratio = 0.20;
    } else if (avg_rtt >= 300) {
        ratio = 0.50;
    } else {
        ratio = 0.20 + 0.30 * (@as(f64, @floatFromInt(avg_rtt - 50)) / 250.0);
    }

    const blsSig: [96]u8 = blk: {
        if (blockData.len < 148 + 4) break :blk [_]u8{0} ** 96;
        const extraLen = std.mem.readInt(u32, blockData[144..148], .big);
        if (extraLen < 192) break :blk [_]u8{0} ** 96;
        var sig: [96]u8 = undefined;
        @memcpy(&sig, blockData[148 + 96 .. 148 + 192]);
        break :blk sig;
    };

    const shreds = try server.turbine.shredBlock(blockData, blockNumber, blockId, blsSig, ratio);
    defer server.turbine.freeShreds(shreds);

    server.mutex.lock();
    defer server.mutex.unlock();

    var peers = std.ArrayList(turbine_mod.StakeWeightedPeer).empty;
    defer peers.deinit(server.allocator);

    if (!std.mem.eql(u8, &server.config.validatorAddress.bytes, &core.types.Address.zero().bytes)) {
        const my_stake = blk: {
            for (server.engine.validator_set.active) |v| {
                if (std.mem.eql(u8, &v.address.bytes, &server.config.validatorAddress.bytes)) {
                    break :blk v.stake;
                }
            }
            break :blk @as(u256, 0);
        };
        try peers.append(server.allocator, .{
            .address = server.config.validatorAddress,
            .stake = my_stake,
        });
    }

    for (server.peers.items) |p| {
        if (p.handshakeComplete) {
            const stake = blk: {
                for (server.engine.validator_set.active) |v| {
                    if (std.mem.eql(u8, &v.address.bytes, &p.validatorAddress.bytes)) {
                        break :blk v.stake;
                    }
                }
                break :blk @as(u256, 0);
            };
            try peers.append(server.allocator, .{
                .address = p.validatorAddress,
                .stake = stake,
            });
        }
    }

    std.debug.print("[TURBINE] Block {d}: peers_in_tree={d}, shreds={d}, connected_peers={d}\n", .{
        blockNumber, peers.items.len, shreds.len, server.peers.items.len,
    });

    if (peers.items.len <= 1) {
        std.debug.print("[TURBINE] Block {d}: Only self in tree, falling back to direct broadcast\n", .{blockNumber});
        for (server.peers.items) |p| {
            if (p.handshakeComplete or p.connected) {
                for (shreds) |shred| {
                    const msg = types.ShredMsg{
                        .blockId = shred.blockId,
                        .blockNumber = shred.blockNumber,
                        .shredIndex = shred.shredIndex,
                        .totalDataShreds = shred.totalDataShreds,
                        .totalParityShreds = shred.totalParityShreds,
                        .shredType = shred.shredType,
                        .payload = shred.payload,
                        .producerSignature = shred.producerSignature,
                        .threadId = shred.threadId,
                    };
                    p.send(types.MsgShred, msg) catch |err| {
                        log.err("TURBINE: Direct-send shred failed: {}", .{err});
                    };
                }
                std.debug.print("[TURBINE] Block {d}: Direct-sent {d} shreds to peer {s}:{d}\n", .{
                    blockNumber, shreds.len, p.ipSlice(), p.port,
                });
            }
        }
        return;
    }

    std.mem.sort(turbine_mod.StakeWeightedPeer, peers.items, {}, struct {
        fn lessThan(_: void, a: turbine_mod.StakeWeightedPeer, b: turbine_mod.StakeWeightedPeer) bool {
            return a.stake > b.stake;
        }
    }.lessThan);

    server.turbine.buildPropTree(peers.items, @intCast(shreds.len)) catch {};

    var our_index: u32 = 0;
    for (peers.items, 0..) |p, idx| {
        if (std.mem.eql(u8, &p.address.bytes, &server.config.validatorAddress.bytes)) {
            our_index = @intCast(idx);
            break;
        }
    }

    const children = server.turbine.tree.getChildren(our_index);
    std.debug.print("[TURBINE] Block {d}: our_index={d}, children_count={d}\n", .{
        blockNumber, our_index, children.len,
    });

    var shreds_sent: u64 = 0;
    for (shreds) |shred| {
        const msg = types.ShredMsg{
            .blockId = shred.blockId,
            .blockNumber = shred.blockNumber,
            .shredIndex = shred.shredIndex,
            .totalDataShreds = shred.totalDataShreds,
            .totalParityShreds = shred.totalParityShreds,
            .shredType = shred.shredType,
            .payload = shred.payload,
            .producerSignature = shred.producerSignature,
            .threadId = shred.threadId,
        };

        for (children) |child| {
            if (child.peerIndex < peers.items.len) {
                const child_addr = peers.items[child.peerIndex].address;
                if (server.findPeerByValidatorAddressLocked(child_addr)) |peer| {
                    peer.send(types.MsgShred, msg) catch |err| {
                        log.err("TURBINE: Send shred to child failed: {}", .{err});
                    };
                    shreds_sent += 1;
                }
            }
        }
    }
    std.debug.print("[TURBINE] Block {d}: Total shreds sent={d}\n", .{blockNumber, shreds_sent});
}

/// Poll consensus engine for pending slash events and broadcast them.
pub fn drainAndBroadcastSlashEvents(server: *Server) !void {
    const events = try server.engine.drainSlashEvents();
    if (events.len == 0) return;
    defer server.allocator.free(events);

    for (events) |event| {
        const msg = types.SlashEvidenceMsg{
            .validator = event.validator,
            .blockNumber = event.blockNumber,
            .reason = @intFromEnum(event.reason),
            .evidenceHash1 = event.evidenceHash1,
            .evidenceHash2 = event.evidenceHash2,
            .reporterSignature = [_]u8{0} ** 96,
        };
        broadcastRaw(server, types.MsgSlashEvidence, std.mem.asBytes(&msg)) catch {};
    }

    log.debug("P2P: Broadcast {d} slash events\n", .{events.len});
}

/// Broadcast to all handshaked peers (RLP-encoded message).
pub fn broadcast(server: *Server, msgCode: u64, msg: anytype) !void {
    server.mutex.lock();
    const peersCopy = server.allocator.dupe(*Peer, server.peers.items) catch {
        server.mutex.unlock();
        return;
    };
    server.mutex.unlock();
    defer server.allocator.free(peersCopy);

    for (peersCopy) |peer| {
        if (peer.handshakeComplete) {
            peer.send(msgCode, msg) catch {};
        }
    }
    server.countPacketsSent(@intCast(peersCopy.len));
}

/// Broadcast raw bytes to all handshaked peers.
pub fn broadcastRaw(server: *Server, msgCode: u64, payload: []const u8) !void {
    server.mutex.lock();
    const peersCopy = server.allocator.dupe(*Peer, server.peers.items) catch {
        server.mutex.unlock();
        return;
    };
    server.mutex.unlock();
    defer server.allocator.free(peersCopy);

    for (peersCopy) |peer| {
        if (peer.handshakeComplete) {
            peer.sendRaw(msgCode, payload) catch {};
        }
    }
    server.countPacketsSent(@intCast(peersCopy.len));
}

/// Broadcast to a subset of peers (fanout), excluding a specific peer.
pub fn broadcastSubset(server: *Server, msgCode: u64, msg: anytype, fanout: u32, exclude: *Peer) !void {
    server.mutex.lock();
    const peersCopy = server.allocator.dupe(*Peer, server.peers.items) catch {
        server.mutex.unlock();
        return;
    };
    server.mutex.unlock();
    defer server.allocator.free(peersCopy);

    var count: u32 = 0;
    for (peersCopy) |peer| {
        if (peer == exclude) continue;
        if (peer.handshakeComplete) {
            peer.send(msgCode, msg) catch continue;
            count += 1;
            if (count >= fanout) break;
        }
    }
}

/// Gossip to peers in a specific subnet.
pub fn gossipToSubnet(server: *Server, subnet: types.SubnetID, msgCode: u64, payload: []const u8, exclude: *Peer) void {
    if (subnet >= types.GOSSIP_SUBNETS) return;

    server.mutex.lock();
    defer server.mutex.unlock();

    for (server.subnetPeers[subnet].items) |peer| {
        if (peer == exclude) continue;
        if (peer.handshakeComplete) {
            peer.sendRaw(msgCode, payload) catch {};
        }
    }
}

/// Broadcast to committee members only.
pub fn broadcastToCommittee(server: *Server, msgCode: u64, payload: []const u8) !void {
    server.mutex.lock();
    const peersCopy = server.allocator.dupe(*Peer, server.peers.items) catch {
        server.mutex.unlock();
        return;
    };
    server.mutex.unlock();
    defer server.allocator.free(peersCopy);

    for (peersCopy) |peer| {
        if (peer.isCommitteeMember and peer.handshakeComplete) {
            peer.sendRaw(msgCode, payload) catch {};
        }
    }
}
