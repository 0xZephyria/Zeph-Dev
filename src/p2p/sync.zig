const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const Peer = @import("peer.zig").Peer;
const turbine_mod = @import("turbine.zig");
const rlp = @import("encoding").rlp;
const Server = @import("server.zig").Server;
const log = core.logger;

/// Handle a GetBlocks request — shred and send requested blocks to the peer.
pub fn handleGetBlocks(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.GetBlocksMsg, payload);
    
    const start_block = try server.chain.getBlockById(msg.startHash) orelse {
        log.debug("GetBlocks: Start block not found for hash {s}", .{&std.fmt.bytesToHex(msg.startHash.bytes, .lower)});
        return;
    };
    defer server.chain.freeBlock(start_block);

    const start_number = start_block.header.number;
    var i: u64 = 1;
    while (i <= msg.limit) : (i += 1) {
        const num = if (msg.direction == 0) start_number + i else if (start_number >= i) start_number - i else break;
        if (server.chain.getBlockByNumber(num)) |blk| {
            defer server.chain.freeBlock(blk);
            
            const block_bytes = core.blockchain.encodeBlockBinary(server.allocator, blk.*) catch |err| {
                log.err("GetBlocks: Failed to encode block {d}: {}", .{num, err});
                continue;
            };
            defer server.allocator.free(block_bytes);

            const blsSig: [96]u8 = blk_sig: {
                if (block_bytes.len < 148 + 4) break :blk_sig [_]u8{0} ** 96;
                const extraLen = std.mem.readInt(u32, block_bytes[144..148], .big);
                if (extraLen < 192) break :blk_sig [_]u8{0} ** 96;
                var sig: [96]u8 = undefined;
                @memcpy(&sig, block_bytes[148 + 96 .. 148 + 192]);
                break :blk_sig sig;
            };

            const blk_id = blk.id();

            const shreds = server.turbine.shredBlock(block_bytes, num, blk_id, blsSig, 0.20) catch |err| {
                log.err("GetBlocks: Failed to shred block {d}: {}", .{num, err});
                continue;
            };
            defer server.turbine.freeShreds(shreds);

            for (shreds) |shred| {
                const shred_msg = types.ShredMsg{
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
                peer.send(types.MsgShred, shred_msg) catch |err| {
                    log.debug("GetBlocks: Failed to send shred msg: {}", .{err});
                };
            }
        } else {
            break;
        }
    }
}

/// Handle incoming BlocksMsg from sync — verify and add blocks to chain.
pub fn handleBlocks(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.BlocksMsg, payload);
    defer {
        for (msg.blocks) |b| {
            b.deinit(server.allocator);
        }
        server.allocator.free(msg.blocks);
    }

    log.info("Received {d} blocks from peer {x}", .{msg.blocks.len, peer.id});

    for (msg.blocks) |block| {
        const blockId = block.id();
        if (server.checkSeenBlockId(blockId)) {
            continue;
        }
        if (block.header.number <= server.chain.getHeadNumber()) {
            const existing = try server.chain.getBlockById(blockId);
            if (existing) |eb| {
                server.chain.freeBlock(eb);
                continue;
            }
        }

        var sync_owned_by_chain = false;
        const heapBlock = try server.allocator.create(core.types.Block);
        heapBlock.* = cloneBlock(server, server.allocator, block) catch |err| {
            server.allocator.destroy(heapBlock);
            return err;
        };
        defer if (!sync_owned_by_chain) {
            heapBlock.deinit(server.allocator);
            server.allocator.destroy(heapBlock);
        };

        const parent_block = try server.chain.getBlockById(block.header.parentId) orelse {
            log.warn("Sync: Parent block not found for block {d}, dropping batch", .{block.header.number});
            return;
        };
        defer server.chain.freeBlock(parent_block);

        server.engine.verify(heapBlock, &parent_block.header) catch |err| {
            log.err("Sync: Block verification failed for block {d}: {}", .{block.header.number, err});
            return;
        };

        const blockNumber = heapBlock.header.number;

        server.dagPool.removeCommitted(heapBlock.transactions);

        const is_head = server.chain.addBlock(heapBlock) catch |err| {
            log.debug("Sync: Failed to add block to chain: {}", .{err});
            return;
        };
        sync_owned_by_chain = is_head;

        server.recordSeenBlockId(blockId);

        server.dagPool.syncWithState();
        server.engine.adaptive.advanceSlot(blockNumber);
        server.engine.syncFinalityFromAdaptive();
        server.gulfStream.advanceSlot(server.engine.adaptive.currentSlot);

        server.engine.handleEpochRotationIfBoundary(blockNumber, blockId.bytes) catch |err| {
            log.err("Sync: Failed to rotate epoch on block {d}: {}", .{blockNumber, err});
        };
    }

    if (server.chain.getHeadNumber() < peer.headNumber) {
        const req = types.GetBlocksMsg{
            .startHash = server.chain.getHeadId(),
            .limit = 64,
            .direction = 0,
        };
        try peer.send(types.MsgGetBlocks, req);
    }
}

/// Deep-clone a block with its own allocations.
fn cloneBlock(server: *Server, allocator: std.mem.Allocator, src: core.types.Block) !core.types.Block {
    _ = server;
    var dest = src;
    dest.header.extraData = try allocator.dupe(u8, src.header.extraData);
    errdefer allocator.free(dest.header.extraData);

    const txs = try allocator.alloc(core.types.Transaction, src.transactions.len);
    errdefer allocator.free(txs);

    for (src.transactions, 0..) |tx, idx| {
        txs[idx] = tx;
        txs[idx].data = try allocator.dupe(u8, tx.data);
    }
    dest.transactions = txs;
    return dest;
}

/// Check all shred collectors for incomplete blocks, send repair requests.
pub fn checkAndRequestRepairs(server: *Server) !void {
    const now = std.time.milliTimestamp();

    var peers = std.ArrayList(turbine_mod.StakeWeightedPeer).empty;
    defer peers.deinit(server.allocator);

    if (!std.mem.eql(u8, &server.config.validatorAddress.bytes, &core.types.Address.zero().bytes)) {
        const my_stake = blk: {
            for (server.engine.activeValidators) |v| {
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

    server.mutex.lock();
    for (server.peers.items) |p| {
        if (p.handshakeComplete) {
            const stake = blk: {
                for (server.engine.activeValidators) |v| {
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
    server.mutex.unlock();

    if (peers.items.len == 0) return;

    std.mem.sort(turbine_mod.StakeWeightedPeer, peers.items, {}, struct {
        fn lessThan(_: void, a: turbine_mod.StakeWeightedPeer, b: turbine_mod.StakeWeightedPeer) bool {
            return a.stake > b.stake;
        }
    }.lessThan);

    var our_index: u32 = 0;
    for (peers.items, 0..) |p, idx| {
        if (std.mem.eql(u8, &p.address.bytes, &server.config.validatorAddress.bytes)) {
            our_index = @intCast(idx);
            break;
        }
    }

    for (&server.turbine.collectorStripes) |*stripe| {
        stripe.mutex.lock();

        var requests = std.ArrayList(struct {
            blockNumber: u64,
            missing: []u32,
            totalShreds: u32,
        }).empty;
        defer {
            for (requests.items) |r| server.allocator.free(r.missing);
            requests.deinit(server.allocator);
        }

        var it = stripe.collectors.iterator();
        while (it.next()) |entry| {
            const collector = entry.value_ptr.*;
            if (collector.complete) continue;

            if (now - collector.createdTime > 150 and now - collector.lastRepairTime > 300) {
                var missing_list = std.ArrayList(u32).empty;
                errdefer missing_list.deinit(server.allocator);

                for (collector.present, 0..) |p, idx| {
                    if (!p) {
                        try missing_list.append(server.allocator, @intCast(idx));
                        if (missing_list.items.len >= 16) break;
                    }
                }

                if (missing_list.items.len > 0) {
                    collector.lastRepairTime = now;
                    try requests.append(server.allocator, .{
                        .blockNumber = collector.blockNumber,
                        .missing = try missing_list.toOwnedSlice(server.allocator),
                        .totalShreds = collector.totalShreds,
                    });
                } else {
                    missing_list.deinit(server.allocator);
                }
            }
        }
        stripe.mutex.unlock();

        for (requests.items) |req| {
            server.mutex.lock();
            server.turbine.buildPropTree(peers.items, req.totalShreds) catch {
                server.mutex.unlock();
                continue;
            };
            server.mutex.unlock();

            const parent_idx_opt = server.turbine.tree.getParentIndex(our_index);
            var target_peer: ?*Peer = null;

            if (parent_idx_opt) |parent_idx| {
                if (parent_idx < peers.items.len) {
                    const parent_addr = peers.items[parent_idx].address;
                    target_peer = server.findPeerByValidatorAddress(parent_addr);
                }
            }

            if (target_peer == null) {
                target_peer = server.findPeerByValidatorAddress(peers.items[0].address);
            }

            if (target_peer == null) {
                server.mutex.lock();
                if (server.peers.items.len > 0) {
                    const rand_idx = std.crypto.random.intRangeLessThan(usize, 0, server.peers.items.len);
                    const p = server.peers.items[rand_idx];
                    if (p.handshakeComplete) {
                        target_peer = p;
                    }
                }
                server.mutex.unlock();
            }

            if (target_peer) |peer| {
                const repair_msg = types.ShredRepairRequestMsg{
                    .blockNumber = req.blockNumber,
                    .shredIndices = req.missing,
                    .requesterAddress = server.config.validatorAddress,
                };
                peer.send(types.MsgShredRepairRequest, repair_msg) catch {};
            }
        }
    }
}

/// Forward pending Gulf Stream TX batches to the predicted leader for next slot.
pub fn forwardGulfStream(server: *Server) !void {
    var drain_result = try server.gulfStream.drainBatch() orelse return;
    defer drain_result.deinit();

    const target = drain_result.target orelse return;

    if (std.mem.eql(u8, &target.validatorAddress.bytes, &server.config.validatorAddress.bytes)) {
        return;
    }

    server.mutex.lock();
    defer server.mutex.unlock();
    var target_peer: ?*Peer = null;
    for (server.peers.items) |peer| {
        if (peer.validatorAddress.eql(target.validatorAddress) and peer.connected and peer.handshakeComplete) {
            target_peer = peer;
            break;
        }
    }

    if (target_peer) |peer| {
        // ── Firewall 4: Only forward to validator peers ─────────────
        if (peer.peerRole != .Validator) return;

        const msg = types.TxBatchMsg{
            .txHashes = &.{},
            .txData = drain_result.txData,
            .compressed = false,
            .batchId = 0,
            .senderSubnet = 0,
        };
        peer.send(types.MsgTxBatch, msg) catch |err| {
            log.warn("Failed to forward batch to leader peer: {}\n", .{err});
        };
        log.info("Gulf Stream: Forwarded {d} TX(s) to predicted proposer {s} (slot {d})\n", .{
            drain_result.txData.len,
            &std.fmt.bytesToHex(target.validatorAddress.bytes, .lower),
            target.slot,
        });
    } else {
        // Fallback: relay via best connected validator (Firewall 4)
        var best_peer: ?*Peer = null;
        for (server.peers.items) |peer| {
            if (peer.connected and peer.handshakeComplete and peer.peerRole == .Validator) {
                if (best_peer == null or peer.score > best_peer.?.score) {
                    best_peer = peer;
                }
            }
        }

        if (best_peer) |peer| {
            const msg = types.TxBatchMsg{
                .txHashes = &.{},
                .txData = drain_result.txData,
                .compressed = false,
                .batchId = 0,
                .senderSubnet = 0,
            };
            peer.send(types.MsgTxBatch, msg) catch {};
            log.debug("Gulf Stream: Proposer {s} not connected. Relayed {d} TX(s) via fallback validator {s}\n", .{
                &std.fmt.bytesToHex(target.validatorAddress.bytes, .lower),
                drain_result.txData.len,
                peer.ipSlice(),
            });
        }
    }
}
