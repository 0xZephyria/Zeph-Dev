const std = @import("std");
const core = @import("core");
const consensus = @import("consensus");
const types = @import("types.zig");
const Peer = @import("peer.zig").Peer;
const turbine_mod = @import("turbine.zig");
const rlp = @import("encoding").rlp;
const Server = @import("server.zig").Server;
const log = core.logger;

/// Dispatch an incoming message to the appropriate handler based on message code.
pub fn handleMessage(server: *Server, peer: *Peer, code: u64, payload: []const u8) !void {
    switch (code) {
        types.MsgStatus => try handleStatus(server, peer, payload),
        types.MsgNewBlock => try handleNewBlock(server, peer, payload),
        types.MsgTxBatch => try handleTxBatch(server, peer, payload),
        types.MsgVote => try handleVote(server, peer, payload),
        types.MsgAuth => try handleAuth(server, peer, payload),
        types.MsgShred => try handleShred(server, peer, payload),
        types.MsgShredRepairRequest => try handleShredRepairRequest(server, peer, payload),
        types.MsgAttestation => try handleAttestation(server, peer, payload),
        types.MsgAggregateAttestation => try handleAggregateAttestation(server, peer, payload),
        types.MsgQuorumCertificate => try handleQC(server, peer, payload),
        types.MsgViewChange => try handleViewChange(server, peer, payload),
        types.MsgSlashEvidence => try handleSlashEvidence(server, peer, payload),
        types.MsgCommitteeHandshake => try handleCommitteeHandshake(server, peer, payload),
        types.MsgSubnetSubscribe => try handleSubnetSubscribe(server, peer, payload),
        types.MsgGetNodeData => try handleGetNodeData(server, peer, payload),
        types.MsgGetPeers => try handleGetPeers(server, peer, payload),
        types.MsgPeers => try handlePeers(server, peer, payload),
        types.MsgPing => try handlePing(server, peer, payload),
        types.MsgPong => try handlePong(server, peer, payload),
        types.MsgGetBlocks => try handleGetBlocks(server, peer, payload),
        types.MsgBlocks => try handleBlocks(server, peer, payload),
        types.MsgThreadAttestation => try handleThreadAttestation(server, peer, payload),
        types.MsgThreadCertificate => try handleThreadCertificate(server, peer, payload),
        types.MsgAdaptiveQC => try handleAdaptiveQC(server, peer, payload),
        types.MsgSnowballQuery => try handleSnowballQuery(server, peer, payload),
        types.MsgSnowballResponse => try handleSnowballResponse(server, peer, payload),
        types.MsgEpochTransition => try handleEpochTransition(server, peer, payload),
        types.MsgThreadTimeoutProof => try handleThreadTimeoutProof(server, peer, payload),
        else => {
            peer.updateScore(-5);
            server.countInvalidPackets();
        },
    }
}

// ── Status ─────────────────────────────────────────────────────────────────

fn handleStatus(server: *Server, peer: *Peer, payload: []const u8) !void {
    if (payload.len > 512) return error.MessageTooLarge;

    const msg = try rlp.decode(server.allocator, types.StatusMsg, payload);

    if (msg.protocolVersion != types.PROTOCOL_VERSION) {
        peer.updateScore(-20);
        return;
    }

    if (!std.mem.eql(u8, &msg.genesisHash.bytes, &server.chain.genesisId.bytes)) {
        peer.updateScore(-50);
        log.warn("P2P: Peer rejected — genesis id mismatch", .{});
        return;
    }

    peer.mutex.lock();
    peer.headHash = msg.headHash;
    peer.headNumber = msg.headNumber;
    peer.lastMessageTime = std.time.milliTimestamp();
    peer.protocolVersion = msg.protocolVersion;
    peer.peerRole = msg.peerRole;
    peer.stakeAmount = msg.stakeAmount;
    peer.subscribedSubnets = msg.subscribedSubnets;
    const was_handshaked = peer.handshakeComplete;
    peer.handshakeComplete = true;
    peer.updateScoreLocked(5);
    peer.mutex.unlock();

    server.registerPeerSubnets(peer);

    if (!was_handshaked) {
        const reciprocal_status = types.StatusMsg{
            .protocolVersion = types.PROTOCOL_VERSION,
            .chainId = server.chain.chainId,
            .genesisHash = server.chain.genesisId,
            .headHash = server.chain.getHeadId(),
            .headNumber = server.chain.getHeadNumber(),
            .challenge = peer.challenge,
            .peerRole = .Validator,
            .subscribedSubnets = server.localSubnets,
            .stakeAmount = blk_stake: {
                var amt: u64 = 0;
                for (server.engine.validator_set.active) |v| {
                    if (std.mem.eql(u8, &v.address.bytes, &server.config.validatorAddress.bytes)) {
                        amt = @intCast(@min(v.stake, std.math.maxInt(u64)));
                        break;
                    }
                }
                break :blk_stake amt;
            },
        };
        peer.send(types.MsgStatus, reciprocal_status) catch |err| {
            log.err("P2P: Failed to send reciprocal Status to peer: {}", .{err});
        };
    }

    if (server.config.identityKey) |priv_key| {
        var expectedChallenge: [32]u8 = undefined;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update("ZEPH_AUTH_V1");
        hasher.update(&msg.challenge);
        var chainIdBuf: [8]u8 = undefined;
        std.mem.writeInt(u64, &chainIdBuf, server.chain.chainId, .big);
        hasher.update(&chainIdBuf);
        hasher.final(&expectedChallenge);

        if (std.crypto.sign.Ed25519.KeyPair.generateDeterministic(priv_key)) |key_pair| {
            if (key_pair.sign(&expectedChallenge, null)) |sig| {
                const auth_msg = types.AuthMsg{
                    .publicKey = key_pair.public_key.toBytes(),
                    .signature = sig.toBytes(),
                    .validatorAddress = server.config.validatorAddress,
                    .stakeProof = [_]u8{0} ** 32,
                };
                peer.send(types.MsgAuth, auth_msg) catch |err| {
                    log.err("P2P: Failed to send AuthMsg to peer: {}", .{err});
                };
            } else |err| {
                log.err("P2P: Failed to sign challenge: {}", .{err});
            }
        } else |err| {
            log.err("P2P: Failed to generate Ed25519 keypair: {}", .{err});
        }
    }

    if (server.chain.getHeadNumber() < msg.headNumber) {
        log.info("P2P: Behind peer {x} (our height {d} < peer height {d}), triggering sync", .{peer.id, server.chain.getHeadNumber(), msg.headNumber});
        const req = types.GetBlocksMsg{
            .startHash = server.chain.getHeadId(),
            .limit = 64,
            .direction = 0,
        };
        peer.send(types.MsgGetBlocks, req) catch |err| {
            log.err("P2P: Failed to send GetBlocks request: {}", .{err});
        };
    }
}

// ── Shared Block Processing Pipeline ────────────────────────────────────────

/// Shared block processing pipeline used by both gossip (handleNewBlock)
/// and Turbine (handleShred) paths.
///
///   engine.verify() → replayBlockTransactions() + stateRoot compare →
///   dagPool.removeCommitted() → chain.addBlock() → bookkeeping → BLS vote
///
/// Does NOT free heapBlock on failure — caller manages ownership via defers.
/// Returns true if block was added as chain head (chain now owns heapBlock).
fn processReceivedBlock(
    server: *Server,
    peer: *Peer,
    heapBlock: *core.types.Block,
) !bool {
    const parent_block = try server.chain.getBlockById(heapBlock.header.parentId) orelse {
        const req = types.GetBlocksMsg{
            .startHash = server.chain.getHeadId(),
            .limit = 64,
            .direction = 0,
        };
        peer.send(types.MsgGetBlocks, req) catch |send_err| {
            log.warn("processReceivedBlock: send GetBlocks failed: {}\n", .{send_err});
        };
        return error.ParentNotFound;
    };
    defer server.chain.freeBlock(parent_block);

    try server.engine.verify(heapBlock, &parent_block.header);

    // ── Firewall 3: Verify finality in ancestor chain ─────────────────
    // A block that passes the height check (number > lastFinalizedBlock)
    // could still be on a fork that orphaned finalized blocks.
    // Walk the ancestor chain to confirm the finalized block is present.
    if (server.engine.lastFinalizedBlock > 0) {
        if (heapBlock.header.number <= server.engine.lastFinalizedBlock) {
            return error.FinalizedBlockConflict;
        }
        const finalized_blk = server.chain.getBlockByNumber(server.engine.lastFinalizedBlock) orelse {
            return error.FinalizedBlockConflict;
        };
        defer server.chain.freeBlock(finalized_blk);
        const finalized_id = finalized_blk.id();

        var current_id = heapBlock.header.parentId;
        var found = false;
        while (!found) {
            if (std.mem.eql(u8, &current_id.bytes, &core.types.Hash.zero().bytes)) break;
            const ancestor = try server.chain.getBlockById(current_id) orelse break;
            defer server.chain.freeBlock(ancestor);
            if (ancestor.header.number == server.engine.lastFinalizedBlock) {
                const ancestor_id = ancestor.id();
                if (std.mem.eql(u8, &ancestor_id.bytes, &finalized_id.bytes)) {
                    found = true;
                }
                break;
            }
            if (ancestor.header.number < server.engine.lastFinalizedBlock) break;
            current_id = ancestor.header.parentId;
        }
        if (!found) return error.FinalizedBlockConflict;
    }

    if (server.dagExecutor) |executor| {
        const computed_root = try executor.replayBlockTransactions(heapBlock.transactions);
        if (!std.mem.eql(u8, &computed_root.bytes, &heapBlock.header.stateRoot.bytes)) {
            log.err("State root mismatch! computed={x} expected={x} — possible fraud by producer {x}",
                .{ computed_root.bytes, heapBlock.header.stateRoot.bytes, heapBlock.header.producer.bytes });
            return error.StateRootMismatch;
        }
    } else {
        log.warn("No DAGExecutor configured — skipping state root validation", .{});
    }

    server.dagPool.removeCommitted(heapBlock.transactions);

    const is_head = try server.chain.addBlock(heapBlock);

    const blockNumber = heapBlock.header.number;
    const blockId = heapBlock.id();

    server.dagPool.syncWithState();
    server.engine.adaptive.advanceSlot(blockNumber);
    server.chain.setLastFinalized(server.engine.lastFinalizedBlock);
    server.gulfStream.advanceSlot(server.engine.adaptive.currentSlot);
    server.engine.handleEpochRotationIfBoundary(blockNumber, blockId.bytes) catch |err| {
        log.err("Block {d}: epoch rotation failed: {}", .{blockNumber, err});
    };

    // Find our validator index (needed for both BLS voting and Snowball)
    var our_index: u32 = 0;
    if (server.engine.blsPrivKey != null) {
        for (server.engine.validator_set.active, 0..) |v, i| {
            if (std.mem.eql(u8, &v.address.bytes, &server.config.validatorAddress.bytes)) {
                our_index = @intCast(i);
                break;
            }
        }
    }

    if (server.engine.blsPrivKey) |_| {
        const view = server.engine.adaptive.currentSlot;
        const vote_sig = server.engine.createVote(blockId, view) catch |err| {
            log.warn("Block {d}: failed to create BLS vote: {}", .{blockNumber, err});
            return is_head;
        };

        const vote_msg = types.VoteMsg{
            .blockId = blockId,
            .blockNumber = blockNumber,
            .view = view,
            .signature = vote_sig,
            .validatorIndex = our_index,
        };
        const vote_payload = rlp.encode(server.allocator, vote_msg) catch |err| {
            log.warn("Block {d}: failed to encode vote: {}", .{blockNumber, err});
            return is_head;
        };
        defer server.allocator.free(vote_payload);
        broadcastToCommittee(server, types.MsgVote, vote_payload) catch |err| {
            log.warn("Block {d}: failed to broadcast vote: {}\n", .{blockNumber, err});
        };
    }

    // ── Tier 3: Activate Snowball for sub-sampled finality ──────
    if (server.snowballEngine) |sb| {
        if (server.engine.getCurrentTier() == .FullLoom) {
            sb.startInstance(blockNumber, blockId, .Accept) catch |err| {
                log.warn("Snowball: startInstance({d}) failed: {}", .{blockNumber, err});
            };

            const epoch_seed = server.engine.epochSeed;
            var selected_peers: [consensus.types.SNOWBALL_K]u32 = undefined;
            const peers_ok = blk: {
                const result = sb.selectPeers(
                    epoch_seed,
                    blockNumber,
                    0,
                    @intCast(server.engine.validator_set.active.len),
                    our_index,
                ) catch |err| {
                    log.warn("Snowball: selectPeers failed: {}", .{err});
                    break :blk false;
                };
                selected_peers = result;
                break :blk true;
            };

            if (peers_ok) {
                sb.setQueriedPeers(blockNumber, &selected_peers);
                for (selected_peers) |peer_idx| {
                    if (peer_idx >= server.engine.validator_set.active.len) continue;
                    const peer_addr = server.engine.validator_set.active[peer_idx].address;
                    const target = server.findPeerByValidatorAddress(peer_addr) orelse continue;
                    const query = types.SnowballQueryMsg{
                        .slot = blockNumber,
                        .blockHash = blockId,
                        .round = 0,
                        .querierIndex = our_index,
                    };
                    target.send(types.MsgSnowballQuery, query) catch continue;
                }
            }
        }
    }

    return is_head;
}

// ── New Block ──────────────────────────────────────────────────────────────

fn handleNewBlock(server: *Server, peer: *Peer, payload: []const u8) !void {
    if (payload.len > 8 * 1024 * 1024) {
        server.countBlocksDroppedOversized();
        peer.updateScore(-10);
        return error.MessageTooLarge;
    }

    const msg = try rlp.decode(server.allocator, types.NewBlockMsg, payload);
    var owned_by_chain = false;
    defer if (!owned_by_chain) msg.block.deinit(server.allocator);

    const headNumber = server.chain.getHeadNumber();
    if (msg.block.header.number <= headNumber) {
        return;
    }
    if (msg.block.header.number > headNumber + 10) {
        server.countBlocksDroppedSemantic();
        return;
    }

    const incomingId = msg.block.id();
    if (server.checkSeenBlockId(incomingId)) {
        server.countBlocksDroppedDuplicate();
        return;
    }
    server.recordSeenBlockId(incomingId);

    const producerKnown = blk: {
        for (server.engine.validator_set.active) |v| {
            if (std.mem.eql(u8, &v.address.bytes, &msg.block.header.producer.bytes)) break :blk true;
        }
        break :blk false;
    };
    if (!producerKnown) {
        server.countBlocksDroppedSemantic();
        peer.updateScore(-10);
        return;
    }

    const heapBlock = try server.allocator.create(core.types.Block);
    heapBlock.* = msg.block;
    defer if (!owned_by_chain) {
        server.allocator.destroy(heapBlock);
    };

    const accepted = processReceivedBlock(server, peer, heapBlock) catch |err| {
        log.debug("handleNewBlock: block rejected: {}", .{err});
        peer.updateScore(-20);
        return;
    };
    owned_by_chain = accepted;

    peer.updateScore(10);

    if (msg.hopCount < 2) {
        var relayMsg = msg;
        relayMsg.hopCount += 1;
        try broadcastSubset(server, types.MsgNewBlock, relayMsg, types.TURBINE_FANOUT, peer);
    }
}

// ── TX Batch ───────────────────────────────────────────────────────────────

fn handleTxBatch(server: *Server, peer: *Peer, payload: []const u8) !void {
    if (payload.len > 4 * 1024 * 1024) {
        peer.updateScore(-10);
        return error.MessageTooLarge;
    }

    const msg = try rlp.decode(server.allocator, types.TxBatchMsg, payload);
    defer {
        server.allocator.free(msg.txHashes);
        for (msg.txData) |txRaw| {
            server.allocator.free(txRaw);
        }
        server.allocator.free(msg.txData);
    }

    var added: u32 = 0;
    for (msg.txData) |txRaw| {
        if (txRaw.len > core.types.Transaction.MAX_WIRE_SIZE) continue;

        const tx = try rlp.decode(server.allocator, core.types.Transaction, txRaw);
        var tx_added = false;
        defer if (!tx_added) tx.deinit(server.allocator);

        const txId = tx.id();
        if (server.checkSeenTxId(txId)) {
            server.countTxsDroppedDuplicate();
            continue;
        }
        server.recordSeenTxId(txId);

        server.dagPool.add(&tx) catch {
            continue;
        };
        tx_added = true;
        added += 1;
    }

    if (added > 0) {
        peer.updateScore(@intCast(@min(added, 10)));
    }
}

// ── Auth ───────────────────────────────────────────────────────────────────

fn handleAuth(server: *Server, peer: *Peer, payload: []const u8) !void {
    if (payload.len > 512) return error.MessageTooLarge;

    const msg = try rlp.decode(server.allocator, types.AuthMsg, payload);

    const pubKeyBytes: [32]u8 = msg.publicKey;

    var expectedChallenge: [32]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("ZEPH_AUTH_V1");
    hasher.update(&peer.challenge);
    var chainIdBuf: [8]u8 = undefined;
    std.mem.writeInt(u64, &chainIdBuf, server.chain.chainId, .big);
    hasher.update(&chainIdBuf);
    hasher.final(&expectedChallenge);

    const valid = try core.account.verify_signature(&expectedChallenge, msg.signature, pubKeyBytes);
    if (!valid) {
        peer.updateScore(-50);
        return error.AuthFailed;
    }

    const addr = core.types.Address.fromPubKey(&pubKeyBytes);
    peer.mutex.lock();
    defer peer.mutex.unlock();
    peer.validatorAddress = addr;
    peer.authenticated = true;
    peer.updateScoreLocked(20);

    @memset(&peer.id, 0);
    @memcpy(peer.id[0..32], &msg.publicKey);

    const node_addr = try std.net.Address.parseIp4(peer.ipSlice(), peer.port);
    var node_hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(peer.id[0..], &node_hash, .{});

    const d_node = discovery_mod.Node{
        .id = peer.id,
        .hash = node_hash,
        .address = node_addr,
        .lastSeen = std.time.milliTimestamp(),
        .lastPing = std.time.milliTimestamp(),
        .pingFailures = 0,
        .peerRole = peer.peerRole,
        .validatorAddress = peer.validatorAddress,
        .subscribedSubnets = peer.subscribedSubnets,
        .stakeAmount = peer.stakeAmount,
    };
    server.discovery.addNode(d_node) catch {};
}

// ── Shred ──────────────────────────────────────────────────────────────────

fn handleShred(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.ShredMsg, payload);
    defer server.allocator.free(msg.payload);

    var shred = turbine_mod.Shred{
        .blockId = msg.blockId,
        .blockNumber = msg.blockNumber,
        .shredIndex = msg.shredIndex,
        .totalDataShreds = msg.totalDataShreds,
        .totalParityShreds = msg.totalParityShreds,
        .shredType = msg.shredType,
        .payload = msg.payload,
        .producerSignature = msg.producerSignature,
        .threadId = msg.threadId,
        .crc32 = 0,
    };
    shred.crc32 = shred.computeCrc();

    std.debug.print("[SHRED-RX] Block {d}: shred {d}/{d} (type={d}) from peer {s}:{d}\n", .{
        msg.blockNumber, msg.shredIndex, msg.totalDataShreds,
        msg.shredType, peer.ipSlice(), peer.port,
    });

    const maybe_block = server.turbine.receiveShred(&shred) catch |err| {
        if (err == error.DuplicateShred) {
            return;
        }
        std.debug.print("[SHRED-RX] Block {d}: receiveShred error: {}\n", .{msg.blockNumber, err});
        return err;
    };

    if (maybe_block) |block_data| {
        std.debug.print("[SHRED-RX] Block {d}: FULLY RECONSTRUCTED ({d} bytes)\n", .{msg.blockNumber, block_data.len});
        const block = core.blockchain.decodeBlockBinary(server.allocator, block_data) catch |err| {
            log.err("Turbine: Failed to decode reconstructed block: {}\n", .{err});
            server.allocator.free(block_data);
            return;
        };
        server.allocator.free(block_data);

        // ── Firewall 2: Verify reconstructed block's id() matches shred claim ──
        const reconstructed_id = block.id();
        if (!std.mem.eql(u8, &reconstructed_id.bytes, &msg.blockId.bytes)) {
            log.err("Turbine: Reconstructed block id mismatch — possible proposer misbehaviour", .{});
            server.countBlocksDroppedSemantic();
            block.deinit(server.allocator);
            return;
        }

        if (block.header.number <= server.chain.getHeadNumber()) {
            block.deinit(server.allocator);
            return;
        }

        const heapBlock = try server.allocator.create(core.types.Block);
        heapBlock.* = block;

        const is_head = processReceivedBlock(server, peer, heapBlock) catch |err| {
            log.debug("Turbine: block {d} rejected: {}", .{block.header.number, err});
            block.deinit(server.allocator);
            server.allocator.destroy(heapBlock);
            return;
        };
        if (!is_head) {
            block.deinit(server.allocator);
            server.allocator.destroy(heapBlock);
            return;
        }

        // Success — chain now owns heapBlock (via setHeadLocked)

        log.info("Turbine: Block {d} fully processed from shreds ({d} TXs)", .{ heapBlock.header.number, heapBlock.transactions.len });
        peer.updateScore(15);
    }

    server.countShredsRelayed();

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

    std.mem.sort(turbine_mod.StakeWeightedPeer, peers.items, {}, struct {
        fn lessThan(_: void, a: turbine_mod.StakeWeightedPeer, b: turbine_mod.StakeWeightedPeer) bool {
            return a.stake > b.stake;
        }
    }.lessThan);

    const total_shreds = msg.totalDataShreds + msg.totalParityShreds;
    server.mutex.lock();
    server.turbine.buildPropTree(peers.items, total_shreds) catch {
        server.mutex.unlock();
        return;
    };
    server.mutex.unlock();

    var our_index: u32 = 0;
    for (peers.items, 0..) |p, idx| {
        if (std.mem.eql(u8, &p.address.bytes, &server.config.validatorAddress.bytes)) {
            our_index = @intCast(idx);
            break;
        }
    }

    const children = server.turbine.tree.getChildren(our_index);
    if (children.len > 0) {
        server.mutex.lock();
        defer server.mutex.unlock();
        for (children) |child| {
            if (child.peerIndex < peers.items.len) {
                const child_addr = peers.items[child.peerIndex].address;
                if (server.findPeerByValidatorAddressLocked(child_addr)) |child_peer| {
                    child_peer.send(types.MsgShred, msg) catch |err| {
                        log.err("TURBINE: Relay shred to child failed: {}", .{err});
                    };
                }
            }
        }
    }
}

// ── Shred Repair Request ───────────────────────────────────────────────────

fn handleShredRepairRequest(server: *Server, peer: *Peer, payload: []const u8) !void {
    const now = std.time.milliTimestamp();
    peer.mutex.lock();
    if (now - peer.repairRequestWindowStart > 60_000) {
        peer.repairRequestCount = 0;
        peer.repairRequestWindowStart = now;
    }
    peer.repairRequestCount += 1;
    if (peer.repairRequestCount > server.config.repairBudget) {
        peer.mutex.unlock();
        peer.updateScore(-5);
        return;
    }
    peer.mutex.unlock();

    const msg = try rlp.decode(server.allocator, types.ShredRepairRequestMsg, payload);
    defer server.allocator.free(msg.shredIndices);

    for (msg.shredIndices) |idx| {
        if (server.turbine.getCachedShred(msg.blockNumber, idx)) |shred| {
            const resp = types.ShredMsg{
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
            peer.send(types.MsgShred, resp) catch |send_err| {
                log.warn("handleShredRepair: send MsgShred to peer {s}:{} failed: {}\n", .{ peer.ipSlice(), peer.port, send_err });
            };
        }
    }
}

// ── Attestation ────────────────────────────────────────────────────────────

fn handleAttestation(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.AttestationMsg, payload);

    const head = server.chain.getHeadNumber();
    if (msg.blockNumber + 10 < head or msg.blockNumber > head + 2) {
        peer.updateScore(-5);
        return;
    }

    peer.updateScore(3);
    server.countAttestationsRelayed();

    gossipToSubnet(server, msg.subnetId, types.MsgAttestation, payload, peer);
}

fn handleAggregateAttestation(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.AggregateAttestationMsg, payload);

    const participation = types.countParticipation(msg.participationBitmap);
    if (participation < types.COMMITTEE_SIZE / 4) {
        peer.updateScore(-10);
        return;
    }

    peer.updateScore(5);

    try broadcastRaw(server, types.MsgAggregateAttestation, payload);
}

fn handleQC(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.QuorumCertificate, payload);

    if (!types.hasQuorum(msg.participationBitmap, types.COMMITTEE_SIZE)) {
        peer.updateScore(-20);
        return;
    }

    peer.updateScore(10);

    try broadcastRaw(server, types.MsgQuorumCertificate, payload);
}

fn handleViewChange(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.ViewChangeMsg, payload);
    peer.updateScore(1);

    const sig_valid = try server.engine.verifyVoteSignature(
        msg.validatorIndex,
        core.types.Hash.zero(),
        msg.view,
        msg.signature,
    );

    if (!sig_valid) {
        peer.updateScore(-20);
        return;
    }

    const quorum_reached = server.engine.voteViewChange(msg.validatorIndex);
    if (quorum_reached) {
        server.engine.completeViewChange();
        server.engine.resetViewChangeBackoff();
        log.info("View change complete — new proposer elected for view {}\n", .{msg.view});
    }

    try broadcastToCommittee(server, types.MsgViewChange, payload);
}

fn handleVote(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.VoteMsg, payload);

    if (msg.view != server.engine.adaptive.currentSlot) return;

    const sig_valid = try server.engine.verifyVoteSignature(
        msg.validatorIndex,
        msg.blockId,
        msg.view,
        msg.signature,
    );

    if (!sig_valid) {
        peer.updateScore(-30);
        return;
    }

    peer.updateScore(5);

    const cons_vote: consensus.types.VoteMsg = .{
        .blockId = msg.blockId,
        .blockNumber = msg.blockNumber,
        .view = msg.view,
        .signature = msg.signature,
        .validatorIndex = msg.validatorIndex,
    };
    const quorum_reached = try server.voteCollector.addVote(cons_vote, server.engine.validator_set.active);

    if (quorum_reached) {
        if (try server.voteCollector.aggregateBlock(msg.blockId, msg.view, server.engine.validator_set.active)) |agg| {
            defer server.allocator.free(agg.voterBitmap);
            if (try server.engine.adaptive.buildQC(msg.blockId, agg)) |qc| {
                server.engine.updateFinality(qc.slot);
                server.chain.setLastFinalized(qc.slot);
                server.engine.resetViewChangeBackoff();

                log.info("QC formed for slot {} — block finalized (stake: {})\n", .{
                    qc.slot,
                    qc.totalAttestingStake,
                });

                const qc_payload = try rlp.encode(server.allocator, qc);
                defer server.allocator.free(qc_payload);
                try broadcastRaw(server, types.MsgAdaptiveQC, qc_payload);
            }
        }
    } else {
        try broadcastToCommittee(server, types.MsgVote, payload);
    }
}

fn handleSlashEvidence(server: *Server, peer: *Peer, payload: []const u8) !void {
    _ = try rlp.decode(server.allocator, types.SlashEvidenceMsg, payload);
    peer.updateScore(5);

    try broadcastRaw(server, types.MsgSlashEvidence, payload);
}

// ── Peer Exchange ─────────────────────────────────────────────────────────

fn handleGetPeers(server: *Server, peer: *Peer, payload: []const u8) !void {
    log.debug("PEX: Received MsgGetPeers from peer {s}:{}\n", .{ peer.ipSlice(), peer.port });
    const msg = try rlp.decode(server.allocator, types.GetPeersMsg, payload);
    _ = msg;

    var node_list = std.ArrayListUnmanaged(types.NodeInfo){};
    defer node_list.deinit(server.allocator);

    server.mutex.lock();
    defer server.mutex.unlock();

    for (server.peers.items) |p| {
        if (!p.handshakeComplete or p == peer) continue;
        var node_info = types.NodeInfo{
            .id = p.id,
            .ip = [_]u8{0} ** 16,
            .ipLen = @intCast(p.ipLen),
            .port = p.port,
            .peerRole = p.peerRole,
            .subnets = p.subscribedSubnets,
        };
        @memcpy(node_info.ip[0..p.ipLen], p.ipSlice());
        try node_list.append(server.allocator, node_info);
    }

    log.debug("PEX: Sending {} peers to {s}:{}\n", .{ node_list.items.len, peer.ipSlice(), peer.port });
    const resp = types.PeersMsg{ .nodes = node_list.items };
    try peer.send(types.MsgPeers, resp);
}

fn handlePeers(server: *Server, peer: *Peer, payload: []const u8) !void {
    log.debug("PEX: Received MsgPeers from peer {s}:{}\n", .{ peer.ipSlice(), peer.port });
    const msg = rlp.decode(server.allocator, types.PeersMsg, payload) catch |err| {
        log.err("PEX: Failed to decode MsgPeers: {}\n", .{err});
        return err;
    };
    defer server.allocator.free(msg.nodes);
    log.debug("PEX: Received {} node entries from {s}:{}\n", .{ msg.nodes.len, peer.ipSlice(), peer.port });

    for (msg.nodes) |node| {
        const ip_str = node.ip[0..node.ipLen];
        log.debug("PEX: Connecting to discovered peer: {s}:{}\n", .{ ip_str, node.port });
        const addr = std.net.Address.parseIp4(ip_str, node.port) catch |err| {
            log.err("PEX: Failed to parse IP address '{s}': {}\n", .{ ip_str, err });
            continue;
        };
        server.connectPeer(addr) catch |err| {
            log.err("PEX: Failed to connect to discovered peer {s}:{}: {}\n", .{ ip_str, node.port, err });
        };
    }
}

// ── Committee ──────────────────────────────────────────────────────────────

fn handleCommitteeHandshake(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.CommitteeHandshakeMsg, payload);

    const thread_subnet: types.SubnetID = @intCast(msg.committeeIndex % types.GOSSIP_SUBNETS);
    peer.setCommitteeAssignment(.{
        .epoch = msg.epoch,
        .slotStart = 0,
        .slotEnd = 0,
        .committeeIndex = msg.committeeIndex,
        .role = msg.role,
        .threadId = thread_subnet,
    });

    peer.blsPubKey = msg.blsPubkey;
    peer.subscribeSubnet(thread_subnet);
    peer.updateScore(5);

    server.mutex.lock();
    defer server.mutex.unlock();
    var already = false;
    for (server.subnetPeers[thread_subnet].items) |sp| {
        if (sp == peer) { already = true; break; }
    }
    if (!already) {
        server.subnetPeers[thread_subnet].append(server.allocator, peer) catch {};
    }
}

fn handleSubnetSubscribe(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.SubnetSubscribeMsg, payload);

    if (msg.subnetId >= types.GOSSIP_SUBNETS) {
        peer.updateScore(-10);
        return;
    }

    peer.subscribeSubnet(msg.subnetId);

    server.mutex.lock();
    defer server.mutex.unlock();

    var found = false;
    for (server.subnetPeers[msg.subnetId].items) |sp| {
        if (sp == peer) {
            found = true;
            break;
        }
    }
    if (!found) {
        server.subnetPeers[msg.subnetId].append(server.allocator, peer) catch {};
    }
}

// ── Node Data ──────────────────────────────────────────────────────────────

fn handleGetNodeData(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.GetNodeDataMsg, payload);
    defer server.allocator.free(msg.hashes);

    var data_list = std.ArrayListUnmanaged([]const u8){};
    defer data_list.deinit(server.allocator);

    for (msg.hashes) |h| {
        if (server.chain.db.read(&h.bytes)) |val| {
            try data_list.append(server.allocator, val);
        } else {
            try data_list.append(server.allocator, &[_]u8{});
        }
    }

    const reply = types.NodeDataMsg{
        .requestId = msg.requestId,
        .data = data_list.items,
    };
    try peer.send(types.MsgNodeData, reply);
}

// ── Ping / Pong ────────────────────────────────────────────────────────────

fn handlePing(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.PingMsg, payload);

    const pong = types.PongMsg{
        .sequence = msg.sequence,
        .timestamp = std.time.milliTimestamp(),
    };
    try peer.send(types.MsgPong, pong);
}

fn handlePong(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.PongMsg, payload);
    const send_time = @as(i64, @bitCast(msg.sequence));
    const now = std.time.milliTimestamp();
    const rtt = now - send_time;
    if (rtt > 0 and rtt < 10000) {
        peer.rtt_ms = @intCast(rtt);
    }
    peer.updateScore(1);
}

// ── Loom Genesis Adaptive Handlers ────────────────────────────────────────

fn handleThreadAttestation(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.ThreadAttestationMsg, payload);

    const head = if (server.chain.currentBlock) |b| b.header.number else 0;
    if (msg.slot + 10 < head or msg.slot > head + 2) {
        peer.updateScore(-3);
        return;
    }

    if (server.threadAttestPool) |pool| {
        const attest = consensus.ThreadAttestation{
            .slot = msg.slot,
            .threadId = msg.threadId,
            .thread_root = msg.threadRoot,
            .validatorIndex = msg.validatorIndex,
            .roleProof = msg.roleProof,
            .blsSignature = msg.blsSignature,
            .attestingStake = msg.attestingStake,
        };
        _ = pool.addAttestation(
            attest,
            server.engine.validator_set.active,
            server.engine.getCurrentTier(),
            &server.engine.adaptive.epochManager.committeeManager,
            server.engine.epochSeed,
            server.engine.validator_set.totalStake(),
        ) catch |err| {
            log.debug("Failed to add thread attestation: {}", .{err});
        };
    }

    peer.updateScore(3);
    server.countAttestationsRelayed();

    gossipToSubnet(server, msg.threadId, types.MsgThreadAttestation, payload, peer);
}

fn handleThreadCertificate(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.ThreadCertificateMsg, payload);

    // Verify quorum against ACTUAL validator set stake (not self-reported message fields).
    // The weaverBitmap tells us which validators signed — look up their real stake.
    const validators = server.engine.validator_set.active;
    var attesting_stake: u256 = 0;
    const max_bitmap_validators = @min(validators.len, 256);
    for (0..max_bitmap_validators) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if (byte_idx < msg.weaverBitmap.len and (msg.weaverBitmap[byte_idx] >> bit_idx) & 1 == 1) {
            attesting_stake += validators[i].stake;
        }
    }

    // Use committee manager's actual stake (Tier 2) or total stake (Tier 1/3) as denominator.
    // This prevents a malicious aggregator from crafting a cert with inflated values.
    const total_thread_stake = server.engine.adaptive.epochManager.committeeManager.getThreadStake(msg.threadId);
    const total_eligible = if (total_thread_stake > 0)
        total_thread_stake
    else
        server.engine.validator_set.totalStake();

    if (total_eligible > 0) {
        if (@as(u512, attesting_stake) * 3 <= @as(u512, total_eligible) * 2) {
            peer.updateScore(-10);
            return;
        }
    }

    const cert = consensus.ThreadCertificate{
        .slot = msg.slot,
        .threadId = msg.threadId,
        .thread_root = msg.threadRoot,
        .aggregateSignature = msg.aggregateSignature,
        .weaverBitmap = msg.weaverBitmap,
        .attestingStake = attesting_stake,
        .totalEligibleStake = total_eligible,
    };
    server.engine.adaptive.addThreadCertificate(cert);

    peer.updateScore(5);
    gossipToSubnet(server, msg.threadId, types.MsgThreadCertificate, payload, peer);
}

fn handleThreadTimeoutProof(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.ThreadTimeoutProofMsg, payload);

    if (msg.slot != server.engine.adaptive.currentSlot) return;

    // Verify BLS signature before accepting
    const sig_valid = try server.engine.verifyThreadTimeoutProof(
        msg.proposerIndex,
        msg.slot,
        msg.threadId,
        msg.signature,
    );
    if (!sig_valid) {
        peer.updateScore(-30);
        return;
    }

    const proof = consensus.types.ThreadTimeoutProof{
        .slot = msg.slot,
        .threadId = msg.threadId,
        .proposerIndex = msg.proposerIndex,
        .signature = msg.signature,
    };
    server.engine.adaptive.addThreadTimeoutProof(proof);

    peer.updateScore(5);
    try broadcastRaw(server, types.MsgThreadTimeoutProof, payload);
}

fn handleAdaptiveQC(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.AdaptiveQCMsg, payload);
    defer server.allocator.free(msg.voterBitmap);

    server.engine.verifyQCAggregate(
        &msg.wovenRoot,
        msg.aggregateSignature,
        msg.voterBitmap,
    ) catch |err| {
        log.warn("handleAdaptiveQC: invalid QC from peer {x}: {}", .{ peer.id, err });
        peer.updateScore(-20);
        return;
    };

    server.engine.updateFinality(msg.slot);
    server.chain.setLastFinalized(msg.slot);
    server.engine.resetViewChangeBackoff();

    log.info("QC received and verified for slot {} — block finalized (stake: {})", .{
        msg.slot, msg.totalAttestingStake,
    });

    peer.updateScore(10);
    try broadcastRaw(server, types.MsgAdaptiveQC, payload);
}

fn handleSnowballQuery(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.SnowballQueryMsg, payload);

    if (server.engine.getCurrentTier() != .FullLoom) {
        peer.updateScore(-2);
        return;
    }

    const accept = if (server.snowballEngine) |sb|
        sb.getPreference(msg.slot) == .Accept
    else
        false;

    // Look up our own validator index and stake for the response
    var our_index: u32 = 0;
    var our_stake: u256 = 0;
    for (server.engine.validator_set.active, 0..) |v, i| {
        if (std.mem.eql(u8, &v.address.bytes, &server.config.validatorAddress.bytes)) {
            our_index = @intCast(i);
            our_stake = v.stake;
            break;
        }
    }

    const response = types.SnowballResponseMsg{
        .slot = msg.slot,
        .blockHash = msg.blockHash,
        .accept = accept,
        .round = msg.round,
        .responderIndex = our_index,
        .responderStake = our_stake,
    };
    try peer.send(types.MsgSnowballResponse, response);
    peer.updateScore(1);
}

fn handleSnowballResponse(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.SnowballResponseMsg, payload);

    // Validate the responder exists in the validator set
    if (msg.responderIndex >= server.engine.validator_set.active.len) {
        peer.updateScore(-5);
        return;
    }

    // Validate the reported stake matches the on-chain validator stake
    const expected_stake = server.engine.validator_set.active[msg.responderIndex].stake;
    if (msg.responderStake != expected_stake) {
        peer.updateScore(-10);
        return;
    }

    if (server.snowballEngine) |sb| {
        const result = sb.recordResponse(
            msg.slot,
            msg.responderIndex,
            msg.accept,
            msg.responderStake,
        );

        // When a round completes without finalization, dispatch the next round
        if (result == .RoundComplete) {
            const epoch_seed = server.engine.epochSeed;
            var our_index: u32 = 0;
            for (server.engine.validator_set.active, 0..) |v, i| {
                if (std.mem.eql(u8, &v.address.bytes, &server.config.validatorAddress.bytes)) {
                    our_index = @intCast(i);
                    break;
                }
            }
            if (sb.nextRound(
                msg.slot,
                epoch_seed,
                our_index,
                @intCast(server.engine.validator_set.active.len),
            )) |peers| {
                for (peers) |peer_idx| {
                    if (peer_idx >= server.engine.validator_set.active.len) continue;
                    const peer_addr = server.engine.validator_set.active[peer_idx].address;
                    const p = server.findPeerByValidatorAddress(peer_addr) orelse continue;
                    const query = types.SnowballQueryMsg{
                        .slot = msg.slot,
                        .blockHash = msg.blockHash,
                        .round = 0, // round managed internally by snowball engine
                        .querierIndex = our_index,
                    };
                    p.send(types.MsgSnowballQuery, query) catch continue;
                }
            } else {
                log.debug("Snowball: nextRound returned null (finalized)", .{});
            }
        }

        // ── Phase 3.4: SnowballFinalization → QC Bridge ──────────
        // When Snowball finalizes with Accept, build a QC proof via
        // quorum.zig and mark the block as finalized in the consensus engine.
        if (result == .Finalized) {
            if (sb.isAccepted(msg.slot)) {
                // Extract Snowball finalization proof
                const proof = sb.getFinalizationProof(msg.slot) orelse {
                    log.warn("Snowball: finalized but no proof for slot {}", .{msg.slot});
                    return;
                };

                // Build a SnowballQuorumCertificate via quorum.zig
                const snowball_qc = consensus.quorum.buildSnowballQC(
                    msg.slot,
                    msg.blockHash,
                    server.engine.epochSeed,
                    @intCast(server.engine.validator_set.active.len),
                    proof,
                );

                // Update finality state
                server.engine.updateFinality(msg.slot);
                server.chain.setLastFinalized(msg.slot);
                server.engine.resetViewChangeBackoff();

                log.info("Snowball finalized block {} (rounds={d}, responders={d}) — block finalized via QC bridge", .{
                    msg.slot,
                    snowball_qc.proof.roundsCompleted,
                    snowball_qc.proof.responderCount,
                });
            } else {
                log.debug("Snowball: slot {} finalized with Reject (timeout)", .{msg.slot});
            }

            // Clean up the Snowball instance regardless of Accept/Reject
            sb.removeInstance(msg.slot);
        }
    }

    peer.updateScore(1);
}

fn handleEpochTransition(server: *Server, peer: *Peer, payload: []const u8) !void {
    const msg = try rlp.decode(server.allocator, types.EpochTransitionMsg, payload);

    log.info("Epoch transition from peer: epoch={d} tier={d} threads={d} validators={d}", .{
        msg.newEpoch, msg.tier, msg.threadCount, msg.validatorCount,
    });

    peer.updateScore(3);
}

// ── Forwarding Declarations (imported from sibling modules) ──────────────

const broadcast = @import("broadcast.zig");
const broadcastRaw = broadcast.broadcastRaw;
const broadcastToCommittee = broadcast.broadcastToCommittee;
const broadcastSubset = broadcast.broadcastSubset;
const gossipToSubnet = broadcast.gossipToSubnet;

const sync = @import("sync.zig");
const handleGetBlocks = sync.handleGetBlocks;
const handleBlocks = sync.handleBlocks;

const discovery_mod = @import("discovery.zig");
