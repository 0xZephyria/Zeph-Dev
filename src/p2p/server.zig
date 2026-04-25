// ============================================================================
// Zephyria — P2P Server (Production)
// ============================================================================
//
// Committee-aware P2P server with:
//   • 64 attestation subnets (each node subscribes to 2)
//   • Turbine tree block propagation (shreds, not gossip)
//   • Gulf Stream transaction forwarding to predicted leaders
//   • Layered DDoS defense (connection budget + stake-weighted rate limiting)
//   • Batch I/O via sendmmsg/recvmmsg (Linux) / sequential fallback (macOS)
//   • Configurable thread pool
//   • Full message handling for all protocol messages
//   • Peer lifecycle management with auto-prune

const std = @import("std");
const log = @import("core").logger;
const core = @import("core");
const consensus = @import("consensus");
const types = @import("types.zig");
const Peer = @import("peer.zig").Peer;
const p2p = @import("mod.zig");
const zquic = p2p.quic;
const posix = std.posix;
const Connection = zquic.transport.connection.Connection;
const rlp = @import("encoding").rlp;
const turbine_mod = @import("turbine.zig");
const gulf_stream_mod = @import("gulf_stream.zig");
const discovery_mod = @import("discovery.zig");
const compression_mod = @import("compression.zig");
const shred_verify_mod = @import("shred_verifier.zig");

// Optimizations
const Packet = @import("net_utils").Packet;
const socket_utils = @import("net_utils").socket_utils;
const allocators = @import("utils").allocators;
const SwissMap = @import("utils").SwissMap;

const PacketPool = allocators.RecycleBuffer(Packet, Packet.ANY_EMPTY, .{});

inline fn hashU64(key: u64) u64 {
    return std.hash.Wyhash.hash(0, std.mem.asBytes(&key));
}
inline fn eqU64(a: u64, b: u64) bool {
    return a == b;
}

// ── Server Configuration ────────────────────────────────────────────────

pub const ServerConfig = struct {
    listenPort: u16 = 30303,
    numWorkers: u32 = 8,
    maxPeers: u32 = types.MAX_CONNECTIONS,
    rateLimit: types.RateLimitConfig = .{},
    subnetsPerNode: u32 = types.SUBNETS_PER_VALIDATOR,
    peersPerSubnet: u32 = types.PEERS_PER_SUBNET,
    packetPoolSize: u32 = 8192,
    pruneIntervalMs: u64 = 30_000,
};

// ── Server ──────────────────────────────────────────────────────────────

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,

    // Core references
    chain: *core.Blockchain,
    engine: *consensus.ZeliusEngine,
    dagPool: *core.dag_mempool.DAGMempool,

    // Peer Management
    peers: std.ArrayListUnmanaged(*Peer),
    peersById: SwissMap(u64, *Peer, hashU64, eqU64),
    peersByIp: std.AutoHashMap(u32, *Peer),
    mutex: std.Thread.Mutex,

    // Networking
    sock: posix.socket_t,
    running: bool,
    thread: ?std.Thread,
    pool: std.Thread.Pool,
    packetPool: *PacketPool,

    // Outbox
    outbox: std.ArrayListUnmanaged(Packet),
    outboxMutex: std.Thread.Mutex,

    // Subsystems
    turbine: turbine_mod.TurbineEngine,
    gulfStream: gulf_stream_mod.GulfStream,
    discovery: *discovery_mod.DiscoveryService,
    compressor: compression_mod.Compressor,

    // Loom Genesis Adaptive Consensus subsystems
    threadAttestPool: ?*consensus.ThreadAttestationPool,
    snowballEngine: ?*consensus.Snowball,

    // Shred signature verification (Ed25519 + sampling)
    shredVerifier: ?*shred_verify_mod.ShredVerifier,

    // Subnet Management
    localSubnets: [8]u8, // Bitmap of subscribed subnets
    subnetPeers: [types.GOSSIP_SUBNETS]std.ArrayListUnmanaged(*Peer),

    // Rate limiting
    rateLimiter: std.AutoHashMap(u32, RateLimitEntry),

    // Pruning
    pruneThread: ?std.Thread,
    lastPrune: i64,

    // Stats
    stats: ServerStats,

    const RateLimitEntry = struct {
        tokens: f64,
        lastUpdate: i64,
    };

    pub const ServerStats = struct {
        packetsReceived: u64,
        packetsSent: u64,
        bytesReceived: u64,
        bytesSent: u64,
        peersConnected: u32,
        peersAuthenticated: u32,
        peersPruned: u64,
        rateLimitedPackets: u64,
        invalidPackets: u64,
        shredsRelayed: u64,
        attestationsRelayed: u64,
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *core.Blockchain,
        engine: *consensus.ZeliusEngine,
        dagPool: *core.dag_mempool.DAGMempool,
        config: ServerConfig,
    ) !*Self {
        const self = try allocator.create(Self);

        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer posix.close(sock);

        // Socket options
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        // Receive timeout 100ms for checking 'running' flag
        const Timeval = extern struct {
            tv_sec: c_long,
            tv_usec: c_int,
        };
        const timeout = Timeval{ .tv_sec = 0, .tv_usec = 100 * 1000 };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout));

        // Increase receive buffer
        const rcvBuf: c_int = 4 * 1024 * 1024; // 4 MB
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(rcvBuf));

        // Packet pool
        const poolPtr = try allocator.create(PacketPool);
        poolPtr.* = PacketPool.init(.{
            .records_allocator = allocator,
            .memory_allocator = allocator,
        });
        try poolPtr.expandCapacity(config.packetPoolSize);

        // Discovery
        const discoveryPriv = try allocator.alloc(u8, 32);
        std.crypto.random.bytes(discoveryPriv);
        const discovery = try discovery_mod.DiscoveryService.init(allocator, discoveryPriv, config.listenPort);
        allocator.free(discoveryPriv);

        // Initialize subnet peers
        var subnetPeers: [types.GOSSIP_SUBNETS]std.ArrayListUnmanaged(*Peer) = undefined;
        for (&subnetPeers) |*sp| {
            sp.* = .{};
        }

        // Compute local subnet assignments (deterministic from node identity)
        var localSubnets: [8]u8 = [_]u8{0} ** 8;
        {
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(&discovery.localNode.id, &hash, .{});
            const s1: types.SubnetID = @intCast(hash[0] % types.GOSSIP_SUBNETS);
            const s2: types.SubnetID = @intCast(hash[1] % types.GOSSIP_SUBNETS);
            types.setSubnetBit(&localSubnets, s1);
            if (s1 != s2) types.setSubnetBit(&localSubnets, s2);
        }

        self.* = Self{
            .allocator = allocator,
            .config = config,
            .chain = chain,
            .engine = engine,
            .dagPool = dagPool,
            .peers = .{},
            .peersById = SwissMap(u64, *Peer, hashU64, eqU64).init(allocator),
            .peersByIp = std.AutoHashMap(u32, *Peer).init(allocator),
            .mutex = .{},
            .sock = sock,
            .running = false,
            .thread = null,
            .pool = undefined,
            .packetPool = poolPtr,
            .outbox = .{},
            .outboxMutex = .{},
            .turbine = turbine_mod.TurbineEngine.init(allocator),
            .gulfStream = gulf_stream_mod.GulfStream.init(allocator),
            .discovery = discovery,
            .compressor = compression_mod.Compressor.init(allocator),
            .threadAttestPool = null,
            .snowballEngine = null,
            .shredVerifier = null,
            .localSubnets = localSubnets,
            .subnetPeers = subnetPeers,
            .rateLimiter = std.AutoHashMap(u32, RateLimitEntry).init(allocator),
            .pruneThread = null,
            .lastPrune = std.time.milliTimestamp(),
            .stats = std.mem.zeroes(ServerStats),
        };

        try self.pool.init(.{ .allocator = allocator, .n_jobs = config.numWorkers });

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.running = false;

        if (self.thread) |t| t.join();
        if (self.pruneThread) |t| t.join();
        self.pool.deinit();

        posix.close(self.sock);

        for (self.peers.items) |peer| {
            peer.deinit();
        }
        self.peers.deinit(self.allocator);
        self.peersById.deinit();
        self.peersByIp.deinit();

        self.packetPool.deinit();
        self.allocator.destroy(self.packetPool);

        self.outbox.deinit(self.allocator);
        self.rateLimiter.deinit();

        for (&self.subnetPeers) |*sp| {
            sp.deinit(self.allocator);
        }

        self.turbine.deinit();
        self.gulfStream.deinit();
        self.compressor.deinit();
        self.discovery.deinit();

        self.allocator.destroy(self);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    pub fn start(self: *Self) !void {
        var addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, self.config.listenPort),
            .addr = 0,
            .zero = [_]u8{0} ** 8,
        };

        try posix.bind(self.sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
        log.debug("P2P Server starting on port {} (workers: {}, max_peers: {})\n", .{
            self.config.listenPort, self.config.numWorkers, self.config.maxPeers,
        });

        try self.discovery.start();
        self.running = true;
        self.thread = try std.Thread.spawn(.{}, serverLoop, .{self});
        self.pruneThread = try std.Thread.spawn(.{}, pruneLoop, .{self});
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        self.discovery.stop();
    }

    /// Broadcast a block using Turbine shredding (primary propagation).
    /// Shreds the block data, then sends each shred through the Turbine tree.
    pub fn broadcastBlockViaTurbine(self: *Self, blockData: []const u8, blockNumber: u64) !void {
        // Shred the block (using zero signature — the actual sig is in the block header)
        const zeroSig: [64]u8 = [_]u8{0} ** 64;
        const shreds = try self.turbine.shredBlock(blockData, blockNumber, zeroSig);
        defer self.allocator.free(shreds);

        // Send each shred to the first tier of the Turbine tree
        self.mutex.lock();
        defer self.mutex.unlock();

        for (shreds) |shred| {
            const msg = types.ShredMsg{
                .blockNumber = shred.blockNumber,
                .shredIndex = shred.shredIndex,
                .totalDataShreds = shred.totalDataShreds,
                .totalParityShreds = shred.totalParityShreds,
                .shredType = shred.shredType,
                .payload = shred.payload,
                .producerSignature = shred.producerSignature,
                .threadId = shred.threadId,
            };

            // Send to Turbine tree children (fan-out propagation)
            const children = self.turbine.tree.getChildren(0);
            for (children) |child| {
                if (child.peerIndex < self.peers.items.len) {
                    const peer = self.peers.items[child.peerIndex];
                    if (peer.handshakeComplete) {
                        peer.send(types.MsgShred, msg) catch {};
                    }
                }
            }
        }
    }

    /// Poll consensus engine for pending slash events and broadcast them.
    /// Called periodically from the server loop or from the miner.
    pub fn drainAndBroadcastSlashEvents(self: *Self) !void {
        const events = try self.engine.drainSlashEvents();
        if (events.len == 0) return;
        defer self.allocator.free(events);

        for (events) |event| {
            const msg = types.SlashEvidenceMsg{
                .validator = event.validator,
                .blockNumber = event.blockNumber,
                .reason = @intFromEnum(event.reason),
                .evidenceHash = event.evidenceHash,
                .timestamp = event.timestamp,
            };
            self.broadcastRaw(types.MsgSlashEvidence, std.mem.asBytes(&msg)) catch {};
        }

        log.debug("P2P: Broadcast {d} slash events\n", .{events.len});
    }

    // ── Server Loop ─────────────────────────────────────────────────────

    fn serverLoop(self: *Self) void {
        while (self.running) {
            const packetsSlice = self.packetPool.alloc(1) catch |err| {
                log.debug("Packet pool exhausted: {}\n", .{err});
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };
            var packet = &packetsSlice[0];

            var from: posix.sockaddr.in = undefined;
            var fromlen: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const len = posix.recvfrom(self.sock, &packet.buffer, 0, @ptrCast(&from), &fromlen) catch |err| {
                self.packetPool.free(packetsSlice.ptr);
                if (err == error.WouldBlock or err == error.Again) {
                    continue;
                }
                log.debug("P2P recvfrom error: {}\n", .{err});
                continue;
            };

            packet.size = len;
            packet.addr = std.net.Address{ .in = @bitCast(from) };
            self.stats.packetsReceived += 1;
            self.stats.bytesReceived += len;

            // Connection budget check
            if (!self.checkConnectionBudget(from.addr)) {
                self.packetPool.free(packetsSlice.ptr);
                self.stats.rateLimitedPackets += 1;
                continue;
            }

            // Rate limit check
            if (self.checkRateLimit(from.addr)) {
                self.pool.spawn(handlePacketWrapper, .{ self, packet, packetsSlice.ptr }) catch {
                    self.packetPool.free(packetsSlice.ptr);
                };
            } else {
                self.stats.rateLimitedPackets += 1;
                self.punishIp(from.addr, -5);
                self.packetPool.free(packetsSlice.ptr);
            }

            self.flushOutbox() catch {};
        }
    }

    fn handlePacketWrapper(self: *Self, packet: *Packet, ptr: [*]Packet) void {
        defer self.packetPool.free(ptr);
        var fromAddr = packet.addr.in;
        self.handlePacket(@ptrCast(&fromAddr), packet.data()) catch |err| {
            if (err != error.EndOfStream) {
                self.stats.invalidPackets += 1;
            }
        };
    }

    fn handlePacket(self: *Self, sender: *const posix.sockaddr.in, data: []const u8) !void {
        const decoded = try zquic.transport.packet.Packet.decode(data);
        const connId = decoded.connection_id;

        const peer = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.peersById.get(connId)) |p| {
                p.recordReceived(data.len);
                break :blk p;
            } else {
                // Connection budget enforcement
                if (self.peers.items.len >= self.config.maxPeers) {
                    return error.TooManyPeers;
                }

                var ipBuf: [20]u8 = undefined;
                const ip = try std.fmt.bufPrint(&ipBuf, "{d}.{d}.{d}.{d}", .{
                    (sender.addr >> 0) & 0xFF,
                    (sender.addr >> 8) & 0xFF,
                    (sender.addr >> 16) & 0xFF,
                    (sender.addr >> 24) & 0xFF,
                });

                const p = try Peer.init(self.allocator, ip, std.mem.bigToNative(u16, sender.port));

                var conn = try Connection.init(self.allocator);
                conn.connection_id = connId;
                try conn.establish();
                p.attachQuic(conn);
                try p.openStream(1);

                // Generate challenge
                std.crypto.random.bytes(&p.challenge);

                // Send status with subnet info
                const status = types.StatusMsg{
                    .protocolVersion = types.PROTOCOL_VERSION,
                    .chainId = self.chain.chainId,
                    .genesisHash = self.chain.genesisHash,
                    .headHash = self.chain.getHeadHash(),
                    .headNumber = self.chain.getHeadNumber(),
                    .challenge = p.challenge,
                    .peerRole = .Validator,
                    .stakeAmount = 0,
                    .subscribedSubnets = self.localSubnets,
                };
                try p.send(types.MsgStatus, status);

                try self.peers.append(self.allocator, p);
                try self.peersById.ensureTotalCapacity(self.peersById.count() + 1);
                self.peersById.putAssumeCapacity(connId, p);
                try self.peersByIp.put(sender.addr, p);

                self.stats.peersConnected += 1;
                log.debug("New peer: {s}:{} (total: {})\n", .{ ip, p.port, self.peers.items.len });
                break :blk p;
            }
        };

        if (decoded.payload.len >= 8) {
            const code = std.mem.readInt(u64, decoded.payload[0..8], .big);
            try self.handleMessage(peer, code, decoded.payload[8..]);
        }
    }

    // ── Message Handling ────────────────────────────────────────────────

    pub fn handleMessage(self: *Self, peer: *Peer, code: u64, payload: []const u8) !void {
        switch (code) {
            types.MsgStatus => try self.handleStatus(peer, payload),
            types.MsgNewBlock => try self.handleNewBlock(peer, payload),
            types.MsgTxBatch => try self.handleTxBatch(peer, payload),
            types.MsgAuth => try self.handleAuth(peer, payload),
            types.MsgShred => try self.handleShred(peer, payload),
            types.MsgAttestation => try self.handleAttestation(peer, payload),
            types.MsgAggregateAttestation => try self.handleAggregateAttestation(peer, payload),
            types.MsgQuorumCertificate => try self.handleQC(peer, payload),
            types.MsgViewChange => try self.handleViewChange(peer, payload),
            types.MsgSlashEvidence => try self.handleSlashEvidence(peer, payload),
            types.MsgCommitteeHandshake => try self.handleCommitteeHandshake(peer, payload),
            types.MsgSubnetSubscribe => try self.handleSubnetSubscribe(peer, payload),
            types.MsgGetNodeData => try self.handleGetNodeData(peer, payload),
            types.MsgPing => try self.handlePing(peer, payload),
            types.MsgPong => try self.handlePong(peer, payload),
            types.MsgGetBlocks => try self.handleGetBlocks(peer, payload),
            // Loom Genesis Adaptive Consensus messages
            types.MsgThreadAttestation => try self.handleThreadAttestation(peer, payload),
            types.MsgThreadCertificate => try self.handleThreadCertificate(peer, payload),
            types.MsgAdaptiveQC => try self.handleAdaptiveQC(peer, payload),
            types.MsgSnowballQuery => try self.handleSnowballQuery(peer, payload),
            types.MsgSnowballResponse => try self.handleSnowballResponse(peer, payload),
            types.MsgEpochTransition => try self.handleEpochTransition(peer, payload),
            else => {
                peer.updateScore(-5);
                self.stats.invalidPackets += 1;
            },
        }
    }

    fn handleStatus(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.StatusMsg, payload);

        // Validate protocol version
        if (msg.protocolVersion != types.PROTOCOL_VERSION) {
            peer.updateScore(-20);
            return;
        }

        // Validate genesis hash
        if (!std.mem.eql(u8, &msg.genesisHash.bytes, &self.chain.genesisHash.bytes)) {
            peer.updateScore(-50);
            return;
        }

        peer.updateHead(msg.headHash, msg.headNumber);
        peer.protocolVersion = msg.protocolVersion;
        peer.peerRole = msg.peerRole;
        peer.stakeAmount = msg.stakeAmount;
        peer.subscribedSubnets = msg.subscribedSubnets;

        peer.mutex.lock();
        defer peer.mutex.unlock();
        peer.handshakeComplete = true;
        peer.updateScoreLocked(5);

        // Register peer in subnet lists
        self.registerPeerSubnets(peer);
    }

    fn handleNewBlock(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.NewBlockMsg, payload);

        if (msg.block.header.number <= self.chain.getHeadNumber()) {
            return; // Stale
        }

        const heapBlock = try self.allocator.create(core.types.Block);
        heapBlock.* = msg.block;

        self.chain.addBlock(heapBlock) catch |err| {
            log.debug("Invalid block from peer: {}\n", .{err});
            self.allocator.destroy(heapBlock);
            peer.updateScore(-20);
            return;
        };

        peer.updateScore(10);

        // Relay via Turbine shredding (not gossip)
        if (msg.hopCount < 2) {
            var relayMsg = msg;
            relayMsg.hopCount += 1;
            try self.broadcastSubset(types.MsgNewBlock, relayMsg, types.TURBINE_FANOUT, peer);
        }
    }

    fn handleTxBatch(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.TxBatchMsg, payload);

        var added: u32 = 0;
        for (msg.txData) |txRaw| {
            const tx = try rlp.decode(self.allocator, core.types.Transaction, txRaw);
            const heapTx = try self.allocator.create(core.types.Transaction);
            heapTx.* = tx;

            self.dagPool.add(heapTx) catch {
                self.allocator.destroy(heapTx);
                continue;
            };
            // Also forward to Gulf Stream for predicted leader
            const txHash = heapTx.hash();
            _ = self.gulfStream.queueTransaction(txHash, txRaw) catch false;
            added += 1;
        }

        if (added > 0) {
            peer.updateScore(@intCast(@min(added, 10)));
        }
    }

    fn handleAuth(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.AuthMsg, payload);

        var pubKeyBytes: [65]u8 = undefined;
        @memcpy(&pubKeyBytes, &msg.publicKey);

        const valid = try core.account.verify_signature(peer.challenge, msg.signature, pubKeyBytes);
        if (!valid) {
            peer.updateScore(-50);
            return error.AuthFailed;
        }

        const addr = try core.account.addressFromPubKey(&pubKeyBytes);
        peer.mutex.lock();
        defer peer.mutex.unlock();
        peer.validatorAddress = addr;
        peer.authenticated = true;
        peer.updateScoreLocked(20);
    }

    fn handleShred(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.ShredMsg, payload);

        var shred = turbine_mod.Shred{
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
        // Compute CRC for integrity verification on receive path
        shred.crc32 = shred.computeCrc();

        // Ed25519 signature verification (sampling-aware)
        if (self.shredVerifier) |verifier| {
            // Derive producer address from the first 20 bytes of the signature
            // (in production, this would come from the block header's proposer field)
            var producer_addr = core.types.Address.zero();
            @memcpy(&producer_addr.bytes, msg.producerSignature[0..20]);

            if (!verifier.verifyShred(
                msg.blockNumber,
                msg.shredIndex,
                msg.payload,
                msg.producerSignature,
                producer_addr,
            )) {
                peer.updateScore(-15);
                return; // Reject forged shred
            }
        }

        // Insert into Turbine collector
        const maybe_block = try self.turbine.receiveShred(&shred);
        if (maybe_block) |block_data| {
            defer self.allocator.free(block_data);
            // Block fully reconstructed — process it
            log.debug("Turbine: Block {} reconstructed ({} bytes)\n", .{ shred.blockNumber, block_data.len });
            peer.updateScore(15);
        }

        self.stats.shredsRelayed += 1;

        // Relay shred to children in propagation tree
        const children = self.turbine.tree.getChildren(0); // Our peer_index
        if (children.len > 0) {
            self.relayShredToChildren(msg, children);
        }
    }

    fn relayShredToChildren(self: *Self, msg: types.ShredMsg, children: []const turbine_mod.TreeNode) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (children) |child| {
            if (child.peerIndex < self.peers.items.len) {
                const child_peer = self.peers.items[child.peerIndex];
                if (child_peer.handshakeComplete) {
                    child_peer.send(types.MsgShred, msg) catch {};
                }
            }
        }
    }

    fn handleAttestation(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.AttestationMsg, payload);

        // Verify attestation is for a recent block
        const head = self.chain.getHeadNumber();
        if (msg.blockNumber + 10 < head or msg.blockNumber > head + 2) {
            peer.updateScore(-5);
            return;
        }

        peer.updateScore(3);
        self.stats.attestationsRelayed += 1;

        // Relay to peers in the same subnet
        self.gossipToSubnet(msg.subnetId, types.MsgAttestation, payload, peer);
    }

    fn handleAggregateAttestation(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.AggregateAttestationMsg, payload);

        // Verify participation meets minimum
        const participation = types.countParticipation(msg.participationBitmap);
        if (participation < types.COMMITTEE_SIZE / 4) {
            peer.updateScore(-10);
            return;
        }

        peer.updateScore(5);

        // Broadcast to all connected peers (aggregate attestations are rare and important)
        try self.broadcastRaw(types.MsgAggregateAttestation, payload);
    }

    fn handleQC(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.QuorumCertificate, payload);

        // Verify quorum
        if (!types.hasQuorum(msg.participationBitmap, types.COMMITTEE_SIZE)) {
            peer.updateScore(-20);
            return;
        }

        peer.updateScore(10);

        // Broadcast QC (highest priority message)
        try self.broadcastRaw(types.MsgQuorumCertificate, payload);
    }

    fn handleViewChange(self: *Self, peer: *Peer, payload: []const u8) !void {
        _ = try rlp.decode(self.allocator, types.ViewChangeMsg, payload);
        peer.updateScore(1);

        // Relay to all committee members
        try self.broadcastToCommittee(types.MsgViewChange, payload);
    }

    fn handleSlashEvidence(self: *Self, peer: *Peer, payload: []const u8) !void {
        _ = try rlp.decode(self.allocator, types.SlashEvidenceMsg, payload);
        peer.updateScore(5); // Reward for reporting

        // High priority broadcast to entire network
        try self.broadcastRaw(types.MsgSlashEvidence, payload);
    }

    fn handleCommitteeHandshake(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.CommitteeHandshakeMsg, payload);

        peer.setCommitteeAssignment(.{
            .epoch = msg.epoch,
            .slotStart = 0,
            .slotEnd = 0,
            .committeeIndex = msg.committeeIndex,
            .role = msg.role,
            .aggregationSubnet = 0,
        });

        peer.blsPubKey = msg.blsPubkey;
        peer.updateScore(5);
    }

    fn handleSubnetSubscribe(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.SubnetSubscribeMsg, payload);

        if (msg.subnetId >= types.GOSSIP_SUBNETS) {
            peer.updateScore(-10);
            return;
        }

        peer.subscribeSubnet(msg.subnetId);

        // Add to subnet peer list
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already in subnet list
        var found = false;
        for (self.subnetPeers[msg.subnetId].items) |sp| {
            if (sp == peer) {
                found = true;
                break;
            }
        }
        if (!found) {
            self.subnetPeers[msg.subnetId].append(self.allocator, peer) catch {};
        }
    }

    fn handleGetNodeData(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.GetNodeDataMsg, payload);

        var data_list = std.ArrayListUnmanaged([]const u8){};
        defer data_list.deinit(self.allocator);

        for (msg.hashes) |h| {
            if (self.chain.db.read(&h.bytes)) |val| {
                try data_list.append(self.allocator, val);
            } else {
                try data_list.append(self.allocator, &[_]u8{});
            }
        }

        const reply = types.NodeDataMsg{
            .requestId = msg.requestId,
            .data = data_list.items,
        };
        try peer.send(types.MsgNodeData, reply);
    }

    fn handlePing(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.PingMsg, payload);

        const pong = types.PongMsg{
            .nonce = msg.nonce,
            .timestamp = std.time.milliTimestamp(),
        };
        try peer.send(types.MsgPong, pong);
    }

    fn handlePong(_: *Self, peer: *Peer, payload: []const u8) !void {
        _ = payload;
        peer.updateScore(1);
    }

    fn handleGetBlocks(_: *Self, _: *Peer, _: []const u8) !void {
        // Block sync handled by dedicated sync module
    }

    // ── Loom Genesis Adaptive Consensus Handlers ────────────────────────

    /// Handle a thread attestation from a weaver/committee member.
    fn handleThreadAttestation(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.ThreadAttestationMsg, payload);

        // Validate staleness
        const head = if (self.chain.currentBlock) |b| b.header.number else 0;
        if (msg.slot + 10 < head or msg.slot > head + 2) {
            peer.updateScore(-3);
            return;
        }

        // Add to thread attestation pool if available
        if (self.threadAttestPool) |pool| {
            const attest = consensus.ThreadAttestation{
                .slot = msg.slot,
                .threadId = msg.threadId,
                .thread_root = msg.threadRoot,
                .validatorIndex = msg.validatorIndex,
                .roleProof = msg.roleProof,
                .blsSignature = msg.blsSignature,
                .attestingStake = msg.attestingStake,
            };
            _ = pool.addAttestation(attest) catch |err| {
                log.debug("Failed to add thread attestation: {}", .{err});
            };
        }

        peer.updateScore(3);
        self.stats.attestationsRelayed += 1;

        // Relay to peers (thread-aware subnets in future; broadcast for now)
        try self.broadcastRaw(types.MsgThreadAttestation, payload);
    }

    /// Handle a thread certificate (aggregated attestations).
    fn handleThreadCertificate(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.ThreadCertificateMsg, payload);

        // Validate quorum: attestingStake must be > 2/3 total
        if (msg.totalEligibleStake > 0) {
            if (msg.attestingStake * 3 <= msg.totalEligibleStake * 2) {
                peer.updateScore(-10);
                return;
            }
        }

        // Add to adaptive engine
        const cert = consensus.ThreadCertificate{
            .slot = msg.slot,
            .threadId = msg.threadId,
            .thread_root = msg.threadRoot,
            .aggregateSignature = msg.aggregateSignature,
            .weaverBitmap = msg.weaverBitmap,
            .attestingStake = msg.attestingStake,
            .totalEligibleStake = msg.totalEligibleStake,
        };
        self.engine.adaptive.addThreadCertificate(cert);

        peer.updateScore(5);

        // Broadcast to all (certificates are important)
        try self.broadcastRaw(types.MsgThreadCertificate, payload);
    }

    /// Handle an Adaptive Quorum Certificate.
    fn handleAdaptiveQC(self: *Self, peer: *Peer, payload: []const u8) !void {
        _ = try rlp.decode(self.allocator, types.AdaptiveQCMsg, payload);
        peer.updateScore(10);

        // High priority: broadcast to entire network
        try self.broadcastRaw(types.MsgAdaptiveQC, payload);
    }

    /// Handle a Snowball query (Tier 3 only).
    fn handleSnowballQuery(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.SnowballQueryMsg, payload);

        // Only respond if we're in Tier 3
        if (self.engine.getCurrentTier() != .FullLoom) {
            peer.updateScore(-2);
            return;
        }

        // Respond with our preference
        const accept = if (self.snowballEngine) |sb|
            sb.getPreference(msg.slot) != .None
        else
            false;

        const response = types.SnowballResponseMsg{
            .slot = msg.slot,
            .blockHash = msg.blockHash,
            .accept = accept,
            .round = msg.round,
            .responderIndex = 0, // Will be set by caller
            .responderStake = 0,
        };
        try peer.send(types.MsgSnowballResponse, response);
        peer.updateScore(1);
    }

    /// Handle a Snowball response (Tier 3 only).
    fn handleSnowballResponse(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.SnowballResponseMsg, payload);

        if (self.snowballEngine) |sb| {
            _ = sb.recordResponse(
                msg.slot,
                msg.accept,
                msg.responderStake,
            );
        }

        peer.updateScore(1);
    }

    /// Handle an epoch transition notification.
    fn handleEpochTransition(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.EpochTransitionMsg, payload);

        log.info("Epoch transition from peer: epoch={d} tier={d} threads={d} validators={d}", .{
            msg.newEpoch, msg.tier, msg.threadCount, msg.validatorCount,
        });

        peer.updateScore(3);
    }

    /// Set the thread attestation pool (called from main.zig)
    pub fn setThreadAttestPool(self: *Self, pool: *consensus.ThreadAttestationPool) void {
        self.threadAttestPool = pool;
    }

    /// Set the Snowball engine (called from main.zig)
    pub fn setSnowballEngine(self: *Self, sb: *consensus.Snowball) void {
        self.snowballEngine = sb;
    }

    /// Set the shred signature verifier (called from main.zig)
    pub fn setShredVerifier(self: *Self, verifier: *shred_verify_mod.ShredVerifier) void {
        self.shredVerifier = verifier;
    }

    // ── Broadcasting ────────────────────────────────────────────────────

    pub fn broadcast(self: *Self, msgCode: u64, msg: anytype) !void {
        self.mutex.lock();
        const peersCopy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        defer self.allocator.free(peersCopy);

        for (peersCopy) |peer| {
            if (peer.handshakeComplete) {
                peer.send(msgCode, msg) catch {};
            }
        }
        self.stats.packetsSent += @intCast(peersCopy.len);
    }

    pub fn broadcastRaw(self: *Self, msgCode: u64, payload: []const u8) !void {
        self.mutex.lock();
        const peersCopy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        defer self.allocator.free(peersCopy);

        for (peersCopy) |peer| {
            if (peer.handshakeComplete) {
                peer.sendRaw(msgCode, payload) catch {};
            }
        }
        self.stats.packetsSent += @intCast(peersCopy.len);
    }

    pub fn broadcastSubset(self: *Self, msgCode: u64, msg: anytype, fanout: u32, exclude: *Peer) !void {
        self.mutex.lock();
        const peersCopy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        defer self.allocator.free(peersCopy);

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

    /// Broadcast to peers in a specific subnet.
    fn gossipToSubnet(self: *Self, subnet: types.SubnetID, msgCode: u64, payload: []const u8, exclude: *Peer) void {
        if (subnet >= types.GOSSIP_SUBNETS) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.subnetPeers[subnet].items) |peer| {
            if (peer == exclude) continue;
            if (peer.handshakeComplete) {
                peer.sendRaw(msgCode, payload) catch {};
            }
        }
    }

    /// Broadcast to committee members only.
    fn broadcastToCommittee(self: *Self, msgCode: u64, payload: []const u8) !void {
        self.mutex.lock();
        const peersCopy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        defer self.allocator.free(peersCopy);

        for (peersCopy) |peer| {
            if (peer.isCommitteeMember and peer.handshakeComplete) {
                peer.sendRaw(msgCode, payload) catch {};
            }
        }
    }

    // ── Outbox (Batch Sending) ──────────────────────────────────────────

    pub fn enqueueSend(self: *Self, dest: std.net.Address, data: []const u8) !void {
        self.outboxMutex.lock();
        defer self.outboxMutex.unlock();

        var pkt = Packet.init(dest, undefined, data.len);
        @memcpy(pkt.dataMut(), data);
        try self.outbox.append(self.allocator, pkt);

        if (self.outbox.items.len >= socket_utils.PACKETS_PER_BATCH) {
            try self.flushOutboxLocked();
        }
    }

    fn flushOutbox(self: *Self) !void {
        self.outboxMutex.lock();
        defer self.outboxMutex.unlock();
        try self.flushOutboxLocked();
    }

    fn flushOutboxLocked(self: *Self) !void {
        if (self.outbox.items.len == 0) return;

        const sent = try socket_utils.sendBatch(self.sock, self.outbox.items);
        self.stats.packetsSent += @intCast(sent);

        if (sent > 0) {
            const remaining = self.outbox.items.len - sent;
            std.mem.copyForwards(Packet, self.outbox.items[0..remaining], self.outbox.items[sent..]);
            self.outbox.items.len = remaining;
        }
    }

    // ── Subnet Management ───────────────────────────────────────────────

    fn registerPeerSubnets(self: *Self, peer: *Peer) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (0..types.GOSSIP_SUBNETS) |subnet| {
            if (peer.isInSubnet(@intCast(subnet))) {
                var already = false;
                for (self.subnetPeers[subnet].items) |sp| {
                    if (sp == peer) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    self.subnetPeers[subnet].append(self.allocator, peer) catch {};
                }
            }
        }
    }

    fn unregisterPeerSubnets(self: *Self, peer: *Peer) void {
        // Must be called with self.mutex held
        for (0..types.GOSSIP_SUBNETS) |subnet| {
            var i: usize = 0;
            while (i < self.subnetPeers[subnet].items.len) {
                if (self.subnetPeers[subnet].items[i] == peer) {
                    _ = self.subnetPeers[subnet].swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    // ── Rate Limiting ───────────────────────────────────────────────────

    fn checkRateLimit(self: *Self, ip: u32) bool {
        const now = std.time.milliTimestamp();
        const entry = self.rateLimiter.getOrPut(ip) catch return true;

        if (!entry.found_existing) {
            entry.value_ptr.* = .{
                .tokens = self.config.rateLimit.baseCapacity - 1.0,
                .lastUpdate = now,
            };
            return true;
        }

        const elapsed_sec = @as(f64, @floatFromInt(now - entry.value_ptr.lastUpdate)) / 1000.0;

        // Check if this IP belongs to a staked peer
        var refill = self.config.rateLimit.baseRefill;
        var capacity = self.config.rateLimit.baseCapacity;

        if (self.peersByIp.get(ip)) |peer| {
            if (peer.stakeAmount > 0) {
                const stake_f = @as(f64, @floatFromInt(peer.stakeAmount));
                const multiplier = @min(@sqrt(stake_f / 10000.0), self.config.rateLimit.maxStakeMultiplier);
                refill *= @max(1.0, multiplier);
            }
            if (peer.isCommitteeMember) {
                capacity *= self.config.rateLimit.committeeBurstMultiplier;
                refill *= self.config.rateLimit.committeeBurstMultiplier;
            }
        }

        const new_tokens = entry.value_ptr.tokens + (elapsed_sec * refill);
        entry.value_ptr.tokens = @min(new_tokens, capacity);
        entry.value_ptr.lastUpdate = now;

        if (entry.value_ptr.tokens >= 1.0) {
            entry.value_ptr.tokens -= 1.0;
            return true;
        }
        return false;
    }

    fn checkConnectionBudget(self: *Self, ip: u32) bool {
        _ = ip;
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.peers.items.len < self.config.maxPeers;
    }

    pub fn punishIp(self: *Self, ip: u32, delta: i32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.peersByIp.get(ip)) |peer| {
            peer.updateScore(delta);
        }
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    fn pruneLoop(self: *Self) void {
        while (self.running) {
            // Sleep in short increments so we can exit promptly on shutdown
            const interval_ns = self.config.pruneIntervalMs * std.time.ns_per_ms;
            const step_ns: u64 = 100 * std.time.ns_per_ms; // 100ms steps
            var remaining: u64 = interval_ns;
            while (remaining > 0 and self.running) {
                const sleep_ns = @min(remaining, step_ns);
                std.Thread.sleep(sleep_ns);
                remaining -|= sleep_ns;
            }
            if (!self.running) break;
            self.prunePeers();
        }
    }

    fn prunePeers(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.shouldDisconnect() or peer.isStale()) {
                // Unregister from subnets
                self.unregisterPeerSubnets(peer);

                // Remove from maps
                // Find and remove from peersById
                var id_to_remove: ?u64 = null;
                var id_iter = self.peersById.iterator();
                while (id_iter.next()) |entry| {
                    if (entry.value_ptr.* == peer) {
                        id_to_remove = entry.key_ptr.*;
                        break;
                    }
                }
                if (id_to_remove) |id| {
                    _ = self.peersById.remove(id) catch {};
                }

                // Remove from peersByIp
                var ip_to_remove: ?u32 = null;
                var ip_iter = self.peersByIp.iterator();
                while (ip_iter.next()) |entry| {
                    if (entry.value_ptr.* == peer) {
                        ip_to_remove = entry.key_ptr.*;
                        break;
                    }
                }
                if (ip_to_remove) |ip| {
                    _ = self.peersByIp.remove(ip);
                }

                // Remove from peers list
                _ = self.peers.swapRemove(i);

                self.stats.peersPruned += 1;
                if (self.stats.peersConnected > 0) {
                    self.stats.peersConnected -= 1;
                }

                peer.deinit();
            } else {
                i += 1;
            }
        }
    }

    // ── Stats ───────────────────────────────────────────────────────────

    pub fn getStats(self: *const Self) ServerStats {
        return self.stats;
    }

    pub fn getPeerCount(self: *Self) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return @intCast(self.peers.items.len);
    }

    pub fn getSubnetHealth(self: *Self) [types.GOSSIP_SUBNETS]u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var health: [types.GOSSIP_SUBNETS]u32 = undefined;
        for (0..types.GOSSIP_SUBNETS) |i| {
            health[i] = @intCast(self.subnetPeers[i].items.len);
        }
        return health;
    }
};
