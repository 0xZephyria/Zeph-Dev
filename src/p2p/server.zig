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
    listen_port: u16 = 30303,
    num_workers: u32 = 8,
    max_peers: u32 = types.MAX_CONNECTIONS,
    rate_limit: types.RateLimitConfig = .{},
    subnets_per_node: u32 = types.SUBNETS_PER_VALIDATOR,
    peers_per_subnet: u32 = types.PEERS_PER_SUBNET,
    packet_pool_size: u32 = 8192,
    prune_interval_ms: u64 = 30_000,
};

// ── Server ──────────────────────────────────────────────────────────────

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,

    // Core references
    chain: *core.Blockchain,
    engine: *consensus.ZeliusEngine,
    tx_pool: *core.tx_pool.TxPool,
    /// DAG mempool for parallel TX admission (set via setDAGPool)
    dag_pool: ?*core.dag_mempool.DAGMempool,

    // Peer Management
    peers: std.ArrayListUnmanaged(*Peer),
    peers_by_id: SwissMap(u64, *Peer, hashU64, eqU64),
    peers_by_ip: std.AutoHashMap(u32, *Peer),
    lock: std.Thread.Mutex,

    // Networking
    sock: posix.socket_t,
    running: bool,
    thread: ?std.Thread,
    pool: std.Thread.Pool,
    packet_pool: *PacketPool,

    // Outbox
    outbox: std.ArrayListUnmanaged(Packet),
    outbox_lock: std.Thread.Mutex,

    // Subsystems
    turbine: turbine_mod.TurbineEngine,
    gulf_stream: gulf_stream_mod.GulfStream,
    discovery: *discovery_mod.DiscoveryService,
    compressor: compression_mod.Compressor,

    // Loom Genesis Adaptive Consensus subsystems
    thread_attest_pool: ?*consensus.ThreadAttestationPool,
    snowball_engine: ?*consensus.Snowball,

    // Shred signature verification (Ed25519 + sampling)
    shred_verifier: ?*shred_verify_mod.ShredVerifier,

    // Subnet Management
    local_subnets: [8]u8, // Bitmap of subscribed subnets
    subnet_peers: [types.GOSSIP_SUBNETS]std.ArrayListUnmanaged(*Peer),

    // Rate limiting
    rate_limiter: std.AutoHashMap(u32, RateLimitEntry),

    // Pruning
    prune_thread: ?std.Thread,
    last_prune: i64,

    // Stats
    stats: ServerStats,

    const RateLimitEntry = struct {
        tokens: f64,
        last_update: i64,
    };

    pub const ServerStats = struct {
        packets_received: u64,
        packets_sent: u64,
        bytes_received: u64,
        bytes_sent: u64,
        peers_connected: u32,
        peers_authenticated: u32,
        peers_pruned: u64,
        rate_limited_packets: u64,
        invalid_packets: u64,
        shreds_relayed: u64,
        attestations_relayed: u64,
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *core.Blockchain,
        engine: *consensus.ZeliusEngine,
        tx_pool: *core.tx_pool.TxPool,
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
        const rcvbuf: c_int = 4 * 1024 * 1024; // 4 MB
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(rcvbuf));

        // Packet pool
        const pool_ptr = try allocator.create(PacketPool);
        pool_ptr.* = PacketPool.init(.{
            .records_allocator = allocator,
            .memory_allocator = allocator,
        });
        try pool_ptr.expandCapacity(config.packet_pool_size);

        // Discovery
        const discovery_priv = try allocator.alloc(u8, 32);
        std.crypto.random.bytes(discovery_priv);
        const discovery = try discovery_mod.DiscoveryService.init(allocator, discovery_priv, config.listen_port);
        allocator.free(discovery_priv);

        // Initialize subnet peers
        var subnet_peers: [types.GOSSIP_SUBNETS]std.ArrayListUnmanaged(*Peer) = undefined;
        for (&subnet_peers) |*sp| {
            sp.* = .{};
        }

        // Compute local subnet assignments (deterministic from node identity)
        var local_subnets: [8]u8 = [_]u8{0} ** 8;
        {
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(&discovery.local_node.id, &hash, .{});
            const s1: types.SubnetID = @intCast(hash[0] % types.GOSSIP_SUBNETS);
            const s2: types.SubnetID = @intCast(hash[1] % types.GOSSIP_SUBNETS);
            types.setSubnetBit(&local_subnets, s1);
            if (s1 != s2) types.setSubnetBit(&local_subnets, s2);
        }

        self.* = Self{
            .allocator = allocator,
            .config = config,
            .chain = chain,
            .engine = engine,
            .tx_pool = tx_pool,
            .dag_pool = null,
            .peers = .{},
            .peers_by_id = SwissMap(u64, *Peer, hashU64, eqU64).init(allocator),
            .peers_by_ip = std.AutoHashMap(u32, *Peer).init(allocator),
            .lock = .{},
            .sock = sock,
            .running = false,
            .thread = null,
            .pool = undefined,
            .packet_pool = pool_ptr,
            .outbox = .{},
            .outbox_lock = .{},
            .turbine = turbine_mod.TurbineEngine.init(allocator),
            .gulf_stream = gulf_stream_mod.GulfStream.init(allocator),
            .discovery = discovery,
            .compressor = compression_mod.Compressor.init(allocator),
            .thread_attest_pool = null,
            .snowball_engine = null,
            .shred_verifier = null,
            .local_subnets = local_subnets,
            .subnet_peers = subnet_peers,
            .rate_limiter = std.AutoHashMap(u32, RateLimitEntry).init(allocator),
            .prune_thread = null,
            .last_prune = std.time.milliTimestamp(),
            .stats = std.mem.zeroes(ServerStats),
        };

        try self.pool.init(.{ .allocator = allocator, .n_jobs = config.num_workers });

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.running = false;

        if (self.thread) |t| t.join();
        if (self.prune_thread) |t| t.join();
        self.pool.deinit();

        posix.close(self.sock);

        for (self.peers.items) |peer| {
            peer.deinit();
        }
        self.peers.deinit(self.allocator);
        self.peers_by_id.deinit();
        self.peers_by_ip.deinit();

        self.packet_pool.deinit();
        self.allocator.destroy(self.packet_pool);

        self.outbox.deinit(self.allocator);
        self.rate_limiter.deinit();

        for (&self.subnet_peers) |*sp| {
            sp.deinit(self.allocator);
        }

        self.turbine.deinit();
        self.gulf_stream.deinit();
        self.compressor.deinit();
        self.discovery.deinit();

        self.allocator.destroy(self);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    pub fn start(self: *Self) !void {
        var addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, self.config.listen_port),
            .addr = 0,
            .zero = [_]u8{0} ** 8,
        };

        try posix.bind(self.sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
        log.debug("P2P Server starting on port {} (workers: {}, max_peers: {})\n", .{
            self.config.listen_port, self.config.num_workers, self.config.max_peers,
        });

        try self.discovery.start();
        self.running = true;
        self.thread = try std.Thread.spawn(.{}, serverLoop, .{self});
        self.prune_thread = try std.Thread.spawn(.{}, pruneLoop, .{self});
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        self.discovery.stop();
    }

    /// Set the DAG mempool for parallel TX admission.
    /// When set, handleTxBatch routes TXs through DAG admission.
    pub fn setDAGPool(self: *Self, pool: *core.dag_mempool.DAGMempool) void {
        self.dag_pool = pool;
    }

    /// Broadcast a block using Turbine shredding (primary propagation).
    /// Shreds the block data, then sends each shred through the Turbine tree.
    pub fn broadcastBlockViaTurbine(self: *Self, block_data: []const u8, block_number: u64) !void {
        // Shred the block (using zero signature — the actual sig is in the block header)
        const zero_sig: [64]u8 = [_]u8{0} ** 64;
        const shreds = try self.turbine.shredBlock(block_data, block_number, zero_sig);
        defer self.allocator.free(shreds);

        // Send each shred to the first tier of the Turbine tree
        self.lock.lock();
        defer self.lock.unlock();

        for (shreds) |shred| {
            const msg = types.ShredMsg{
                .block_number = shred.block_number,
                .shred_index = shred.shred_index,
                .total_data_shreds = shred.total_data_shreds,
                .total_parity_shreds = shred.total_parity_shreds,
                .shred_type = shred.shred_type,
                .payload = shred.payload,
                .producer_signature = shred.producer_signature,
                .thread_id = shred.thread_id,
            };

            // Send to Turbine tree children (fan-out propagation)
            const children = self.turbine.tree.getChildren(0);
            for (children) |child| {
                if (child.peer_index < self.peers.items.len) {
                    const peer = self.peers.items[child.peer_index];
                    if (peer.handshake_complete) {
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
                .block_number = event.block_number,
                .reason = @intFromEnum(event.reason),
                .evidence_hash = event.evidence_hash,
                .timestamp = event.timestamp,
            };
            self.broadcastRaw(types.MsgSlashEvidence, std.mem.asBytes(&msg)) catch {};
        }

        log.debug("P2P: Broadcast {d} slash events\n", .{events.len});
    }

    // ── Server Loop ─────────────────────────────────────────────────────

    fn serverLoop(self: *Self) void {
        while (self.running) {
            const packets_slice = self.packet_pool.alloc(1) catch |err| {
                log.debug("Packet pool exhausted: {}\n", .{err});
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };
            var packet = &packets_slice[0];

            var from: posix.sockaddr.in = undefined;
            var fromlen: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const len = posix.recvfrom(self.sock, &packet.buffer, 0, @ptrCast(&from), &fromlen) catch |err| {
                self.packet_pool.free(packets_slice.ptr);
                if (err == error.WouldBlock or err == error.Again) {
                    continue;
                }
                log.debug("P2P recvfrom error: {}\n", .{err});
                continue;
            };

            packet.size = len;
            packet.addr = std.net.Address{ .in = @bitCast(from) };
            self.stats.packets_received += 1;
            self.stats.bytes_received += len;

            // Connection budget check
            if (!self.checkConnectionBudget(from.addr)) {
                self.packet_pool.free(packets_slice.ptr);
                self.stats.rate_limited_packets += 1;
                continue;
            }

            // Rate limit check
            if (self.checkRateLimit(from.addr)) {
                self.pool.spawn(handlePacketWrapper, .{ self, packet, packets_slice.ptr }) catch {
                    self.packet_pool.free(packets_slice.ptr);
                };
            } else {
                self.stats.rate_limited_packets += 1;
                self.punishIp(from.addr, -5);
                self.packet_pool.free(packets_slice.ptr);
            }

            self.flushOutbox() catch {};
        }
    }

    fn handlePacketWrapper(self: *Self, packet: *Packet, ptr: [*]Packet) void {
        defer self.packet_pool.free(ptr);
        var from_addr = packet.addr.in;
        self.handlePacket(@ptrCast(&from_addr), packet.data()) catch |err| {
            if (err != error.EndOfStream) {
                self.stats.invalid_packets += 1;
            }
        };
    }

    fn handlePacket(self: *Self, sender: *const posix.sockaddr.in, data: []const u8) !void {
        const decoded = try zquic.transport.packet.Packet.decode(data);
        const conn_id = decoded.connection_id;

        const peer = blk: {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.peers_by_id.get(conn_id)) |p| {
                p.recordReceived(data.len);
                break :blk p;
            } else {
                // Connection budget enforcement
                if (self.peers.items.len >= self.config.max_peers) {
                    return error.TooManyPeers;
                }

                var ip_buf: [20]u8 = undefined;
                const ip = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                    (sender.addr >> 0) & 0xFF,
                    (sender.addr >> 8) & 0xFF,
                    (sender.addr >> 16) & 0xFF,
                    (sender.addr >> 24) & 0xFF,
                });

                const p = try Peer.init(self.allocator, ip, std.mem.bigToNative(u16, sender.port));

                var conn = try Connection.init(self.allocator);
                conn.connection_id = conn_id;
                try conn.establish();
                p.attachQuic(conn);
                try p.openStream(1);

                // Generate challenge
                std.crypto.random.bytes(&p.challenge);

                // Send status with subnet info
                const status = types.StatusMsg{
                    .protocol_version = types.PROTOCOL_VERSION,
                    .chain_id = self.chain.chain_id,
                    .genesis_hash = self.chain.genesis_hash,
                    .head_hash = self.chain.get_head_hash(),
                    .head_number = self.chain.get_head_number(),
                    .challenge = p.challenge,
                    .peer_role = .Validator,
                    .stake_amount = 0,
                    .subscribed_subnets = self.local_subnets,
                };
                try p.send(types.MsgStatus, status);

                try self.peers.append(self.allocator, p);
                try self.peers_by_id.ensureTotalCapacity(self.peers_by_id.count() + 1);
                self.peers_by_id.putAssumeCapacity(conn_id, p);
                try self.peers_by_ip.put(sender.addr, p);

                self.stats.peers_connected += 1;
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
                self.stats.invalid_packets += 1;
            },
        }
    }

    fn handleStatus(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.StatusMsg, payload);

        // Validate protocol version
        if (msg.protocol_version != types.PROTOCOL_VERSION) {
            peer.updateScore(-20);
            return;
        }

        // Validate genesis hash
        if (!std.mem.eql(u8, &msg.genesis_hash.bytes, &self.chain.genesis_hash.bytes)) {
            peer.updateScore(-50);
            return;
        }

        peer.updateHead(msg.head_hash, msg.head_number);
        peer.protocol_version = msg.protocol_version;
        peer.peer_role = msg.peer_role;
        peer.stake_amount = msg.stake_amount;
        peer.subscribed_subnets = msg.subscribed_subnets;

        peer.lock.lock();
        defer peer.lock.unlock();
        peer.handshake_complete = true;
        peer.updateScoreLocked(5);

        // Register peer in subnet lists
        self.registerPeerSubnets(peer);
    }

    fn handleNewBlock(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.NewBlockMsg, payload);

        if (msg.block.header.number <= self.chain.get_head_number()) {
            return; // Stale
        }

        const heap_block = try self.allocator.create(core.types.Block);
        heap_block.* = msg.block;

        self.chain.add_block(heap_block) catch |err| {
            log.debug("Invalid block from peer: {}\n", .{err});
            self.allocator.destroy(heap_block);
            peer.updateScore(-20);
            return;
        };

        peer.updateScore(10);

        // Relay via Turbine shredding (not gossip)
        if (msg.hop_count < 2) {
            var relay_msg = msg;
            relay_msg.hop_count += 1;
            try self.broadcastSubset(types.MsgNewBlock, relay_msg, types.TURBINE_FANOUT, peer);
        }
    }

    fn handleTxBatch(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.TxBatchMsg, payload);

        var added: u32 = 0;
        for (msg.tx_data) |tx_raw| {
            const tx = try rlp.decode(self.allocator, core.types.Transaction, tx_raw);
            const heap_tx = try self.allocator.create(core.types.Transaction);
            heap_tx.* = tx;

            // Route through DAG mempool if available (primary path)
            if (self.dag_pool) |dag| {
                dag.add(heap_tx) catch {
                    self.allocator.destroy(heap_tx);
                    continue;
                };
                // Also forward to Gulf Stream for predicted leader
                const tx_hash = heap_tx.hash();
                _ = self.gulf_stream.queueTransaction(tx_hash, tx_raw) catch false;
                added += 1;
            } else {
                // Fallback to legacy pool
                _ = self.tx_pool.add(heap_tx) catch {
                    self.allocator.destroy(heap_tx);
                    continue;
                };
                added += 1;
            }
        }

        if (added > 0) {
            peer.updateScore(@intCast(@min(added, 10)));
        }
    }

    fn handleAuth(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.AuthMsg, payload);

        var pub_key_bytes: [65]u8 = undefined;
        @memcpy(&pub_key_bytes, &msg.public_key);

        const valid = try core.account.verify_signature(peer.challenge, msg.signature, pub_key_bytes);
        if (!valid) {
            peer.updateScore(-50);
            return error.AuthFailed;
        }

        const addr = try core.account.addressFromPubKey(&pub_key_bytes);
        peer.lock.lock();
        defer peer.lock.unlock();
        peer.validator_address = addr;
        peer.authenticated = true;
        peer.updateScoreLocked(20);
    }

    fn handleShred(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.ShredMsg, payload);

        var shred = turbine_mod.Shred{
            .block_number = msg.block_number,
            .shred_index = msg.shred_index,
            .total_data_shreds = msg.total_data_shreds,
            .total_parity_shreds = msg.total_parity_shreds,
            .shred_type = msg.shred_type,
            .payload = msg.payload,
            .producer_signature = msg.producer_signature,
            .thread_id = msg.thread_id,
            .crc32 = 0,
        };
        // Compute CRC for integrity verification on receive path
        shred.crc32 = shred.computeCrc();

        // Ed25519 signature verification (sampling-aware)
        if (self.shred_verifier) |verifier| {
            // Derive producer address from the first 20 bytes of the signature
            // (in production, this would come from the block header's proposer field)
            var producer_addr = core.types.Address.zero();
            @memcpy(&producer_addr.bytes, msg.producer_signature[0..20]);

            if (!verifier.verifyShred(
                msg.block_number,
                msg.shred_index,
                msg.payload,
                msg.producer_signature,
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
            log.debug("Turbine: Block {} reconstructed ({} bytes)\n", .{ shred.block_number, block_data.len });
            peer.updateScore(15);
        }

        self.stats.shreds_relayed += 1;

        // Relay shred to children in propagation tree
        const children = self.turbine.tree.getChildren(0); // Our peer_index
        if (children.len > 0) {
            self.relayShredToChildren(msg, children);
        }
    }

    fn relayShredToChildren(self: *Self, msg: types.ShredMsg, children: []const turbine_mod.TreeNode) void {
        self.lock.lock();
        defer self.lock.unlock();

        for (children) |child| {
            if (child.peer_index < self.peers.items.len) {
                const child_peer = self.peers.items[child.peer_index];
                if (child_peer.handshake_complete) {
                    child_peer.send(types.MsgShred, msg) catch {};
                }
            }
        }
    }

    fn handleAttestation(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.AttestationMsg, payload);

        // Verify attestation is for a recent block
        const head = self.chain.get_head_number();
        if (msg.block_number + 10 < head or msg.block_number > head + 2) {
            peer.updateScore(-5);
            return;
        }

        peer.updateScore(3);
        self.stats.attestations_relayed += 1;

        // Relay to peers in the same subnet
        self.gossipToSubnet(msg.subnet_id, types.MsgAttestation, payload, peer);
    }

    fn handleAggregateAttestation(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.AggregateAttestationMsg, payload);

        // Verify participation meets minimum
        const participation = types.countParticipation(msg.participation_bitmap);
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
        if (!types.hasQuorum(msg.participation_bitmap, types.COMMITTEE_SIZE)) {
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
            .slot_start = 0,
            .slot_end = 0,
            .committee_index = msg.committee_index,
            .role = msg.role,
            .aggregation_subnet = 0,
        });

        peer.bls_pubkey = msg.bls_pubkey;
        peer.updateScore(5);
    }

    fn handleSubnetSubscribe(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.SubnetSubscribeMsg, payload);

        if (msg.subnet_id >= types.GOSSIP_SUBNETS) {
            peer.updateScore(-10);
            return;
        }

        peer.subscribeSubnet(msg.subnet_id);

        // Add to subnet peer list
        self.lock.lock();
        defer self.lock.unlock();

        // Check if already in subnet list
        var found = false;
        for (self.subnet_peers[msg.subnet_id].items) |sp| {
            if (sp == peer) {
                found = true;
                break;
            }
        }
        if (!found) {
            self.subnet_peers[msg.subnet_id].append(self.allocator, peer) catch {};
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
            .request_id = msg.request_id,
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
        const head = self.chain.get_head_number();
        if (msg.slot + 10 < head or msg.slot > head + 2) {
            peer.updateScore(-3);
            return;
        }

        // Add to thread attestation pool if available
        if (self.thread_attest_pool) |pool| {
            const attest = consensus.ThreadAttestation{
                .slot = msg.slot,
                .thread_id = msg.thread_id,
                .thread_root = msg.thread_root,
                .validator_index = msg.validator_index,
                .role_proof = msg.role_proof,
                .bls_signature = msg.bls_signature,
                .attesting_stake = msg.attesting_stake,
            };
            _ = pool.addAttestation(attest) catch |err| {
                log.debug("Failed to add thread attestation: {}", .{err});
            };
        }

        peer.updateScore(3);
        self.stats.attestations_relayed += 1;

        // Relay to peers (thread-aware subnets in future; broadcast for now)
        try self.broadcastRaw(types.MsgThreadAttestation, payload);
    }

    /// Handle a thread certificate (aggregated attestations).
    fn handleThreadCertificate(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.ThreadCertificateMsg, payload);

        // Validate quorum: attesting_stake must be > 2/3 total
        if (msg.total_eligible_stake > 0) {
            if (msg.attesting_stake * 3 <= msg.total_eligible_stake * 2) {
                peer.updateScore(-10);
                return;
            }
        }

        // Add to adaptive engine
        const adaptive = self.engine.getAdaptive();
        const cert = consensus.ThreadCertificate{
            .slot = msg.slot,
            .thread_id = msg.thread_id,
            .thread_root = msg.thread_root,
            .aggregate_signature = msg.aggregate_signature,
            .weaver_bitmap = msg.weaver_bitmap,
            .attesting_stake = msg.attesting_stake,
            .total_eligible_stake = msg.total_eligible_stake,
        };
        adaptive.addThreadCertificate(cert);

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
        const accept = if (self.snowball_engine) |sb|
            sb.getPreference(msg.slot) != .None
        else
            false;

        const response = types.SnowballResponseMsg{
            .slot = msg.slot,
            .block_hash = msg.block_hash,
            .accept = accept,
            .round = msg.round,
            .responder_index = 0, // Will be set by caller
            .responder_stake = 0,
        };
        try peer.send(types.MsgSnowballResponse, response);
        peer.updateScore(1);
    }

    /// Handle a Snowball response (Tier 3 only).
    fn handleSnowballResponse(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.SnowballResponseMsg, payload);

        if (self.snowball_engine) |sb| {
            _ = sb.recordResponse(
                msg.slot,
                msg.accept,
                msg.responder_stake,
            );
        }

        peer.updateScore(1);
    }

    /// Handle an epoch transition notification.
    fn handleEpochTransition(self: *Self, peer: *Peer, payload: []const u8) !void {
        const msg = try rlp.decode(self.allocator, types.EpochTransitionMsg, payload);

        log.info("Epoch transition from peer: epoch={d} tier={d} threads={d} validators={d}", .{
            msg.new_epoch, msg.tier, msg.thread_count, msg.validator_count,
        });

        peer.updateScore(3);
    }

    /// Set the thread attestation pool (called from main.zig)
    pub fn setThreadAttestPool(self: *Self, pool: *consensus.ThreadAttestationPool) void {
        self.thread_attest_pool = pool;
    }

    /// Set the Snowball engine (called from main.zig)
    pub fn setSnowballEngine(self: *Self, sb: *consensus.Snowball) void {
        self.snowball_engine = sb;
    }

    /// Set the shred signature verifier (called from main.zig)
    pub fn setShredVerifier(self: *Self, verifier: *shred_verify_mod.ShredVerifier) void {
        self.shred_verifier = verifier;
    }

    // ── Broadcasting ────────────────────────────────────────────────────

    pub fn broadcast(self: *Self, msg_code: u64, msg: anytype) !void {
        self.lock.lock();
        const peers_copy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.lock.unlock();
            return;
        };
        self.lock.unlock();
        defer self.allocator.free(peers_copy);

        for (peers_copy) |peer| {
            if (peer.handshake_complete) {
                peer.send(msg_code, msg) catch {};
            }
        }
        self.stats.packets_sent += @intCast(peers_copy.len);
    }

    pub fn broadcastRaw(self: *Self, msg_code: u64, payload: []const u8) !void {
        self.lock.lock();
        const peers_copy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.lock.unlock();
            return;
        };
        self.lock.unlock();
        defer self.allocator.free(peers_copy);

        for (peers_copy) |peer| {
            if (peer.handshake_complete) {
                peer.sendRaw(msg_code, payload) catch {};
            }
        }
        self.stats.packets_sent += @intCast(peers_copy.len);
    }

    pub fn broadcastSubset(self: *Self, msg_code: u64, msg: anytype, fanout: u32, exclude: *Peer) !void {
        self.lock.lock();
        const peers_copy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.lock.unlock();
            return;
        };
        self.lock.unlock();
        defer self.allocator.free(peers_copy);

        var count: u32 = 0;
        for (peers_copy) |peer| {
            if (peer == exclude) continue;
            if (peer.handshake_complete) {
                peer.send(msg_code, msg) catch continue;
                count += 1;
                if (count >= fanout) break;
            }
        }
    }

    /// Broadcast to peers in a specific subnet.
    fn gossipToSubnet(self: *Self, subnet: types.SubnetID, msg_code: u64, payload: []const u8, exclude: *Peer) void {
        if (subnet >= types.GOSSIP_SUBNETS) return;

        self.lock.lock();
        defer self.lock.unlock();

        for (self.subnet_peers[subnet].items) |peer| {
            if (peer == exclude) continue;
            if (peer.handshake_complete) {
                peer.sendRaw(msg_code, payload) catch {};
            }
        }
    }

    /// Broadcast to committee members only.
    fn broadcastToCommittee(self: *Self, msg_code: u64, payload: []const u8) !void {
        self.lock.lock();
        const peers_copy = self.allocator.dupe(*Peer, self.peers.items) catch {
            self.lock.unlock();
            return;
        };
        self.lock.unlock();
        defer self.allocator.free(peers_copy);

        for (peers_copy) |peer| {
            if (peer.is_committee_member and peer.handshake_complete) {
                peer.sendRaw(msg_code, payload) catch {};
            }
        }
    }

    // ── Outbox (Batch Sending) ──────────────────────────────────────────

    pub fn enqueueSend(self: *Self, dest: std.net.Address, data: []const u8) !void {
        self.outbox_lock.lock();
        defer self.outbox_lock.unlock();

        var pkt = Packet.init(dest, undefined, data.len);
        @memcpy(pkt.dataMut(), data);
        try self.outbox.append(self.allocator, pkt);

        if (self.outbox.items.len >= socket_utils.PACKETS_PER_BATCH) {
            try self.flushOutboxLocked();
        }
    }

    fn flushOutbox(self: *Self) !void {
        self.outbox_lock.lock();
        defer self.outbox_lock.unlock();
        try self.flushOutboxLocked();
    }

    fn flushOutboxLocked(self: *Self) !void {
        if (self.outbox.items.len == 0) return;

        const sent = try socket_utils.sendBatch(self.sock, self.outbox.items);
        self.stats.packets_sent += @intCast(sent);

        if (sent > 0) {
            const remaining = self.outbox.items.len - sent;
            std.mem.copyForwards(Packet, self.outbox.items[0..remaining], self.outbox.items[sent..]);
            self.outbox.items.len = remaining;
        }
    }

    // ── Subnet Management ───────────────────────────────────────────────

    fn registerPeerSubnets(self: *Self, peer: *Peer) void {
        self.lock.lock();
        defer self.lock.unlock();

        for (0..types.GOSSIP_SUBNETS) |subnet| {
            if (peer.isInSubnet(@intCast(subnet))) {
                var already = false;
                for (self.subnet_peers[subnet].items) |sp| {
                    if (sp == peer) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    self.subnet_peers[subnet].append(self.allocator, peer) catch {};
                }
            }
        }
    }

    fn unregisterPeerSubnets(self: *Self, peer: *Peer) void {
        // Must be called with self.lock held
        for (0..types.GOSSIP_SUBNETS) |subnet| {
            var i: usize = 0;
            while (i < self.subnet_peers[subnet].items.len) {
                if (self.subnet_peers[subnet].items[i] == peer) {
                    _ = self.subnet_peers[subnet].swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    // ── Rate Limiting ───────────────────────────────────────────────────

    fn checkRateLimit(self: *Self, ip: u32) bool {
        const now = std.time.milliTimestamp();
        const entry = self.rate_limiter.getOrPut(ip) catch return true;

        if (!entry.found_existing) {
            entry.value_ptr.* = .{
                .tokens = self.config.rate_limit.base_capacity - 1.0,
                .last_update = now,
            };
            return true;
        }

        const elapsed_sec = @as(f64, @floatFromInt(now - entry.value_ptr.last_update)) / 1000.0;

        // Check if this IP belongs to a staked peer
        var refill = self.config.rate_limit.base_refill;
        var capacity = self.config.rate_limit.base_capacity;

        if (self.peers_by_ip.get(ip)) |peer| {
            if (peer.stake_amount > 0) {
                const stake_f = @as(f64, @floatFromInt(peer.stake_amount));
                const multiplier = @min(@sqrt(stake_f / 10000.0), self.config.rate_limit.max_stake_multiplier);
                refill *= @max(1.0, multiplier);
            }
            if (peer.is_committee_member) {
                capacity *= self.config.rate_limit.committee_burst_multiplier;
                refill *= self.config.rate_limit.committee_burst_multiplier;
            }
        }

        const new_tokens = entry.value_ptr.tokens + (elapsed_sec * refill);
        entry.value_ptr.tokens = @min(new_tokens, capacity);
        entry.value_ptr.last_update = now;

        if (entry.value_ptr.tokens >= 1.0) {
            entry.value_ptr.tokens -= 1.0;
            return true;
        }
        return false;
    }

    fn checkConnectionBudget(self: *Self, ip: u32) bool {
        _ = ip;
        self.lock.lock();
        defer self.lock.unlock();
        return self.peers.items.len < self.config.max_peers;
    }

    pub fn punishIp(self: *Self, ip: u32, delta: i32) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.peers_by_ip.get(ip)) |peer| {
            peer.updateScore(delta);
        }
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    fn pruneLoop(self: *Self) void {
        while (self.running) {
            // Sleep in short increments so we can exit promptly on shutdown
            const interval_ns = self.config.prune_interval_ms * std.time.ns_per_ms;
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
        self.lock.lock();
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.shouldDisconnect() or peer.isStale()) {
                // Unregister from subnets
                self.unregisterPeerSubnets(peer);

                // Remove from maps
                // Find and remove from peers_by_id
                var id_to_remove: ?u64 = null;
                var id_iter = self.peers_by_id.iterator();
                while (id_iter.next()) |entry| {
                    if (entry.value_ptr.* == peer) {
                        id_to_remove = entry.key_ptr.*;
                        break;
                    }
                }
                if (id_to_remove) |id| {
                    _ = self.peers_by_id.remove(id) catch {};
                }

                // Remove from peers_by_ip
                var ip_to_remove: ?u32 = null;
                var ip_iter = self.peers_by_ip.iterator();
                while (ip_iter.next()) |entry| {
                    if (entry.value_ptr.* == peer) {
                        ip_to_remove = entry.key_ptr.*;
                        break;
                    }
                }
                if (ip_to_remove) |ip| {
                    _ = self.peers_by_ip.remove(ip);
                }

                // Remove from peers list
                _ = self.peers.swapRemove(i);

                self.stats.peers_pruned += 1;
                if (self.stats.peers_connected > 0) {
                    self.stats.peers_connected -= 1;
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
        self.lock.lock();
        defer self.lock.unlock();
        return @intCast(self.peers.items.len);
    }

    pub fn getSubnetHealth(self: *Self) [types.GOSSIP_SUBNETS]u32 {
        self.lock.lock();
        defer self.lock.unlock();
        var health: [types.GOSSIP_SUBNETS]u32 = undefined;
        for (0..types.GOSSIP_SUBNETS) |i| {
            health[i] = @intCast(self.subnet_peers[i].items.len);
        }
        return health;
    }
};
