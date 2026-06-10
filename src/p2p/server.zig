// ============================================================================
// Zephyria — P2P Server (Orchestration Layer)
// ============================================================================
//
// Thin orchestration: connection accept, message dispatch, IO, lifecycle.
// Submodules: message_handlers.zig, broadcast.zig, sync.zig, peer.zig
//
//   • 128 thread-topology subnets (each node subscribes to 1)
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
const rlp = @import("encoding").rlp;
const turbine_mod = @import("turbine.zig");
const gulf_stream_mod = @import("gulf_stream.zig");
const discovery_mod = @import("discovery.zig");
const compression_mod = @import("compression.zig");
const stun_mod = @import("stun.zig");
const message_handlers = @import("message_handlers.zig");
const broadcast_mod = @import("broadcast.zig");
const sync_mod = @import("sync.zig");

const Packet = @import("net_utils").Packet;
const socket_utils = @import("net_utils").socket_utils;
const allocators = @import("utils").allocators;
const SwissMap = @import("utils").SwissMap;
const utils = @import("utils");
const secureZero = utils.secureZero;

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
    packetPoolSize: u32 = 2048,
    pruneIntervalMs: u64 = 30_000,
    validatorAddress: core.types.Address = core.types.Address.zero(),
    enableStun: bool = true,
    stunHost: []const u8 = "stun.l.google.com",
    stunPort: u16 = 19302,
    publicIp: ?[]const u8 = null,
    identityKey: ?[32]u8 = null,
    repairBudget: u16 = 100,
    gulfStreamIntervalMs: u64 = 10,
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

    // Subnet Management
    localSubnets: [16]u8,
    subnetPeers: [types.GOSSIP_SUBNETS]std.ArrayListUnmanaged(*Peer),

    // Rate limiting
    rateLimiter: std.AutoHashMap(u32, utils.TokenBucket),

    // Pruning / forwarding threads
    pruneThread: ?std.Thread,
    gulfStreamThread: ?std.Thread,
    lastPrune: i64,

    // Stats
    stats: ServerStats,

    // ── Firewall 4: Anti-replay rolling windows ──────────────────────
    seenBlockIds: [512]core.types.Hash,
    seenBlockIdIdx: u16,
    seenTxIds: [4096]core.types.Hash,
    seenTxIdIdx: u16,

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
        blocksDroppedDuplicate: u64,
        txsDroppedDuplicate: u64,
        blocksDroppedOversized: u64,
        blocksDroppedSemantic: u64,
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

        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        const Timeval = extern struct {
            tv_sec: c_long,
            tv_usec: c_int,
        };
        const timeout = Timeval{ .tv_sec = 0, .tv_usec = 100 * 1000 };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout));

        const rcvBuf: c_int = 4 * 1024 * 1024;
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(rcvBuf));
        const sndBuf: c_int = 4 * 1024 * 1024;
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(sndBuf));

        const poolPtr = try allocator.create(PacketPool);
        poolPtr.* = PacketPool.init(.{
            .records_allocator = allocator,
            .memory_allocator = allocator,
        });
        try poolPtr.expandCapacity(config.packetPoolSize);

        var discoveryPriv: [32]u8 = undefined;
        defer secureZero(discoveryPriv[0..]);
        if (config.identityKey) |id_key| {
            discoveryPriv = id_key;
        } else {
            std.crypto.random.bytes(&discoveryPriv);
        }
        const discovery = try discovery_mod.DiscoveryService.init(allocator, &discoveryPriv, config.listenPort);

        var subnetPeers: [types.GOSSIP_SUBNETS]std.ArrayListUnmanaged(*Peer) = undefined;
        for (&subnetPeers) |*sp| {
            sp.* = .{};
        }

        var localSubnets: [16]u8 = [_]u8{0} ** 16;
        types.setSubnetBit(&localSubnets, 0);

        discovery.localNode.validatorAddress = config.validatorAddress;
        discovery.localNode.subscribedSubnets = localSubnets;
        discovery.localZnr.validatorAddr = config.validatorAddress;
        discovery.localZnr.subnets = localSubnets;
        if (!std.mem.eql(u8, &config.validatorAddress.bytes, &core.types.Address.zero().bytes)) {
            discovery.localNode.stakeAmount = 100_000_000_000;
            discovery.localZnr.stake = 100_000_000_000;
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
            .gulfStream = gulf_stream_mod.GulfStream.init(allocator, engine, dagPool),
            .discovery = discovery,
            .compressor = compression_mod.Compressor.init(allocator),
            .threadAttestPool = null,
            .snowballEngine = null,
            .localSubnets = localSubnets,
            .subnetPeers = subnetPeers,
            .rateLimiter = std.AutoHashMap(u32, utils.TokenBucket).init(allocator),
            .pruneThread = null,
            .gulfStreamThread = null,
            .lastPrune = std.time.milliTimestamp(),
            .stats = std.mem.zeroes(ServerStats),
            .seenBlockIds = [_]core.types.Hash{core.types.Hash.zero()} ** 512,
            .seenBlockIdIdx = 0,
            .seenTxIds = [_]core.types.Hash{core.types.Hash.zero()} ** 4096,
            .seenTxIdIdx = 0,
        };

        try self.pool.init(.{ .allocator = allocator, .n_jobs = config.numWorkers });

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.running = false;

        if (self.thread) |t| t.join();
        if (self.pruneThread) |t| t.join();
        if (self.gulfStreamThread) |t| t.join();
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

    // ── Lifecycle ───────────────────────────────────────────────────

    pub fn start(self: *Self) !void {
        var addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, self.config.listenPort),
            .addr = 0,
            .zero = [_]u8{0} ** 8,
        };

        const max_retries = 10;
        var attempt: u32 = 0;
        while (attempt < max_retries) : (attempt += 1) {
            addr.port = std.mem.nativeToBig(u16, self.config.listenPort + @as(u16, @intCast(attempt)));
            if (posix.bind(self.sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in))) {
                if (attempt > 0) {
                    self.config.listenPort += @as(u16, @intCast(attempt));
                    log.warn("P2P: port conflict, moved to {}\n", .{self.config.listenPort});
                }
                break;
            } else |err| switch (err) {
                error.AddressInUse => continue,
                else => |e| return e,
            }
        } else {
            log.err("P2P: failed to bind after {} attempts\n", .{max_retries});
            return error.AddressInUse;
        }

        log.debug("P2P Server starting on port {} (workers: {}, max_peers: {})\n", .{
            self.config.listenPort, self.config.numWorkers, self.config.maxPeers,
        });

        if (self.config.publicIp) |pub_ip| {
            if (std.net.Address.parseIp4(pub_ip, self.config.listenPort)) |ext_addr| {
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ext_addr.in.sa.addr)).*;
                log.debug("P2P: Using configured public IP address {d}.{d}.{d}.{d}\n", .{
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                });
                self.discovery.localNode.address = ext_addr;
                self.discovery.localZnr.ip4 = ip_bytes;
                self.discovery.localZnr.udpPort = self.config.listenPort;
            } else |err| {
                log.err("P2P: Failed to parse configured public IP address '{s}': {}\n", .{ pub_ip, err });
            }
        } else if (self.config.enableStun) {
            log.debug("STUN: Querying STUN server {s}:{} for external IP...\n", .{ self.config.stunHost, self.config.stunPort });
            var resolved = false;
            if (stun_mod.discoverExternalAddress(self.config.stunHost, self.config.stunPort)) |ext_addr| {
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ext_addr.in.sa.addr)).*;
                log.debug("STUN: Discovered public IP address {d}.{d}.{d}.{d}\n", .{
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                });
                self.discovery.localNode.address = ext_addr;
                self.discovery.localZnr.ip4 = ip_bytes;
                self.discovery.localZnr.udpPort = self.config.listenPort;
                resolved = true;
            } else |err| {
                log.debug("STUN: Discovery failed: {}. Trying HTTP fallback...\n", .{err});
            }

            if (!resolved) {
                if (stun_mod.discoverExternalAddressHttp(self.allocator)) |ext_addr| {
                    const ip_bytes = @as(*const [4]u8, @ptrCast(&ext_addr.in.sa.addr)).*;
                    log.debug("HTTP: Discovered public IP address {d}.{d}.{d}.{d}\n", .{
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                    });
                    self.discovery.localNode.address = std.net.Address.initIp4(ip_bytes, self.config.listenPort);
                    self.discovery.localZnr.ip4 = ip_bytes;
                    self.discovery.localZnr.udpPort = self.config.listenPort;
                } else |err| {
                    log.debug("HTTP: IP Discovery failed: {}. Falling back to default bindings.\n", .{err});
                }
            }
        }

        try self.discovery.start();
        self.running = true;
        self.thread = try std.Thread.spawn(.{}, serverLoop, .{self});
        self.pruneThread = try std.Thread.spawn(.{}, pruneLoop, .{self});
        self.gulfStreamThread = try std.Thread.spawn(.{}, gulfStreamLoop, .{self});

        self.discovery.mutex.lock();
        const bootstrap_copy = try self.allocator.dupe(discovery_mod.Node, self.discovery.bootstrapNodes.items);
        self.discovery.mutex.unlock();
        defer self.allocator.free(bootstrap_copy);

        for (bootstrap_copy) |node| {
            self.connectPeer(node.address) catch |err| {
                log.debug("Failed to connect to bootstrap node: {}\n", .{err});
            };
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        self.discovery.stop();
    }

    // ── Server Loop ─────────────────────────────────────────────────

    fn serverLoop(self: *Self) void {
        while (self.running) {
            const packetsSlice = self.packetPool.alloc(1) catch |err| {
                log.debug("Packet pool exhausted ({}), trying to expand pool capacity...\n", .{err});
                self.packetPool.expandCapacity(64) catch |exp_err| {
                    log.err("Failed to expand packet pool capacity: {}\n", .{exp_err});
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                };
                continue;
            };
            var packet = &packetsSlice[0];

            var from: posix.sockaddr.in = undefined;
            var fromlen: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const len = posix.recvfrom(self.sock, &packet.buffer, 0, @ptrCast(&from), &fromlen) catch |err| {
                self.packetPool.free(packetsSlice.ptr);
                self.flushOutbox() catch {};
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

            if (!self.checkConnectionBudget(from.addr)) {
                self.packetPool.free(packetsSlice.ptr);
                self.stats.rateLimitedPackets += 1;
                continue;
            }

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
                log.warn("P2P packet process error: {} from {d}.{d}.{d}.{d}:{}\n", .{
                    err,
                    (fromAddr.sa.addr >> 0) & 0xFF,
                    (fromAddr.sa.addr >> 8) & 0xFF,
                    (fromAddr.sa.addr >> 16) & 0xFF,
                    (fromAddr.sa.addr >> 24) & 0xFF,
                    std.mem.bigToNative(u16, fromAddr.sa.port),
                });
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
                p.connection_id = connId;
                p.server = self;

                std.crypto.random.bytes(&p.challenge);

                const status = types.StatusMsg{
                    .protocolVersion = types.PROTOCOL_VERSION,
                    .chainId = self.chain.chainId,
                    .genesisHash = self.chain.genesisId,
                    .headHash = self.chain.getHeadId(),
                    .headNumber = self.chain.getHeadNumber(),
                    .challenge = p.challenge,
                    .peerRole = .Validator,
                    .stakeAmount = blk_stake: {
                        var amt: u64 = 0;
                        for (self.engine.activeValidators) |v| {
                            if (std.mem.eql(u8, &v.address.bytes, &self.config.validatorAddress.bytes)) {
                                amt = @intCast(@min(v.stake, std.math.maxInt(u64)));
                                break;
                            }
                        }
                        break :blk_stake amt;
                    },
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
            try message_handlers.handleMessage(self, peer, code, decoded.payload[8..]);
        }
    }

    // ── Public API — External Entry Points ──────────────────────────

    pub fn broadcastBlockViaTurbine(self: *Self, blockData: []const u8, blockNumber: u64, blockId: core.types.Hash) !void {
        try broadcast_mod.broadcastBlockViaTurbine(self, blockData, blockNumber, blockId);
    }

    pub fn drainAndBroadcastSlashEvents(self: *Self) !void {
        try broadcast_mod.drainAndBroadcastSlashEvents(self);
    }

    pub fn broadcast(self: *Self, msgCode: u64, msg: anytype) !void {
        try broadcast_mod.broadcast(self, msgCode, msg);
    }

    pub fn connectPeer(self: *Self, address: std.net.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return try self.connectPeerLocked(address);
    }

    fn connectPeerLocked(self: *Self, address: std.net.Address) !void {
        const ip = switch (address.any.family) {
            std.posix.AF.INET => address.in.sa.addr,
            else => return error.UnsupportedAddressFamily,
        };

        if (self.peers.items.len >= self.config.maxPeers) {
            return error.TooManyPeers;
        }

        for (self.peers.items) |p| {
            const p_addr = try std.net.Address.parseIp4(p.ipSlice(), p.port);
            if (p_addr.in.sa.port == address.in.sa.port and p_addr.in.sa.addr == address.in.sa.addr) {
                return;
            }
        }

        var ip_buf: [20]u8 = undefined;
        const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
            (ip >> 0) & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF,
        });

        const p = try Peer.init(self.allocator, ip_str, std.mem.bigToNative(u16, address.in.sa.port));
        p.server = self;

        std.crypto.random.bytes(&p.challenge);

        const status = types.StatusMsg{
            .protocolVersion = types.PROTOCOL_VERSION,
            .chainId = self.chain.chainId,
            .genesisHash = self.chain.genesisId,
            .headHash = self.chain.getHeadId(),
            .headNumber = self.chain.getHeadNumber(),
            .challenge = p.challenge,
            .peerRole = .Validator,
            .subscribedSubnets = self.localSubnets,
            .stakeAmount = 0,
        };
        try p.send(types.MsgStatus, status);

        try self.peers.append(self.allocator, p);
        try self.peersById.ensureTotalCapacity(self.peersById.count() + 1);
        self.peersById.putAssumeCapacity(p.connection_id, p);
        try self.peersByIp.put(ip, p);

        self.stats.peersConnected += 1;
        log.debug("Proactively connecting to peer: {s}:{} (total: {})\n", .{ ip_str, p.port, self.peers.items.len });
    }

    pub fn setThreadAttestPool(self: *Self, pool: *consensus.ThreadAttestationPool) void {
        self.threadAttestPool = pool;
    }

    pub fn setSnowballEngine(self: *Self, sb: *consensus.Snowball) void {
        self.snowballEngine = sb;
    }

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

    pub fn findPeerByValidatorAddress(self: *Self, addr: core.types.Address) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.findPeerByValidatorAddressLocked(addr);
    }

    // ── Internal Peer Helpers ───────────────────────────────────────

    pub fn findPeerByValidatorAddressLocked(self: *Self, addr: core.types.Address) ?*Peer {
        for (self.peers.items) |peer| {
            if (peer.handshakeComplete and std.mem.eql(u8, &peer.validatorAddress.bytes, &addr.bytes)) {
                return peer;
            }
        }
        return null;
    }

    pub fn registerPeerSubnets(self: *Self, peer: *Peer) void {
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

    // ── Rate Limiting ───────────────────────────────────────────────

    fn checkRateLimit(self: *Self, ip: u32) bool {
        const now = std.time.milliTimestamp();
        const gop = self.rateLimiter.getOrPut(ip) catch return true;

        if (!gop.found_existing) {
            var bucket = utils.TokenBucket.init(
                self.config.rateLimit.baseCapacity,
                self.config.rateLimit.baseRefill,
            );
            if (!bucket.tryConsume(1.0, now)) return false;
            gop.value_ptr.* = bucket;
            return true;
        }

        var capacity = self.config.rateLimit.baseCapacity;
        var refill_rate = self.config.rateLimit.baseRefill;

        if (self.peersByIp.get(ip)) |peer| {
            if (peer.stakeAmount > 0) {
                const stake_f = @as(f64, @floatFromInt(peer.stakeAmount));
                const multiplier = @min(@sqrt(stake_f / 10000.0), self.config.rateLimit.maxStakeMultiplier);
                refill_rate *= @max(1.0, multiplier);
            }
            if (peer.isCommitteeMember) {
                capacity *= self.config.rateLimit.committeeBurstMultiplier;
                refill_rate *= self.config.rateLimit.committeeBurstMultiplier;
            }
        }

        gop.value_ptr.capacity = capacity;
        gop.value_ptr.refill_rate = refill_rate;

        return gop.value_ptr.tryConsume(1.0, now);
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

    // ── Pruning ─────────────────────────────────────────────────────

    fn pruneLoop(self: *Self) void {
        while (self.running) {
            sync_mod.checkAndRequestRepairs(self) catch |err| {
                log.debug("Error in checkAndRequestRepairs: {}\n", .{err});
            };
            self.prunePeers();
            var remaining: u64 = self.config.pruneIntervalMs;
            const step_ms: u64 = 100;
            while (remaining > 0 and self.running) {
                std.Thread.sleep(step_ms * std.time.ns_per_ms);
                remaining -|= step_ms;
            }
        }
    }

    fn prunePeers(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.shouldDisconnect() or peer.isStale()) {
                self.unregisterPeerSubnets(peer);

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

                _ = self.peers.swapRemove(i);

                self.stats.peersPruned += 1;
                if (self.stats.peersConnected > 0) {
                    self.stats.peersConnected -= 1;
                }

                peer.deinit();
            } else {
                if (now - peer.lastMessageTime > 15_000) {
                    const ping_msg = types.PingMsg{
                        .sequence = @bitCast(now),
                        .timestamp = now,
                    };
                    peer.send(types.MsgPing, ping_msg) catch {};
                }
                i += 1;
            }
        }

        if (self.peers.items.len < self.config.maxPeers) {
            const needed = self.config.maxPeers - self.peers.items.len;
            if (self.discovery.findClosest(self.discovery.localNode.hash, needed)) |discovered| {
                defer self.allocator.free(discovered);
                for (discovered) |node| {
                    if (std.mem.eql(u8, &node.id, &self.discovery.localNode.id)) continue;
                    self.connectPeerLocked(node.address) catch {};
                }
            } else |_| {}
        }

        if (self.peers.items.len > 0 and self.peers.items.len < self.config.maxPeers) {
            const rand_idx = std.crypto.random.intRangeLessThan(usize, 0, self.peers.items.len);
            const rand_peer = self.peers.items[rand_idx];
            log.debug("PEX: Periodic check for {s}:{} (handshakeComplete={})\n", .{ rand_peer.ipSlice(), rand_peer.port, rand_peer.handshakeComplete });
            if (rand_peer.handshakeComplete) {
                log.debug("PEX: Triggering MsgGetPeers to {s}:{}\n", .{ rand_peer.ipSlice(), rand_peer.port });
                const req = types.GetPeersMsg{ .version = types.PROTOCOL_VERSION };
                rand_peer.send(types.MsgGetPeers, req) catch |err| {
                    log.debug("PEX: Failed to send MsgGetPeers to {s}:{}: {}\n", .{ rand_peer.ipSlice(), rand_peer.port, err });
                };
            }
        }
    }

    // ── Gulf Stream ─────────────────────────────────────────────────

    fn gulfStreamLoop(self: *Self) void {
        while (self.running) {
            sync_mod.forwardGulfStream(self) catch |err| {
                log.debug("Error forwarding Gulf Stream batches: {}\n", .{err});
            };
            std.Thread.sleep(self.config.gulfStreamIntervalMs * std.time.ns_per_ms);
        }
    }

    // ── Outbox ──────────────────────────────────────────────────────

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

    // ── Firewall 4: Anti-Replay Rolling Windows ─────────────────────

    pub fn checkSeenBlockId(self: *Self, blkId: core.types.Hash) bool {
        for (&self.seenBlockIds) |*slot| {
            if (std.mem.eql(u8, &slot.bytes, &blkId.bytes)) return true;
        }
        return false;
    }

    pub fn recordSeenBlockId(self: *Self, blkId: core.types.Hash) void {
        self.seenBlockIds[self.seenBlockIdIdx % 512] = blkId;
        self.seenBlockIdIdx +%= 1;
    }

    pub fn checkSeenTxId(self: *Self, txId: core.types.Hash) bool {
        for (&self.seenTxIds) |*slot| {
            if (std.mem.eql(u8, &slot.bytes, &txId.bytes)) return true;
        }
        return false;
    }

    pub fn recordSeenTxId(self: *Self, txId: core.types.Hash) void {
        self.seenTxIds[self.seenTxIdIdx % 4096] = txId;
        self.seenTxIdIdx +%= 1;
    }
};
