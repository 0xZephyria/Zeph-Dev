const std = @import("std");
const core = @import("core");
const storage = @import("storage");
const consensus = @import("consensus");
const p2p = @import("p2p");
const rpc = @import("rpc");
const node = @import("node");
const utils = @import("utils");
const vm_bridge = @import("vm_bridge");

const Address = core.types.Address;
const Block = core.types.Block;
const Header = core.types.Header;
const Hash = core.types.Hash;

pub const VirtualNode = struct {
    allocator: std.mem.Allocator,
    node_index: u32,
    p2p_port: u16,
    http_port: u16,
    data_dir: []const u8,
    is_miner: bool,
    running: std.atomic.Value(bool),

    // Thread-safe wrapper allocator
    ts_allocator_wrapper: std.heap.ThreadSafeAllocator,
    ts_allocator: std.mem.Allocator,

    // Core structures
    db: storage.Database,
    db_adapter: storage.DB,
    world_state: *core.state.State,
    chain: *core.blockchain.Blockchain,
    engine: *consensus.zelius.ZeliusEngine,
    dag_pool: *core.dag_mempool.DAGMempool,
    dag_executor: *core.dag_executor.DAGExecutor,
    block_producer: *core.block_producer.BlockProducer,
    p2p_server: *p2p.Server,
    rpc_server: *rpc.Server,
    miner: ?*node.miner.Miner = null,
    epoch_integration: ?*node.EpochIntegration = null,

    // Threads
    miner_thread: ?std.Thread = null,

    pub fn init(
        backing_allocator: std.mem.Allocator,
        node_index: u32,
        p2p_port: u16,
        http_port: u16,
        data_dir: []const u8,
        is_miner: bool,
        validators: []const consensus.types.ValidatorInfo,
        miner_priv_key: [32]u8,
    ) !*VirtualNode {
        const self = try backing_allocator.create(VirtualNode);
        errdefer backing_allocator.destroy(self);

        self.allocator = backing_allocator;
        self.node_index = node_index;
        self.p2p_port = p2p_port;
        self.http_port = http_port;
        self.data_dir = try backing_allocator.dupe(u8, data_dir);
        self.is_miner = is_miner;
        self.running = std.atomic.Value(bool).init(true);

        self.ts_allocator_wrapper = std.heap.ThreadSafeAllocator{ .child_allocator = backing_allocator };
        self.ts_allocator = self.ts_allocator_wrapper.allocator();

        self.db = undefined;
        self.db_adapter = undefined;
        self.world_state = undefined;
        self.chain = undefined;
        self.engine = undefined;
        self.dag_pool = undefined;
        self.dag_executor = undefined;
        self.block_producer = undefined;
        self.p2p_server = undefined;
        self.rpc_server = undefined;
        self.miner = null;
        self.epoch_integration = null;

        // Open DB
        try std.fs.cwd().makePath(data_dir);
        self.db = try storage.open(self.ts_allocator, data_dir);
        self.db_adapter = self.db.asAbstractDB();

        // World state
        self.world_state = try self.ts_allocator.create(core.state.State);
        self.world_state.* = core.state.State.init(self.ts_allocator, self.db_adapter);

        // Chain
        self.chain = try core.blockchain.Blockchain.init(self.ts_allocator, self.db_adapter, 88888);

        // Consensus Engine
        self.engine = try consensus.zelius.ZeliusEngine.init(self.ts_allocator, validators);

        // Set identity keys
        self.engine.privKey = miner_priv_key;
        self.engine.setBlsPrivKey(&miner_priv_key);

        // Mempool & Executor
        self.dag_pool = try core.dag_mempool.DAGMempool.init(self.ts_allocator, self.world_state, .{
            .maxSequenceGap = 1024,
            .maxTxsPerLane = 1024,
            .enableSanitization = false,
        });

        self.dag_executor = try self.ts_allocator.create(core.dag_executor.DAGExecutor);
        self.dag_executor.* = core.dag_executor.DAGExecutor.init(self.ts_allocator, self.world_state, .{});

        // Block Producer
        self.block_producer = try self.ts_allocator.create(core.block_producer.BlockProducer);
        self.block_producer.* = core.block_producer.BlockProducer.init(
            self.ts_allocator,
            self.chain,
            self.world_state,
            try core.accounts.eoa.addressFromPrivKey(miner_priv_key),
            60_000_000,
        );
        self.block_producer.setDAGPipeline(self.dag_pool, self.dag_executor);

        // Initialize genesis block if chain is empty
        if (self.chain.getHead() == null) {
            const network = core.genesis.getNetworkConfig("devnet");
            const alloc = try core.genesis.getGenesisAllocations(self.ts_allocator, "devnet");
            defer self.ts_allocator.free(alloc);
            const sysContracts = try core.genesis.getGenesisSystemContracts(self.ts_allocator, "devnet");
            defer self.ts_allocator.free(sysContracts);
            
            const genesis = core.genesis.Genesis{
                .config = network,
                .alloc = alloc,
                .systemContracts = sysContracts,
            };
            var genesisBlock = try core.genesis.applyGenesis(self.ts_allocator, self.db_adapter, genesis);
            _ = try self.chain.addBlock(genesisBlock);
            const genesisId = genesisBlock.id();
            self.chain.setGenesisId(genesisId);
        }

        self.p2p_server = try p2p.Server.init(self.ts_allocator, self.chain, self.engine, self.dag_pool, .{
            .listenPort = p2p_port,
            .validatorAddress = try core.accounts.eoa.addressFromPrivKey(miner_priv_key),
            .identityKey = miner_priv_key,
            .enableStun = false,
            .maxPeers = 32,
            .numWorkers = 4,
            .packetPoolSize = 2048,
            .rateLimit = .{
                .baseCapacity = 100_000.0,
                .baseRefill = 50_000.0,
            },
        });

        // RPC Server
        self.rpc_server = try rpc.Server.init(
            self.ts_allocator,
            http_port,
            self.chain,
            self.dag_pool,
            self.dag_executor,
            self.world_state,
        );
        self.rpc_server.setP2P(self.p2p_server);

        // Miner setup if is_miner
        if (is_miner) {
            self.miner = try node.miner.Miner.init(
                self.ts_allocator,
                self.chain,
                self.dag_pool,
                self.engine,
                self.dag_executor,
                self.world_state,
                try core.accounts.eoa.addressFromPrivKey(miner_priv_key),
                &self.running,
                self.block_producer,
            );
            self.miner.?.setP2p(self.p2p_server);

            self.epoch_integration = try node.EpochIntegration.init(self.ts_allocator, self.db_adapter, 100);
            self.miner.?.setEpochIntegration(self.epoch_integration.?);

            // Find validator index
            var our_idx: u32 = 0;
            const val_addr = try core.accounts.eoa.addressFromPrivKey(miner_priv_key);
            for (validators, 0..) |v, vi| {
                if (std.mem.eql(u8, &v.address.bytes, &val_addr.bytes)) {
                    our_idx = @intCast(vi);
                    break;
                }
            }
            self.miner.?.setValidatorIndex(our_idx);
        }

        return self;
    }

    pub fn start(self: *VirtualNode) !void {
        try self.p2p_server.start();
        try self.rpc_server.start();

        if (self.miner) |m| {
            self.running.store(true, .seq_cst);
            m.running.store(true, .seq_cst);
            
            self.miner_thread = try std.Thread.spawn(.{}, struct {
                fn run(miner_ptr: *node.miner.Miner) void {
                    miner_ptr.start() catch |err| {
                        std.log.err("Miner thread crashed: {}", .{err});
                    };
                }
            }.run, .{m});
        }
    }

    pub fn stop(self: *VirtualNode) void {
        self.running.store(false, .seq_cst);
        if (self.miner) |m| {
            m.running.store(false, .seq_cst);
            if (self.miner_thread) |t| {
                t.join();
                self.miner_thread = null;
            }
        }
        
        self.p2p_server.deinit();
        self.rpc_server.deinit();
    }

    pub fn deinit(self: *VirtualNode) void {
        self.stop();
        
        if (self.miner) |m| {
            self.ts_allocator.destroy(m);
        }
        if (self.epoch_integration) |ei| {
            ei.deinit();
        }
        
        self.ts_allocator.destroy(self.block_producer);
        self.ts_allocator.destroy(self.dag_executor);
        
        self.dag_pool.deinit();
        self.chain.deinit();
        
        self.engine.deinit();
        
        self.world_state.deinit();
        self.ts_allocator.destroy(self.world_state);
        
        self.db.close();
        
        self.allocator.free(self.data_dir);
        self.allocator.destroy(self);
    }
};
