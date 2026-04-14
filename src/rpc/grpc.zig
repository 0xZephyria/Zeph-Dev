const log = @import("core").logger;
const std = @import("std");
const p2p_mod = @import("p2p");
const grpc = p2p_mod.grpc;
const core = @import("core");
const types = core.types;
// vm module removed — RISC-V VM is accessed via vm_bridge in main.zig
const SecurityManager = @import("security.zig").SecurityManager;
const encoding = @import("encoding");
const rlp = encoding.rlp;

const Blockchain = core.blockchain.Blockchain;
const TxPool = core.tx_pool.TxPool;
const Executor = core.executor.Executor;

pub const GrpcServer = struct {
    allocator: std.mem.Allocator,
    server: grpc.GrpcServer,
    port: u16,

    // Dependencies
    chain: *Blockchain,
    tx_pool: *TxPool,
    executor: *Executor,
    security: *SecurityManager,
    p2p: ?*p2p_mod.Server,

    pub fn init(allocator: std.mem.Allocator, port: u16, chain: *Blockchain, pool: *TxPool, exec: *Executor) !*GrpcServer {
        const self = try allocator.create(GrpcServer);

        // Init Security
        const sec = try SecurityManager.init(allocator);
        // Load secret
        sec.load_or_generate_secret("./node_data/jwt.hex") catch |err| {
            log.debug("⚠️ Failed to load JWT secret: {}\n", .{err});
        };

        // Use secret for gRPC lib
        // Convert [32]u8 to slice
        const secret_slice = &sec.secret;

        self.* = GrpcServer{
            .allocator = allocator,
            // Library GrpcServer.init returns the struct, not pointer
            .server = try grpc.GrpcServer.init(allocator, port, secret_slice),
            .port = port,
            .chain = chain,
            .tx_pool = pool,
            .executor = exec,
            .security = sec,
            .p2p = null,
        };
        return self;
    }

    pub fn set_p2p(self: *GrpcServer, p2p_server: *p2p_mod.Server) void {
        self.p2p = p2p_server;
    }

    pub fn deinit(self: *GrpcServer) void {
        self.security.deinit();
        self.server.deinit();
        self.allocator.destroy(self);
    }

    pub fn start(self: *GrpcServer) !void {
        log.debug("🚀 Starting gRPC Server (ziglana) on port {}\n", .{self.port});
        const thread = try std.Thread.spawn(.{}, GrpcServer.run, .{self});
        thread.detach();
    }

    fn run(self: *GrpcServer) !void {
        try self.server.start();
    }
};

pub const EthServiceImpl = struct {
    context: *GrpcServer,

    // Helper: Authenticate request
    fn check_auth(self: *EthServiceImpl, ctx: grpc.Context) bool {
        // Stub: In real usage, verify ctx.metadata("authorization")
        _ = self;
        _ = ctx;
        return true;
    }

    // Helper: Hex string to BigInt
    fn hexToU64(allocator: std.mem.Allocator, hex: []const u8) !u64 {
        _ = allocator;
        if (std.mem.startsWith(u8, hex, "0x")) {
            return std.fmt.parseInt(u64, hex[2..], 16);
        }
        return std.fmt.parseInt(u64, hex, 10);
    }

    // --- ETH API ---

    pub fn GetBlockNumber(self: *EthServiceImpl, ctx: grpc.Context, _: void) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        const num = if (self.context.chain.get_head()) |b| b.header.number else 0;
        return std.fmt.allocPrint(self.context.allocator, "0x{x}", .{num});
    }

    pub fn GetBalance(self: *EthServiceImpl, ctx: grpc.Context, req_json: []const u8) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        // Stub parsing req_json to get address str
        // For duplication of Go logic:
        // address = common.HexToAddress(req.Address)
        // blockNumber = req.BlockNumber

        // Mock Implementation due to lack of JSON parser in this file/std lib easily accessible without extensive setup
        // Assuming we rely on Protobuf generated structs which are passed as args (not json strings).
        // Since we are compiling against a hypothetical bindings lib, we assume arg is struct.
        // But for this file I must write code that *compiles* with what we have.

        // We will assume AddressRequest struct (from proto) is passed.
        // req: AddressRequest
        _ = req_json;
        const address = types.Address.zero();
        const bal = self.context.chain.state.get_balance(address);
        return std.fmt.allocPrint(self.context.allocator, "0x{x}", .{bal});
    }

    pub fn SendRawTransaction(self: *EthServiceImpl, ctx: grpc.Context, req_data: []const u8) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;

        // Decode RLP
        var tx = try rlp.decode(self.context.allocator, types.Transaction, req_data);

        // Add to Pool
        try self.context.tx_pool.add(&tx);

        return std.fmt.allocPrint(self.context.allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&tx.hash().bytes)});
    }

    pub fn GetBlockByNumber(self: *EthServiceImpl, ctx: grpc.Context, req_num: []const u8) ![]const u8 {
        _ = req_num; // Avoid unused variable error
        if (!self.check_auth(ctx)) return error.Unauthorized;
        // Mock parse req_num
        const num = 0;

        if (self.context.chain.get_block_by_number(num)) |block| {
            // Serialize Block to JSON/Protobuf response
            // For now, return Hash as stub of full block
            return std.fmt.allocPrint(self.context.allocator, "Block 0x{s}", .{std.fmt.fmtSliceHexLower(&block.hash().bytes)});
        }
        return "null";
    }

    pub fn GetBlockByHash(self: *EthServiceImpl, ctx: grpc.Context, req_hash: []const u8) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        // Mock hash
        _ = req_hash;
        // Use chain logic
        // if (self.context.chain.get_block_by_hash(hash)) ...
        return "null";
    }

    pub fn Call(self: *EthServiceImpl, ctx: grpc.Context, req_data: []const u8) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        // Simulate execution
        // 1. Create Overlay
        var overlay = try self.context.chain.state.new_overlay();
        defer overlay.deinit();

        // 2. Mock execution result
        // In real logic, we'd set up EVM with overlay and run bytes.
        _ = req_data;

        return "0x";
    }

    pub fn ChainId(self: *EthServiceImpl, ctx: grpc.Context, _: void) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        return std.fmt.allocPrint(self.context.allocator, "0x{x}", .{self.context.chain.chain_id});
    }

    // --- NET API ---

    pub fn NetVersion(self: *EthServiceImpl, ctx: grpc.Context, _: void) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        return std.fmt.allocPrint(self.context.allocator, "{}", .{self.context.chain.chain_id});
    }

    pub fn NetListening(self: *EthServiceImpl, ctx: grpc.Context, _: void) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        return "true";
    }

    pub fn NetPeerCount(self: *EthServiceImpl, ctx: grpc.Context, _: void) ![]const u8 {
        if (!self.check_auth(ctx)) return error.Unauthorized;
        var count: usize = 0;
        if (self.context.p2p) |p| {
            count = p.peers.items.len;
        }
        return std.fmt.allocPrint(self.context.allocator, "0x{x}", .{count});
    }

    // --- WEB3 API ---

    pub fn ClientVersion(self: *EthServiceImpl, ctx: grpc.Context, _: void) ![]const u8 {
        _ = self;
        _ = ctx;
        return "Zephyria/v1.0.0/zig";
    }
};
