const log = @import("core").logger;
const std = @import("std");
const core = @import("core");
const p2p = @import("p2p");
const types = core.types;
const encoding = @import("encoding");
const rlp = encoding.rlp;
const storage = @import("storage");
const hex = @import("utils").hex;
const filters = @import("filters.zig");

pub const RpcHandler = struct {
    allocator: std.mem.Allocator,
    chain: *core.blockchain.Blockchain,
    dagPool: *core.dag_mempool.DAGMempool,
    dagExecutor: *core.dag_executor.DAGExecutor,
    state: *core.state.State,
    p2p: ?*p2p.Server,

    // Historical state for time-travel queries (optional)
    historical: ?*core.HistoricalState,

    /// Filter engine for eth_newFilter / eth_getLogs
    filterEngine: filters.FilterEngine,

    /// Block filter tracking (filter_id → last_seen_block)
    blockFilters: std.AutoHashMap(u64, u64),
    nextFilterId: u64,

    /// Node start time for uptime reporting
    nodeStartTime: i64,

    pub fn init(
        allocator: std.mem.Allocator,
        chain: *core.blockchain.Blockchain,
        dagPool: *core.dag_mempool.DAGMempool,
        dagExecutor: *core.dag_executor.DAGExecutor,
        state: *core.state.State,
    ) RpcHandler {
        return .{
            .allocator = allocator,
            .chain = chain,
            .dagPool = dagPool,
            .dagExecutor = dagExecutor,
            .state = state,
            .p2p = null,
            .historical = null,
            .filterEngine = filters.FilterEngine.init(allocator),
            .blockFilters = std.AutoHashMap(u64, u64).init(allocator),
            .nextFilterId = 0x10000,
            .nodeStartTime = std.time.timestamp(),
        };
    }

    /// Connect historical state for time-travel queries
    pub fn setHistoricalState(self: *RpcHandler, hist: *core.HistoricalState) void {
        self.historical = hist;
    }

    pub fn setP2p(self: *RpcHandler, p2pServer: *p2p.Server) void {
        self.p2p = p2pServer;
    }

    pub fn setDagPool(self: *RpcHandler, dagPool: *core.dag_mempool.DAGMempool) void {
        self.dagPool = dagPool;
    }

    pub fn handleRequest(self: *RpcHandler, allocator: std.mem.Allocator, method: []const u8, params: std.json.Value) anyerror!std.json.Value {
        if (std.mem.eql(u8, method, "eth_chainId")) {
            return self.ethChainId(allocator);
        } else if (std.mem.eql(u8, method, "eth_blockNumber")) {
            return self.ethBlockNumber(allocator);
        } else if (std.mem.eql(u8, method, "net_version")) {
            return self.netVersion(allocator);
        } else if (std.mem.eql(u8, method, "web3_clientVersion")) {
            return std.json.Value{ .string = "forgeyria/v1.0.0" };
        } else if (std.mem.eql(u8, method, "eth_getBalance")) {
            return self.ethGetBalance(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_sendRawTransaction")) {
            return self.ethSendRawTransaction(allocator, params);
        } else if (std.mem.eql(u8, method, "forge_getBalance")) {
            return self.forgeGetBalance(allocator, params);
        } else if (std.mem.eql(u8, method, "forge_sendTransaction")) {
            return self.forgeSendTransaction(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getTransactionCount")) {
            return self.ethGetTransactionCount(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getBlockByNumber")) {
            return self.ethGetBlockByNumber(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_estimateGas")) {
            return self.ethEstimateGas(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_gasPrice")) {
            return self.ethGasPrice(allocator);
        } else if (std.mem.eql(u8, method, "eth_maxPriorityFeePerGas")) {
            return self.ethMaxPriorityFeePerGas(allocator);
        } else if (std.mem.eql(u8, method, "eth_feeHistory")) {
            return self.ethFeeHistory(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_call")) {
            return self.ethCall(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getCode")) {
            return self.ethGetCode(allocator, params);
        } else if (std.mem.eql(u8, method, "net_listening")) {
            return self.netListening(allocator);
        } else if (std.mem.eql(u8, method, "net_peerCount")) {
            return self.netPeerCount(allocator);
        } else if (std.mem.eql(u8, method, "eth_getTransactionReceipt")) {
            return self.ethGetTransactionReceipt(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getBlockByHash")) {
            return self.ethGetBlockByHash(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_sendTransaction")) {
            return self.ethSendTransaction(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getTransactionByHash")) {
            return self.ethGetTransactionByHash(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getStorageAt")) {
            return self.ethGetStorageAt(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_accounts")) {
            return self.ethAccounts(allocator);
        } else if (std.mem.eql(u8, method, "eth_syncing")) {
            return self.ethSyncing(allocator);
        } else if (std.mem.eql(u8, method, "eth_getLogs")) {
            return self.ethGetLogs(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_mining")) {
            return self.ethMining(allocator);
        } else if (std.mem.eql(u8, method, "eth_hashrate")) {
            return self.ethHashrate(allocator);
        } else if (std.mem.eql(u8, method, "eth_getBlockTransactionCountByNumber")) {
            return self.ethGetBlockTransactionCountByNumber(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getBlockTransactionCountByHash")) {
            return self.ethGetBlockTransactionCountByHash(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getUncleCountByBlockNumber")) {
            return self.ethGetUncleCountByBlockNumber(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getUncleCountByBlockHash")) {
            return self.ethGetUncleCountByBlockHash(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_protocolVersion")) {
            return self.ethProtocolVersion(allocator);
            // ── New eth_* methods ──
        } else if (std.mem.eql(u8, method, "eth_getTransactionByBlockNumberAndIndex")) {
            return self.ethGetTransactionByBlockNumberAndIndex(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getTransactionByBlockHashAndIndex")) {
            return self.ethGetTransactionByBlockHashAndIndex(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_newFilter")) {
            return self.ethNewFilter(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_newBlockFilter")) {
            return self.ethNewBlockFilter(allocator);
        } else if (std.mem.eql(u8, method, "eth_getFilterChanges")) {
            return self.ethGetFilterChanges(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_getFilterLogs")) {
            return self.ethGetFilterLogs(allocator, params);
        } else if (std.mem.eql(u8, method, "eth_uninstallFilter")) {
            return self.ethUninstallFilter(allocator, params);
        } else if (std.mem.eql(u8, method, "web3_sha3")) {
            return self.web3Sha3(allocator, params);
            // ── Zephyria-Specific RPC Methods ──
        } else if (std.mem.eql(u8, method, "forge_getDAGMetrics")) {
            return self.forgeGetDAGMetrics(allocator);
        } else if (std.mem.eql(u8, method, "forge_getThreadInfo")) {
            return self.forgeGetThreadInfo(allocator);
        } else if (std.mem.eql(u8, method, "forge_getAccountTypes")) {
            return self.forgeGetAccountTypes(allocator);
        } else if (std.mem.eql(u8, method, "forge_getNodeInfo")) {
            return self.forgeGetNodeInfo(allocator);
        } else if (std.mem.eql(u8, method, "forge_getMempoolStats")) {
            return self.forgeGetMempoolStats(allocator);
        } else if (std.mem.eql(u8, method, "forge_getMempoolContent")) {
            return self.forgeGetMempoolContent(allocator);
        } else if (std.mem.eql(u8, method, "forge_getBlockProducerInfo")) {
            return self.forgeGetBlockProducerInfo(allocator);
        } else if (std.mem.eql(u8, method, "forge_getPeers")) {
            return self.forgeGetPeers(allocator);
        } else if (std.mem.eql(u8, method, "forge_getVMStats")) {
            return self.forgeGetVMStats(allocator);
        } else if (std.mem.eql(u8, method, "forge_getShardDistribution")) {
            return self.forgeGetShardDistribution(allocator);
        } else if (std.mem.eql(u8, method, "forge_getConfig")) {
            return self.forgeGetConfig(allocator);
        } else if (std.mem.eql(u8, method, "forge_getExecutorStats")) {
            return self.forgeGetExecutorStats(allocator);
        } else if (std.mem.eql(u8, method, "forge_getStateMetrics")) {
            return self.forgeGetStateMetrics(allocator);
        } else if (std.mem.eql(u8, method, "forge_getChainMetrics")) {
            return self.forgeGetChainMetrics(allocator);
        } else if (std.mem.eql(u8, method, "forge_pendingTransactions")) {
            return self.forgePendingTransactions(allocator);
        } else if (std.mem.eql(u8, method, "forge_compileEOF") or std.mem.eql(u8, method, "forge_compile") or std.mem.eql(u8, method, "forgecompile")) {
            return self.forgeCompileEOF(allocator, params);
        }

        return error.MethodNotFound;
    }

    // Methods

    fn ethChainId(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        const chain_id = self.chain.chainId;
        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{chain_id}) };
    }

    fn ethGasPrice(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        // Compute from recent block base fees if available
        if (self.chain.currentBlock) |head| {
            const base_fee = head.header.baseFee;
            if (base_fee > 0) {
                // gas_price = base_fee + priority_fee (2 Gwei)
                const priority_fee: u256 = 2_000_000_000;
                const price = base_fee + priority_fee;
                return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{price}) };
            }
        }
        // Fallback: 20 Gwei
        return std.json.Value{ .string = "0x4a817c800" };
    }

    fn ethMaxPriorityFeePerGas(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        _ = allocator;
        // Return 2 Gwei (matches Go default)
        return std.json.Value{ .string = "0x77359400" };
    }

    fn ethFeeHistory(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = self;
        var count: usize = 1;
        if (params == .array and params.array.items.len > 0) {
            const v = params.array.items[0];
            if (v == .integer) {
                count = @as(usize, @intCast(v.integer));
            } else if (v == .string) {
                const s = v.string;
                const trimmed = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
                count = try std.fmt.parseInt(usize, trimmed, 16);
            }
        }

        if (count > 1024) count = 1024;

        // Count percentiles
        var percentile_count: usize = 0;
        if (params.array.items.len > 2 and params.array.items[2] == .array) {
            percentile_count = params.array.items[2].array.items.len;
        }

        var map = std.json.ObjectMap.init(allocator);
        // Minimal valid fee history
        try map.put("oldestBlock", std.json.Value{ .string = "0x1" });

        var baseFees = std.json.Array.init(allocator);
        var gasRatios = std.json.Array.init(allocator);
        var rewards = std.json.Array.init(allocator);

        // Fill arrays
        var i: usize = 0;
        while (i < count) : (i += 1) {
            try baseFees.append(std.json.Value{ .string = "0x430e23400" });
            try gasRatios.append(std.json.Value{ .float = 0.0 });

            var block_rewards = std.json.Array.init(allocator);
            var j: usize = 0;
            while (j < percentile_count) : (j += 1) {
                // Return 2 Gwei (0x77359400) for every requested percentile
                try block_rewards.append(std.json.Value{ .string = "0x77359400" });
            }
            try rewards.append(std.json.Value{ .array = block_rewards });
        }
        // baseFee needs count + 1 items
        try baseFees.append(std.json.Value{ .string = "0x430e23400" });

        try map.put("baseFeePerGas", std.json.Value{ .array = baseFees });
        try map.put("gasUsedRatio", std.json.Value{ .array = gasRatios });
        try map.put("reward", std.json.Value{ .array = rewards });
        return std.json.Value{ .object = map };
    }

    fn ethEstimateGas(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        log.debug("[RPC] ethEstimateGas\n", .{});
        if (params != .array or params.array.items.len < 1) {
            // Default: simple transfer
            return std.json.Value{ .string = "0x5208" };
        }
        const tx_obj = params.array.items[0];
        if (tx_obj != .object) {
            return std.json.Value{ .string = "0x5208" };
        }

        // Parse fields from the call object
        const to_str = if (tx_obj.object.get("to")) |v| (if (v == .string) v.string else null) else null;
        const data_str = if (tx_obj.object.get("data")) |v| (if (v == .string) v.string else null) else if (tx_obj.object.get("input")) |v| (if (v == .string) v.string else null) else null;

        // Calculate intrinsic gas
        var gas: u64 = 21000; // Base tx cost

        // Contract creation adds 32000
        if (to_str == null) {
            gas += 32000;
        }

        // Data cost: 4 gas per zero byte, 16 gas per non-zero byte
        if (data_str) |ds| {
            const data_bytes = hex.decode(allocator, ds) catch &[_]u8{};
            defer if (data_bytes.len > 0) allocator.free(data_bytes);
            for (data_bytes) |b| {
                gas += if (b == 0) @as(u64, 4) else @as(u64, 16);
            }
        }

        // VM simulation for gas estimation
        if (self.dagExecutor.vmCallback != null) {
            const from_str = if (tx_obj.object.get("from")) |v| (if (v == .string) v.string else null) else null;
            var from_addr: types.Address = types.Address.zero();
            if (from_str) |fs| {
                const trimmed = if (std.mem.startsWith(u8, fs, "0x")) fs[2..] else fs;
                _ = std.fmt.hexToBytes(&from_addr.bytes, trimmed) catch {};
            }

            const value_str = if (tx_obj.object.get("value")) |v| (if (v == .string) v.string else null) else null;
            const value: u256 = if (value_str) |vs| blk: {
                const trimmed = if (std.mem.startsWith(u8, vs, "0x")) vs[2..] else vs;
                break :blk std.fmt.parseInt(u256, trimmed, 16) catch 0;
            } else 0;

            const call_data = if (data_str) |ds|
                (hex.decode(allocator, ds) catch &[_]u8{})
            else
                &[_]u8{};
            defer if (call_data.len > 0) allocator.free(call_data);

            if (to_str == null and call_data.len > 0) {
                // Contract creation — simulate initcode execution

                var overlay = core.state.Overlay.init(allocator, self.state);
                defer overlay.deinit();

                const vm_result = self.dagExecutor.vmCallback.?.execute(call_data, call_data, 30_000_000, &overlay, from_addr, value);
                defer if (vm_result.returnData.len > 0) self.allocator.free(vm_result.returnData);
                if (vm_result.success) {
                    gas += vm_result.gasUsed;
                }
            } else if (to_str) |ts| {
                // Contract call — simulate on existing code
                var to_addr: types.Address = undefined;
                const trimmed = if (std.mem.startsWith(u8, ts, "0x")) ts[2..] else ts;
                _ = std.fmt.hexToBytes(&to_addr.bytes, trimmed) catch {
                    return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{gas}) };
                };

                const code = self.state.getCode(to_addr) catch &[_]u8{};
                defer if (code.len > 0) self.state.allocator.free(code);

                if (code.len > 0) {
                    var overlay = self.state.newOverlay() catch {
                        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{gas}) };
                    };
                    defer overlay.deinit();

                    const vm_result = self.dagExecutor.vmCallback.?.execute(code, call_data, 30_000_000, &overlay, from_addr, value);
                    defer if (vm_result.returnData.len > 0) self.allocator.free(vm_result.returnData);
                    if (vm_result.success) {
                        gas = 21000 + vm_result.gasUsed;
                    }
                }
            }
        }

        // Add 20% safety margin (standard practice)
        gas = gas + (gas / 5);

        // Cap at block gas limit
        const block_gas_limit: u64 = 30_000_000;
        if (gas > block_gas_limit) gas = block_gas_limit;

        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{gas}) };
    }

    fn ethCall(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        log.debug("[RPC] ethCall\n", .{});
        if (params != .array or params.array.items.len < 1) return std.json.Value{ .string = "0x" };
        const tx_obj = params.array.items[0];
        if (tx_obj != .object) return std.json.Value{ .string = "0x" };

        // Parse "to" address — required for ethCall
        const to_str = if (tx_obj.object.get("to")) |v| (if (v == .string) v.string else null) else null;
        if (to_str == null) return std.json.Value{ .string = "0x" };

        var to_addr: types.Address = undefined;
        const trimmed_to = if (std.mem.startsWith(u8, to_str.?, "0x")) to_str.?[2..] else to_str.?;
        _ = try std.fmt.hexToBytes(&to_addr.bytes, trimmed_to);

        // Check if target has code
        const code = self.state.getCode(to_addr) catch &[_]u8{};
        defer if (code.len > 0) self.state.allocator.free(code);

        if (code.len == 0 or self.dagExecutor.vmCallback == null) {
            return std.json.Value{ .string = "0x" };
        }

        // Parse from, value, data
        const from_str = if (tx_obj.object.get("from")) |v| (if (v == .string) v.string else null) else null;
        var from_addr: types.Address = types.Address.zero();
        if (from_str) |fs| {
            const trimmed = if (std.mem.startsWith(u8, fs, "0x")) fs[2..] else fs;
            _ = std.fmt.hexToBytes(&from_addr.bytes, trimmed) catch {};
        }

        const data_str = if (tx_obj.object.get("data")) |v| (if (v == .string) v.string else null) else if (tx_obj.object.get("input")) |v| (if (v == .string) v.string else null) else null;
        const call_data = if (data_str) |ds|
            (hex.decode(allocator, ds) catch &[_]u8{})
        else
            &[_]u8{};
        defer if (call_data.len > 0) allocator.free(call_data);

        const value_str = if (tx_obj.object.get("value")) |v| (if (v == .string) v.string else null) else null;
        const value: u256 = if (value_str) |vs| blk: {
            const trimmed = if (std.mem.startsWith(u8, vs, "0x")) vs[2..] else vs;
            break :blk std.fmt.parseInt(u256, trimmed, 16) catch 0;
        } else 0;

        // Execute on a read-only overlay (not committed)
        var overlay = try self.state.newOverlay();
        defer overlay.deinit();

        const vm_result = self.dagExecutor.vmCallback.?.execute(code, call_data, 30_000_000, &overlay, from_addr, value);
        defer if (vm_result.returnData.len > 0) self.allocator.free(vm_result.returnData);

        if (vm_result.success and vm_result.returnData.len > 0) {
            const hex_out = try hex.encode(allocator, vm_result.returnData);
            return std.json.Value{ .string = hex_out };
        }

        return std.json.Value{ .string = "0x" };
    }

    fn ethGetCode(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const addr_str = params.array.items[0].string;
        log.debug("[RPC] ethGetCode: {s}\n", .{addr_str});

        var address: types.Address = undefined;
        const trimmed = if (std.mem.startsWith(u8, addr_str, "0x")) addr_str[2..] else addr_str;
        _ = try std.fmt.hexToBytes(&address.bytes, trimmed);

        const code = try self.state.getCode(address);
        defer self.state.allocator.free(code);

        log.debug("[RPC] ethGetCode: Len={d}\n", .{code.len});

        // hex imported at top level
        const encoded = try hex.encode(allocator, code);
        const result_str = try std.fmt.allocPrint(allocator, "0x{s}", .{encoded});
        return std.json.Value{ .string = result_str };
    }

    fn netVersion(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "{d}", .{self.chain.chainId}) };
    }

    fn ethBlockNumber(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        const height = self.chain.getHeadNumber();
        log.debug("[RPC] ethBlockNumber: {d}\n", .{height});
        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{height}) };
    }

    fn netListening(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        _ = allocator;
        return std.json.Value{ .bool = true };
    }

    fn netPeerCount(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var count: usize = 0;
        if (self.p2p) |p| {
            p.mutex.lock();
            defer p.mutex.unlock();
            count = p.peers.items.len;
        }
        var b: [32]u8 = undefined;
        const out = try hex.toHexBuffer(&b, count);
        return std.json.Value{ .string = try allocator.dupe(u8, out) };
    }

    fn ethGetBalance(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        // Ethereum-compatible: params: [address, blockTag]
        // blockTag can be: "latest", "earliest", "pending", or hex block number
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;

        const addr_str = params.array.items[0].string;
        var address: types.Address = undefined;
        const trimmed = if (std.mem.startsWith(u8, addr_str, "0x")) addr_str[2..] else addr_str;
        _ = try std.fmt.hexToBytes(&address.bytes, trimmed);

        // Parse block tag (default to "latest")
        const block_tag: []const u8 = if (params.array.items.len > 1 and params.array.items[1] == .string)
            params.array.items[1].string
        else
            "latest";

        const balance = try self.getBalanceAt(address, block_tag);

        // Return as proper Ethereum quantity hex (0x-prefixed, no leading zeros)
        // hex imported at top level
        return std.json.Value{ .string = try hex.toHex(allocator, balance) };
    }

    fn forgeGetBalance(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        // Ethereum-compatible: params: [address, blockTag]
        // blockTag can be: "latest", "earliest", "pending", or hex block number
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;

        const addr_str = params.array.items[0].string;
        var address: types.Address = undefined;
        const trimmed = if (std.mem.startsWith(u8, addr_str, "0x")) addr_str[2..] else addr_str;
        _ = try std.fmt.hexToBytes(&address.bytes, trimmed);

        // Parse block tag (default to "latest")
        const block_tag: []const u8 = if (params.array.items.len > 1 and params.array.items[1] == .string)
            params.array.items[1].string
        else
            "latest";

        const balance = try self.getBalanceAt(address, block_tag);

        // Return as proper Ethereum quantity hex (0x-prefixed, no leading zeros)
        // hex imported at top level
        return std.json.Value{ .string = try hex.toHex(allocator, balance) };
    }

    fn ethGetTransactionCount(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        // Ethereum-compatible: params: [address, blockTag]
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;

        const addr_str = params.array.items[0].string;
        var address: types.Address = undefined;
        const trimmed = if (std.mem.startsWith(u8, addr_str, "0x")) addr_str[2..] else addr_str;
        _ = try std.fmt.hexToBytes(&address.bytes, trimmed);

        // Parse block tag (default to "latest")
        const block_tag: []const u8 = if (params.array.items.len > 1 and params.array.items[1] == .string)
            params.array.items[1].string
        else
            "latest";

        var nonce = try self.getNonceAt(address, block_tag);

        // For "pending" tag: use DAG mempool nonce
        if (std.mem.eql(u8, block_tag, "pending")) {
            nonce = self.dagPool.pendingNonce(address);
        }

        log.debug("[RPC] ethGetTransactionCount: Tag={s} -> Nonce={d}\n", .{ block_tag, nonce });
        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{nonce}) };
    }

    /// Get balance at a specific block (Ethereum-compatible)
    fn getBalanceAt(self: *RpcHandler, address: types.Address, block_tag: []const u8) !u256 {
        // Handle special tags
        if (std.mem.eql(u8, block_tag, "latest") or std.mem.eql(u8, block_tag, "pending")) {
            return self.state.getBalance(address);
        }

        if (std.mem.eql(u8, block_tag, "earliest")) {
            // Block 0 - query historical state
            if (self.historical) |hist| {
                return hist.getBalanceAt(address, 0);
            }
            return 0; // Genesis balance
        }

        // Parse hex block number
        const trimmed = if (std.mem.startsWith(u8, block_tag, "0x")) block_tag[2..] else block_tag;
        const block_num = std.fmt.parseInt(u64, trimmed, 16) catch {
            return self.state.getBalance(address); // Fallback to latest
        };

        // Check if querying historical block
        const head = self.chain.getHeadNumber();
        if (block_num >= head) {
            // Current or future block - use current state
            return self.state.getBalance(address);
        }

        // Historical query - use HistoricalState if available
        if (self.historical) |hist| {
            return hist.getBalanceAt(address, block_num);
        }

        // No historical state connected - return current balance with warning
        std.log.warn("Historical query for block {d} but no HistoricalState connected", .{block_num});
        return self.state.getBalance(address);
    }

    /// Get nonce at a specific block (Ethereum-compatible)
    fn getNonceAt(self: *RpcHandler, address: types.Address, block_tag: []const u8) !u64 {
        if (std.mem.eql(u8, block_tag, "latest") or std.mem.eql(u8, block_tag, "pending")) {
            return self.state.getNonce(address);
        }

        if (std.mem.eql(u8, block_tag, "earliest")) {
            if (self.historical) |hist| {
                return hist.getNonceAt(address, 0);
            }
            return 0;
        }

        const trimmed = if (std.mem.startsWith(u8, block_tag, "0x")) block_tag[2..] else block_tag;
        const block_num = std.fmt.parseInt(u64, trimmed, 16) catch {
            return self.state.getNonce(address);
        };

        const head = self.chain.getHeadNumber();
        if (block_num >= head) {
            return self.state.getNonce(address);
        }

        if (self.historical) |hist| {
            return hist.getNonceAt(address, block_num);
        }

        return self.state.getNonce(address);
    }

    fn ethSendRawTransaction(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;

        const raw_tx_hex = params.array.items[0].string;
        log.debug("[RPC] ethSendRawTransaction: len={d}\n", .{raw_tx_hex.len});

        const trimmed = if (std.mem.startsWith(u8, raw_tx_hex, "0x")) raw_tx_hex[2..] else raw_tx_hex;
        const actual_bytes = hex.decode(allocator, trimmed) catch |err| {
            log.debug("[RPC] hex decode failed: {}\n", .{err});
            return error.InvalidParams;
        };

        // Decode RLP transaction
        const tx_decode = @import("core").tx_decode;
        const tx = tx_decode.decodeTransaction(allocator, actual_bytes) catch |err| {
            log.debug("[RPC] TX decode failed: {}\n", .{err});
            return error.InvalidParams;
        };

        const heap_tx = try self.allocator.create(types.Transaction);
        heap_tx.* = tx;
        heap_tx.data = try self.allocator.dupe(u8, tx.data);

        // Add to DAG mempool
        self.dagPool.add(heap_tx) catch |err| {
            log.debug("[RPC] DAG mempool rejected TX: {}\n", .{err});
            heap_tx.deinit(self.allocator);
            self.allocator.destroy(heap_tx);

            // For nonce-too-low or already-known, just return the hash so MetaMask doesn't hang
            if (err == error.NonceTooLow or err == error.InsufficientFunds or err == error.IntrinsicGasTooLow) {
                var hash_out: [32]u8 = undefined;
                const h = tx.hash();
                @memcpy(&hash_out, &h.bytes);
                return std.json.Value{ .string = try hex.encode(allocator, &hash_out) };
            }
            return err;
        };

        // Return Hash
        var hash_out: [32]u8 = undefined;
        const hash = tx.hash();
        @memcpy(&hash_out, &hash.bytes);
        return std.json.Value{ .string = try hex.encode(allocator, &hash_out) };
    }

    fn forgeSendTransaction(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;

        const raw_tx_hex = params.array.items[0].string;
        log.debug("[RPC] forgeSendTransaction: len={d}\n", .{raw_tx_hex.len});

        const trimmed = if (std.mem.startsWith(u8, raw_tx_hex, "0x")) raw_tx_hex[2..] else raw_tx_hex;
        const actual_bytes = hex.decode(allocator, trimmed) catch |err| {
            log.debug("[RPC] hex decode failed: {}\n", .{err});
            return error.InvalidParams;
        };

        // Decode RLP transaction
        const tx_decode = @import("core").tx_decode;
        const tx = tx_decode.decodeTransaction(allocator, actual_bytes) catch |err| {
            log.debug("[RPC] TX decode failed: {}\n", .{err});
            return error.InvalidParams;
        };

        const heap_tx = try self.allocator.create(types.Transaction);
        heap_tx.* = tx;
        heap_tx.data = try self.allocator.dupe(u8, tx.data);

        // Add to DAG mempool
        self.dagPool.add(heap_tx) catch |err| {
            log.debug("[RPC] DAG mempool rejected TX: {}\n", .{err});
            heap_tx.deinit(self.allocator);
            self.allocator.destroy(heap_tx);
            return err;
        };

        // Return Hash
        var hash_out: [32]u8 = undefined;
        const hash = tx.hash();
        @memcpy(&hash_out, &hash.bytes);
        return std.json.Value{ .string = try hex.encode(allocator, &hash_out) };
    }

    fn formatBlock(self: *RpcHandler, allocator: std.mem.Allocator, block: *types.Block, full_tx: bool) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);
        // hex imported at top level

        var buf: [66]u8 = undefined;

        // Number
        try map.put("number", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.number}) });

        var h_res: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        const encoded = try block.header.rlpEncode(allocator);
        defer allocator.free(encoded);
        hasher.update(encoded);
        hasher.final(&h_res);

        try map.put("hash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &h_res)) });
        try map.put("parentHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &block.header.parentHash.bytes)) });
        try map.put("stateRoot", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &block.header.verkleRoot.bytes)) });

        // PoS-compatible fields
        const zero_hash = [_]u8{0} ** 32;
        try map.put("sha3Uncles", std.json.Value{ .string = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347" });
        try map.put("miner", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &block.header.coinbase.bytes)) });
        try map.put("transactionsRoot", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &block.header.txHash.bytes)) });
        try map.put("receiptsRoot", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &zero_hash)) });
        try map.put("logsBloom", std.json.Value{ .string = "0x" ++ "00" ** 256 });
        try map.put("difficulty", std.json.Value{ .string = "0x0" });
        try map.put("totalDifficulty", std.json.Value{ .string = "0x0" });
        try map.put("extraData", std.json.Value{ .string = try hex.encode(allocator, block.header.extraData) });
        try map.put("size", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{encoded.len}) });
        try map.put("mixHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &zero_hash)) });
        try map.put("nonce", std.json.Value{ .string = "0x0000000000000000" }); // PoS zero nonce
        try map.put("uncles", std.json.Value{ .array = std.json.Array.init(allocator) });
        try map.put("withdrawals", std.json.Value{ .array = std.json.Array.init(allocator) });
        try map.put("withdrawalsRoot", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &zero_hash)) });

        // Transactions
        var txs = std.json.Array.init(allocator);
        for (block.transactions, 0..) |tx, i| {
            if (full_tx) {
                var tx_map = std.json.ObjectMap.init(allocator);
                try tx_map.put("hash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.hash().bytes)) });
                try tx_map.put("nonce", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.nonce}) });
                try tx_map.put("blockHash", map.get("hash").?);
                try tx_map.put("blockNumber", map.get("number").?);
                try tx_map.put("transactionIndex", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{i}) });
                try tx_map.put("from", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.from.bytes)) });
                if (tx.to) |to| {
                    try tx_map.put("to", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &to.bytes)) });
                } else {
                    try tx_map.put("to", std.json.Value.null);
                }
                try tx_map.put("value", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.value}) });
                try tx_map.put("gas", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasLimit}) });
                try tx_map.put("gasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasPrice}) });
                try tx_map.put("input", std.json.Value{ .string = try hex.encode(allocator, tx.data) });
                try tx_map.put("type", std.json.Value{ .string = "0x2" }); // Default to EIP-1559 for now
                try tx_map.put("chainId", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{self.chain.chainId}) });
                // Signature
                try tx_map.put("v", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.v}) });
                var r_bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &r_bytes, tx.r, .big);
                try tx_map.put("r", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &r_bytes)) });
                var s_bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &s_bytes, tx.s, .big);
                try tx_map.put("s", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &s_bytes)) });

                try txs.append(std.json.Value{ .object = tx_map });
            } else {
                try txs.append(std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.hash().bytes)) });
            }
        }
        try map.put("transactions", std.json.Value{ .array = txs });

        // Timestamp and gas
        try map.put("timestamp", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.time}) });
        try map.put("gasLimit", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.gasLimit}) });
        try map.put("gasUsed", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.gasUsed}) });
        try map.put("baseFeePerGas", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.baseFee}) });

        return std.json.Value{ .object = map };
    }
    fn ethGetBlockByNumber(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const block_tag = params.array.items[0].string;
        const full_tx = if (params.array.items.len > 1) params.array.items[1].bool else false;

        var block: ?*types.Block = null;

        if (std.mem.eql(u8, block_tag, "latest")) {
            if (self.chain.currentBlock) |head| {
                // Return copy via get_block_by_number using head number
                block = self.chain.getBlockByNumber(head.header.number);
            }
            // Fallback: use get_block_by_number with current height if head is null or whatever logic
            // Actually self.chain.currentBlock might be the way.
            // Let's assume getBlockByNumber works.
            // block = self.chain.getBlockByNumber(self.chain.height);
            // Let's stick to safe path: parse hex or special tags.
        }

        if (block == null) {
            // Try parsing number
            if (std.mem.startsWith(u8, block_tag, "0x")) {
                const num = std.fmt.parseInt(u64, block_tag[2..], 16) catch return error.InvalidParams;
                block = self.chain.getBlockByNumber(num);
            } else if (std.mem.eql(u8, block_tag, "latest")) {
                // If currentBlock is null, maybe genesis?
                // self.chain.currentBlock is ?*Block
                if (self.chain.currentBlock) |head| {
                    block = self.chain.getBlockByNumber(head.header.number);
                }
            } else if (std.mem.eql(u8, block_tag, "earliest")) {
                block = self.chain.getBlockByNumber(0);
            }
        }

        if (block) |b| {
            defer self.chain.freeBlock(b);
            return self.formatBlock(allocator, b, full_tx);
        }
        return std.json.Value.null;
    }
    fn ethGetTransactionReceipt(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const tx_hash_hex = params.array.items[0].string;
        log.debug("[RPC] eth_getTransactionReceipt: {s}\n", .{tx_hash_hex});

        var tx_hash: types.Hash = undefined;
        const trimmed = if (std.mem.startsWith(u8, tx_hash_hex, "0x")) tx_hash_hex[2..] else tx_hash_hex;
        _ = std.fmt.hexToBytes(&tx_hash.bytes, trimmed) catch {
            return error.InvalidParams;
        };

        // 1. Get Transaction Location (catch errors gracefully)
        const loc = self.chain.getTransactionLocation(tx_hash) catch |err| {
            log.debug("[RPC] getTransactionLocation error: {}\n", .{err});
            return std.json.Value.null;
        };

        if (loc) |location| {
            log.debug("[RPC] Tx found at block, index {d}\n", .{location.txIndex});
            // 2. Get Block (catch RLP decode errors gracefully — corrupted/migrated data)
            const block = self.chain.getBlockByHash(location.blockHash) catch |err| {
                log.debug("[RPC] getBlockByHash failed (RLP issue?): {}\n", .{err});
                return std.json.Value.null;
            };

            if (block) |b| {
                defer self.chain.freeBlock(b);

                // 3. Find Transaction (we know index)
                if (location.txIndex >= b.transactions.len) {
                    log.debug("[RPC] Tx index {} out of bounds (len {})\n", .{ location.txIndex, b.transactions.len });
                    return std.json.Value.null;
                }
                const tx = b.transactions[location.txIndex];

                // Recover real sender address from signature (decodeFromRLP sets from=zero)
                const tx_decode = @import("core").tx_decode;
                const real_from = tx_decode.recoverFromTx(allocator, tx) catch tx.from;

                // 4. Construct Receipt
                var map = std.json.ObjectMap.init(allocator);
                // hex imported at top level

                try map.put("transactionHash", std.json.Value{ .string = try hex.encode(allocator, &tx_hash.bytes) });
                try map.put("transactionIndex", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{location.txIndex}) });
                try map.put("blockHash", std.json.Value{ .string = try hex.encode(allocator, &location.blockHash.bytes) });
                try map.put("blockNumber", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{b.header.number}) });
                try map.put("from", std.json.Value{ .string = try hex.encode(allocator, &real_from.bytes) });

                log.debug("[RPC] Returning valid receipt for block {d}\n", .{b.header.number});

                if (tx.to) |to| {
                    try map.put("to", std.json.Value{ .string = try hex.encode(allocator, &to.bytes) });
                    try map.put("contractAddress", std.json.Value.null);
                } else {
                    try map.put("to", std.json.Value.null);
                    const contract_addr = tx.deriveContractAddress();
                    try map.put("contractAddress", std.json.Value{ .string = try hex.encode(allocator, &contract_addr.bytes) });
                }

                try map.put("cumulativeGasUsed", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasLimit}) });
                try map.put("gasUsed", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasLimit}) });

                // EIP-1559 fields
                var effective_gas_price = tx.gasPrice;
                if (b.header.baseFee > 0) {
                    effective_gas_price = b.header.baseFee + (if (tx.gasPrice > b.header.baseFee) tx.gasPrice - b.header.baseFee else 0);
                }
                if (effective_gas_price == 0) effective_gas_price = 1000; // Minimal default

                try map.put("effectiveGasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{effective_gas_price}) });
                try map.put("status", std.json.Value{ .string = "0x1" });
                try map.put("type", std.json.Value{ .string = "0x2" }); // EIP-1559
                try map.put("root", std.json.Value{ .string = "0x" });
                try map.put("logs", std.json.Value{ .array = std.json.Array.init(allocator) });
                try map.put("logsBloom", std.json.Value{ .string = "0x" ++ "00" ** 256 });

                return std.json.Value{ .object = map };
            }
        }

        // Check if tx is in the pending pool — return null (MetaMask expects null for pending)
        log.debug("[RPC] Receipt NOT found for {s} (may be pending)\n", .{tx_hash_hex});
        return std.json.Value.null;
    }

    fn ethGetBlockByHash(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const block_hash_hex = params.array.items[0].string;
        const full_tx = if (params.array.items.len > 1) params.array.items[1].bool else false;

        var block_hash: types.Hash = undefined;
        const bytes = try std.fmt.hexToBytes(&block_hash.bytes, std.mem.trimLeft(u8, block_hash_hex, "0x"));
        if (bytes.len != 32) return error.InvalidParams;

        if (try self.chain.getBlockByHash(block_hash)) |block| {
            defer self.chain.freeBlock(block);
            return self.formatBlock(allocator, block, full_tx);
        }
        return std.json.Value.null;
    }

    fn ethGetTransactionByHash(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const tx_hash_hex = params.array.items[0].string;
        log.debug("[RPC] eth_getTransactionByHash: {s}\n", .{tx_hash_hex});

        var tx_hash: types.Hash = undefined;
        const bytes = try std.fmt.hexToBytes(&tx_hash.bytes, std.mem.trimLeft(u8, tx_hash_hex, "0x"));
        if (bytes.len != 32) return error.InvalidParams;

        // 1. Check Blockchain
        if (try self.chain.getTransactionLocation(tx_hash)) |loc| {
            log.debug("[RPC] eth_getTransactionByHash: Found in Chain at block index {d}\n", .{loc.txIndex});
            if (try self.chain.getBlockByHash(loc.blockHash)) |block| {
                defer self.chain.freeBlock(block);

                if (loc.txIndex < block.transactions.len) {
                    const tx = block.transactions[loc.txIndex];
                    return self.formatTransaction(allocator, tx, block, loc.txIndex, tx_hash);
                }
            }
        }

        // 2. Check Transaction Pool
        if (self.dagPool.get(tx_hash)) |tx| {
            log.debug("[RPC] eth_getTransactionByHash: Found in Pool (Pending)\n", .{});

            // pool.get returns *Transaction, dereference for formatTransaction
            return self.formatTransaction(allocator, tx, null, 0, tx_hash);
        }

        log.debug("[RPC] eth_getTransactionByHash: Not Found\n", .{});
        return std.json.Value.null;
    }
    fn formatTransaction(self: *RpcHandler, allocator: std.mem.Allocator, tx: types.Transaction, block: ?*types.Block, tx_index: usize, tx_hash: types.Hash) !std.json.Value {
        _ = self;
        // IMPORTANT: Each hex encoding must be immediately duped to prevent buffer aliasing.
        // encodeBuffer writes into a shared stack buffer — without duping, all fields
        // would point to the same memory and MetaMask would see corrupted data.
        var buf: [66]u8 = undefined;

        var map = std.json.ObjectMap.init(allocator);

        try map.put("hash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx_hash.bytes)) });
        try map.put("nonce", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.nonce}) });

        if (block) |b| {
            try map.put("blockHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &b.hash().bytes)) });
            try map.put("blockNumber", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{b.header.number}) });
            try map.put("transactionIndex", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx_index}) });
        } else {
            try map.put("blockHash", std.json.Value.null);
            try map.put("blockNumber", std.json.Value.null);
            try map.put("transactionIndex", std.json.Value.null);
        }

        try map.put("from", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.from.bytes)) });
        if (tx.to) |to| {
            try map.put("to", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &to.bytes)) });
        } else {
            try map.put("to", std.json.Value.null);
        }

        try map.put("value", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.value}) });
        try map.put("gas", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasLimit}) });
        try map.put("gasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasPrice}) });
        try map.put("input", std.json.Value{ .string = try hex.encode(allocator, tx.data) });
        try map.put("type", std.json.Value{ .string = "0x0" });
        try map.put("chainId", std.json.Value{ .string = "0x1869f" });

        // Signature parts
        try map.put("v", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.v}) });
        var r_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &r_bytes, tx.r, .big);
        try map.put("r", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &r_bytes)) });
        var s_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &s_bytes, tx.s, .big);
        try map.put("s", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &s_bytes)) });

        return std.json.Value{ .object = map };
    }

    fn parseJsonString(val: std.json.Value) ?[]const u8 {
        return switch (val) {
            .string => |s| s,
            else => null,
        };
    }

    fn parseJsonU64(val: std.json.Value) !u64 {
        switch (val) {
            .integer => |i| return @intCast(i),
            .string => |s| {
                if (std.mem.startsWith(u8, s, "0x")) {
                    return std.fmt.parseInt(u64, s[2..], 16);
                }
                return std.fmt.parseInt(u64, s, 10);
            },
            else => return error.InvalidParamType,
        }
    }

    fn parseJsonU256(val: std.json.Value) !u256 {
        switch (val) {
            .integer => |i| return @intCast(i),
            .string => |s| {
                if (std.mem.startsWith(u8, s, "0x")) {
                    return std.fmt.parseInt(u256, s[2..], 16);
                }
                return std.fmt.parseInt(u256, s, 10);
            },
            else => return error.InvalidParamType,
        }
    }

    fn ethSendTransaction(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        log.debug("[RPC] eth_sendTransaction called\n", .{});
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const tx_obj = params.array.items[0];
        if (tx_obj != .object) return error.InvalidParams;

        // Extract fields robustly
        const from_val = tx_obj.object.get("from") orelse return error.InvalidParams;
        const from_str = parseJsonString(from_val) orelse return error.InvalidParams;

        // Optional fields with defaults
        var to_addr: ?types.Address = null;
        if (tx_obj.object.get("to")) |val| {
            if (parseJsonString(val)) |s| {
                if (s.len > 0 and !std.mem.eql(u8, s, "0x")) {
                    var addr: types.Address = undefined;
                    _ = try std.fmt.hexToBytes(&addr.bytes, std.mem.trimLeft(u8, s, "0x"));
                    to_addr = addr;
                }
            }
        }

        const data_val = tx_obj.object.get("data");
        const data_str = if (data_val) |v| parseJsonString(v) orelse "0x" else "0x";

        // Gas Limit (default 21000)
        var gas_limit: u64 = 21000;
        if (tx_obj.object.get("gas")) |val| {
            gas_limit = parseJsonU64(val) catch 21000;
        }

        // Value (default 0)
        var value: u256 = 0;
        if (tx_obj.object.get("value")) |val| {
            value = parseJsonU256(val) catch 0;
        }

        // Gas Price (default 20 Gwei)
        var gas_price: u256 = 20000000000;
        if (tx_obj.object.get("gasPrice")) |val| {
            gas_price = parseJsonU256(val) catch 20000000000;
        }

        log.debug("[RPC] Parsed params: GasLimit={d} Value={x} GasPrice={x}\n", .{ gas_limit, value, gas_price });

        var address: types.Address = undefined;
        _ = try std.fmt.hexToBytes(&address.bytes, std.mem.trimLeft(u8, from_str, "0x"));

        // Helper to parse hex data
        const data_bytes = try hex.decode(allocator, data_str);

        // Get Nonce from state
        const nonce = self.state.getNonce(address);
        log.debug("[RPC] Nonce: {d}\n", .{nonce});

        // Sign it!
        // Hardcoded Devnet Validator Key (ac09... for funded account)
        var secret_key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&secret_key, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

        const Secp256k1 = std.crypto.ecc.Secp256k1;
        const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, std.crypto.hash.sha3.Keccak256);

        const sk = try Ecdsa.SecretKey.fromBytes(secret_key);
        const key_pair = try Ecdsa.KeyPair.fromSecretKey(sk);

        const derived_pub = key_pair.public_key.toUncompressedSec1();
        const account = @import("core").account;
        const derived_addr = try account.addressFromPubKey(&derived_pub);
        log.debug("[RPC] KeyPair Derived Addr: {x} (Expected: {x})\n", .{ derived_addr.bytes, address.bytes });

        // 1. Hash Signing Data
        const SigningData = struct {
            nonce: u64,
            gas_price: u256,
            gas_limit: u64,
            to: ?types.Address,
            value: u256,
            data: []const u8,
            chain_id: u64,
            zero1: u8 = 0,
            zero2: u8 = 0,
        };

        const signing_data = SigningData{
            .nonce = nonce,
            .gas_price = gas_price,
            .gas_limit = gas_limit,
            .to = to_addr,
            .value = value,
            .data = data_bytes,
            .chain_id = self.chain.chainId,
        };

        var hash: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        const encoded_signing = try rlp.encode(allocator, signing_data);
        defer allocator.free(encoded_signing);
        hasher.update(encoded_signing);
        hasher.final(&hash);
        log.debug("[RPC] Hash created\n", .{});

        // 2. Sign
        const sig = try key_pair.sign(encoded_signing, null);

        const sig_bytes = sig.toBytes(); // 64 bytes (r, s)
        log.debug("[RPC] Signed\n", .{});

        // 3. Find Recovery ID
        var recovery_id: u8 = 0;
        var found = false;

        // Extract r, s
        var r_bytes: [32]u8 = undefined;
        var s_bytes: [32]u8 = undefined;
        @memcpy(&r_bytes, sig_bytes[0..32]);
        @memcpy(&s_bytes, sig_bytes[32..64]);

        log.debug("[RPC] Sig R: {x}\n", .{r_bytes});
        log.debug("[RPC] Sig S: {x}\n", .{s_bytes});
        log.debug("[RPC] Hash: {x}\n", .{hash});

        // Normalize S if necessary (EIP-2)
        var s_scalar_val = try Secp256k1.scalar.Scalar.fromBytes(s_bytes, .big);
        if (s_bytes[0] >= 0x80) {
            log.debug("[RPC] Normalizing High S\n", .{});
            s_scalar_val = s_scalar_val.neg();
            s_bytes = s_scalar_val.toBytes(.big);
        }

        var recid: u8 = 0;
        while (recid < 4) : (recid += 1) {
            const pub_key = account.recover_public_key(hash, r_bytes, s_bytes, recid) catch |err| {
                log.debug("[RPC] Recid {d} failed: {}\n", .{ recid, err });
                continue;
            };
            const recovered_addr = try account.addressFromPubKey(&pub_key);

            if (std.mem.eql(u8, &recovered_addr.bytes, &address.bytes)) {
                recovery_id = recid;
                found = true;
                break;
            }
        }

        if (!found) {
            log.debug("[RPC] Recovery failed\n", .{});
            return error.SigningFailed;
        }
        log.debug("[RPC] Recovered ID: {d}\n", .{recovery_id});

        // 4. Construct Transaction
        const tx = types.Transaction{
            .nonce = nonce,
            .gasPrice = gas_price,
            .gasLimit = gas_limit,
            .to = to_addr,
            .value = value,
            .data = data_bytes,
            .v = self.chain.chainId * 2 + 35 + recovery_id,
            .r = std.mem.readInt(u256, &r_bytes, .big),
            .s = std.mem.readInt(u256, &s_bytes, .big),
            .from = address,
        };

        // RLP Encode
        const encoded_tx = try rlp.encode(allocator, tx);

        // Wrap in forge_sendtransaction format
        // hex imported at top level
        const raw_tx_str = try hex.encode(allocator, encoded_tx);
        log.debug("[RPC] Sending Raw TX: {s}\n", .{raw_tx_str});

        var new_params = std.json.Array.init(allocator);
        try new_params.append(std.json.Value{ .string = raw_tx_str });

        return self.forgeSendTransaction(allocator, std.json.Value{ .array = new_params });
    }

    // ── New MetaMask-required methods ──

    fn ethGetStorageAt(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 2) return error.InvalidParams;
        const addr_str = params.array.items[0].string;
        const slot_str = params.array.items[1].string;

        var address: types.Address = undefined;
        _ = try std.fmt.hexToBytes(&address.bytes, std.mem.trimLeft(u8, addr_str, "0x"));

        var slot: [32]u8 = [_]u8{0} ** 32;
        const slot_hex = std.mem.trimLeft(u8, slot_str, "0x");
        if (slot_hex.len <= 64) {
            const decoded = try std.fmt.hexToBytes(slot[32 - slot_hex.len / 2 ..], slot_hex);
            _ = decoded;
        }

        const value = self.state.getStorage(address, slot);
        return std.json.Value{ .string = try hex.encode(allocator, &value) };
    }

    fn ethAccounts(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        // MetaMask manages its own accounts — return empty array
        return std.json.Value{ .array = std.json.Array.init(allocator) };
    }

    fn ethSyncing(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = allocator;
        // Return sync status with block info
        const head = self.chain.getHeadNumber();
        if (head == 0) {
            // No blocks yet — could still be syncing
            return std.json.Value{ .bool = false };
        }
        // If we have blocks, report as synced (single-node net)
        // For a production multi-node setup, compare with highest known block
        return std.json.Value{ .bool = false };
    }

    fn ethGetLogs(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        // Parse filter params and return matching logs
        if (params != .array or params.array.items.len < 1) {
            return std.json.Value{ .array = std.json.Array.init(allocator) };
        }
        const filter_obj = params.array.items[0];
        if (filter_obj != .object) {
            return std.json.Value{ .array = std.json.Array.init(allocator) };
        }

        // Parse block range
        var from_block: u64 = 0;
        var to_block: u64 = self.chain.getHeadNumber();

        if (filter_obj.object.get("fromBlock")) |v| {
            if (v == .string) {
                if (std.mem.eql(u8, v.string, "latest")) {
                    from_block = to_block;
                } else if (std.mem.eql(u8, v.string, "earliest")) {
                    from_block = 0;
                } else {
                    const trimmed = if (std.mem.startsWith(u8, v.string, "0x")) v.string[2..] else v.string;
                    from_block = std.fmt.parseInt(u64, trimmed, 16) catch 0;
                }
            }
        }
        if (filter_obj.object.get("toBlock")) |v| {
            if (v == .string) {
                if (std.mem.eql(u8, v.string, "latest")) {
                    to_block = self.chain.getHeadNumber();
                } else if (!std.mem.eql(u8, v.string, "earliest")) {
                    const trimmed = if (std.mem.startsWith(u8, v.string, "0x")) v.string[2..] else v.string;
                    to_block = std.fmt.parseInt(u64, trimmed, 16) catch to_block;
                }
            }
        }

        // Cap range to prevent DoS
        const max_range: u64 = 10000;
        if (to_block > from_block + max_range) {
            to_block = from_block + max_range;
        }

        // Parse address filter
        var addresses = std.json.Array.init(allocator);
        _ = &addresses;
        const addr_filter = filter_obj.object.get("address");

        // Scan blocks for logs
        var result = std.json.Array.init(allocator);
        var block_num = from_block;
        while (block_num <= to_block) : (block_num += 1) {
            if (self.chain.getBlockByNumber(block_num)) |block| {
                defer self.chain.freeBlock(block);

                // For each transaction, check if address matches
                for (block.transactions, 0..) |tx, tx_idx| {
                    // Filter by address if specified
                    if (addr_filter) |af| {
                        var matches = false;
                        if (af == .string) {
                            if (tx.to) |to| {
                                const to_hex = hex.encode(allocator, &to.bytes) catch continue;
                                if (std.ascii.eqlIgnoreCase(af.string, to_hex)) matches = true;
                            }
                        } else if (af == .array) {
                            if (tx.to) |to| {
                                const to_hex = hex.encode(allocator, &to.bytes) catch continue;
                                for (af.array.items) |item| {
                                    if (item == .string and std.ascii.eqlIgnoreCase(item.string, to_hex)) {
                                        matches = true;
                                        break;
                                    }
                                }
                            }
                        } else {
                            matches = true;
                        }
                        if (!matches) continue;
                    }

                    // Build log entry skeleton
                    var log_obj = std.json.ObjectMap.init(allocator);
                    try log_obj.put("blockNumber", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.number}) });

                    var h_res: [32]u8 = undefined;
                    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                    const encoded = try block.header.rlpEncode(allocator);
                    defer allocator.free(encoded);
                    hasher.update(encoded);
                    hasher.final(&h_res);
                    var buf: [66]u8 = undefined;
                    try log_obj.put("blockHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &h_res)) });

                    try log_obj.put("transactionIndex", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx_idx}) });
                    try log_obj.put("transactionHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.hash().bytes)) });
                    if (tx.to) |to| {
                        try log_obj.put("address", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &to.bytes)) });
                    }
                    try log_obj.put("data", std.json.Value{ .string = "0x" });
                    try log_obj.put("topics", std.json.Value{ .array = std.json.Array.init(allocator) });
                    try log_obj.put("logIndex", std.json.Value{ .string = "0x0" });
                    try log_obj.put("removed", std.json.Value{ .bool = false });

                    try result.append(std.json.Value{ .object = log_obj });
                }
            }
        }

        return std.json.Value{ .array = result };
    }

    fn ethMining(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        _ = allocator;
        return std.json.Value{ .bool = false };
    }

    fn ethHashrate(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        _ = allocator;
        return std.json.Value{ .string = "0x0" };
    }

    fn ethGetBlockTransactionCountByNumber(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const block_tag = params.array.items[0].string;

        var block: ?*types.Block = null;
        if (std.mem.eql(u8, block_tag, "latest")) {
            if (self.chain.currentBlock) |head| {
                block = self.chain.getBlockByNumber(head.header.number);
            }
        } else if (std.mem.startsWith(u8, block_tag, "0x")) {
            const num = std.fmt.parseInt(u64, block_tag[2..], 16) catch return error.InvalidParams;
            block = self.chain.getBlockByNumber(num);
        } else if (std.mem.eql(u8, block_tag, "earliest")) {
            block = self.chain.getBlockByNumber(0);
        }

        if (block) |b| {
            defer self.chain.freeBlock(b);
            return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{b.transactions.len}) };
        }
        return std.json.Value.null;
    }

    fn ethGetBlockTransactionCountByHash(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const hash_hex = params.array.items[0].string;

        var block_hash: types.Hash = undefined;
        _ = try std.fmt.hexToBytes(&block_hash.bytes, std.mem.trimLeft(u8, hash_hex, "0x"));

        if (try self.chain.getBlockByHash(block_hash)) |b| {
            defer self.chain.freeBlock(b);
            return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{b.transactions.len}) };
        }
        return std.json.Value.null;
    }

    fn ethGetUncleCountByBlockNumber(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        _ = allocator;
        // PoS — no uncles
        return std.json.Value{ .string = "0x0" };
    }

    fn ethGetUncleCountByBlockHash(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        _ = allocator;
        return std.json.Value{ .string = "0x0" };
    }

    fn ethProtocolVersion(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        _ = allocator;
        return std.json.Value{ .string = "0x44" }; // 68
    }

    fn forgeCompileEOF(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = self;
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const source_code = params.array.items[0].string;

        // Create temporary file
        const tmp_path = "/tmp/forgeyria_compile.sol";
        try std.fs.cwd().writeFile(.{ .sub_path = tmp_path, .data = source_code });

        const forgec_args = [_][]const u8{
            "forgec",
            "--evm-version",
            "prague",
            "--combined-json",
            "bin",
            tmp_path,
        };

        var child = std.process.Child.init(&forgec_args, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        const stdout = try child.stdout.?.readToEndAlloc(allocator, 10 * 1024 * 1024);
        const stderr = try child.stderr.?.readToEndAlloc(allocator, 10 * 1024 * 1024);
        const term = try child.wait();

        if (term.Exited != 0) {
            var map = std.json.ObjectMap.init(allocator);
            try map.put("success", std.json.Value{ .bool = false });
            try map.put("error", std.json.Value{ .string = try allocator.dupe(u8, stderr) });
            return std.json.Value{ .object = map };
        }

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, stdout, .{});
        defer parsed.deinit();

        const contracts = parsed.value.object.get("contracts") orelse return error.InternalError;

        var results = std.json.Array.init(allocator);
        var iter = contracts.object.iterator();
        while (iter.next()) |entry| {
            const bin = entry.value_ptr.object.get("bin") orelse continue;
            var obj = std.json.ObjectMap.init(allocator);
            try obj.put("name", std.json.Value{ .string = try allocator.dupe(u8, entry.key_ptr.*) });
            try obj.put("bytecode", std.json.Value{ .string = try allocator.dupe(u8, bin.string) });
            try results.append(std.json.Value{ .object = obj });
        }

        var res_map = std.json.ObjectMap.init(allocator);
        try res_map.put("success", std.json.Value{ .bool = true });
        try res_map.put("contracts", std.json.Value{ .array = results });
        return std.json.Value{ .object = res_map };
    }

    // ================================================================
    // New eth_* Methods
    // ================================================================

    fn ethGetTransactionByBlockNumberAndIndex(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 2) return error.InvalidParams;
        const block_tag = params.array.items[0].string;
        const index_str = params.array.items[1].string;

        const tx_index = blk: {
            const trimmed = if (std.mem.startsWith(u8, index_str, "0x")) index_str[2..] else index_str;
            break :blk std.fmt.parseInt(u64, trimmed, 16) catch return error.InvalidParams;
        };

        var block: ?*types.Block = null;
        if (std.mem.eql(u8, block_tag, "latest")) {
            if (self.chain.currentBlock) |head| {
                block = self.chain.getBlockByNumber(head.header.number);
            }
        } else if (std.mem.startsWith(u8, block_tag, "0x")) {
            const num = std.fmt.parseInt(u64, block_tag[2..], 16) catch return error.InvalidParams;
            block = self.chain.getBlockByNumber(num);
        } else if (std.mem.eql(u8, block_tag, "earliest")) {
            block = self.chain.getBlockByNumber(0);
        }

        if (block) |b| {
            defer self.chain.freeBlock(b);
            if (tx_index < b.transactions.len) {
                const tx = b.transactions[tx_index];
                return self.formatTransaction(allocator, tx, b, tx_index, tx.hash());
            }
        }
        return std.json.Value.null;
    }

    fn ethGetTransactionByBlockHashAndIndex(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 2) return error.InvalidParams;
        const hash_hex = params.array.items[0].string;
        const index_str = params.array.items[1].string;

        const tx_index = blk: {
            const trimmed = if (std.mem.startsWith(u8, index_str, "0x")) index_str[2..] else index_str;
            break :blk std.fmt.parseInt(u64, trimmed, 16) catch return error.InvalidParams;
        };

        var block_hash: types.Hash = undefined;
        _ = try std.fmt.hexToBytes(&block_hash.bytes, std.mem.trimLeft(u8, hash_hex, "0x"));

        if (try self.chain.getBlockByHash(block_hash)) |b| {
            defer self.chain.freeBlock(b);
            if (tx_index < b.transactions.len) {
                const tx = b.transactions[tx_index];
                return self.formatTransaction(allocator, tx, b, tx_index, tx.hash());
            }
        }
        return std.json.Value.null;
    }

    fn ethNewFilter(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const filter_obj = params.array.items[0];
        if (filter_obj != .object) return error.InvalidParams;

        var from_block: ?u64 = null;
        var to_block: ?u64 = null;

        if (filter_obj.object.get("fromBlock")) |v| {
            if (v == .string) {
                if (std.mem.eql(u8, v.string, "latest")) {
                    from_block = self.chain.getHeadNumber();
                } else if (std.mem.eql(u8, v.string, "earliest")) {
                    from_block = 0;
                } else {
                    const trimmed = if (std.mem.startsWith(u8, v.string, "0x")) v.string[2..] else v.string;
                    from_block = std.fmt.parseInt(u64, trimmed, 16) catch null;
                }
            }
        }

        if (filter_obj.object.get("toBlock")) |v| {
            if (v == .string) {
                if (std.mem.eql(u8, v.string, "latest")) {
                    to_block = self.chain.getHeadNumber();
                } else {
                    const trimmed = if (std.mem.startsWith(u8, v.string, "0x")) v.string[2..] else v.string;
                    to_block = std.fmt.parseInt(u64, trimmed, 16) catch null;
                }
            }
        }

        const empty_addrs = [_]types.Address{};
        const empty_topics = [4]?[]const types.Hash{ null, null, null, null };

        const filter_id = try self.filterEngine.createFilter(
            from_block,
            to_block,
            &empty_addrs,
            empty_topics,
        );

        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{filter_id}) };
    }

    fn ethNewBlockFilter(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        const filter_id = self.nextFilterId;
        self.nextFilterId += 1;

        const current_head = self.chain.getHeadNumber();
        try self.blockFilters.put(filter_id, current_head);

        return std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{filter_id}) };
    }

    fn ethGetFilterChanges(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const id_val = params.array.items[0];
        const filter_id = blk: {
            if (id_val == .string) {
                const trimmed = if (std.mem.startsWith(u8, id_val.string, "0x")) id_val.string[2..] else id_val.string;
                break :blk std.fmt.parseInt(u64, trimmed, 16) catch return error.InvalidParams;
            } else if (id_val == .integer) {
                break :blk @as(u64, @intCast(id_val.integer));
            }
            return error.InvalidParams;
        };

        // Check block filters first
        if (self.blockFilters.get(filter_id)) |last_block| {
            const current_head = self.chain.getHeadNumber();
            var result = std.json.Array.init(allocator);

            if (current_head > last_block) {
                var block_num = last_block + 1;
                while (block_num <= current_head) : (block_num += 1) {
                    if (self.chain.getBlockByNumber(block_num)) |block| {
                        defer self.chain.freeBlock(block);
                        var buf: [66]u8 = undefined;
                        var h_res: [32]u8 = undefined;
                        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                        const encoded = block.header.rlpEncode(allocator) catch continue;
                        defer allocator.free(encoded);
                        hasher.update(encoded);
                        hasher.final(&h_res);
                        try result.append(std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &h_res)) });
                    }
                }
                self.blockFilters.put(filter_id, current_head) catch {};
            }
            return std.json.Value{ .array = result };
        }

        // Check log filters
        if (self.filterEngine.getFilter(filter_id)) |_| {
            // Return empty for now — no new logs yet
            return std.json.Value{ .array = std.json.Array.init(allocator) };
        }

        return error.InvalidParams;
    }

    fn ethGetFilterLogs(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        // Same as eth_getLogs but scoped to a filter — return empty for now
        return std.json.Value{ .array = std.json.Array.init(allocator) };
    }

    fn ethUninstallFilter(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = allocator;
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const id_val = params.array.items[0];
        const filter_id = blk: {
            if (id_val == .string) {
                const trimmed = if (std.mem.startsWith(u8, id_val.string, "0x")) id_val.string[2..] else id_val.string;
                break :blk std.fmt.parseInt(u64, trimmed, 16) catch return error.InvalidParams;
            } else if (id_val == .integer) {
                break :blk @as(u64, @intCast(id_val.integer));
            }
            return error.InvalidParams;
        };

        // Try removing from block filters
        if (self.blockFilters.remove(filter_id)) {
            return std.json.Value{ .bool = true };
        }

        // Try removing from log filters
        if (self.filterEngine.removeFilter(filter_id)) {
            return std.json.Value{ .bool = true };
        }

        return std.json.Value{ .bool = false };
    }

    fn web3Sha3(self: *RpcHandler, allocator: std.mem.Allocator, params: std.json.Value) !std.json.Value {
        _ = self;
        if (params != .array or params.array.items.len < 1) return error.InvalidParams;
        const data_hex = params.array.items[0].string;

        const trimmed = if (std.mem.startsWith(u8, data_hex, "0x")) data_hex[2..] else data_hex;
        const data = hex.decode(allocator, trimmed) catch return error.InvalidParams;
        defer if (data.len > 0) allocator.free(data);

        var hash: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(data);
        hasher.final(&hash);

        return std.json.Value{ .string = try hex.encode(allocator, &hash) };
    }

    // ================================================================
    // Zephyria-Specific RPC Methods (forge_ namespace)
    // ================================================================

    /// Returns live DAG execution pipeline metrics from the actual mempool.
    fn forgeGetDAGMetrics(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        // Pipeline architecture
        try map.put("pipeline", std.json.Value{ .string = "dag_first" });
        try map.put("executionModel", std.json.Value{ .string = "parallel_isolated_accounts" });
        try map.put("conflictResolution", std.json.Value{ .string = "credit_receipts" });
        try map.put("accountTypes", std.json.Value{ .integer = 8 });
        try map.put("storageIsolation", std.json.Value{ .string = "one_slot_one_account" });
        try map.put("targetTPS", std.json.Value{ .integer = 1_000_000 });
        try map.put("maxExecutionLanes", std.json.Value{ .integer = 64 });

        // Live DAG mempool stats
        if (true) {
            const stats = self.dagPool.getStats();
            var live = std.json.ObjectMap.init(allocator);
            try live.put("totalVertices", std.json.Value{ .integer = @intCast(stats.totalVertices) });
            try live.put("activeLanes", std.json.Value{ .integer = @intCast(stats.activeLanes) });
            try live.put("totalAdded", std.json.Value{ .integer = @intCast(stats.totalAdded) });
            try live.put("totalRejected", std.json.Value{ .integer = @intCast(stats.totalRejected) });
            try live.put("totalEvicted", std.json.Value{ .integer = @intCast(stats.totalEvicted) });
            try live.put("gcEvicted", std.json.Value{ .integer = @intCast(stats.totalGcEvicted) });
            try live.put("duplicateRejected", std.json.Value{ .integer = @intCast(stats.duplicateRejected) });
            try live.put("rateLimited", std.json.Value{ .integer = @intCast(stats.rateLimited) });
            try live.put("nonceRejected", std.json.Value{ .integer = @intCast(stats.nonceRejected) });
            try live.put("gasPriceRejected", std.json.Value{ .integer = @intCast(stats.gasPriceRejected) });
            try live.put("replacementCount", std.json.Value{ .integer = @intCast(stats.replacementCount) });
            try live.put("bloomCount", std.json.Value{ .integer = @intCast(stats.bloomCount) });
            try live.put("maxShardLoad", std.json.Value{ .integer = @intCast(stats.maxShardLoad) });
            try live.put("hotShardPremiumApplied", std.json.Value{ .integer = @intCast(stats.hotShardPremiumApplied) });
            try map.put("live", std.json.Value{ .object = live });
        }

        return std.json.Value{ .object = map };
    }

    /// Returns consensus/thread info with runtime data.
    fn forgeGetThreadInfo(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        // Consensus info
        try map.put("consensusProtocol", std.json.Value{ .string = "loom_genesis" });
        try map.put("signatureScheme", std.json.Value{ .string = "BLS12-381" });
        try map.put("finality", std.json.Value{ .string = "single_slot" });
        try map.put("slotsPerEpoch", std.json.Value{ .integer = 1024 });

        // Runtime data
        const now = std.time.timestamp();
        const uptime_secs = now - self.nodeStartTime;
        try map.put("uptimeSeconds", std.json.Value{ .integer = uptime_secs });
        try map.put("currentBlock", std.json.Value{ .integer = @intCast(self.chain.getHeadNumber()) });

        // P2P peer count
        var peer_count: usize = 0;
        if (self.p2p) |p| {
            p.mutex.lock();
            defer p.mutex.unlock();
            peer_count = p.peers.items.len;
        }
        try map.put("connectedPeers", std.json.Value{ .integer = @intCast(peer_count) });

        // Block production rate
        if (self.chain.currentBlock) |head| {
            if (head.header.number > 0) {
                const first_block = self.chain.getBlockByNumber(1);
                if (first_block) |fb| {
                    defer self.chain.freeBlock(fb);
                    const elapsed = if (head.header.time > fb.header.time) head.header.time - fb.header.time else 1;
                    const blocks = head.header.number;
                    if (elapsed > 0) {
                        const bps = (blocks * 100) / elapsed; // blocks per 100 seconds
                        try map.put("avgBlockTimeMs", std.json.Value{ .integer = @intCast(if (bps > 0) (100_000 / bps) else 0) });
                    }
                }
            }
        }

        // Adaptive tiers
        var tiers = std.json.Array.init(allocator);
        {
            var t1 = std.json.ObjectMap.init(allocator);
            try t1.put("name", std.json.Value{ .string = "FullBFT" });
            try t1.put("validatorRange", std.json.Value{ .string = "1-100" });
            try tiers.append(std.json.Value{ .object = t1 });
        }
        {
            var t2 = std.json.ObjectMap.init(allocator);
            try t2.put("name", std.json.Value{ .string = "CommitteeLoom" });
            try t2.put("validatorRange", std.json.Value{ .string = "101-2000" });
            try tiers.append(std.json.Value{ .object = t2 });
        }
        {
            var t3 = std.json.ObjectMap.init(allocator);
            try t3.put("name", std.json.Value{ .string = "FullLoom" });
            try t3.put("validatorRange", std.json.Value{ .string = "2001+" });
            try tiers.append(std.json.Value{ .object = t3 });
        }
        try map.put("tiers", std.json.Value{ .array = tiers });

        return std.json.Value{ .object = map };
    }

    /// Returns the isolated account type taxonomy used by Zephyria.
    fn forgeGetAccountTypes(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        var types_arr = std.json.Array.init(allocator);

        const account_types = [_]struct { id: u8, name: []const u8, desc: []const u8, key_scheme: []const u8 }{
            .{ .id = 0, .name = "EOA", .desc = "Externally Owned Account", .key_scheme = "keccak256(address)" },
            .{ .id = 1, .name = "ContractRoot", .desc = "Contract metadata and nonce", .key_scheme = "keccak256(address || 0x01)" },
            .{ .id = 2, .name = "Code", .desc = "Contract bytecode (immutable)", .key_scheme = "keccak256(address || 0x02)" },
            .{ .id = 3, .name = "Config", .desc = "Contract configuration", .key_scheme = "keccak256(address || 0x03)" },
            .{ .id = 4, .name = "StorageCell", .desc = "Per-slot isolated storage", .key_scheme = "keccak256(address || slot)" },
            .{ .id = 5, .name = "DerivedState", .desc = "Per-user derived storage", .key_scheme = "keccak256(user || contract || slot)" },
            .{ .id = 6, .name = "Vault", .desc = "Contract balance holder (separated from storage)", .key_scheme = "keccak256(vault || address)" },
            .{ .id = 7, .name = "System", .desc = "Protocol-level system account", .key_scheme = "fixed prefix" },
        };

        for (account_types) |at| {
            var obj = std.json.ObjectMap.init(allocator);
            try obj.put("id", std.json.Value{ .integer = at.id });
            try obj.put("name", std.json.Value{ .string = at.name });
            try obj.put("description", std.json.Value{ .string = at.desc });
            try obj.put("keyDerivation", std.json.Value{ .string = at.key_scheme });
            try types_arr.append(std.json.Value{ .object = obj });
        }

        var map = std.json.ObjectMap.init(allocator);
        try map.put("model", std.json.Value{ .string = "isolated_accounts" });
        try map.put("parallelism", std.json.Value{ .string = "zero_conflict_by_construction" });
        try map.put("types", std.json.Value{ .array = types_arr });
        try map.put("sdkBindings", std.json.Value{ .string = "DerivedStorage, VaultAccess, GlobalAccumulator, StorageCellRef, AccountScheme" });

        return std.json.Value{ .object = map };
    }

    // ================================================================
    // New forge_* Introspection Methods
    // ================================================================

    /// Returns comprehensive node info: version, chain, genesis, uptime.
    fn forgeGetNodeInfo(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        try map.put("client", std.json.Value{ .string = "Zephyria/v0.1.0/zig-edition" });
        try map.put("chainId", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{self.chain.chainId}) });
        try map.put("networkId", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "{d}", .{self.chain.chainId}) });

        var buf: [66]u8 = undefined;
        try map.put("genesisHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &self.chain.genesisHash.bytes)) });

        const head = self.chain.getHeadNumber();
        try map.put("headBlock", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head}) });

        if (self.chain.currentBlock) |block| {
            try map.put("headHash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &block.hash().bytes)) });
            try map.put("headTimestamp", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{block.header.time}) });
        }

        // Uptime
        const now = std.time.timestamp();
        const uptime = now - self.nodeStartTime;
        try map.put("uptimeSeconds", std.json.Value{ .integer = uptime });

        // Protocols
        var protocols = std.json.Array.init(allocator);
        try protocols.append(std.json.Value{ .string = "eth/68" });
        try protocols.append(std.json.Value{ .string = "forge/1" });
        try map.put("protocols", std.json.Value{ .array = protocols });

        // P2P info
        var peer_count: usize = 0;
        if (self.p2p) |p| {
            p.mutex.lock();
            defer p.mutex.unlock();
            peer_count = p.peers.items.len;
        }
        try map.put("peerCount", std.json.Value{ .integer = @intCast(peer_count) });

        // Architecture
        try map.put("execution", std.json.Value{ .string = "RISC-V VM (Zephyr)" });
        try map.put("stateDB", std.json.Value{ .string = "Verkle Trie" });
        try map.put("consensus", std.json.Value{ .string = "Loom" });
        try map.put("mempool", std.json.Value{ .string = "DAG-Based Sharded" });

        return std.json.Value{ .object = map };
    }

    /// Returns combined mempool stats from DAG and legacy pools.
    fn forgeGetMempoolStats(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        // DAG mempool
        if (true) {
            const stats = self.dagPool.getStats();
            var dag_map = std.json.ObjectMap.init(allocator);
            try dag_map.put("pending", std.json.Value{ .integer = @intCast(stats.totalVertices) });
            try dag_map.put("activeSenders", std.json.Value{ .integer = @intCast(stats.activeLanes) });
            try dag_map.put("totalAdmitted", std.json.Value{ .integer = @intCast(stats.totalAdded) });
            try dag_map.put("totalRejected", std.json.Value{ .integer = @intCast(stats.totalRejected) });
            try dag_map.put("totalEvicted", std.json.Value{ .integer = @intCast(stats.totalEvicted) });
            try dag_map.put("gcEvicted", std.json.Value{ .integer = @intCast(stats.totalGcEvicted) });
            try dag_map.put("duplicates", std.json.Value{ .integer = @intCast(stats.duplicateRejected) });
            try dag_map.put("rateLimited", std.json.Value{ .integer = @intCast(stats.rateLimited) });
            try dag_map.put("replacements", std.json.Value{ .integer = @intCast(stats.replacementCount) });
            try dag_map.put("bloomFilterEntries", std.json.Value{ .integer = @intCast(stats.bloomCount) });
            try dag_map.put("maxShardLoad", std.json.Value{ .integer = @intCast(stats.maxShardLoad) });
            try dag_map.put("shardCount", std.json.Value{ .integer = 256 });
            try map.put("dag", std.json.Value{ .object = dag_map });
        }

        // Legacy pool
        const pool_stats = self.dagPool.getStats();
        var legacy_map = std.json.ObjectMap.init(allocator);
        try legacy_map.put("pending", std.json.Value{ .integer = @intCast(pool_stats.totalVertices) });
        try legacy_map.put("rejected", std.json.Value{ .integer = @intCast(pool_stats.totalRejected) });
        try legacy_map.put("evicted", std.json.Value{ .integer = @intCast(pool_stats.totalEvicted) });
        try legacy_map.put("bloomEntries", std.json.Value{ .integer = @intCast(pool_stats.bloomCount) });
        try map.put("legacy", std.json.Value{ .object = legacy_map });

        // Combined
        const dag_count: u32 = self.dagPool.count();
        try map.put("totalPending", std.json.Value{ .integer = @intCast(dag_count + pool_stats.totalVertices) });
        try map.put("primaryPool", std.json.Value{ .string = "dag" });

        return std.json.Value{ .object = map };
    }

    /// Returns pending transactions grouped by sender (like txpool_content).
    fn forgeGetMempoolContent(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);
        var buf: [66]u8 = undefined;

        // Get pending from legacy pool
        var pending_map = std.json.ObjectMap.init(allocator);
        const pending_txs = try self.dagPool.pending(allocator);
        defer allocator.free(pending_txs);

        for (pending_txs) |tx| {
            const addr_hex = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.from.bytes));

            var tx_obj = std.json.ObjectMap.init(allocator);
            try tx_obj.put("nonce", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.nonce}) });
            try tx_obj.put("gasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasPrice}) });
            try tx_obj.put("gasLimit", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasLimit}) });
            try tx_obj.put("value", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.value}) });
            if (tx.to) |to| {
                try tx_obj.put("to", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &to.bytes)) });
            } else {
                try tx_obj.put("to", std.json.Value.null);
            }
            try tx_obj.put("dataSize", std.json.Value{ .integer = @intCast(tx.data.len) });

            // Build or append to the array for this sender
            const existing = pending_map.get(addr_hex);
            if (existing) |arr_val| {
                var arr = arr_val.array;
                try arr.append(std.json.Value{ .object = tx_obj });
            } else {
                var arr = std.json.Array.init(allocator);
                try arr.append(std.json.Value{ .object = tx_obj });
                try pending_map.put(addr_hex, std.json.Value{ .array = arr });
            }
        }

        try map.put("pending", std.json.Value{ .object = pending_map });
        try map.put("txCount", std.json.Value{ .integer = @intCast(pending_txs.len) });

        return std.json.Value{ .object = map };
    }

    /// Returns block producer info and gas configuration.
    fn forgeGetBlockProducerInfo(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        // Gas configuration
        try map.put("blockGasLimit", std.json.Value{ .string = "0x1c9c380" }); // 30M
        try map.put("minGasPrice", std.json.Value{ .string = "0x3b9aca00" }); // 1 Gwei
        try map.put("baseFeeEnabled", std.json.Value{ .bool = true });

        if (self.chain.currentBlock) |head| {
            try map.put("latestBaseFee", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head.header.baseFee}) });
            try map.put("latestGasUsed", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head.header.gasUsed}) });
            try map.put("latestGasLimit", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head.header.gasLimit}) });

            var buf: [66]u8 = undefined;
            try map.put("coinbase", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &head.header.coinbase.bytes)) });
        }

        // Execution model
        try map.put("executionEngine", std.json.Value{ .string = "parallel_wave_executor" });
        try map.put("vmTarget", std.json.Value{ .string = "RISC-V RV64IM" });
        try map.put("maxContractSize", std.json.Value{ .integer = 49152 }); // EIP-3860

        return std.json.Value{ .object = map };
    }

    /// Returns connected P2P peers with details.
    fn forgeGetPeers(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var result = std.json.Array.init(allocator);

        if (self.p2p) |p| {
            p.mutex.lock();
            defer p.mutex.unlock();

            for (p.peers.items) |peer| {
                var peer_obj = std.json.ObjectMap.init(allocator);
                try peer_obj.put("id", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "{x}", .{@as(u64, @intFromPtr(peer))}) });
                try peer_obj.put("connected", std.json.Value{ .bool = true });
                try result.append(std.json.Value{ .object = peer_obj });
            }
        }

        var map = std.json.ObjectMap.init(allocator);
        try map.put("peers", std.json.Value{ .array = result });
        try map.put("count", std.json.Value{ .integer = @intCast(result.items.len) });
        try map.put("maxPeers", std.json.Value{ .integer = 50 });

        return std.json.Value{ .object = map };
    }

    /// Returns VM pool statistics and code cache info.
    fn forgeGetVMStats(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        _ = self;
        var map = std.json.ObjectMap.init(allocator);

        try map.put("vmArchitecture", std.json.Value{ .string = "RISC-V RV64IM" });
        try map.put("executorType", std.json.Value{ .string = "threaded_interpreter" });
        try map.put("features", std.json.Value{ .string = "pre-decoded insn cache, per-block gas, basic block analysis, zero-copy SLOAD/SSTORE" });
        try map.put("callDepthLimit", std.json.Value{ .integer = 1024 });
        try map.put("maxInitcodeSize", std.json.Value{ .integer = 49152 });

        // Code cache info
        var cache = std.json.ObjectMap.init(allocator);
        try cache.put("type", std.json.Value{ .string = "LRU" });
        try cache.put("maxEntries", std.json.Value{ .integer = 100 });
        try cache.put("keyType", std.json.Value{ .string = "code_hash" });
        try cache.put("valueType", std.json.Value{ .string = "DecodedInsn[]" });
        try map.put("codeCache", std.json.Value{ .object = cache });

        // Optimization info
        var opts = std.json.ObjectMap.init(allocator);
        try opts.put("threadedDispatch", std.json.Value{ .bool = true });
        try opts.put("basicBlockGas", std.json.Value{ .bool = true });
        try opts.put("superInstructions", std.json.Value{ .bool = true });
        try opts.put("zeroCopySyscalls", std.json.Value{ .bool = true });
        try opts.put("reentryGuards", std.json.Value{ .bool = true });
        try opts.put("eip3860Metering", std.json.Value{ .bool = true });
        try map.put("optimizations", std.json.Value{ .object = opts });

        return std.json.Value{ .object = map };
    }

    /// Returns per-shard distribution of DAG mempool vertices.
    fn forgeGetShardDistribution(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        if (true) {
            const dag = self.dagPool;
            const dag_mempool = core.dag_mempool;
            var shard_data = std.json.Array.init(allocator);
            var total_vertices: u64 = 0;
            var non_empty_shards: u32 = 0;
            var max_load: u32 = 0;

            for (0..dag_mempool.SHARD_COUNT) |i| {
                const shard = &dag.shards[i];
                if (shard.vertexCount > 0) {
                    var shard_obj = std.json.ObjectMap.init(allocator);
                    try shard_obj.put("id", std.json.Value{ .integer = @intCast(i) });
                    try shard_obj.put("vertices", std.json.Value{ .integer = @intCast(shard.vertexCount) });
                    try shard_obj.put("gas", std.json.Value{ .integer = @intCast(shard.totalGas) });
                    try shard_data.append(std.json.Value{ .object = shard_obj });
                    non_empty_shards += 1;
                    if (shard.vertexCount > max_load) max_load = shard.vertexCount;
                }
                total_vertices += shard.vertexCount;
            }

            try map.put("shards", std.json.Value{ .array = shard_data });
            try map.put("totalShards", std.json.Value{ .integer = dag_mempool.SHARD_COUNT });
            try map.put("activeShards", std.json.Value{ .integer = @intCast(non_empty_shards) });
            try map.put("totalVertices", std.json.Value{ .integer = @intCast(total_vertices) });
            try map.put("maxShardLoad", std.json.Value{ .integer = @intCast(max_load) });
            try map.put("avgShardLoad", std.json.Value{ .integer = @intCast(if (non_empty_shards > 0) total_vertices / non_empty_shards else 0) });
        } else {
            try map.put("available", std.json.Value{ .bool = false });
            try map.put("message", std.json.Value{ .string = "DAG mempool not active" });
        }

        return std.json.Value{ .object = map };
    }

    /// Returns node runtime configuration.
    fn forgeGetConfig(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        // Chain
        var chain_cfg = std.json.ObjectMap.init(allocator);
        try chain_cfg.put("chainId", std.json.Value{ .integer = @intCast(self.chain.chainId) });
        try chain_cfg.put("blockGasLimit", std.json.Value{ .integer = 30_000_000 });
        try map.put("chain", std.json.Value{ .object = chain_cfg });

        // Pool
        var pool_cfg = std.json.ObjectMap.init(allocator);
        try pool_cfg.put("maxPoolSize", std.json.Value{ .integer = @intCast(self.dagPool.config.maxTotalVertices) });
        try pool_cfg.put("minGasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{self.dagPool.config.minGasPrice}) });
        try pool_cfg.put("replacementBumpPct", std.json.Value{ .integer = 10 });
        try map.put("txPool", std.json.Value{ .object = pool_cfg });

        // DAG
        if (true) {
            const dag = self.dagPool;
            var dag_cfg = std.json.ObjectMap.init(allocator);
            try dag_cfg.put("maxTxsPerLane", std.json.Value{ .integer = @intCast(dag.config.maxTxsPerLane) });
            try dag_cfg.put("maxTotalVertices", std.json.Value{ .integer = @intCast(dag.config.maxTotalVertices) });
            try dag_cfg.put("shardCount", std.json.Value{ .integer = 256 });
            try dag_cfg.put("minGasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{dag.config.minGasPrice}) });
            try map.put("dagMempool", std.json.Value{ .object = dag_cfg });
        }

        // VM
        var vm_cfg = std.json.ObjectMap.init(allocator);
        try vm_cfg.put("maxCallDepth", std.json.Value{ .integer = 1024 });
        try vm_cfg.put("maxInitcodeSize", std.json.Value{ .integer = 49152 });
        try vm_cfg.put("codeCacheSize", std.json.Value{ .integer = 100 });
        try map.put("vm", std.json.Value{ .object = vm_cfg });

        return std.json.Value{ .object = map };
    }

    /// Returns parallel executor statistics.
    fn forgeGetExecutorStats(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        try map.put("type", std.json.Value{ .string = "parallel_wave_executor" });
        try map.put("vmEnabled", std.json.Value{ .bool = self.dagExecutor.vmCallback != null });

        // Block processing stats from latest block
        if (self.chain.currentBlock) |head| {
            var latest = std.json.ObjectMap.init(allocator);
            try latest.put("blockNumber", std.json.Value{ .integer = @intCast(head.header.number) });
            try latest.put("txCount", std.json.Value{ .integer = @intCast(head.transactions.len) });
            try latest.put("gasUsed", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head.header.gasUsed}) });
            try latest.put("gasLimit", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head.header.gasLimit}) });

            // Gas utilization percentage
            const utilization = if (head.header.gasLimit > 0)
                (head.header.gasUsed * 100) / head.header.gasLimit
            else
                0;
            try latest.put("gasUtilizationPct", std.json.Value{ .integer = @intCast(utilization) });
            try map.put("latestBlock", std.json.Value{ .object = latest });
        }

        // Execution config
        var exec_cfg = std.json.ObjectMap.init(allocator);
        try exec_cfg.put("blockGasLimit", std.json.Value{ .integer = @intCast(self.dagExecutor.config.blockGasLimit) });
        try exec_cfg.put("maxThreads", std.json.Value{ .integer = @intCast(self.dagExecutor.config.numThreads) });
        try map.put("config", std.json.Value{ .object = exec_cfg });

        return std.json.Value{ .object = map };
    }

    /// Returns state trie metrics.
    fn forgeGetStateMetrics(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        try map.put("type", std.json.Value{ .string = "verkle_trie" });

        // State root from latest block
        if (self.chain.currentBlock) |head| {
            var buf: [66]u8 = undefined;
            try map.put("stateRoot", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &head.header.verkleRoot.bytes)) });
        }

        // Trie size estimate
        const trie = self.state.trie;
        const trie_stats = trie.getStats();
        try map.put("totalNodes", std.json.Value{ .integer = @intCast(trie_stats.total_nodes) });
        try map.put("internalNodes", std.json.Value{ .integer = @intCast(trie_stats.internal_nodes) });
        try map.put("leafNodes", std.json.Value{ .integer = @intCast(trie_stats.leaf_nodes) });
        try map.put("totalValues", std.json.Value{ .integer = @intCast(trie_stats.total_values) });
        try map.put("treeDepth", std.json.Value{ .integer = @intCast(trie_stats.tree_depth) });

        // Storage backend
        try map.put("backend", std.json.Value{ .string = "RocksDB-compatible" });
        try map.put("proofType", std.json.Value{ .string = "Verkle (IPA commitment)" });

        return std.json.Value{ .object = map };
    }

    /// Returns chain-level metrics: block times, TPS, gas usage.
    fn forgeGetChainMetrics(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var map = std.json.ObjectMap.init(allocator);

        const head_num = self.chain.getHeadNumber();
        try map.put("headBlock", std.json.Value{ .integer = @intCast(head_num) });
        try map.put("chainId", std.json.Value{ .integer = @intCast(self.chain.chainId) });

        // Compute metrics from recent blocks (last 10)
        const sample_size: u64 = 10;
        const start_block = if (head_num > sample_size) head_num - sample_size else 0;

        var total_txs: u64 = 0;
        var total_gas: u64 = 0;
        var first_time: u64 = 0;
        var last_time: u64 = 0;
        var block_count: u64 = 0;
        var block_times = std.json.Array.init(allocator);
        var prev_time: u64 = 0;

        var bn = start_block;
        while (bn <= head_num) : (bn += 1) {
            if (self.chain.getBlockByNumber(bn)) |block| {
                defer self.chain.freeBlock(block);

                total_txs += block.transactions.len;
                total_gas += block.header.gasUsed;
                block_count += 1;

                if (first_time == 0) first_time = block.header.time;
                last_time = block.header.time;

                if (prev_time > 0 and block.header.time > prev_time) {
                    try block_times.append(std.json.Value{ .integer = @intCast(block.header.time - prev_time) });
                }
                prev_time = block.header.time;
            }
        }

        try map.put("sampleBlocks", std.json.Value{ .integer = @intCast(block_count) });
        try map.put("totalTransactions", std.json.Value{ .integer = @intCast(total_txs) });
        try map.put("totalGasUsed", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{total_gas}) });
        try map.put("blockTimes", std.json.Value{ .array = block_times });

        // TPS calculation
        const elapsed = if (last_time > first_time) last_time - first_time else 1;
        const tps = total_txs / elapsed;
        try map.put("avgTPS", std.json.Value{ .integer = @intCast(tps) });
        try map.put("avgGasPerBlock", std.json.Value{ .integer = @intCast(if (block_count > 0) total_gas / block_count else 0) });
        try map.put("avgTxPerBlock", std.json.Value{ .integer = @intCast(if (block_count > 0) total_txs / block_count else 0) });

        // Current base fee
        if (self.chain.currentBlock) |head| {
            try map.put("currentBaseFee", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{head.header.baseFee}) });
        }

        return std.json.Value{ .object = map };
    }

    /// Returns all pending transactions (like txpool_inspect).
    fn forgePendingTransactions(self: *RpcHandler, allocator: std.mem.Allocator) !std.json.Value {
        var result = std.json.Array.init(allocator);
        var buf: [66]u8 = undefined;

        // Get from legacy pool
        const pending = try self.dagPool.pending(allocator);
        defer allocator.free(pending);

        for (pending) |tx| {
            var tx_obj = std.json.ObjectMap.init(allocator);
            try tx_obj.put("hash", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.hash().bytes)) });
            try tx_obj.put("from", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &tx.from.bytes)) });
            if (tx.to) |to| {
                try tx_obj.put("to", std.json.Value{ .string = try allocator.dupe(u8, try hex.encodeBuffer(&buf, &to.bytes)) });
            } else {
                try tx_obj.put("to", std.json.Value.null);
            }
            try tx_obj.put("nonce", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.nonce}) });
            try tx_obj.put("value", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.value}) });
            try tx_obj.put("gasPrice", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasPrice}) });
            try tx_obj.put("gas", std.json.Value{ .string = try std.fmt.allocPrint(allocator, "0x{x}", .{tx.gasLimit}) });
            try tx_obj.put("input", std.json.Value{ .string = try hex.encode(allocator, tx.data) });
            try result.append(std.json.Value{ .object = tx_obj });
        }

        return std.json.Value{ .array = result };
    }
};
