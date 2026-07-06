const std = @import("std");
const core = @import("core");
const consensus = @import("consensus");
const node_runner = @import("node_runner.zig");
const load_generator = @import("load_generator.zig");
const dashboard = @import("dashboard.zig");
const attack_scenario = @import("attack_scenario.zig");

fn printUsage() void {
    std.debug.print(
        \\⚡ ZEPHYRIA NETWORK SIMULATOR ⚡
        \\
        \\Usage:
        \\  zephyria-sim [options]
        \\
        \\Options:
        \\  --nodes <number>    Number of virtual nodes to spin up (default: 3)
        \\  --tx-rate <rate>    Target transaction injection rate in TPS (default: 100)
        \\  --duration <sec>    Simulation duration in seconds, 0 for infinite (default: 0)
        \\  -h, --help          Show this help message
        \\
    , .{});
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer {
        _ = gpa.deinit();
    }
    const backing_alloc = gpa.allocator();

    var ts_alloc_wrapper = std.heap.ThreadSafeAllocator{ .child_allocator = backing_alloc };
    const allocator = ts_alloc_wrapper.allocator();

    // Parse args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var node_count: u32 = 3;
    var tx_rate: u32 = 100;
    var duration_sec: u64 = 0;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--nodes")) {
            if (i + 1 < args.len) {
                node_count = try std.fmt.parseInt(u32, args[i + 1], 10);
                i += 1;
            } else {
                std.debug.print("Error: --nodes requires a value\n", .{});
                printUsage();
                return;
            }
        } else if (std.mem.eql(u8, args[i], "--tx-rate")) {
            if (i + 1 < args.len) {
                tx_rate = try std.fmt.parseInt(u32, args[i + 1], 10);
                i += 1;
            } else {
                std.debug.print("Error: --tx-rate requires a value\n", .{});
                printUsage();
                return;
            }
        } else if (std.mem.eql(u8, args[i], "--duration")) {
            if (i + 1 < args.len) {
                duration_sec = try std.fmt.parseInt(u64, args[i + 1], 10);
                i += 1;
            } else {
                std.debug.print("Error: --duration requires a value\n", .{});
                printUsage();
                return;
            }
        } else if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
            printUsage();
            return;
        } else {
            std.debug.print("Error: Unknown argument '{s}'\n", .{args[i]});
            printUsage();
            return;
        }
    }

    if (node_count == 0) {
        std.debug.print("Error: --nodes must be at least 1\n", .{});
        return;
    }

    std.debug.print("Initializing simulation with {d} nodes at {d} TPS target rate...\n", .{ node_count, tx_rate });

    // Setup validators array deterministically
    const validator_count = if (node_count > 1) node_count - 1 else 1;
    var validator_keys = try allocator.alloc([32]u8, node_count);
    defer allocator.free(validator_keys);

    var validators = try allocator.alloc(consensus.types.ValidatorInfo, validator_count);
    defer {
        for (validators) |v| {
            allocator.free(v.name);
        }
        allocator.free(validators);
    }

    for (0..node_count) |ni| {
        var seed_bytes: [32]u8 = undefined;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update("zephyria-sim-seed");
        var idx_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &idx_le, @intCast(ni), .little);
        hasher.update(&idx_le);
        hasher.final(&seed_bytes);
        validator_keys[ni] = seed_bytes;
    }

    for (0..validator_count) |vi| {
        const seed_bytes = validator_keys[vi];
        const val_addr = try core.accounts.eoa.addressFromPrivKey(seed_bytes);
        const name = try std.fmt.allocPrint(allocator, "validator-{d}", .{vi});
        validators[vi] = .{
            .address = val_addr,
            .stake = 100_000_000_000_000_000_000_000, // 100k ZEE
            .status = .Active,
            .blsPubKey = consensus.keys.deriveBlsPubKey(seed_bytes),
            .commission = 500, // 5%
            .activationBlock = 0,
            .slashCount = 0,
            .totalRewards = 0,
            .name = name,
            .website = "",
        };
    }

    // Initialize virtual nodes array
    var nodes = try allocator.alloc(*node_runner.VirtualNode, node_count);
    defer allocator.free(nodes);

    var paths = try allocator.alloc([]const u8, node_count);
    defer {
        for (paths) |p| {
            allocator.free(p);
        }
        allocator.free(paths);
    }

    for (0..node_count) |ni| {
        const p2p_port = @as(u16, @intCast(30300 + ni));
        const http_port = @as(u16, @intCast(8545 + ni));
        const is_miner = (ni < validator_count); // first N-1 are miners, last is sync
        const data_dir = try std.fmt.allocPrint(allocator, "sim_data_v{d}", .{ni});
        paths[ni] = data_dir;

        // Clean up pre-existing directory
        std.fs.cwd().deleteTree(data_dir) catch {};

        nodes[ni] = try node_runner.VirtualNode.init(
            allocator,
            @intCast(ni),
            p2p_port,
            http_port,
            data_dir,
            is_miner,
            validators,
            validator_keys[ni],
        );
    }

    // Perform initial epoch rotation on all nodes to kick off consensus
    for (nodes) |node| {
        const initial_stakes = try allocator.alloc(u256, validators.len);
        defer allocator.free(initial_stakes);
        @memset(initial_stakes, 100_000_000_000);
        try node.engine.rotateEpoch(0, node.chain.genesisId.bytes, initial_stakes);
    }

    // Start P2P and RPC servers, and miners
    for (nodes) |node| {
        try node.start();
    }

    // Link peers together. We connect everyone to Validator 0's address.
    if (node_count > 1) {
        const val0_addr = try std.net.Address.parseIp4("127.0.0.1", 30300);
        for (1..node_count) |ni| {
            nodes[ni].p2p_server.connectPeer(val0_addr) catch |err| {
                std.debug.print("Warning: Node {d} failed to connect to Node 0: {}\n", .{ ni, err });
            };
        }
    }

    // Start load generator on Node 0 (the miner node)
    var load_gen = try load_generator.LoadGenerator.init(allocator, nodes[0], tx_rate);
    defer load_gen.deinit();
    try load_gen.start();

    // Spawn interactive keyboard input thread
    var input_running = std.atomic.Value(bool).init(true);
    var cmd_atom = std.atomic.Value(u8).init(0);
    const input_reader = StdinReader{
        .running = &input_running,
        .cmd_atom = &cmd_atom,
    };
    const input_thread = try std.Thread.spawn(.{}, StdinReader.run, .{input_reader});

    // Main control & drawing loop
    const start_time = std.time.timestamp();
    var active_attack: ?[]const u8 = null;

    while (true) {
        const now = std.time.timestamp();
        const elapsed = @as(u64, @intCast(now - start_time));

        // Draw Dashboard
        dashboard.printDashboard(nodes, load_gen, active_attack, elapsed);

        // Check time limit
        if (duration_sec > 0 and elapsed >= duration_sec) {
            std.debug.print("Simulation duration of {d}s reached. Exiting...\n", .{duration_sec});
            break;
        }

        // Check commands from stdin thread
        const cmd = cmd_atom.swap(0, .seq_cst);
        if (cmd != 0) {
            switch (cmd) {
                '1' => {
                    active_attack = "Double-Signing";
                    attack_scenario.runDoubleSign(nodes) catch |err| {
                        std.debug.print("DoubleSign attack failed: {}\n", .{err});
                    };
                },
                '2' => {
                    active_attack = "Transaction Replay";
                    attack_scenario.runReplay(nodes) catch |err| {
                        std.debug.print("Replay attack failed: {}\n", .{err});
                    };
                },
                '3' => {
                    active_attack = "UDP Spam/Eclipse";
                    attack_scenario.runSpam(nodes) catch |err| {
                        std.debug.print("Spam attack failed: {}\n", .{err});
                    };
                },
                '4' => {
                    active_attack = "Validator Downtime";
                    attack_scenario.runDowntime(nodes) catch |err| {
                        std.debug.print("Downtime attack failed: {}\n", .{err});
                    };
                },
                '5' => {
                    if (load_gen.running.load(.seq_cst)) {
                        load_gen.stop();
                        std.debug.print("Stopped load generator.\n", .{});
                    } else {
                        try load_gen.start();
                        std.debug.print("Started load generator.\n", .{});
                    }
                },
                'Q', 'q' => {
                    std.debug.print("Quitting simulation...\n", .{});
                    break;
                },
                else => {},
            }
        }

        std.Thread.sleep(1000 * std.time.ns_per_ms);
    }

    // Clean up input thread
    input_running.store(false, .seq_cst);
    
    // Close stdin to unblock the stdin thread's blocking read
    std.posix.close(std.fs.File.stdin().handle);
    input_thread.join();

    // Stop transaction generator thread before deinitializing nodes to prevent use-after-free
    load_gen.stop();

    // Clean up nodes
    for (nodes) |node| {
        node.deinit();
    }

    // Remove data directories
    for (paths) |p| {
        std.fs.cwd().deleteTree(p) catch {};
    }
}

const StdinReader = struct {
    running: *std.atomic.Value(bool),
    cmd_atom: *std.atomic.Value(u8),
    
    pub fn run(self: StdinReader) void {
        const stdin = std.fs.File.stdin();
        var buf: [1024]u8 = undefined;
        var f_reader = stdin.reader(&buf);
        const reader = &f_reader.interface;
        while (self.running.load(.seq_cst)) {
            const line = reader.takeDelimiter('\n') catch {
                break;
            };
            const actual_line = line orelse break;
            const trimmed = std.mem.trim(u8, actual_line, " \r\t");
            if (trimmed.len > 0) {
                const char = trimmed[0];
                self.cmd_atom.store(char, .seq_cst);
            }
        }
    }
};
