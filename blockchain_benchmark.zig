const std = @import("std");
const storage = @import("storage");
const consensus = @import("consensus");
const core = @import("core");
const utils = @import("utils");
const vm_bridge = @import("vm_bridge");
const rlp = @import("rlp");
const encoding = @import("encoding");
const vm = @import("vm");

const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";

const Config = struct {
    txs_count: u32 = 10000,
    threads: u32 = 8,
    file_path: []const u8 = "./TokenTest.fozbin",
    db_path: []const u8 = "./blockchain_bench_data_db",
    is_polka: bool = false,
};

fn printHelp(writer: anytype) !void {
    try writer.print(
        \\
        \\  {s}Zephyria Blockchain Simulation Benchmark{s}
        \\
        \\  USAGE
        \\    blockchain_benchmark [OPTIONS]
        \\
        \\  OPTIONS
        \\    --txs     <n>       Number of transactions to execute (default: 10000)
        \\    --threads <n>       Number of execution threads       (default: 8)
        \\    --file    <path>    Path to .fozbin contract package  (default: ./TokenTest.fozbin)
        \\    --db      <path>    Temporary DB directory path       (default: ./blockchain_bench_data_db)
        \\    --polka             Run benchmark using PolkaVM compatible contract (default: false)
        \\
        \\  EXAMPLES
        \\    zig build bench-blockchain -- --txs 10000 --threads 8
        \\
    , .{ BOLD, RESET });
}

pub fn main() !void {
    // Use c_allocator (thread-safe malloc/free) instead of GPA.
    // GPA has internal locking that serializes multi-threaded allocations.
    const allocator = std.heap.c_allocator;

    var stdout_wrapper = std.fs.File.stdout().writer(&.{});
    const stdout = &stdout_wrapper.interface;
    var stderr_wrapper = std.fs.File.stderr().writer(&.{});
    const stderr = &stderr_wrapper.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cfg = Config{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--txs")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--txs requires a number\n", .{});
                return;
            }
            cfg.txs_count = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--threads")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--threads requires a number\n", .{});
                return;
            }
            cfg.threads = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--file")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--file requires a path\n", .{});
                return;
            }
            cfg.file_path = args[i];
        } else if (std.mem.eql(u8, arg, "--db")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--db requires a path\n", .{});
                return;
            }
            cfg.db_path = args[i];
        } else if (std.mem.eql(u8, arg, "--polka")) {
            cfg.is_polka = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp(stdout);
            return;
        } else {
            try stderr.print("Unknown argument: {s}\n", .{arg});
            try printHelp(stderr);
            std.process.exit(1);
        }
    }

    // Read the contract package bytecode
    if (cfg.is_polka and std.mem.eql(u8, cfg.file_path, "./TokenTest.fozbin")) {
        cfg.file_path = "vm/polkavm/revive-transfer-example.elf";
    }
    try stdout.print("Loading contract package from: {s}...\n", .{cfg.file_path});
    const bytecode = loadFile(allocator, cfg.file_path) catch |err| {
        try stderr.print("Failed to load contract package: {}\n", .{err});
        return err;
    };
    defer allocator.free(bytecode);

    // Create Arena-backed FlatTable directly (ZephyrDB backend — no checkpoint/WAL)
    try stdout.print("Initializing Arena + FlatTable...\n", .{});
    var arena = try storage.zephyrdb.Arena.initForTesting(allocator, 256 * 1024 * 1024);
    errdefer arena.deinit();

    var flat_kv = try storage.zephyrdb.FlatTable.init(&arena, null);
    errdefer {
        flat_kv.deinit();
        arena.deinit();
    }

    const db_adapter = storage.DB{
        .ptr = &flat_kv,
        .writeFn = struct {
            fn write(ptr: *anyopaque, key: []const u8, value: []const u8) !void {
                const ft: *storage.zephyrdb.FlatTable = @ptrCast(@alignCast(ptr));
                var key32: [32]u8 = [_]u8{0} ** 32;
                @memcpy(key32[0..@min(key.len, @as(usize, 32))], key);
                try ft.put(key32, value);
            }
        }.write,
        .readFn = struct {
            fn read(ptr: *anyopaque, key: []const u8) ?[]const u8 {
                const ft: *storage.zephyrdb.FlatTable = @ptrCast(@alignCast(ptr));
                var key32: [32]u8 = [_]u8{0} ** 32;
                @memcpy(key32[0..@min(key.len, @as(usize, 32))], key);
                return ft.get(key32);
            }
        }.read,
        .deleteFn = null,
    };
    var worldState = core.state.State.init(allocator, db_adapter);
    defer {
        worldState.deinit();
        flat_kv.deinit();
        arena.deinit();
    }

    const num_senders = 500;
    var senders = try allocator.alloc(core.types.Address, num_senders);
    defer allocator.free(senders);

    try stdout.print("Generating {} genesis accounts...\n", .{num_senders});
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    for (0..num_senders) |j| {
        var addr_bytes: [32]u8 = undefined;
        random.bytes(&addr_bytes);
        senders[j] = core.types.Address{ .bytes = addr_bytes };
        try worldState.setBalance(senders[j], 1000000000000000000000000000000000);
        try worldState.setSequence(senders[j], 0);
    }

    const contract_addr = core.types.Address{
        .bytes = [_]u8{ 0x10, 0x10 } ++ [_]u8{0} ** 30,
    };
    try worldState.setCode(contract_addr, bytecode);

    // Generate transactions
    try stdout.print("Generating {} transactions...\n", .{cfg.txs_count});
    var txs = try allocator.alloc(core.types.Transaction, cfg.txs_count);
    defer allocator.free(txs);

    const dummy_data = try allocator.alloc(u8, 1);
    dummy_data[0] = 0x00;
    defer allocator.free(dummy_data);

    for (0..cfg.txs_count) |j| {
        const sender_idx = j % num_senders;
        const sender = senders[sender_idx];
        const nonce = j / num_senders;

        txs[j] = core.types.Transaction{
            .sequence = nonce,
            .computePrice = 1000000000,
            .executionBudget = 2000000,
            .from = sender,
            .to = contract_addr,
            .value = 0,
            .data = dummy_data,
        };
    }

    // Configure DAG Pipeline
    try stdout.print("Initializing VMBridge and DAGExecutor...\n", .{});
    var riscvBridge = try vm_bridge.VMBridge.init(allocator, .{
        .enableJit = true,
        .optimizationLevel = .Fast,
        .traceExecution = false,
    });
    defer riscvBridge.deinit();

    riscvBridge.setExecutionContext(.{
        .timestamp = @intCast(@max(0, std.time.timestamp())),
        .blockNumber = 1,
        .chainId = 99999,
        .producer = [_]u8{0} ** 32,
        .prevRandao = [_]u8{0} ** 32,
    });

    var dagExecutor = core.dag_executor.DAGExecutor.init(allocator, &worldState, .{
        .numThreads = cfg.threads,
        .blockExecutionBudget = 1_000_000_000,
        .producer = core.types.Address.zero(),
        .transferFastPath = true,
    });

    dagExecutor.setVMCallback(riscvBridge.getCallback());

    // Run DAG Scheduler
    try stdout.print("Scheduling transactions via DAG Scheduler...\n", .{});
    var timer = try std.time.Timer.start();
    var plan = try core.dag_scheduler.scheduleFromTxs(allocator, txs, .{
        .numThreads = cfg.threads,
        .minTxsPerThread = 1,
    });
    defer plan.deinit();
    const schedule_time_ns = timer.read();

    // Execute Block
    try stdout.print("Executing block with {} lanes...\n", .{plan.lanes.len});
    var block_res = try dagExecutor.executeBlock(&plan);
    defer block_res.deinit(allocator);

    var succeeded: u32 = 0;
    for (block_res.txResults) |r| {
        if (r.success) succeeded += 1;
    }

    const total_pipeline_ns = block_res.executionTimeNs + block_res.mergeTimeNs + block_res.commitTimeNs + schedule_time_ns;
    const txs_f = @as(f64, @floatFromInt(cfg.txs_count));
    const phase1_secs = @as(f64, @floatFromInt(block_res.executionTimeNs)) / 1_000_000_000.0;
    const overall_secs = @as(f64, @floatFromInt(total_pipeline_ns)) / 1_000_000_000.0;

    const phase1_tps = if (phase1_secs > 0) txs_f / phase1_secs else 0.0;
    const overall_tps = if (overall_secs > 0) txs_f / overall_secs else 0.0;

    try stdout.print("\n", .{});
    try stdout.print("{s}========================================================================{s}\n", .{ BOLD ++ GREEN, RESET });
    try stdout.print("{s}                     SIMULATED BLOCKCHAIN BENCHMARK RESULTS            {s}\n", .{ BOLD, RESET });
    try stdout.print("{s}========================================================================{s}\n", .{ BOLD ++ GREEN, RESET });
    try stdout.print("  {s}Transactions executed:{s}   {} / {}\n", .{ BOLD, RESET, succeeded, cfg.txs_count });
    try stdout.print("  {s}Execution threads:{s}       {}\n", .{ BOLD, RESET, cfg.threads });
    try stdout.print("  {s}Lanes scheduled:{s}         {}\n", .{ BOLD, RESET, plan.lanes.len });
    try stdout.print("\n", .{});
    try stdout.print("  {s}LATENCY BREAKDOWN:{s}\n", .{ BOLD ++ CYAN, RESET });
    try stdout.print("    ├─ {s}DAG Scheduling:{s}        {d:.3} ms\n", .{ DIM, RESET, @as(f64, @floatFromInt(schedule_time_ns)) / 1_000_000.0 });
    try stdout.print("    ├─ {s}Phase 1 (Parallel Lane):{s} {d:.3} ms\n", .{ DIM, RESET, @as(f64, @floatFromInt(block_res.executionTimeNs)) / 1_000_000.0 });
    try stdout.print("    ├─ {s}Phase 2 (Delta Merge):{s}   {d:.3} ms\n", .{ DIM, RESET, @as(f64, @floatFromInt(block_res.mergeTimeNs)) / 1_000_000.0 });
    try stdout.print("    └─ {s}Phase 3 (ZephyrDB(Flat) Commit):{s}  {d:.3} ms\n", .{ DIM, RESET, @as(f64, @floatFromInt(block_res.commitTimeNs)) / 1_000_000.0 });
    try stdout.print("    {s}------------------------------------{s}\n", .{ DIM, RESET });
    try stdout.print("    {s}Total Block Pipeline:{s}     {d:.3} ms\n", .{ BOLD, RESET, @as(f64, @floatFromInt(total_pipeline_ns)) / 1_000_000.0 });
    try stdout.print("\n", .{});
    try stdout.print("  {s}THROUGHPUT ANALYSIS:{s}\n", .{ BOLD ++ YELLOW, RESET });
    try stdout.print("    • {s}VM-Only Projection (Baseline):{s}  ~45,600 tx/sec\n", .{ DIM, RESET });
    try stdout.print("    • {s}Phase 1 (Parallel Lane VM):{s}     {d:.2} tx/sec\n", .{ BOLD, RESET, phase1_tps });
    try stdout.print("    • {s}Overall Simulated L1 Workflow:{s}  {s}{d:.2} tx/sec{s}\n", .{ BOLD ++ GREEN, RESET, BOLD ++ GREEN, overall_tps, RESET });
    try stdout.print("========================================================================\n\n", .{});

    vm.contractLoader.deinitAotCache(allocator);
}

fn loadFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const size = (try file.stat()).size;
    const buf = try allocator.alloc(u8, size);
    _ = try file.readAll(buf);
    return buf;
}
