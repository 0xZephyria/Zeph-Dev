// ============================================================================
// ForgeVM Test Suite — Zephyria Production Readiness & TPS Viability Tool
// ============================================================================
//
// Usage (build.zig):
//   const suite = b.addExecutable(.{ .name = "forge_test_suite", .root_source_file = ... });
//   suite.root_module.addImport("vm", vm_module);
//
// Run modes:
//   ./forge_test_suite --file contract.fozbin          # execute + correctness report
//   ./forge_test_suite --hex 13000000730000000         # raw hex bytecode
//   ./forge_test_suite --file contract.fozbin --bench 100000
//                                                      # benchmark N iterations
//   ./forge_test_suite --file contract.fozbin --bench 100000 --threads 8
//                                                      # projected multi-core TPS
//   ./forge_test_suite --selftest                      # built-in VM correctness suite
//   ./forge_test_suite --all contract.fozbin           # selftest + exec + bench

const std = @import("std");
const vm = @import("vm");

const executor = vm.executor;
const sandbox = vm.sandbox;
const forge_format = vm.forge_format;
const forge_loader = vm.forge_loader;
const contract_loader = vm.contract_loader;
const syscall_dispatch = vm.syscall_dispatch;
const gas_table = vm.gas_table;
const decoder = vm.decoder;

const ForgeVM = executor.ForgeVM;
const ExecutionStatus = executor.ExecutionStatus;
const ExecutionResult = executor.ExecutionResult;
const SandboxMemory = sandbox.SandboxMemory;
const HostEnv = syscall_dispatch.HostEnv;
const VMPool = vm.vm_pool.VMPool;
const PoolConfig = vm.vm_pool.PoolConfig;

// ============================================================================
// ANSI colour helpers (gracefully disabled on non-TTY)
// ============================================================================
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";

// ============================================================================
// CLI configuration
// ============================================================================

const Config = struct {
    /// Path to a .fozbin contract package
    file_path: ?[]const u8 = null,
    /// Hex-encoded raw bytecode (no 0x prefix required)
    hex_bytecode: ?[]const u8 = null,
    /// ABI-encoded calldata bytes (hex)
    calldata_hex: ?[]const u8 = null,
    /// Gas limit for each execution
    gas_limit: u64 = 10_000_000,
    /// Number of benchmark iterations (0 = no bench)
    bench_iters: u64 = 0,
    /// Simulated thread count for TPS projection
    threads: u32 = 1,
    /// Run built-in VM correctness self-tests
    selftest: bool = false,
    /// Run everything: selftest + single exec + bench (if iters > 0)
    all: bool = false,
    /// Emit JSON output instead of human-readable
    json: bool = false,
    /// Verbose: print per-iteration gas and timing
    verbose: bool = false,
};

// ============================================================================
// Benchmark statistics
// ============================================================================

const BenchStats = struct {
    iterations: u64,
    total_ns: u64,
    min_ns: u64,
    max_ns: u64,
    mean_ns: u64,
    median_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    /// Gas consumed per execution (from the last run; consistent contracts are deterministic)
    gas_per_exec: u64,
    /// How many executions ended with each status
    status_counts: [7]u64,
    /// Faults encountered
    fault_count: u64,
    fault_reason: ?[]const u8,

    pub fn calculatePercentiles(self: *BenchStats, samples: []u64) void {
        if (samples.len == 0) return;
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        const len = samples.len;
        self.median_ns = samples[len / 2];
        self.p95_ns = samples[@min(len - 1, len * 95 / 100)];
        self.p99_ns = samples[@min(len - 1, len * 99 / 100)];
    }

    fn throughput_per_sec(self: *const BenchStats) f64 {
        if (self.total_ns == 0) return 0;
        return @as(f64, @floatFromInt(self.iterations)) /
            (@as(f64, @floatFromInt(self.total_ns)) / 1_000_000_000.0);
    }

    fn projected_tps(self: *const BenchStats, threads: u32) f64 {
        return self.throughput_per_sec() * @as(f64, @floatFromInt(threads));
    }

    fn mean_us(self: *const BenchStats) f64 {
        return @as(f64, @floatFromInt(self.mean_ns)) / 1000.0;
    }

    fn p99_us(self: *const BenchStats) f64 {
        return @as(f64, @floatFromInt(self.p99_ns)) / 1000.0;
    }
};

// ============================================================================
// Correctness test record
// ============================================================================

const TestResult = struct {
    name: []const u8,
    passed: bool,
    message: []const u8,
};

// ============================================================================
// Main entry point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_wrapper = std.fs.File.stdout().writer(&.{});
    const stdout = &stdout_wrapper.interface;
    var stderr_wrapper = std.fs.File.stderr().writer(&.{});
    const stderr = &stderr_wrapper.interface;

    // ── Parse CLI args ──────────────────────────────────────────────
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cfg = Config{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--file") or std.mem.eql(u8, arg, "-f")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--file requires a path\n", .{});
                return;
            }
            cfg.file_path = args[i];
        } else if (std.mem.eql(u8, arg, "--hex")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--hex requires hex bytes\n", .{});
                return;
            }
            cfg.hex_bytecode = args[i];
        } else if (std.mem.eql(u8, arg, "--calldata")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--calldata requires hex bytes\n", .{});
                return;
            }
            cfg.calldata_hex = args[i];
        } else if (std.mem.eql(u8, arg, "--gas")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--gas requires a number\n", .{});
                return;
            }
            cfg.gas_limit = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--bench") or std.mem.eql(u8, arg, "-b")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--bench requires iteration count\n", .{});
                return;
            }
            cfg.bench_iters = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--threads") or std.mem.eql(u8, arg, "-t")) {
            i += 1;
            if (i >= args.len) {
                try stderr.print("--threads requires a number\n", .{});
                return;
            }
            cfg.threads = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--selftest")) {
            cfg.selftest = true;
        } else if (std.mem.eql(u8, arg, "--all") or std.mem.eql(u8, arg, "-a")) {
            cfg.all = true;
            // Next positional is optional file
            if (i + 1 < args.len and args[i + 1][0] != '-') {
                i += 1;
                cfg.file_path = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--json")) {
            cfg.json = true;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            cfg.verbose = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp(stdout);
            return;
        } else {
            // Treat bare positional as file path
            cfg.file_path = arg;
        }
    }

    if (args.len == 1) {
        try printHelp(stdout);
        return;
    }

    // ── Load bytecode ───────────────────────────────────────────────
    var bytecode_buf: ?[]u8 = null;
    defer if (bytecode_buf) |b| allocator.free(b);

    var is_forge_package = false;

    if (cfg.file_path) |path| {
        bytecode_buf = try loadFile(allocator, path);
        is_forge_package = isFozbin(bytecode_buf.?);
    } else if (cfg.hex_bytecode) |hex| {
        bytecode_buf = try decodeHex(allocator, hex);
    }

    // ── Load calldata ───────────────────────────────────────────────
    var calldata: []const u8 = &[_]u8{};
    var calldata_buf: ?[]u8 = null;
    defer if (calldata_buf) |b| allocator.free(b);

    if (cfg.calldata_hex) |hex| {
        calldata_buf = try decodeHex(allocator, hex);
        calldata = calldata_buf.?;
    }

    // ── Banner ──────────────────────────────────────────────────────
    if (!cfg.json) {
        try stdout.print(
            "\n{s}ForgeVM Test Suite{s}  —  Zephyria TPS Viability Analyzer\n",
            .{ BOLD, RESET },
        );
        try stdout.print(
            "{s}════════════════════════════════════════════════════════{s}\n\n",
            .{ DIM, RESET },
        );
    }

    var all_passed = true;

    // ── Self-test mode ──────────────────────────────────────────────
    if (cfg.selftest or cfg.all) {
        const ok = try runSelfTests(allocator, stdout, cfg.json);
        if (!ok) all_passed = false;
    }

    // ── Single execution ────────────────────────────────────────────
    if (bytecode_buf != null and !cfg.json) {
        const detected = if (is_forge_package) ".fozbin package" else if (bytecode_buf.?.len >= 4 and
            bytecode_buf.?[0] == 0x7F and
            bytecode_buf.?[1] == 'E') "ELF binary" else "raw bytecode";
        try stdout.print("{s}[ SINGLE EXECUTION  —  {s} ]{s}\n", .{ BOLD, detected, RESET });
        const single = try runSingleExecution(allocator, bytecode_buf.?, calldata, cfg.gas_limit, is_forge_package);
        try printSingleResult(stdout, single);
        if (single.status != .returned and single.status != .breakpoint) all_passed = false;
    }

    // ── Benchmark mode ──────────────────────────────────────────────
    if (bytecode_buf != null and cfg.bench_iters > 0) {
        if (!cfg.json) {
            try stdout.print(
                "\n{s}[ BENCHMARK  —  {} iterations  ×  {} thread(s) projected ]{s}\n",
                .{ BOLD, cfg.bench_iters, cfg.threads, RESET },
            );
        }

        const stats = try runBenchmark(
            allocator,
            bytecode_buf.?,
            calldata,
            cfg.gas_limit,
            cfg.bench_iters,
            cfg.threads,
            is_forge_package,
            cfg.verbose,
            stdout,
        );

        if (cfg.json) {
            try printBenchJson(stdout, stats, cfg.threads, cfg.file_path orelse "<hex>");
        } else {
            try printBenchReport(stdout, stats, cfg.threads);
        }

        try printTpsAnalysis(stdout, stats, cfg.threads, cfg.json);
    } else if (bytecode_buf == null and !cfg.selftest and !cfg.all) {
        try stderr.print("No bytecode provided. Use --file, --hex, or --selftest.\n", .{});
        try printHelp(stderr);
        std.process.exit(1);
    }

    if (!cfg.json) {
        const overall_msg = if (all_passed)
            GREEN ++ "All checks passed." ++ RESET
        else
            RED ++ "Some checks failed — review output above." ++ RESET;
        try stdout.print("\n{s}\n\n", .{overall_msg});
    }
}

// ============================================================================
// File / hex loading
// ============================================================================

fn loadFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const size = (try file.stat()).size;
    const buf = try allocator.alloc(u8, size);
    _ = try file.readAll(buf);
    return buf;
}

/// Returns true only if the data starts with the .fozbin magic AND is
/// at least as large as a ForgeHeader.  A file with the right 4 magic bytes
/// but wrong length is still handed to the ELF fallback.
fn isFozbin(data: []const u8) bool {
    if (data.len < @sizeOf(forge_format.ForgeHeader)) return false;
    return std.mem.eql(u8, data[0..4], &forge_format.FORGE_MAGIC);
}

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    // Strip optional 0x prefix and any whitespace
    var src = hex;
    if (src.len >= 2 and src[0] == '0' and (src[1] == 'x' or src[1] == 'X'))
        src = src[2..];

    // Remove spaces / newlines
    var clean = try allocator.alloc(u8, src.len);
    defer allocator.free(clean);
    var ci: usize = 0;
    for (src) |c| {
        if (c != ' ' and c != '\n' and c != '\r' and c != '\t') {
            clean[ci] = c;
            ci += 1;
        }
    }
    const clean_slice = clean[0..ci];

    if (clean_slice.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, clean_slice.len / 2);
    _ = try std.fmt.hexToBytes(out, clean_slice);
    return out;
}

// ============================================================================
// Single execution
// ============================================================================

const SingleResult = struct {
    status: ExecutionStatus,
    gas_used: u64,
    gas_remaining: u64,
    return_data: []const u8,
    fault_pc: u32,
    fault_reason: ?[]const u8,
    elapsed_ns: u64,
    log_count: usize,
    bytecode_len: usize,
};

fn runSingleExecution(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    is_package: bool,
) !SingleResult {
    var env = HostEnv.init(allocator);
    defer env.deinit();
    env.gas_limit = gas_limit;
    env.chain_id = 99999;
    env.block_number = 1;
    env.timestamp = @intCast(std.time.timestamp());

    var timer = try std.time.Timer.start();

    // Cascade: try .fozbin → ELF → raw bytecode.
    // Never propagate an error — always produce a ContractResult so the
    // suite can report what happened rather than panic.
    const cr = blk: {
        if (is_package) {
            if (contract_loader.executeFromZeph(allocator, bytecode, calldata, gas_limit, &env)) |r| {
                break :blk r;
            } else |zeph_err| {
                // .fozbin parse failed — try treating the payload as raw ELF
                // (common when a .fozbin wrapper is malformed but the ELF inside is intact)
                std.debug.print(
                    "[suite] .fozbin parse failed ({s}), falling back to ELF loader\n",
                    .{@errorName(zeph_err)},
                );
                env.clearTransientStorage();
                if (contract_loader.executeFromElf(allocator, bytecode, calldata, gas_limit, &env)) |r| {
                    break :blk r;
                } else |elf_err| {
                    std.debug.print(
                        "[suite] ELF loader also failed ({s}), treating as raw bytecode\n",
                        .{@errorName(elf_err)},
                    );
                }
            }
        } else {
            if (contract_loader.executeFromElf(allocator, bytecode, calldata, gas_limit, &env)) |r| {
                break :blk r;
            } else |elf_err| {
                std.debug.print(
                    "[suite] ELF loader failed ({s}), treating as raw bytecode\n",
                    .{@errorName(elf_err)},
                );
            }
        }

        // Final fallback: load raw bytes directly into code region and execute
        env.clearTransientStorage();
        var mem = try sandbox.SandboxMemory.init(allocator);
        defer mem.deinit();

        const code_len = @min(bytecode.len, sandbox.CODE_SIZE);
        mem.loadCode(bytecode[0..code_len]) catch |e| {
            std.debug.print("[suite] loadCode failed: {s}\n", .{@errorName(e)});
            break :blk contract_loader.ContractResult{
                .status = .fault,
                .gas_used = 0,
                .gas_remaining = gas_limit,
                .return_data = &[_]u8{},
                .logs = &[_]syscall_dispatch.LogEntry{},
                .fault_pc = 0,
                .fault_reason = "loadCode failed",
            };
        };
        if (calldata.len > 0) _ = mem.loadCalldata(calldata) catch {};

        const handler = syscall_dispatch.createHandler(&env);
        var raw_vm = ForgeVM.init(&mem, @intCast(code_len), gas_limit, handler);
        raw_vm.host_ctx = &env;
        const raw_result = raw_vm.execute();

        var ret: []const u8 = &[_]u8{};
        if (raw_result.return_data_len > 0) {
            ret = mem.getReturnData(raw_result.return_data_offset, raw_result.return_data_len) catch &[_]u8{};
        }

        break :blk contract_loader.ContractResult{
            .status = raw_result.status,
            .gas_used = raw_result.gas_used,
            .gas_remaining = raw_result.gas_remaining,
            .return_data = ret,
            .logs = env.logs.items,
            .fault_pc = raw_result.fault_pc,
            .fault_reason = raw_result.fault_reason,
        };
    };

    const elapsed = timer.read();

    return SingleResult{
        .status = cr.status,
        .gas_used = cr.gas_used,
        .gas_remaining = cr.gas_remaining,
        .return_data = cr.return_data,
        .fault_pc = cr.fault_pc,
        .fault_reason = cr.fault_reason,
        .elapsed_ns = elapsed,
        .log_count = cr.logs.len,
        .bytecode_len = bytecode.len,
    };
}

fn printSingleResult(writer: anytype, r: SingleResult) !void {
    const status_color = switch (r.status) {
        .returned => GREEN,
        .reverted => YELLOW,
        .breakpoint => CYAN,
        else => RED,
    };
    try writer.print("  Status         : {s}{s}{s}\n", .{ status_color, @tagName(r.status), RESET });
    try writer.print("  Gas used       : {} / {} ({d:.1}%)\n", .{
        r.gas_used,
        r.gas_used + r.gas_remaining,
        if (r.gas_used + r.gas_remaining > 0)
            100.0 * @as(f64, @floatFromInt(r.gas_used)) /
                @as(f64, @floatFromInt(r.gas_used + r.gas_remaining))
        else
            0.0,
    });
    try writer.print("  Return data    : {} bytes\n", .{r.return_data.len});
    try writer.print("  Logs emitted   : {}\n", .{r.log_count});
    try writer.print("  Bytecode size  : {} bytes\n", .{r.bytecode_len});
    try writer.print("  Wall time      : {d:.3} µs\n", .{@as(f64, @floatFromInt(r.elapsed_ns)) / 1000.0});
    if (r.status == .fault) {
        try writer.print("  {s}Fault PC       : 0x{x}{s}\n", .{ RED, r.fault_pc, RESET });
        try writer.print("  {s}Fault reason   : {s}{s}\n", .{ RED, r.fault_reason orelse "unknown", RESET });
    }
    try writer.print("\n", .{});
}

const WorkerContext = struct {
    allocator: std.mem.Allocator,
    pool: *VMPool,
    bytecode: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    iterations: u64,
    is_package: bool,
    verbose: bool,
    stats: BenchStats = undefined,
    samples: []u64 = undefined,
    err: ?anyerror = null,
};

fn benchmarkWorker(ctx: *WorkerContext) void {
    // samples are pre-allocated by the caller (runBenchmark) in the WorkerContext
    @memset(ctx.samples, 0);

    var status_counts = [_]u64{0} ** 7;
    var total_ns: u64 = 0;
    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;
    var last_gas: u64 = 0;
    var fault_count: u64 = 0;
    var last_fault_reason: ?[]const u8 = null;

    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const local_allocator = fba.allocator();

    var env = HostEnv.init(local_allocator);
    defer env.deinit();

    const mem = ctx.pool.acquire() orelse {
        ctx.err = error.PoolExhausted;
        return;
    };
    defer ctx.pool.release(mem);

    env.gas_limit = ctx.gas_limit;
    env.chain_id = 99999;
    env.block_number = 1;
    env.timestamp = 1_700_000_000;

    var i: u64 = 0;
    while (i < ctx.iterations) : (i += 1) {
        env.clearTransientStorage();
        env.sload_cache_count = 0;

        var iter_timer = std.time.Timer.start() catch |e| {
            ctx.err = e;
            return;
        };

        const cr = blk: {
            if (ctx.is_package) {
                if (contract_loader.executeFromZephWithMemory(ctx.allocator, mem, ctx.bytecode, ctx.calldata, ctx.gas_limit, &env)) |r| {
                    break :blk r;
                } else |_| {}
            } else {
                if (contract_loader.executeWithMemory(ctx.allocator, mem, ctx.bytecode, ctx.calldata, ctx.gas_limit, &env)) |r| {
                    break :blk r;
                } else |_| {}
            }
            fault_count += 1;
            last_fault_reason = "loader_failed";
            break :blk contract_loader.ContractResult{
                .status = .fault,
                .gas_used = 0,
                .gas_remaining = ctx.gas_limit,
                .return_data = &[_]u8{},
                .logs = &[_]syscall_dispatch.LogEntry{},
                .fault_pc = 0,
                .fault_reason = "loader failed",
            };
        };

        const elapsed = iter_timer.read();
        ctx.samples[i] = elapsed;
        total_ns += elapsed;
        if (elapsed < min_ns) min_ns = elapsed;
        if (elapsed > max_ns) max_ns = elapsed;
        last_gas = cr.gas_used;

        const status_idx: usize = @intFromEnum(cr.status);
        if (status_idx < status_counts.len) status_counts[status_idx] += 1;
    }

    ctx.stats = BenchStats{
        .iterations = ctx.iterations,
        .total_ns = total_ns,
        .min_ns = if (min_ns == std.math.maxInt(u64)) 0 else min_ns,
        .max_ns = max_ns,
        .mean_ns = if (ctx.iterations > 0) total_ns / ctx.iterations else 0,
        .median_ns = 0,
        .p95_ns = 0,
        .p99_ns = 0,
        .gas_per_exec = last_gas,
        .status_counts = status_counts,
        .fault_count = fault_count,
        .fault_reason = last_fault_reason,
    };
}

fn runBenchmark(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    calldata: []const u8,
    gas_limit: u64,
    iterations: u64,
    threads_count: u32,
    is_package: bool,
    verbose: bool,
    writer: anytype,
) !BenchStats {
    if (threads_count <= 1) {
        var status_counts = [_]u64{0} ** 7;
        var total_ns: u64 = 0;
        var min_ns: u64 = std.math.maxInt(u64);
        var max_ns: u64 = 0;
        var last_gas: u64 = 0;
        var fault_count: u64 = 0;
        var last_fault_reason: ?[]const u8 = null;

        var samples = try allocator.alloc(u64, iterations);
        defer allocator.free(samples);

        var pool = try VMPool.init(allocator, .{ .pool_size = 1, .max_overflow = 0 });
        defer pool.deinit();
        const mem = pool.acquire() orelse return error.PoolExhausted;
        defer pool.release(mem);

        var env = HostEnv.init(allocator);
        defer env.deinit();

        var i: u64 = 0;
        while (i < iterations) : (i += 1) {
            env.gas_limit = gas_limit;
            env.chain_id = 99999;
            env.block_number = 1;
            env.timestamp = 1_700_000_000;
            env.clearTransientStorage();
            env.sload_cache_count = 0;
            var iter_timer = try std.time.Timer.start();
            const cr = blk: {
                if (is_package) {
                    if (contract_loader.executeFromZephWithMemory(allocator, mem, bytecode, calldata, gas_limit, &env)) |r| break :blk r else |_| {}
                } else {
                    if (contract_loader.executeWithMemory(allocator, mem, bytecode, calldata, gas_limit, &env)) |r| break :blk r else |_| {}
                }
                fault_count += 1;
                last_fault_reason = "loader_failed";
                break :blk contract_loader.ContractResult{
                    .status = .fault,
                    .gas_used = 0,
                    .gas_remaining = gas_limit,
                    .return_data = &[_]u8{},
                    .logs = &[_]syscall_dispatch.LogEntry{},
                    .fault_pc = 0,
                    .fault_reason = "loader failed",
                };
            };
            const elapsed = iter_timer.read();
            samples[i] = elapsed;
            total_ns += elapsed;
            if (elapsed < min_ns) min_ns = elapsed;
            if (elapsed > max_ns) max_ns = elapsed;
            last_gas = cr.gas_used;

            const status_idx: usize = @intFromEnum(cr.status);
            if (status_idx < status_counts.len) status_counts[status_idx] += 1;

            if (!verbose and i % @max(1, iterations / 20) == 0) {
                try writer.print("\r  Running...  {d:>3}%  ({} / {})", .{ (i * 100) / iterations, i, iterations });
            }
        }
        if (!verbose) try writer.print("\r  Running...  100%  ({} / {})          \n", .{ iterations, iterations });

        var stats = BenchStats{
            .iterations = iterations,
            .total_ns = total_ns,
            .min_ns = if (min_ns == std.math.maxInt(u64)) 0 else min_ns,
            .max_ns = max_ns,
            .mean_ns = if (iterations > 0) total_ns / iterations else 0,
            .median_ns = 0,
            .p95_ns = 0,
            .p99_ns = 0,
            .gas_per_exec = last_gas,
            .status_counts = status_counts,
            .fault_count = fault_count,
            .fault_reason = last_fault_reason,
        };
        stats.calculatePercentiles(samples);
        return stats;
    }

    // Multi-threaded path
    try writer.print("  Initializing VMPool and spawning {d} worker threads...\n", .{threads_count});

    var pool = try VMPool.init(allocator, .{
        .pool_size = threads_count,
        .max_overflow = threads_count,
    });
    defer pool.deinit();

    const threads = try allocator.alloc(std.Thread, threads_count);
    defer allocator.free(threads);

    const workers = try allocator.alloc(WorkerContext, threads_count);
    defer allocator.free(workers);

    const iters_per_thread = iterations / threads_count;
    const extra_iters = iterations % threads_count;

    var spawned: u32 = 0;
    errdefer {
        for (0..spawned) |j| threads[j].join();
    }

    for (0..threads_count) |j| {
        const thread_iters = iters_per_thread + (if (j < extra_iters) @as(u64, 1) else 0);
        const thread_samples = try allocator.alloc(u64, thread_iters);

        workers[j] = .{
            .allocator = allocator,
            .pool = &pool,
            .bytecode = bytecode,
            .calldata = calldata,
            .gas_limit = gas_limit,
            .iterations = thread_iters,
            .samples = thread_samples,
            .is_package = is_package,
            .verbose = verbose,
        };

        threads[j] = try std.Thread.spawn(.{}, benchmarkWorker, .{&workers[j]});
        spawned += 1;
    }

    var total_ns: u64 = 0;
    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;
    var last_gas: u64 = 0;
    var fault_count: u64 = 0;
    var status_counts = [_]u64{0} ** 7;
    var last_fault_reason: ?[]const u8 = null;

    var all_samples = try allocator.alloc(u64, iterations);
    defer allocator.free(all_samples);
    var sample_ptr: usize = 0;

    for (0..threads_count) |j| {
        threads[j].join();
        const w = &workers[j];
        if (w.err) |err| return err;

        total_ns += w.stats.total_ns;
        if (w.stats.min_ns < min_ns) min_ns = w.stats.min_ns;
        if (w.stats.max_ns > max_ns) max_ns = w.stats.max_ns;
        last_gas = w.stats.gas_per_exec;
        fault_count += w.stats.fault_count;
        if (w.stats.fault_reason) |fr| last_fault_reason = fr;

        for (0..status_counts.len) |si| status_counts[si] += w.stats.status_counts[si];

        @memcpy(all_samples[sample_ptr..][0..w.samples.len], w.samples);
        sample_ptr += w.samples.len;
        allocator.free(w.samples);
    }

    try writer.print("  All threads completed. Aggregating results...\n", .{});

    var stats = BenchStats{
        .iterations = iterations,
        .total_ns = total_ns,
        .min_ns = if (min_ns == std.math.maxInt(u64)) 0 else min_ns,
        .max_ns = max_ns,
        .mean_ns = if (iterations > 0) total_ns / iterations else 0,
        .median_ns = 0,
        .p95_ns = 0,
        .p99_ns = 0,
        .gas_per_exec = last_gas,
        .status_counts = status_counts,
        .fault_count = fault_count,
        .fault_reason = last_fault_reason,
    };
    stats.calculatePercentiles(all_samples);
    return stats;
}

fn printBenchReport(writer: anytype, s: BenchStats, threads: u32) !void {
    try writer.print("\n{s}  Latency Distribution{s}\n", .{ BOLD, RESET });
    try writer.print("  ┌─────────────┬──────────────────────┐\n", .{});
    try writer.print("  │ Min         │ {d:>12.3} µs      │\n", .{@as(f64, @floatFromInt(s.min_ns)) / 1000.0});
    try writer.print("  │ Mean        │ {d:>12.3} µs      │\n", .{@as(f64, @floatFromInt(s.mean_ns)) / 1000.0});
    try writer.print("  │ Median      │ {d:>12.3} µs      │\n", .{@as(f64, @floatFromInt(s.median_ns)) / 1000.0});
    try writer.print("  │ P95         │ {d:>12.3} µs      │\n", .{@as(f64, @floatFromInt(s.p95_ns)) / 1000.0});
    try writer.print("  │ P99         │ {d:>12.3} µs      │\n", .{@as(f64, @floatFromInt(s.p99_ns)) / 1000.0});
    try writer.print("  │ Max         │ {d:>12.3} µs      │\n", .{@as(f64, @floatFromInt(s.max_ns)) / 1000.0});
    try writer.print("  └─────────────┴──────────────────────┘\n", .{});

    try writer.print("\n{s}  Throughput{s}\n", .{ BOLD, RESET });
    const tps_single = s.throughput_per_sec();
    const tps_proj = s.projected_tps(threads);
    try writer.print("  Single-core TPS   : {s}{d:>12.0}{s} tx/sec\n", .{ CYAN, tps_single, RESET });
    if (threads > 1) {
        try writer.print("  Projected ({d} cores): {s}{d:>12.0}{s} tx/sec\n", .{ threads, CYAN, tps_proj, RESET });
    }
    try writer.print("  Total iterations  : {d:>12}\n", .{s.iterations});
    try writer.print("  Total wall time   : {d:>12.3} ms\n", .{@as(f64, @floatFromInt(s.total_ns)) / 1_000_000.0});
    try writer.print("  Gas/exec          : {d:>12}\n", .{s.gas_per_exec});

    try writer.print("\n{s}  Execution Status Breakdown{s}\n", .{ BOLD, RESET });
    const status_names = [_][]const u8{ "running", "returned", "reverted", "out_of_gas", "fault", "breakpoint", "self_destruct" };
    for (status_names, 0..) |name, si| {
        if (s.status_counts[si] > 0) {
            const pct = 100.0 * @as(f64, @floatFromInt(s.status_counts[si])) /
                @as(f64, @floatFromInt(s.iterations));
            const col = switch (si) {
                1 => GREEN,
                2 => YELLOW,
                3, 4 => RED,
                else => DIM,
            };
            try writer.print("  {s}{s:<14}{s}: {d:>10}  ({d:.1}%)\n", .{
                col, name, RESET, s.status_counts[si], pct,
            });
        }
    }
    if (s.fault_count > 0) {
        try writer.print("  {s}Last fault reason: {s}{s}\n", .{ RED, s.fault_reason orelse "unknown", RESET });
    }
}

fn printTpsAnalysis(writer: anytype, s: BenchStats, threads: u32, json: bool) !void {
    const tps_1c = s.throughput_per_sec();
    const tps_proj = s.projected_tps(threads);
    const target: f64 = 1_000_000.0;

    // Cores needed to reach 1M TPS at this per-core rate
    const cores_needed: f64 = if (tps_1c > 0) target / tps_1c else std.math.inf(f64);

    const pct_of_target = tps_proj / target * 100.0;
    const viable = tps_proj >= target;
    const marginal = !viable and tps_proj >= target * 0.5;

    if (json) {
        try writer.print(
            \\  "tps_analysis": {{
            \\    "single_core_tps": {d:.2},
            \\    "projected_tps_{d}c": {d:.2},
            \\    "target_tps": 1000000,
            \\    "pct_of_target": {d:.2},
            \\    "cores_to_reach_1m": {d:.1},
            \\    "verdict": "{s}"
            \\  }}
        , .{
            tps_1c,        threads,                                                     tps_proj,
            pct_of_target, if (cores_needed > 99999) @as(f64, 99999) else cores_needed, if (viable) "VIABLE" else if (marginal) "MARGINAL" else "NOT_VIABLE",
        });
        return;
    }

    try writer.print("\n{s}  1M TPS Viability Analysis{s}\n", .{ BOLD, RESET });
    try writer.print("  ──────────────────────────────────────────────────\n", .{});
    try writer.print("  Target            : 1,000,000 tx/sec\n", .{});
    try writer.print("  Single-core rate  : {d:>12.0} tx/sec\n", .{tps_1c});
    if (threads > 1) {
        try writer.print("  Projected ({d:>2}c)   : {d:>12.0} tx/sec\n", .{ threads, tps_proj });
    }
    try writer.print("  % of target       : {d:>11.1}%\n", .{pct_of_target});
    try writer.print("  Cores to reach 1M : {d:>12.1}\n", .{if (cores_needed > 99999) @as(f64, 99999) else cores_needed});

    const verdict_color = if (viable) GREEN else if (marginal) YELLOW else RED;
    const verdict_text = if (viable)
        "VIABLE  — 1M TPS reachable at this workload"
    else if (marginal)
        "MARGINAL — within 2× of target; optimise hot paths"
    else
        "NOT YET  — more work needed (see recommendations below)";

    try writer.print("\n  {s}VERDICT: {s}{s}\n", .{ verdict_color, verdict_text, RESET });

    // Recommendations
    try writer.print("\n{s}  Recommendations{s}\n", .{ BOLD, RESET });
    if (s.mean_ns > 10_000) { // > 10 µs/tx
        try writer.print("  • Mean latency {d:.1} µs > 10 µs target — profile hot syscalls\n", .{s.mean_us()});
    }
    if (s.p99_ns > s.mean_ns * 5) {
        try writer.print("  • P99 ({d:.1} µs) is {d:.1}× mean — check GC/allocation pressure\n", .{ s.p99_us(), @as(f64, @floatFromInt(s.p99_ns)) / @as(f64, @floatFromInt(s.mean_ns)) });
    }
    if (s.fault_count > 0) {
        try writer.print("  • {s}{} fault(s) detected{s} — contract may have correctness issues\n", .{ RED, s.fault_count, RESET });
    }
    if (!viable) {
        try writer.print("  • Enable --threads {} to simulate {d:.0} projected TPS on a {d}-core machine\n", .{ @as(u32, @intFromFloat(@ceil(cores_needed))), tps_1c * @ceil(cores_needed), @as(u32, @intFromFloat(@ceil(cores_needed))) });
        try writer.print("  • Use runThreaded() (basic block gas batching, 2-3× speedup)\n", .{});
        try writer.print("  • Use VMPool to eliminate per-TX alloc (pre-allocated sandboxes)\n", .{});
    }
    try writer.print("\n", .{});
}

fn printBenchJson(writer: anytype, s: BenchStats, threads: u32, source: []const u8) !void {
    try writer.print("{{\n", .{});
    try writer.print("  \"source\": \"{s}\",\n", .{source});
    try writer.print("  \"iterations\": {},\n", .{s.iterations});
    try writer.print("  \"total_ms\": {d:.3},\n", .{@as(f64, @floatFromInt(s.total_ns)) / 1_000_000.0});
    try writer.print("  \"latency_us\": {{\n", .{});
    try writer.print("    \"min\":    {d:.3},\n", .{@as(f64, @floatFromInt(s.min_ns)) / 1000.0});
    try writer.print("    \"mean\":   {d:.3},\n", .{@as(f64, @floatFromInt(s.mean_ns)) / 1000.0});
    try writer.print("    \"median\": {d:.3},\n", .{@as(f64, @floatFromInt(s.median_ns)) / 1000.0});
    try writer.print("    \"p95\":    {d:.3},\n", .{@as(f64, @floatFromInt(s.p95_ns)) / 1000.0});
    try writer.print("    \"p99\":    {d:.3},\n", .{@as(f64, @floatFromInt(s.p99_ns)) / 1000.0});
    try writer.print("    \"max\":    {d:.3}\n", .{@as(f64, @floatFromInt(s.max_ns)) / 1000.0});
    try writer.print("  }},\n", .{});
    try writer.print("  \"throughput\": {{\n", .{});
    try writer.print("    \"single_core_tps\": {d:.2},\n", .{s.throughput_per_sec()});
    try writer.print("    \"projected_{d}c_tps\": {d:.2},\n", .{ threads, s.projected_tps(threads) });
    try writer.print("    \"gas_per_exec\": {}\n", .{s.gas_per_exec});
    try writer.print("  }},\n", .{});
    try printTpsAnalysis(writer, s, threads, true);
    try writer.print("\n}}\n", .{});
}

// ============================================================================
// Built-in VM self-test suite
// ============================================================================

fn runSelfTests(allocator: std.mem.Allocator, writer: anytype, as_json: bool) !bool {
    if (!as_json) {
        try writer.print("{s}[ SELF-TESTS  —  Built-in VM Correctness Suite ]{s}\n\n", .{ BOLD, RESET });
    }

    var results = std.ArrayListUnmanaged(TestResult){};
    defer results.deinit(allocator);

    // ── Test helpers ────────────────────────────────────────────────
    // All tests build a raw RISC-V program, execute it, and check postconditions.

    // Encode helpers
    const encodeI = struct {
        fn f(rd: u5, rs1: u5, funct3: u3, imm: i12, opcode: u7) u32 {
            const imm_u: u32 = @as(u32, @bitCast(@as(i32, imm))) & 0xFFF;
            return (imm_u << 20) | (@as(u32, rs1) << 15) | (@as(u32, funct3) << 12) |
                (@as(u32, rd) << 7) | opcode;
        }
    }.f;
    const encodeR = struct {
        fn f(rd: u5, rs1: u5, rs2: u5, funct3: u3, funct7: u7) u32 {
            return (@as(u32, funct7) << 25) | (@as(u32, rs2) << 20) |
                (@as(u32, rs1) << 15) | (@as(u32, funct3) << 12) |
                (@as(u32, rd) << 7) | 0b0110011;
        }
    }.f;
    const EBREAK: u32 = 0x00100073;
    const OP_IMM: u7 = 0b0010011;

    // ── ADDI: basic ALU ─────────────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, 42, OP_IMM), // ADDI x1, x0, 42
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "ADDI x1, x0, 42",
            .passed = r.regs[1] == 42 and r.status == .breakpoint,
            .message = "x1 should equal 42",
        });
    }

    // ── Negative immediate / sign extension ─────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, -1, OP_IMM), // ADDI x1, x0, -1
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        const expected: u64 = @bitCast(@as(i64, -1));
        try results.append(allocator, .{
            .name = "ADDI sign-extension (-1)",
            .passed = r.regs[1] == expected and r.status == .breakpoint,
            .message = "x1 should be 0xFFFFFFFFFFFFFFFF",
        });
    }

    // ── x0 hardwired to zero ─────────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(0, 0, 0, 99, OP_IMM), // ADDI x0, x0, 99 — should be ignored
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "x0 hardwired zero",
            .passed = r.regs[0] == 0 and r.status == .breakpoint,
            .message = "x0 must always be 0",
        });
    }

    // ── ADD (R-type) ─────────────────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, 100, OP_IMM), // x1 = 100
            encodeI(2, 0, 0, 23, OP_IMM), // x2 = 23
            encodeR(3, 1, 2, 0, 0), // x3 = x1 + x2 = 123
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "ADD x3, x1, x2",
            .passed = r.regs[3] == 123 and r.status == .breakpoint,
            .message = "100 + 23 should equal 123",
        });
    }

    // ── SUB ──────────────────────────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, 50, OP_IMM), // x1 = 50
            encodeI(2, 0, 0, 20, OP_IMM), // x2 = 20
            encodeR(3, 1, 2, 0, 0b0100000), // SUB x3, x1, x2
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "SUB x3, x1, x2",
            .passed = r.regs[3] == 30 and r.status == .breakpoint,
            .message = "50 - 20 should equal 30",
        });
    }

    // ── MUL (M extension) ────────────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, 7, OP_IMM), // x1 = 7
            encodeI(2, 0, 0, 6, OP_IMM), // x2 = 6
            encodeR(3, 1, 2, 0b000, 0b0000001), // MUL x3, x1, x2
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "MUL x3, x1, x2 (7×6)",
            .passed = r.regs[3] == 42 and r.status == .breakpoint,
            .message = "7 × 6 should equal 42",
        });
    }

    // ── DIV by zero returns -1 ───────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, 42, OP_IMM), // x1 = 42
            encodeI(2, 0, 0, 0, OP_IMM), // x2 = 0
            encodeR(3, 1, 2, 0b100, 0b0000001), // DIV x3, x1, x2
            EBREAK,
        };
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "DIV by zero → -1",
            .passed = r.regs[3] == std.math.maxInt(u64) and r.status == .breakpoint,
            .message = "RISC-V spec: DIV/0 = -1",
        });
    }

    // ── Out of gas ───────────────────────────────────────────────────
    {
        const code = [_]u32{
            encodeI(1, 0, 0, 1, OP_IMM),
            encodeI(1, 1, 0, 1, OP_IMM),
            encodeI(1, 1, 0, 1, OP_IMM),
            encodeI(1, 1, 0, 1, OP_IMM),
        };
        const r = try execWords(allocator, &code, 2); // only 2 gas
        try results.append(allocator, .{
            .name = "Out-of-gas halts execution",
            .passed = r.status == .out_of_gas,
            .message = "status should be out_of_gas",
        });
    }

    // ── BEQ branch taken ─────────────────────────────────────────────
    {
        // Layout:
        //   PC 0:  ADDI x1, x0, 5
        //   PC 4:  ADDI x2, x0, 5
        //   PC 8:  BEQ  x1, x2, +8   → branch to PC 16
        //   PC 12: ADDI x3, x0, 99   ← skipped
        //   PC 16: ADDI x3, x0, 1    ← branch target
        //   PC 20: EBREAK
        //
        // B-type offset +8: imm[12]=0, imm[11]=0, imm[10:5]=000000,
        //                   imm[4:1]=0100, imm[0]=0 → 0x00208463
        const beq: u32 = 0x00208463; // BEQ x1, x2, +8
        const code = [_]u32{
            encodeI(1, 0, 0, 5, OP_IMM), // x1 = 5
            encodeI(2, 0, 0, 5, OP_IMM), // x2 = 5
            beq, // BEQ x1, x2, +8 → PC 16
            encodeI(3, 0, 0, 99, OP_IMM), // skipped
            encodeI(3, 0, 0, 1, OP_IMM), // x3 = 1
            EBREAK,
        };
        const r = try execWords(allocator, &code, 100_000);
        try results.append(allocator, .{
            .name = "BEQ branch taken",
            .passed = r.regs[3] == 1 and r.status == .breakpoint,
            .message = "x3 should be 1 (99 was skipped)",
        });
    }

    // ── LW/SW memory round-trip ───────────────────────────────────────
    {
        const heap: u32 = sandbox.HEAP_START;
        const lui_heap: u32 = (heap & 0xFFFFF000) | (2 << 7) | 0b0110111; // LUI x2, upper
        const sw: u32 = 0b0000000_00001_00010_010_00000_0100011; // SW x1, 0(x2)
        const lw: u32 = 0b000000000000_00010_010_00011_0000011; // LW x3, 0(x2)
        const code = [_]u32{
            encodeI(1, 0, 0, 0x7E, OP_IMM), // x1 = 0x7E
            lui_heap,
            sw,
            lw,
            EBREAK,
        };
        const r = try execWords(allocator, &code, 100_000);
        try results.append(allocator, .{
            .name = "SW + LW memory round-trip",
            .passed = r.regs[3] == 0x7E and r.status == .breakpoint,
            .message = "LW should load the value stored by SW",
        });
    }

    // ── ECALL without handler → fault ────────────────────────────────
    {
        const ecall: u32 = 0x00000073;
        const code = [_]u32{ecall};
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "ECALL without handler → fault",
            .passed = r.status == .fault,
            .message = "should fault with no syscall handler installed",
        });
    }

    // ── EBREAK → breakpoint status ───────────────────────────────────
    {
        const code = [_]u32{EBREAK};
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "EBREAK → breakpoint status",
            .passed = r.status == .breakpoint,
            .message = "should stop with breakpoint status",
        });
    }

    // ── Illegal opcode → fault ────────────────────────────────────────
    {
        const code = [_]u32{0x0000007F}; // opcode 0x7F — not valid RV64IM
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "Illegal opcode → fault",
            .passed = r.status == .fault,
            .message = "illegal instruction must fault",
        });
    }

    // ── Sandbox: write to code region → fault ────────────────────────
    {
        // Try to store to address 0 (code region) — should be PermissionDenied → fault
        // SW x0, 0(x0)
        const sw_code: u32 = 0b0000000_00000_00000_010_00000_0100011;
        const code = [_]u32{sw_code};
        const r = try execWords(allocator, &code, 10_000);
        try results.append(allocator, .{
            .name = "Sandbox: write to code region blocked",
            .passed = r.status == .fault,
            .message = "store to code region must fault",
        });
    }

    // ── Gas accounting ──────────────────────────────────────────────────
    {
        // Each ADDI uses OP_IMM opcode → ALU_IMM = 1 gas each.
        // EBREAK uses the SYSTEM opcode (0x73), same as ECALL.
        // The fast opcode-table path charges ECALL_BASE = 3 for all SYSTEM
        // instructions — EBREAK vs ECALL is only distinguishable after a full
        // decode, which the fast path deliberately skips.
        // Total: 3 × 1 + 3 = 6 gas.
        const code = [_]u32{
            encodeI(1, 0, 0, 1, OP_IMM), // 1 gas (OP_IMM → ALU_IMM)
            encodeI(1, 1, 0, 1, OP_IMM), // 1 gas
            encodeI(1, 1, 0, 1, OP_IMM), // 1 gas
            EBREAK, // 3 gas (SYSTEM opcode → ECALL_BASE)
        };
        const r = try execWords(allocator, &code, 100_000);
        try results.append(allocator, .{
            .name = "Gas accounting (3 ADDI + EBREAK = 6 gas)",
            .passed = r.gas_used == 6 and r.status == .breakpoint,
            .message = "gas_used should be exactly 6 (EBREAK shares SYSTEM opcode cost)",
        });
    }

    // ── Step limit blocks infinite loops ─────────────────────────────
    {
        // Tight infinite loop: JAL x0, 0 (jump to self)
        const jal_self: u32 = 0b00000000000000000000_00000_1101111; // JAL x0, 0
        const code = [_]u32{jal_self};
        const r = try execWords(allocator, &code, 100_000_000);
        try results.append(allocator, .{
            .name = "Step limit kills infinite loop",
            .passed = r.status == .fault or r.status == .out_of_gas,
            .message = "infinite loop must be halted by step limit or gas",
        });
    }

    // ── FORGE .fozbin round-trip (build + parse + execute) ───────────
    {
        const nop: u32 = 0x00000013; // ADDI x0, x0, 0 — NOP
        const bytecode = std.mem.sliceAsBytes(&[_]u32{ nop, EBREAK });
        const pkg = forge_format.build(allocator, bytecode, .{}) catch null;
        var forge_ok = false;
        if (pkg) |p| {
            defer allocator.free(p);
            const parsed = forge_format.parse(p) catch null;
            if (parsed) |pp| {
                forge_ok = std.mem.eql(u8, pp.bytecode, bytecode);
            }
        }
        try results.append(allocator, .{
            .name = ".fozbin build + parse round-trip",
            .passed = forge_ok,
            .message = "bytecode must survive forge_format.build → parse",
        });
    }

    // ── Print results ────────────────────────────────────────────────
    var passed: usize = 0;
    var failed: usize = 0;

    for (results.items) |tr| {
        if (tr.passed) {
            passed += 1;
            if (!as_json) {
                try writer.print("  {s}PASS{s}  {s}\n", .{ GREEN, RESET, tr.name });
            }
        } else {
            failed += 1;
            if (!as_json) {
                try writer.print("  {s}FAIL{s}  {s}  ← {s}\n", .{ RED, RESET, tr.name, tr.message });
            }
        }
    }

    if (!as_json) {
        try writer.print("\n  {s}Result: {}/{} passed{s}\n\n", .{
            if (failed == 0) GREEN else RED,
            passed,
            passed + failed,
            RESET,
        });
    }

    return failed == 0;
}

// ============================================================================
// Low-level exec helper for self-test (no .fozbin, no ELF — raw words)
// ============================================================================

const RawExecResult = struct {
    status: ExecutionStatus,
    regs: [32]u64,
    gas_used: u64,
};

fn execWords(
    allocator: std.mem.Allocator,
    words: []const u32,
    gas: u64,
) !RawExecResult {
    const code_bytes = std.mem.sliceAsBytes(words);

    var mem = try SandboxMemory.init(allocator);
    defer mem.deinit();
    try mem.loadCode(code_bytes);

    var env = HostEnv.init(allocator);
    defer env.deinit();

    const handler = syscall_dispatch.createHandler(&env);
    var forge_vm = ForgeVM.init(&mem, @intCast(code_bytes.len), gas, handler);
    forge_vm.host_ctx = &env;

    const result = forge_vm.execute();
    return .{
        .status = result.status,
        .regs = forge_vm.regs,
        .gas_used = result.gas_used,
    };
}

// ============================================================================
// Help text
// ============================================================================

fn printHelp(writer: anytype) !void {
    try writer.print(
        \\
        \\  {s}ForgeVM Test Suite{s}  —  Zephyria TPS Viability Analyzer
        \\
        \\  USAGE
        \\    forge_test_suite [OPTIONS]
        \\
        \\  INPUT
        \\    --file   <path>    Load a .fozbin contract package
        \\    --hex    <bytes>   Raw hex-encoded RISC-V bytecode (no 0x prefix needed)
        \\    --calldata <hex>   ABI-encoded calldata to pass to the contract
        \\
        \\  EXECUTION OPTIONS
        \\    --gas    <n>       Gas limit per execution           (default: 10,000,000)
        \\    --bench  <n>       Run N benchmark iterations         (default: off)
        \\    --threads <n>      Core count for TPS projection      (default: 1)
        \\
        \\  MODES
        \\    --selftest         Run built-in VM correctness suite
        \\    --all [file]       Selftest + single exec + bench (if --bench set)
        \\    --json             Emit machine-readable JSON output
        \\    --verbose          Print per-iteration timing details
        \\
        \\  EXAMPLES
        \\    # Execute a .fozbin contract
        \\    forge_test_suite --file token.fozbin
        \\
        \\    # Benchmark 1M iterations and project 16-core TPS
        \\    forge_test_suite --file token.fozbin --bench 1000000 --threads 16
        \\
        \\    # Raw hex bytecode (ADDI x1, x0, 42 then EBREAK)
        \\    forge_test_suite --hex "930002002001007300000000"
        \\
        \\    # Full suite: selftest + exec + bench
        \\    forge_test_suite --all token.fozbin --bench 50000 --threads 8
        \\
        \\    # JSON output for CI integration
        \\    forge_test_suite --file token.fozbin --bench 10000 --json
        \\
    , .{ BOLD, RESET });
}
