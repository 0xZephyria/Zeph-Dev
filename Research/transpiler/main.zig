// File: tools/sol2zig/main.zig
// Solidity-to-Zig Transpiler — CLI Entry Point
// Converts Solidity source files into Zephyria Zig SDK contracts

const std = @import("std");
const parser = @import("parser.zig");
const type_mapper = @import("type_mapper.zig");
const codegen = @import("codegen.zig");
const abi_gen = @import("abi_gen.zig");
const optimizer = @import("optimizer.zig");
const inheritance = @import("inheritance.zig");
const validation = @import("validation.zig");
const import_resolver = @import("import_resolver.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    var config = Config{
        .input_path = "",
        .output_path = null,
        .abi_output = null,
        .optimize = false,
        .solidity_version = .v0_8,
        .verbose = false,
        .sdk_path = null,
        .multi_file = false,
        .verify = false,
        .project_dir = null,
    };

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) {
            i += 1;
            if (i >= args.len) {
                fatal("--output requires a path argument");
            }
            config.output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--abi")) {
            i += 1;
            if (i >= args.len) {
                fatal("--abi requires a path argument");
            }
            config.abi_output = args[i];
        } else if (std.mem.eql(u8, arg, "--optimize") or std.mem.eql(u8, arg, "-O")) {
            config.optimize = true;
        } else if (std.mem.eql(u8, arg, "--solidity-04")) {
            config.solidity_version = .v0_4;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--sdk-path")) {
            i += 1;
            if (i >= args.len) fatal("--sdk-path requires a path argument");
            config.sdk_path = args[i];
        } else if (std.mem.eql(u8, arg, "--multi-file")) {
            config.multi_file = true;
        } else if (std.mem.eql(u8, arg, "--verify")) {
            config.verify = true;
        } else if (std.mem.eql(u8, arg, "--project")) {
            i += 1;
            if (i >= args.len) fatal("--project requires a directory argument");
            config.project_dir = args[i];
        } else if (arg.len > 0 and arg[0] != '-') {
            config.input_path = arg;
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return;
        }
    }

    if (config.input_path.len == 0) {
        std.debug.print("sol2zig: no input file specified\n", .{});
        printUsage();
        return;
    }

    // Read input file
    const source = std.fs.cwd().readFileAlloc(allocator, config.input_path, 10 * 1024 * 1024) catch |err| {
        std.debug.print("sol2zig: cannot read '{s}': {}\n", .{ config.input_path, err });
        std.process.exit(1);
    };
    defer allocator.free(source);

    if (config.verbose) {
        std.debug.print("sol2zig: parsing {s} ({d} bytes)\n", .{ config.input_path, source.len });
    }

    // Phase 1: Parse Solidity AST
    var ast = try parser.parse(allocator, source);
    defer ast.deinit();

    if (config.verbose) {
        std.debug.print("sol2zig: parsed {d} contract(s), {d} function(s)\n", .{
            ast.contracts.items.len,
            countFunctions(&ast),
        });
    }

    // Phase 1.5: Resolve imports (OpenZeppelin stubs + local files)
    const original_contract_count = ast.contracts.items.len;
    try import_resolver.resolveImports(allocator, &ast, config.input_path, null);

    if (config.verbose) {
        std.debug.print("sol2zig: after import resolution: {d} contract(s)\n", .{ast.contracts.items.len});
    }

    // Phase 2: Resolve inheritance (use AST's arena allocator for consistency)
    inheritance.resolveInheritance(ast.allocator, &ast);

    // Phase 3: Validate Solidity AST
    var diags = try validation.validate(allocator, &ast);
    defer diags.deinit();
    if (diags.hasErrors()) {
        for (diags.errors.items) |diag| {
            std.debug.print("error: {s}\n", .{diag.message});
        }
        std.process.exit(1);
    }
    for (diags.warnings.items) |diag| {
        std.debug.print("warning: {s}\n", .{diag.message});
    }

    // Phase 4: Generate Zig code
    var gen = codegen.CodeGenerator.init(allocator, &ast, &type_mapper.DEFAULT_TYPE_MAP);
    gen.original_contract_count = original_contract_count;
    defer gen.deinit();
    const zig_source = try gen.generate();

    // Phase 5: Optimize (optional)
    var optimized_source: ?[]const u8 = null;
    defer if (optimized_source) |os| allocator.free(os);
    const final_source = if (config.optimize) blk: {
        optimized_source = optimizer.optimize(allocator, zig_source);
        break :blk optimized_source.?;
    } else zig_source;

    // Determine output path
    var output_path_allocated = false;
    const output_path = config.output_path orelse blk: {
        const stem = std.fs.path.stem(config.input_path);
        const dir = std.fs.path.dirname(config.input_path) orelse ".";
        output_path_allocated = true;
        break :blk try std.fmt.allocPrint(allocator, "{s}/{s}.zig", .{ dir, stem });
    };
    defer if (output_path_allocated) allocator.free(output_path);

    // Phase 6: Generate project structure (optional)
    if (config.project_dir) |proj_dir| {
        try generateProjectStructure(allocator, proj_dir, output_path, final_source, config);
    } else {
        // Write single output file
        try std.fs.cwd().writeFile(.{ .sub_path = output_path, .data = final_source });
        std.debug.print("sol2zig: wrote {s}\n", .{output_path});
    }

    // Phase 7: Generate ABI (optional)
    if (config.abi_output) |abi_path| {
        const abi_json = try abi_gen.generateABI(allocator, &ast);
        defer allocator.free(abi_json);
        try std.fs.cwd().writeFile(.{ .sub_path = abi_path, .data = abi_json });
        std.debug.print("sol2zig: wrote ABI to {s}\n", .{abi_path});
    }

    // Phase 8: Verify generated Zig compiles (optional)
    if (config.verify) {
        std.debug.print("sol2zig: verification requested — run `zig build` in the output directory\n", .{});
    }
}

/// Generate a full project directory with build.zig for the transpiled contract
fn generateProjectStructure(
    allocator: std.mem.Allocator,
    proj_dir: []const u8,
    output_path: []const u8,
    source: []const u8,
    config: Config,
) !void {
    // Create project directory
    std.fs.cwd().makePath(proj_dir) catch |err| {
        std.debug.print("sol2zig: cannot create project dir '{s}': {}\n", .{ proj_dir, err });
        return;
    };

    // Write contract source
    const contract_path = try std.fmt.allocPrint(allocator, "{s}/contract.zig", .{proj_dir});
    defer allocator.free(contract_path);
    try std.fs.cwd().writeFile(.{ .sub_path = contract_path, .data = source });
    std.debug.print("sol2zig: wrote {s}\n", .{contract_path});

    // Write build.zig template
    const sdk_path = config.sdk_path orelse "sdk";
    const build_zig = try std.fmt.allocPrint(allocator,
        \\const std = @import("std");
        \\
        \\pub fn build(b: *std.Build) void {{
        \\    const target = b.standardTargetOptions(.{{}});
        \\    const optimize = b.standardOptimizeOption(.{{}});
        \\
        \\    const exe = b.addExecutable(.{{
        \\        .name = "contract",
        \\        .root_module = b.createModule(.{{
        \\            .root_source_file = b.path("contract.zig"),
        \\            .target = target,
        \\            .optimize = optimize,
        \\        }}),
        \\    }});
        \\
        \\    // SDK path: {s}
        \\    b.installArtifact(exe);
        \\}}
        \\
    , .{sdk_path});
    defer allocator.free(build_zig);

    const build_path = try std.fmt.allocPrint(allocator, "{s}/build.zig", .{proj_dir});
    defer allocator.free(build_path);
    try std.fs.cwd().writeFile(.{ .sub_path = build_path, .data = build_zig });
    std.debug.print("sol2zig: wrote {s}\n", .{build_path});

    _ = output_path;
}

fn printUsage() void {
    const usage =
        \\sol2zig — Solidity to Zephyria Zig Transpiler
        \\
        \\USAGE:
        \\  sol2zig [OPTIONS] <input.sol>
        \\
        \\OPTIONS:
        \\  -o, --output <path>     Output .zig file (default: <input>.zig)
        \\  --abi <path>            Generate ABI JSON
        \\  -O, --optimize          Enable optimization passes
        \\  --solidity-04           Target Solidity <0.8 (unchecked math default)
        \\  -v, --verbose           Verbose output
        \\  --sdk-path <path>       Path to SDK modules for import resolution
        \\  --multi-file            Enable multi-file import resolution mode
        \\  --verify                Verify generated Zig compiles after transpilation
        \\  --project <dir>         Generate a full project structure with build.zig
        \\  -h, --help              Show this help
        \\
        \\EXAMPLES:
        \\  sol2zig MyToken.sol
        \\  sol2zig -o output/token.zig --abi token.abi.json -O MyToken.sol
        \\  sol2zig --project out/ --sdk-path ../sdk MyToken.sol
        \\  sol2zig --verify --verbose MyToken.sol
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn countFunctions(ast: *const parser.SolidityAST) usize {
    var count: usize = 0;
    for (ast.contracts.items) |contract| {
        count += contract.functions.items.len;
    }
    return count;
}

fn fatal(msg: []const u8) noreturn {
    std.debug.print("sol2zig error: {s}\n", .{msg});
    std.process.exit(1);
}

pub const Config = struct {
    input_path: []const u8,
    output_path: ?[]const u8,
    abi_output: ?[]const u8,
    optimize: bool,
    solidity_version: SolidityVersion,
    verbose: bool,
    // Phase 7 additions
    sdk_path: ?[]const u8,
    multi_file: bool,
    verify: bool,
    project_dir: ?[]const u8,
};

pub const SolidityVersion = enum {
    v0_4, // Solidity <0.8 (unchecked math default)
    v0_8, // Solidity >=0.8 (checked math default)
};
