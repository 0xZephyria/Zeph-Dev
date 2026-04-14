// File: tools/sol2zig/import_resolver.zig
// Resolves Solidity import statements by:
//   1. Mapping @openzeppelin/* paths to bundled SDK stub contracts
//   2. Resolving relative paths (./foo.sol, ../bar.sol) to local files
// Parsed contracts from resolved imports are merged into the main AST.

const std = @import("std");
const parser = @import("parser.zig");

/// Well-known import path mappings to bundled stub files.
/// Keys are the Solidity import path prefixes, values are the stub filenames
/// in the sdk/openzeppelin/ directory.
const OZ_MAPPINGS = [_]struct { prefix: []const u8, stub: []const u8 }{
    .{ .prefix = "@openzeppelin/contracts/token/ERC20/ERC20.sol", .stub = "ERC20.sol" },
    .{ .prefix = "@openzeppelin/contracts/token/ERC20/IERC20.sol", .stub = "ERC20.sol" },
    .{ .prefix = "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol", .stub = "ERC20.sol" },
    .{ .prefix = "@openzeppelin/contracts/access/Ownable.sol", .stub = "Ownable.sol" },
    .{ .prefix = "@openzeppelin/contracts/utils/Context.sol", .stub = "ERC20.sol" }, // Context is in ERC20 stub
    .{ .prefix = "@openzeppelin/contracts/security/ReentrancyGuard.sol", .stub = "ReentrancyGuard.sol" },
    .{ .prefix = "@openzeppelin/contracts/security/Pausable.sol", .stub = "Pausable.sol" },
    .{ .prefix = "@openzeppelin/contracts/token/ERC721/ERC721.sol", .stub = "ERC721.sol" },
};

/// Resolve all imports in the AST by parsing referenced files and merging
/// their contracts into the main AST.
///
/// Parameters:
///   - allocator: memory allocator
///   - ast: the parsed AST (modified in-place with merged contracts)
///   - input_path: path to the original .sol file (for relative import resolution)
///   - exe_dir: directory of the sol2zig executable (for finding bundled stubs)
pub fn resolveImports(
    allocator: std.mem.Allocator,
    ast: *parser.SolidityAST,
    input_path: []const u8,
    exe_dir: ?[]const u8,
) !void {
    // Track which stub files we've already parsed (by stub filename) to avoid duplicates
    var resolved = std.StringHashMap(void).init(allocator);
    defer resolved.deinit();

    // Get input file's directory for relative path resolution
    const input_dir = std.fs.path.dirname(input_path) orelse ".";

    for (ast.imports.items) |import_def| {
        const import_path = import_def.path;

        // Try OpenZeppelin mapping first
        if (try resolveOZImport(allocator, ast, import_path, exe_dir, &resolved)) {
            continue;
        }

        // Try relative path resolution
        if (try resolveRelativeImport(allocator, ast, import_path, input_dir, &resolved)) {
            continue;
        }

        // Unresolved import — print warning
        std.debug.print("warning: unresolved import '{s}' — skipping\n", .{import_path});
    }
}

/// Attempt to resolve an import as an OpenZeppelin bundled stub.
/// Returns true if resolved.
fn resolveOZImport(
    allocator: std.mem.Allocator,
    ast: *parser.SolidityAST,
    import_path: []const u8,
    exe_dir: ?[]const u8,
    resolved: *std.StringHashMap(void),
) !bool {
    for (&OZ_MAPPINGS) |mapping| {
        if (std.mem.eql(u8, import_path, mapping.prefix)) {
            // Already resolved this stub?
            if (resolved.contains(mapping.stub)) return true;
            try resolved.put(mapping.stub, {});

            // Find the stub file — try multiple locations
            const stub_source = try findAndReadStub(allocator, mapping.stub, exe_dir);
            if (stub_source) |source| {
                defer allocator.free(source);
                try parseAndMerge(allocator, ast, source);
                std.debug.print("sol2zig: resolved import '{s}' → bundled {s}\n", .{ import_path, mapping.stub });
                return true;
            } else {
                std.debug.print("warning: bundled stub '{s}' not found for import '{s}'\n", .{ mapping.stub, import_path });
                return false;
            }
        }
    }
    return false;
}

/// Attempt to resolve an import as a relative file path.
/// Returns true if resolved.
fn resolveRelativeImport(
    allocator: std.mem.Allocator,
    ast: *parser.SolidityAST,
    import_path: []const u8,
    input_dir: []const u8,
    resolved: *std.StringHashMap(void),
) !bool {
    // Only handle relative paths
    if (import_path.len < 2) return false;
    if (import_path[0] != '.' and import_path[0] != '/') return false;

    // Already resolved?
    if (resolved.contains(import_path)) return true;
    try resolved.put(import_path, {});

    // Construct full path
    const full_path = try std.fs.path.resolve(allocator, &.{ input_dir, import_path });
    defer allocator.free(full_path);

    const source = std.fs.cwd().readFileAlloc(allocator, full_path, 10 * 1024 * 1024) catch |err| {
        std.debug.print("warning: cannot read import '{s}' ({s}): {}\n", .{ import_path, full_path, err });
        return false;
    };
    defer allocator.free(source);

    try parseAndMerge(allocator, ast, source);
    std.debug.print("sol2zig: resolved import '{s}' → {s}\n", .{ import_path, full_path });
    return true;
}

/// Find and read a bundled stub file. Searches in multiple locations:
///   1. <exe_dir>/sdk/openzeppelin/<stub>
///   2. ./sdk/openzeppelin/<stub> (relative to cwd)
fn findAndReadStub(
    allocator: std.mem.Allocator,
    stub_name: []const u8,
    exe_dir: ?[]const u8,
) !?[]const u8 {
    // Location 1: relative to executable
    if (exe_dir) |dir| {
        const path = try std.fmt.allocPrint(allocator, "{s}/sdk/openzeppelin/{s}", .{ dir, stub_name });
        defer allocator.free(path);
        if (std.fs.cwd().readFileAlloc(allocator, path, 10 * 1024 * 1024)) |source| {
            return source;
        } else |_| {}
    }

    // Location 2: relative to cwd
    {
        const path = try std.fmt.allocPrint(allocator, "sdk/openzeppelin/{s}", .{stub_name});
        defer allocator.free(path);
        if (std.fs.cwd().readFileAlloc(allocator, path, 10 * 1024 * 1024)) |source| {
            return source;
        } else |_| {}
    }

    return null;
}

/// Parse a Solidity source string and merge contracts into the target AST.
/// Uses the target AST's arena allocator directly via Parser.parseSourceInto()
/// so all imported data lives in the same memory arena as the main AST.
fn parseAndMerge(
    _: std.mem.Allocator,
    target_ast: *parser.SolidityAST,
    source: []const u8,
) !void {
    // CRITICAL: The parser stores slices that reference the source string.
    // The caller will free the original source buffer after this returns.
    // We must copy the source into the AST's arena so the slices remain
    // valid for the lifetime of the AST.
    const arena_source = try target_ast.allocator.dupe(u8, source);
    var p = parser.Parser.init(target_ast.allocator, arena_source);
    try p.parseSourceInto(target_ast);
}
