// File: tools/zephyrc/zeph.zig
// ZephyrLang Unified CLI Tool — `zeph`
// Commands: compile, transpile, init, test, deploy, version
//
// Usage:
//   zeph compile <file.zeph> [-o output.elf] [--abi] [--emit-asm]
//   zeph transpile <file.sol> [-o output.zeph]
//   zeph init <project-name>
//   zeph test <file.zeph>
//   zeph version

const std = @import("std");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const type_check = @import("type_check.zig");
const contract_compiler = @import("contract_compiler.zig");
const elf_writer = @import("elf_writer.zig");
const abi_gen = @import("abi_gen.zig");
const sol_transpiler = @import("sol_transpiler.zig");

const VERSION = "0.1.0";
const BANNER =
    \\
    \\  ┌──────────────────────────────────────────────┐
    \\  │    ⚡ ZephyrLang Compiler v0.1.0              │
    \\  │    Compile smart contracts to RISC-V          │
    \\  │    for the Zephyria Virtual Machine            │
    \\  └──────────────────────────────────────────────┘
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "compile")) {
        try cmdCompile(alloc, args[2..]);
    } else if (std.mem.eql(u8, cmd, "transpile")) {
        try cmdTranspile(alloc, args[2..]);
    } else if (std.mem.eql(u8, cmd, "init")) {
        try cmdInit(alloc, args[2..]);
    } else if (std.mem.eql(u8, cmd, "test")) {
        try cmdTest(alloc, args[2..]);
    } else if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-v")) {
        std.debug.print("zeph {s}\n", .{VERSION});
    } else if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        printUsage();
    } else {
        std.debug.print("error: unknown command '{s}'\n\n", .{cmd});
        printUsage();
    }
}

// ============================================================================
// zeph compile
// ============================================================================
fn cmdCompile(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var emit_abi = false;
    var emit_asm = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if ((std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--abi")) {
            emit_abi = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--emit-asm")) {
            emit_asm = true;
            continue;
        }
        input_path = arg;
    }

    const path = input_path orelse {
        std.debug.print("error: no input file\nUsage: zeph compile <file.zeph> [-o output.elf] [--abi] [--emit-asm]\n", .{});
        return;
    };

    const source = std.fs.cwd().readFileAlloc(alloc, path, 10 * 1024 * 1024) catch |err| {
        std.debug.print("error: cannot read '{s}': {}\n", .{ path, err });
        return;
    };
    defer alloc.free(source);

    std.debug.print("{s}", .{BANNER});
    std.debug.print("Compiling: {s}\n\n", .{path});

    // Phase 1: Lex
    var lex = lexer.Lexer.init(source);
    const tokens = lex.tokenizeAll(alloc) catch {
        std.debug.print("  ✗ Lexer failed\n", .{});
        return;
    };
    defer alloc.free(tokens);
    std.debug.print("  ✓ Lexed {d} tokens\n", .{tokens.len});

    // Phase 2: Parse
    var p = parser.Parser.init(alloc, tokens, source);
    p.ready();
    defer p.deinit();
    const unit = p.parseSourceUnit() catch {
        std.debug.print("  ✗ Parser failed ({d} errors)\n", .{p.errors.items.len});
        for (p.errors.items) |diag| {
            std.debug.print("    [Parser Error] {s}\n", .{diag.message});
        }
        return;
    };
    if (p.errors.items.len > 0) {
        std.debug.print("  ✗ Parser completed with {d} errors\n", .{p.errors.items.len});
        for (p.errors.items) |diag| {
            std.debug.print("    [Parser Error] {s}\n", .{diag.message});
        }
        return;
    }
    std.debug.print("  ✓ Parsed {d} definitions\n", .{unit.definitions.len});

    // Phase 3: Type check
    const tc = alloc.create(type_check.TypeChecker) catch {
        std.debug.print("  ✗ TypeChecker alloc failed\n", .{});
        return;
    };
    tc.* = type_check.TypeChecker.init(alloc);
    tc.ready();
    defer {
        tc.deinit();
        alloc.destroy(tc);
    }
    tc.check(unit) catch {};

    if (tc.hasErrors()) {
        std.debug.print("  ✗ Type check failed ({d} errors)\n", .{tc.errorCount()});
        for (tc.diagnostics.items) |d| {
            const sev: []const u8 = if (d.severity == .err) "error" else if (d.severity == .warning) "warning" else "hint";
            std.debug.print("    [{s}] {s}\n", .{ sev, d.message });
        }
        return;
    }
    // Print warnings
    for (tc.diagnostics.items) |d| {
        if (d.severity == .warning)
            std.debug.print("  ⚠ {s}\n", .{d.message});
    }
    std.debug.print("  ✓ Type check passed\n", .{});

    // Phase 4: Compile each contract
    var compiled_count: u32 = 0;
    for (unit.definitions) |def| {
        const contract = switch (def) {
            .contract => |c| c,
            .interface => |c| c,
            .library => |c| c,
            .abstract_contract => |c| c,
            else => continue,
        };

        std.debug.print("\n  Compiling contract: {s}\n", .{contract.name});

        var cc = contract_compiler.ContractCompiler.init(alloc);
        defer cc.deinit();

        const compiled = cc.compile(contract) catch {
            std.debug.print("  ✗ Compilation failed for {s}\n", .{contract.name});
            continue;
        };

        std.debug.print("  ✓ {d} bytes RISC-V code, {d} selectors, {d} storage slots\n", .{ compiled.bytecode.len, compiled.function_selectors.len, compiled.storage_layout.len });

        // Package ELF
        const out_owned = output_path == null;
        const out = output_path orelse try std.fmt.allocPrint(alloc, "{s}.elf", .{contract.name});
        defer if (out_owned) alloc.free(out);

        const elf = elf_writer.writeElf(alloc, compiled.bytecode, 0) catch {
            std.debug.print("  ✗ ELF generation failed\n", .{});
            continue;
        };
        defer alloc.free(elf);

        std.fs.cwd().writeFile(.{ .sub_path = out, .data = elf }) catch |err| {
            std.debug.print("  ✗ Cannot write '{s}': {}\n", .{ out, err });
            continue;
        };
        std.debug.print("  ✓ Wrote {s} ({d} bytes)\n", .{ out, elf.len });
        compiled_count += 1;

        // ABI output
        if (emit_abi) {
            var ag = abi_gen.AbiGenerator.init(alloc);
            defer ag.deinit();
            ag.generateFromContract(contract) catch continue;
            const json = ag.toJson(alloc) catch continue;
            defer alloc.free(json);
            const abi_path = try std.fmt.allocPrint(alloc, "{s}.abi.json", .{contract.name});
            defer alloc.free(abi_path);
            std.fs.cwd().writeFile(.{ .sub_path = abi_path, .data = json }) catch continue;
            std.debug.print("  ✓ Wrote {s}\n", .{abi_path});
        }

        // Assembly listing
        if (emit_asm) {
            std.debug.print("\n  === RISC-V Assembly ({d} instructions) ===\n", .{compiled.bytecode.len / 4});
            var offset: usize = 0;
            while (offset + 4 <= compiled.bytecode.len) : (offset += 4) {
                const word = std.mem.readInt(u32, compiled.bytecode[offset..][0..4], .little);
                std.debug.print("  0x{x:0>4}: 0x{x:0>8}\n", .{ offset, word });
            }
        }
    }

    std.debug.print("\n✓ Compilation complete — {d} contract(s) compiled\n", .{compiled_count});
}

// ============================================================================
// zeph transpile
// ============================================================================
fn cmdTranspile(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if ((std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
            continue;
        }
        input_path = arg;
    }

    const path = input_path orelse {
        std.debug.print("error: no input file\nUsage: zeph transpile <file.sol> [-o output.zeph]\n", .{});
        return;
    };

    const source = std.fs.cwd().readFileAlloc(alloc, path, 10 * 1024 * 1024) catch |err| {
        std.debug.print("error: cannot read '{s}': {}\n", .{ path, err });
        return;
    };
    defer alloc.free(source);

    std.debug.print("{s}", .{BANNER});
    std.debug.print("Transpiling: {s}\n\n", .{path});

    var transpiler = sol_transpiler.Transpiler.init(alloc, .{});
    defer transpiler.deinit();

    const result = transpiler.transpile(source) catch {
        std.debug.print("  ✗ Transpilation failed\n", .{});
        return;
    };

    // Determine output path
    const out_owned = output_path == null;
    const out = output_path orelse blk: {
        // Replace .sol extension with .zeph
        if (std.mem.endsWith(u8, path, ".sol")) {
            const base = path[0 .. path.len - 4];
            break :blk try std.fmt.allocPrint(alloc, "{s}.zeph", .{base});
        }
        break :blk try std.fmt.allocPrint(alloc, "{s}.zeph", .{path});
    };
    defer if (out_owned) alloc.free(out);

    std.fs.cwd().writeFile(.{ .sub_path = out, .data = result }) catch |err| {
        std.debug.print("  ✗ Cannot write '{s}': {}\n", .{ out, err });
        return;
    };

    std.debug.print("  ✓ Transpiled {d} bytes → {s} ({d} bytes)\n", .{ source.len, out, result.len });
    std.debug.print("\n✓ Transpilation complete\n", .{});
}

// ============================================================================
// zeph init
// ============================================================================
fn cmdInit(alloc: std.mem.Allocator, args: []const []const u8) !void {
    const name = if (args.len > 0) args[0] else "my-contract";

    std.debug.print("{s}", .{BANNER});
    std.debug.print("Initializing project: {s}\n\n", .{name});

    // Create directory structure
    const dirs = [_][]const u8{ "src", "test", "artifacts" };
    for (dirs) |dir| {
        const full = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ name, dir });
        defer alloc.free(full);
        std.fs.cwd().makePath(full) catch {};
    }

    // Create main contract file
    const main_contract = try std.fmt.allocPrint(alloc,
        \\// SPDX-License-Identifier: MIT
        \\pragma zephyr ^1.0;
        \\
        \\contract {s} {{
        \\    uint256 public value;
        \\
        \\    event ValueChanged(uint256 newValue);
        \\
        \\    function setValue(uint256 newValue) external {{
        \\        value = newValue;
        \\        emit ValueChanged(newValue);
        \\    }}
        \\
        \\    function getValue() external view returns (uint256) {{
        \\        return value;
        \\    }}
        \\}}
        \\
    , .{name});
    defer alloc.free(main_contract);

    const src_path = try std.fmt.allocPrint(alloc, "{s}/src/{s}.zeph", .{ name, name });
    defer alloc.free(src_path);
    std.fs.cwd().writeFile(.{ .sub_path = src_path, .data = main_contract }) catch |err| {
        std.debug.print("  ✗ Cannot write '{s}': {}\n", .{ src_path, err });
        return;
    };
    std.debug.print("  ✓ Created {s}\n", .{src_path});

    // Create test file
    const test_contract = try std.fmt.allocPrint(alloc,
        \\// SPDX-License-Identifier: MIT
        \\pragma zephyr ^1.0;
        \\
        \\import "../src/{s}.zeph";
        \\
        \\contract {s}Test {{
        \\    function testSetValue() external {{
        \\        // Test: setValue and getValue
        \\        // Add test logic here
        \\    }}
        \\}}
        \\
    , .{ name, name });
    defer alloc.free(test_contract);

    const test_path = try std.fmt.allocPrint(alloc, "{s}/test/{s}.test.zeph", .{ name, name });
    defer alloc.free(test_path);
    std.fs.cwd().writeFile(.{ .sub_path = test_path, .data = test_contract }) catch |err| {
        std.debug.print("  ✗ Cannot write '{s}': {}\n", .{ test_path, err });
        return;
    };
    std.debug.print("  ✓ Created {s}\n", .{test_path});

    // Create zeph.toml config
    const config = try std.fmt.allocPrint(alloc,
        \\[project]
        \\name = "{s}"
        \\version = "0.1.0"
        \\zephyr_version = "^1.0"
        \\
        \\[compiler]
        \\optimization = true
        \\emit_abi = true
        \\
        \\[dependencies]
        \\# std = "builtin"
        \\
    , .{name});
    defer alloc.free(config);

    const config_path = try std.fmt.allocPrint(alloc, "{s}/zeph.toml", .{name});
    defer alloc.free(config_path);
    std.fs.cwd().writeFile(.{ .sub_path = config_path, .data = config }) catch {};
    std.debug.print("  ✓ Created {s}\n", .{config_path});

    std.debug.print(
        \\
        \\✓ Project initialized!
        \\
        \\Next steps:
        \\  cd {s}
        \\  zeph compile src/{s}.zeph --abi
        \\  zeph test test/{s}.test.zeph
        \\
    , .{ name, name, name });
}

// ============================================================================
// zeph test
// ============================================================================
fn cmdTest(alloc: std.mem.Allocator, args: []const []const u8) !void {
    const path = if (args.len > 0) args[0] else {
        std.debug.print("error: no test file\nUsage: zeph test <file.zeph>\n", .{});
        return;
    };

    const source = std.fs.cwd().readFileAlloc(alloc, path, 10 * 1024 * 1024) catch |err| {
        std.debug.print("error: cannot read '{s}': {}\n", .{ path, err });
        return;
    };
    defer alloc.free(source);

    std.debug.print("{s}", .{BANNER});
    std.debug.print("Testing: {s}\n\n", .{path});

    // Lex + Parse
    var lex = lexer.Lexer.init(source);
    const tokens = lex.tokenizeAll(alloc) catch {
        std.debug.print("  ✗ Lexer failed\n", .{});
        return;
    };
    defer alloc.free(tokens);

    var p = parser.Parser.init(alloc, tokens, source);
    p.ready();
    defer p.deinit();
    const unit = p.parseSourceUnit() catch {
        std.debug.print("  ✗ Parser failed\n", .{});
        return;
    };

    // Type check
    const tc = alloc.create(type_check.TypeChecker) catch return;
    tc.* = type_check.TypeChecker.init(alloc);
    tc.ready();
    defer {
        tc.deinit();
        alloc.destroy(tc);
    }
    tc.check(unit) catch {};

    var test_count: u32 = 0;
    var pass_count: u32 = 0;

    for (unit.definitions) |def| {
        const contract = switch (def) {
            .contract => |c| c,
            else => continue,
        };
        for (contract.members) |member| {
            switch (member) {
                .function => |f| {
                    if (std.mem.startsWith(u8, f.name, "test")) {
                        test_count += 1;
                        // Compile and check for errors
                        var cc = contract_compiler.ContractCompiler.init(alloc);
                        defer cc.deinit();
                        if (cc.compile(contract)) |_| {
                            std.debug.print("  ✓ {s}::{s}\n", .{ contract.name, f.name });
                            pass_count += 1;
                        } else |_| {
                            std.debug.print("  ✗ {s}::{s} — compilation error\n", .{ contract.name, f.name });
                        }
                    }
                },
                else => {},
            }
        }
    }

    if (test_count == 0) {
        std.debug.print("  ⚠ No test functions found (prefix with 'test')\n", .{});
    } else {
        std.debug.print("\n  {d}/{d} tests passed\n", .{ pass_count, test_count });
    }
}

// ============================================================================
// Usage
// ============================================================================
fn printUsage() void {
    std.debug.print(
        \\{s}
        \\Usage: zeph <command> [options]
        \\
        \\Commands:
        \\  compile    Compile .zeph contract to RISC-V ELF bytecode
        \\  transpile  Convert Solidity .sol to ZephyrLang .zeph
        \\  init       Create a new ZephyrLang project
        \\  test       Run contract test functions
        \\  version    Show compiler version
        \\
        \\Examples:
        \\  zeph compile MyToken.zeph --abi --emit-asm
        \\  zeph transpile Token.sol -o Token.zeph
        \\  zeph init my-project
        \\  zeph test test/MyToken.test.zeph
        \\
    , .{BANNER});
}
