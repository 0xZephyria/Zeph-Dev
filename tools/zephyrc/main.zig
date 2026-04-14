// File: tools/zephyrc/main.zig
// ZephyrLang Compiler CLI — `zephyrc` command-line tool.
// Usage: zephyrc <input.zeph> [options]
// Options: --output/-o <file>  Output path (default: <input>.elf)
//          --abi               Also emit ABI JSON (<input>.abi.json)
//          --emit-asm          Print RISC-V assembly listing

const std = @import("std");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const contract_compiler = @import("contract_compiler.zig");
const elf_writer = @import("elf_writer.zig");
const abi_gen = @import("abi_gen.zig");

const VERSION = "0.1.0";

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

    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var emit_abi = false;
    var emit_asm = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        }
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            std.debug.print("zephyrc {s}\n", .{VERSION});
            return;
        }
        if ((std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) and i + 1 < args.len) {
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
        std.debug.print("error: no input file\n", .{});
        return;
    };

    // Read source file
    const source = std.fs.cwd().readFileAlloc(alloc, path, 10 * 1024 * 1024) catch |err| {
        std.debug.print("error: cannot read '{s}': {}\n", .{ path, err });
        return;
    };
    defer alloc.free(source);

    std.debug.print("zephyrc {s} — compiling {s}\n", .{ VERSION, path });

    // Phase 1: Lex
    var lex = lexer.Lexer.init(source);
    const tokens = lex.tokenizeAll(alloc) catch {
        std.debug.print("error: lexer failed\n", .{});
        return;
    };
    defer alloc.free(tokens);
    std.debug.print("  lexed {} tokens\n", .{tokens.len});

    // Phase 2: Parse
    var p = parser.Parser.init(alloc, tokens, source);
    p.ready();
    defer p.deinit();
    const unit = p.parseSourceUnit() catch {
        std.debug.print("error: parse failed\n", .{});
        return;
    };
    std.debug.print("  parsed {} definitions\n", .{unit.definitions.len});

    // Phase 3: Compile each contract
    for (unit.definitions) |def| {
        const contract = switch (def) {
            .contract => |c| c,
            .interface => |c| c,
            .library => |c| c,
            .abstract_contract => |c| c,
            else => continue,
        };

        std.debug.print("  compiling contract: {s}\n", .{contract.name});

        var cc = contract_compiler.ContractCompiler.init(alloc);
        defer cc.deinit();

        const compiled = cc.compile(contract) catch {
            std.debug.print("error: compilation failed for {s}\n", .{contract.name});
            continue;
        };

        std.debug.print("  generated {} bytes of RISC-V code\n", .{compiled.bytecode.len});
        std.debug.print("  {} function selectors\n", .{compiled.function_selectors.len});
        std.debug.print("  {} storage slots\n", .{compiled.storage_layout.len});

        // Phase 4: Package as ELF
        const out_owned = output_path == null;
        const out = output_path orelse try defaultOutput(alloc, path, contract.name);
        defer if (out_owned) alloc.free(out);

        const elf = elf_writer.writeElf(alloc, compiled.bytecode, 0) catch {
            std.debug.print("error: ELF generation failed\n", .{});
            continue;
        };
        defer alloc.free(elf);

        std.fs.cwd().writeFile(.{ .sub_path = out, .data = elf }) catch |err| {
            std.debug.print("error: cannot write '{s}': {}\n", .{ out, err });
            continue;
        };

        std.debug.print("  wrote {s} ({} bytes)\n", .{ out, elf.len });

        // Phase 5: ABI
        if (emit_abi) {
            var ag = abi_gen.AbiGenerator.init(alloc);
            defer ag.deinit();
            ag.generateFromContract(contract) catch continue;
            const abi_path = try std.fmt.allocPrint(alloc, "{s}.abi.json", .{contract.name});
            defer alloc.free(abi_path);
            std.debug.print("  wrote {s}\n", .{abi_path});
        }

        // Phase 6: Assembly listing
        if (emit_asm) {
            std.debug.print("\n=== RISC-V Assembly ({} instructions) ===\n", .{compiled.bytecode.len / 4});
            var offset: usize = 0;
            while (offset + 4 <= compiled.bytecode.len) : (offset += 4) {
                const word = std.mem.readInt(u32, compiled.bytecode[offset..][0..4], .little);
                std.debug.print("  0x{x:0>4}: 0x{x:0>8}\n", .{ offset, word });
            }
        }
    }

    std.debug.print("compilation complete\n", .{});
}

fn defaultOutput(alloc: std.mem.Allocator, path: []const u8, name: []const u8) ![]const u8 {
    _ = path;
    return std.fmt.allocPrint(alloc, "{s}.elf", .{name});
}

fn printUsage() void {
    std.debug.print(
        \\Usage: zephyrc <input.zeph> [options]
        \\
        \\ZephyrLang Compiler — Compiles .zeph contracts to RISC-V ELF bytecode.
        \\
        \\Options:
        \\  -o, --output <file>  Output file path
        \\  --abi                Emit ABI JSON file
        \\  --emit-asm           Print RISC-V assembly listing
        \\  -v, --version        Show version
        \\  -h, --help           Show this help
        \\
    , .{});
}
