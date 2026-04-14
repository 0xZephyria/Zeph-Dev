const std = @import("std");
const elf_parser = @import("elf_parser");
const zeph_format = @import("zeph_format");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip executable name

    var out_path: ?[]const u8 = null;
    var elf_path: ?[]const u8 = null;
    var abi_path: ?[]const u8 = null;
    var meta_path: ?[]const u8 = null;
    var gen_hex = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--out") or std.mem.eql(u8, arg, "-o")) {
            out_path = args.next() orelse {
                std.debug.print("Expected path after {s}\n", .{arg});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--elf")) {
            elf_path = args.next() orelse {
                std.debug.print("Expected file path after --elf\n", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--abi")) {
            abi_path = args.next() orelse {
                std.debug.print("Expected file path after --abi\n", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--metadata")) {
            meta_path = args.next() orelse {
                std.debug.print("Expected file path after --metadata\n", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--hex")) {
            gen_hex = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            printUsage();
            return error.InvalidArgs;
        }
    }

    if (elf_path == null or out_path == null) {
        std.debug.print("Error: --elf and --out are required.\n", .{});
        printUsage();
        return error.InvalidArgs;
    }

    // Read input ELF file
    const elf_data = try std.fs.cwd().readFileAlloc(allocator, elf_path.?, std.math.maxInt(usize));
    defer allocator.free(elf_data);

    // Make sure it is a valid RISC-V ELF
    _ = elf_parser.parse(elf_data) catch |err| {
        std.debug.print("Failed to parse input ELF file. Error: {}\n", .{err});
        return err;
    };

    // In our simplified ZephVM, we package the entire ELF since the loader handles mapping.
    // However, if we wanted a true flat binary we would extract `.text` and `.data`.
    // We'll bundle the whole ELF.

    // Optional reads
    var abi_data: ?[]const u8 = null;
    if (abi_path) |p| {
        abi_data = try std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize));
    }
    defer if (abi_data) |d| allocator.free(d);

    var meta_data: ?[]const u8 = null;
    if (meta_path) |p| {
        meta_data = try std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize));
    }
    defer if (meta_data) |d| allocator.free(d);

    // Build the package
    const pkg_bytes = try zeph_format.build(allocator, elf_data, abi_data, meta_data);
    defer allocator.free(pkg_bytes);

    // Write to output (.zeph binary)
    const out_file = try std.fs.cwd().createFile(out_path.?, .{});
    defer out_file.close();
    try out_file.writeAll(pkg_bytes);

    if (gen_hex) {
        // Also write to output (.zeph.hex string prefixed with 0x)
        const hex_out_path = try std.fmt.allocPrint(allocator, "{s}.hex", .{out_path.?});
        defer allocator.free(hex_out_path);

        const hex_file = try std.fs.cwd().createFile(hex_out_path, .{});
        defer hex_file.close();

        // We write '0x' first
        try hex_file.writeAll("0x");

        // Encode the bytecode into a continuous hex string
        const hex_chars = "0123456789abcdef";
        var hex_buffer: [1024]u8 = undefined;
        var i: usize = 0;
        while (i < pkg_bytes.len) {
            const chunk_size = @min(pkg_bytes.len - i, hex_buffer.len / 2);
            for (pkg_bytes[i .. i + chunk_size], 0..) |byte, buf_idx| {
                hex_buffer[buf_idx * 2] = hex_chars[byte >> 4];
                hex_buffer[buf_idx * 2 + 1] = hex_chars[byte & 0x0F];
            }
            try hex_file.writeAll(hex_buffer[0 .. chunk_size * 2]);
            i += chunk_size;
        }

        std.debug.print("Successfully packaged {s} into {s} and {s} ({} bytes)\n", .{ elf_path.?, out_path.?, hex_out_path, pkg_bytes.len });
    } else {
        std.debug.print("Successfully packaged {s} into {s} ({} bytes)\n", .{ elf_path.?, out_path.?, pkg_bytes.len });
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: zeph-pack [options]
        \\
        \\Options:
        \\  -o, --out <path>       Output path for the generated .zeph file
        \\  --elf <path>           Input RISC-V ELF binary
        \\  --abi <path>           (Optional) JSON ABI file
        \\  --metadata <path>      (Optional) JSON Metadata file
        \\  --hex                  (Optional) Generate a .zeph.hex string prefixed with 0x mapped exactly for deployment
        \\  -h, --help             Show this help message
        \\
    , .{});
}
