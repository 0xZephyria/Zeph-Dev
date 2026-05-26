const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const file_path = "vm/polkavm/revive-transfer-example.elf";
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(data);

    const is64 = data[4] == 2;
    if (!is64) {
        std.debug.print("Not ELF64\n", .{});
        return;
    }

    const elf = std.elf;
    const hdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, data[0..@sizeOf(elf.Elf64_Ehdr)]);
    const shoff = hdr.e_shoff;
    const shentsize = hdr.e_shentsize;
    const shstrndx = hdr.e_shstrndx;

    const str_sh_off = shoff + @as(u64, shstrndx) * shentsize;
    const str_sh = std.mem.bytesAsValue(elf.Elf64_Shdr, data[str_sh_off..][0..@sizeOf(elf.Elf64_Shdr)]);
    const shstrtab = data[str_sh.sh_offset .. str_sh.sh_offset + str_sh.sh_size];

    var opt_symtab: ?[]align(1) const elf.Elf64_Sym = null;
    var opt_strtab: ?[]const u8 = null;

    var i: u16 = 0;
    while (i < hdr.e_shnum) : (i += 1) {
        const offset = shoff + @as(u64, i) * shentsize;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, data[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
        const name_offset = sh.sh_name;
        var name_len: usize = 0;
        while (name_offset + name_len < shstrtab.len and shstrtab[name_offset + name_len] != 0) : (name_len += 1) {}
        const name = shstrtab[name_offset .. name_offset + name_len];

        if (std.mem.eql(u8, name, ".symtab")) {
            const syms_count = sh.sh_size / @sizeOf(elf.Elf64_Sym);
            const syms_ptr = @as([*]align(1) const elf.Elf64_Sym, @ptrCast(data[sh.sh_offset..].ptr));
            opt_symtab = syms_ptr[0..syms_count];
        } else if (std.mem.eql(u8, name, ".strtab")) {
            opt_strtab = data[sh.sh_offset .. sh.sh_offset + sh.sh_size];
        }
    }

    if (opt_symtab) |syms| {
        const strtab = opt_strtab.?;
        std.debug.print("=== ELF SYMBOLS ===\n", .{});
        for (syms) |sym| {
            const name_offset = sym.st_name;
            var len: usize = 0;
            while (name_offset + len < strtab.len and strtab[name_offset + len] != 0) : (len += 1) {}
            const sym_name = strtab[name_offset .. name_offset + len];
            if (sym_name.len > 0) {
                std.debug.print("{s} (val: 0x{x}, info: {})\n", .{sym_name, sym.st_value, sym.st_info});
            }
        }
    }
}
