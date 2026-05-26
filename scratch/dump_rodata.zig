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

    const elf = std.elf;
    const hdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, data[0..@sizeOf(elf.Elf64_Ehdr)]);
    const shoff = hdr.e_shoff;
    const shentsize = hdr.e_shentsize;
    const shstrndx = hdr.e_shstrndx;

    const str_sh_off = shoff + @as(u64, shstrndx) * shentsize;
    const str_sh = std.mem.bytesAsValue(elf.Elf64_Shdr, data[str_sh_off..][0..@sizeOf(elf.Elf64_Shdr)]);
    const shstrtab = data[str_sh.sh_offset .. str_sh.sh_offset + str_sh.sh_size];

    var i: u16 = 0;
    while (i < hdr.e_shnum) : (i += 1) {
        const offset = shoff + @as(u64, i) * shentsize;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, data[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
        const name_offset = sh.sh_name;
        var name_len: usize = 0;
        while (name_offset + name_len < shstrtab.len and shstrtab[name_offset + name_len] != 0) : (name_len += 1) {}
        const name = shstrtab[name_offset .. name_offset + name_len];

        if (std.mem.eql(u8, name, ".rodata.str1.1")) {
            std.debug.print("Found .rodata.str1.1 section: size={d} bytes\n", .{sh.sh_size});
            const rodata = data[sh.sh_offset .. sh.sh_offset + sh.sh_size];
            
            // Print printable chunks
            var j: usize = 0;
            while (j < rodata.len) {
                if (std.ascii.isPrint(rodata[j])) {
                    var len: usize = 0;
                    while (j + len < rodata.len and std.ascii.isPrint(rodata[j + len])) : (len += 1) {}
                    if (len >= 4) {
                        std.debug.print("String: '{s}'\n", .{rodata[j .. j + len]});
                        j += len;
                        continue;
                    }
                }
                j += 1;
            }
        }
    }
}
