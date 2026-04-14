// File: tools/zephyrc/elf_writer.zig
// ZephyrLang ELF Writer — Packages compiled bytecode as a minimal ELF binary.
// Produces a valid RISC-V ELF32 executable loadable by ZephVM's contract_loader.

const std = @import("std");

const ELF_MAGIC = [4]u8{ 0x7f, 'E', 'L', 'F' };

const Elf32Header = extern struct {
    e_ident: [16]u8,
    e_type: u16 align(1),
    e_machine: u16 align(1),
    e_version: u32 align(1),
    e_entry: u32 align(1),
    e_phoff: u32 align(1),
    e_shoff: u32 align(1),
    e_flags: u32 align(1),
    e_ehsize: u16 align(1),
    e_phentsize: u16 align(1),
    e_phnum: u16 align(1),
    e_shentsize: u16 align(1),
    e_shnum: u16 align(1),
    e_shstrndx: u16 align(1),
};

const Elf32Phdr = extern struct {
    p_type: u32 align(1),
    p_offset: u32 align(1),
    p_vaddr: u32 align(1),
    p_paddr: u32 align(1),
    p_filesz: u32 align(1),
    p_memsz: u32 align(1),
    p_flags: u32 align(1),
    p_align: u32 align(1),
};

const EH_SIZE = @sizeOf(Elf32Header);
const PH_SIZE = @sizeOf(Elf32Phdr);

pub fn writeElf(alloc: std.mem.Allocator, code: []const u8, entry: u32) ![]u8 {
    const code_offset: u32 = EH_SIZE + PH_SIZE; // code starts after headers
    const total_size = code_offset + @as(u32, @intCast(code.len));

    var buf = try alloc.alloc(u8, total_size);

    // ELF header
    var ehdr: Elf32Header = std.mem.zeroes(Elf32Header);
    @memcpy(ehdr.e_ident[0..4], &ELF_MAGIC);
    ehdr.e_ident[4] = 1; // ELFCLASS32
    ehdr.e_ident[5] = 1; // ELFDATA2LSB
    ehdr.e_ident[6] = 1; // EV_CURRENT
    ehdr.e_type = 2; // ET_EXEC
    ehdr.e_machine = 0xF3; // EM_RISCV
    ehdr.e_version = 1;
    ehdr.e_entry = entry;
    ehdr.e_phoff = EH_SIZE;
    ehdr.e_ehsize = EH_SIZE;
    ehdr.e_phentsize = PH_SIZE;
    ehdr.e_phnum = 1;

    // Program header — single LOAD segment for code
    var phdr: Elf32Phdr = std.mem.zeroes(Elf32Phdr);
    phdr.p_type = 1; // PT_LOAD
    phdr.p_offset = code_offset;
    phdr.p_vaddr = 0;
    phdr.p_paddr = 0;
    phdr.p_filesz = @intCast(code.len);
    phdr.p_memsz = @intCast(code.len);
    phdr.p_flags = 5; // PF_R | PF_X
    phdr.p_align = 4;

    // Copy headers into buffer
    const ehdr_bytes = std.mem.asBytes(&ehdr);
    @memcpy(buf[0..EH_SIZE], ehdr_bytes);
    const phdr_bytes = std.mem.asBytes(&phdr);
    @memcpy(buf[EH_SIZE..][0..PH_SIZE], phdr_bytes);
    @memcpy(buf[code_offset..], code);

    return buf;
}

// ============================================================================
// Tests
// ============================================================================
const testing = std.testing;

test "elf_writer: produces valid ELF" {
    const code = [_]u8{ 0x13, 0x05, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00 }; // addi a0,zero,1; ecall
    const elf = try writeElf(testing.allocator, &code, 0);
    defer testing.allocator.free(elf);
    // Check ELF magic
    try testing.expectEqualSlices(u8, &ELF_MAGIC, elf[0..4]);
    // Check machine = RISC-V
    try testing.expectEqual(@as(u16, 0xF3), std.mem.readInt(u16, elf[18..20], .little));
    // Code is present at the right offset
    try testing.expectEqual(@as(u8, 0x13), elf[EH_SIZE + PH_SIZE]);
}
