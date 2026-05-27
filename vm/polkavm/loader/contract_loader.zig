// File: vm/loader/contract_loader.zig
// Contract loader for ForgeVM.
// Orchestrates: .forge parse → ELF extract → validate → sandbox setup → execute.

const std = @import("std");
const forgeLoader = @import("forge_loader.zig");
const forgeFormat = @import("forge_format.zig");
const sandbox = @import("../memory/sandbox.zig");
const executor = @import("../core/executor.zig");
const threaded_executor = @import("../core/threaded_executor.zig");
const basic_block = @import("../core/basic_block.zig");
const syscallDispatch = @import("../syscall/dispatch.zig");
const zephbinLoader = @import("zephbin_loader.zig");
const gasMeter = @import("../gas/meter.zig");
const aot = @import("../compiler/aot.zig");

const enable_debug_logging = false;

inline fn debugPrint(comptime format: []const u8, args: anytype) void {
    if (comptime enable_debug_logging) {
        std.debug.print(format, args);
    }
}

pub const LoadError = error{
    // Format errors
    InvalidPackage,
    InvalidElf,
    CodeTooLarge,
    // Runtime errors
    OutOfMemory,
    ExecutionFailed,
};

/// Result of loading and executing a contract
pub const ContractResult = struct {
    status: executor.ExecutionStatus,
    gasUsed: u64,
    gasRemaining: u64,
    returnData: []const u8,
    logs: []const syscallDispatch.LogEntry,
    faultPc: u32,
    faultReason: ?[]const u8,
};

/// Load and execute a contract from raw bytecode (ELF binary).
/// This is the simpler path — no .forge packaging, just raw ELF.
pub fn executeFromElf(
    allocator: std.mem.Allocator,
    elfData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeWithMemory(allocator, &memory, elfData, calldata, gasLimit, env);
}

fn loadRelocatableElf(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    elfData: []const u8,
    env: *syscallDispatch.HostEnv,
) !u32 {
    const elf = std.elf;
    const is64 = elfData[4] == 2;
    if (!is64) return error.UnsupportedElfClass;

    const hdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, elfData[0..@sizeOf(elf.Elf64_Ehdr)]);
    const shoff = hdr.e_shoff;
    const shentsize = hdr.e_shentsize;
    const shnum = hdr.e_shnum;
    const shstrndx = hdr.e_shstrndx;

    const str_sh_off = shoff + @as(u64, shstrndx) * shentsize;
    const str_sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[str_sh_off..][0..@sizeOf(elf.Elf64_Shdr)]);
    const shstrtab = elfData[str_sh.sh_offset .. str_sh.sh_offset + str_sh.sh_size];

    const section_vaddrs = try allocator.alloc(u32, shnum);
    defer allocator.free(section_vaddrs);
    @memset(section_vaddrs, 0);

    var heap_ptr: u32 = sandbox.heapStart;

    // First pass: find .text and assign its vaddr to 0x0000_0000
    var text_sec_idx: ?u16 = null;
    var i: u16 = 0;
    while (i < shnum) : (i += 1) {
        const offset = shoff + @as(u64, i) * shentsize;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (sh.sh_size == 0) continue;

        const name_offset = sh.sh_name;
        var name_len: usize = 0;
        while (name_offset + name_len < shstrtab.len and shstrtab[name_offset + name_len] != 0) : (name_len += 1) {}
        const name = shstrtab[name_offset .. name_offset + name_len];

        if (std.mem.eql(u8, name, ".text")) {
            text_sec_idx = i;
            section_vaddrs[i] = 0x0000_0000;
            if (sh.sh_size > sandbox.codeSize) return error.CodeTooLarge;
            @memcpy(memory.backing[0..sh.sh_size], elfData[sh.sh_offset .. sh.sh_offset + sh.sh_size]);
        }
    }

    if (text_sec_idx == null) return error.NoCode;

    // Second pass: load other SHF_ALLOC sections
    i = 0;
    while (i < shnum) : (i += 1) {
        if (i == text_sec_idx.?) continue;
        const offset = shoff + @as(u64, i) * shentsize;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (sh.sh_size == 0) continue;

        if ((sh.sh_flags & elf.SHF_ALLOC) != 0) {
            const alignment: u32 = @intCast(sh.sh_addralign);
            if (alignment > 0) {
                heap_ptr = std.mem.alignForward(u32, heap_ptr, alignment);
            }

            section_vaddrs[i] = heap_ptr;

            if (sh.sh_type != elf.SHT_NOBITS) {
                if (heap_ptr + sh.sh_size > sandbox.heapEnd + 1) return error.TooLarge;
                @memcpy(memory.backing[heap_ptr .. heap_ptr + sh.sh_size], elfData[sh.sh_offset .. sh.sh_offset + sh.sh_size]);
            }
            heap_ptr += @intCast(sh.sh_size);
        }
    }
    if (enable_debug_logging) {
        std.debug.print("=== LOADED SECTIONS ===\n", .{});
        var sec_idx: u16 = 0;
        while (sec_idx < shnum) : (sec_idx += 1) {
            const offset = shoff + @as(u64, sec_idx) * shentsize;
            const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
            const name_offset = sh.sh_name;
            var name_len: usize = 0;
            while (name_offset + name_len < shstrtab.len and shstrtab[name_offset + name_len] != 0) : (name_len += 1) {}
            const name = shstrtab[name_offset .. name_offset + name_len];
            std.debug.print("Section {}: '{s}' vaddr=0x{x} size={} type={}\n", .{
                sec_idx, name, section_vaddrs[sec_idx], sh.sh_size, sh.sh_type,
            });
        }
    }

    var opt_symtab: ?[]align(1) const elf.Elf64_Sym = null;
    var opt_strtab: ?[]const u8 = null;

    i = 0;
    while (i < shnum) : (i += 1) {
        const offset = shoff + @as(u64, i) * shentsize;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (sh.sh_type == elf.SHT_SYMTAB) {
            const syms_count = sh.sh_size / @sizeOf(elf.Elf64_Sym);
            opt_symtab = @as([*]align(1) const elf.Elf64_Sym, @ptrCast(elfData[sh.sh_offset..].ptr))[0..syms_count];
        } else if (sh.sh_type == elf.SHT_STRTAB) {
            if (i != shstrndx) {
                opt_strtab = elfData[sh.sh_offset .. sh.sh_offset + sh.sh_size];
            }
        }
    }

    const symtab = opt_symtab orelse return error.InvalidElf;
    const strtab = opt_strtab orelse return error.InvalidElf;

    const sym_vaddrs = try allocator.alloc(u32, symtab.len);
    defer allocator.free(sym_vaddrs);
    @memset(sym_vaddrs, 0);

    for (symtab, 0..) |sym, sym_idx| {
        const shndx = sym.st_shndx;
        if (shndx == elf.SHN_UNDEF) {
            sym_vaddrs[sym_idx] = 0;
        } else if (shndx < shnum) {
            sym_vaddrs[sym_idx] = section_vaddrs[shndx] + @as(u32, @truncate(sym.st_value));
        } else {
            sym_vaddrs[sym_idx] = @truncate(sym.st_value);
        }
    }

    if (enable_debug_logging) {
        std.debug.print("PRE-RELOCATION HEX DUMP OF MEMORY 0x280..0x2c0:\n", .{});
        var dump_idx: u32 = 0x280;
        while (dump_idx < 0x2c0) : (dump_idx += 4) {
            const word_val = std.mem.readInt(u32, memory.backing[dump_idx..][0..4], .little);
            std.debug.print("0x{x:0>4}: 0x{x:0>8}\n", .{ dump_idx, word_val });
        }
    }

    // Third pass: resolve relocations
    i = 0;
    while (i < shnum) : (i += 1) {
        const offset = shoff + @as(u64, i) * shentsize;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (sh.sh_type == elf.SHT_RELA) {
            const target_sec_idx = sh.sh_info;
            if (target_sec_idx >= shnum) continue;
            if (target_sec_idx != text_sec_idx.? and section_vaddrs[target_sec_idx] == 0) continue;
            const target_vaddr = section_vaddrs[target_sec_idx];

            const rela_count = sh.sh_size / @sizeOf(elf.Elf64_Rela);
            const relas = @as([*]align(1) const elf.Elf64_Rela, @ptrCast(elfData[sh.sh_offset..].ptr))[0..rela_count];

            for (relas) |rela| {
                const sym_idx = rela.r_info >> 32;
                const r_type = rela.r_info & 0xffffffff;
                if (sym_idx >= symtab.len) continue;

                const S = sym_vaddrs[sym_idx];
                const A = rela.r_addend;
                const P = target_vaddr + @as(u32, @truncate(rela.r_offset));

                if (enable_debug_logging) {
                    const sym = symtab[sym_idx];
                    const name_offset = sym.st_name;
                    var name_len: usize = 0;
                    while (name_offset + name_len < strtab.len and strtab[name_offset + name_len] != 0) : (name_len += 1) {}
                    const sym_name = strtab[name_offset .. name_offset + name_len];
                    std.debug.print("APPLY RELOC: offset=0x{x} type={} target_vaddr=0x{x} P=0x{x} sym='{s}' S=0x{x} A={}\n", .{
                        rela.r_offset, r_type, target_vaddr, P, sym_name, S, A,
                    });
                }

                switch (r_type) {
                    1 => { // R_RISCV_32
                        const val = @as(u32, @truncate(S +% @as(u64, @bitCast(A))));
                        std.mem.writeInt(u32, memory.backing[P..][0..4], val, .little);
                    },
                    2 => { // R_RISCV_64
                        const val = S +% @as(u64, @bitCast(A));
                        std.mem.writeInt(u64, memory.backing[P..][0..8], val, .little);
                    },
                    16 => { // R_RISCV_BRANCH
                        const roffset = @as(i64, S) + A - P;
                        var inst = std.mem.readInt(u32, memory.backing[P..][0..4], .little);
                        inst &= ~@as(u32, 0xFE000F80);
                        const u_offset = @as(u32, @truncate(@as(u64, @bitCast(roffset))));
                        const bit12 = (u_offset >> 12) & 1;
                        const imm10_5 = (u_offset >> 5) & 0x3F;
                        const imm4_1 = (u_offset >> 1) & 0x0F;
                        const imm11 = (u_offset >> 11) & 1;
                        const encoded = (bit12 << 31) | (imm10_5 << 25) | (imm4_1 << 8) | (imm11 << 7);
                        inst |= encoded;
                        std.mem.writeInt(u32, memory.backing[P..][0..4], inst, .little);
                    },
                    18, 19 => { // R_RISCV_CALL / R_RISCV_CALL_PLT
                        const roffset = @as(i64, S) + A - P;
                        var auipc = std.mem.readInt(u32, memory.backing[P..][0..4], .little);
                        var jalr = std.mem.readInt(u32, memory.backing[P + 4 ..][0..4], .little);

                        const high20 = @as(i32, @truncate((roffset + 0x800) >> 12));
                        const low12 = @as(i32, @truncate(roffset)) - (high20 << 12);

                        debugPrint("RELOC 18/19: P=0x{x}, S=0x{x}, roffset={}, high20=0x{x}, low12={}\n", .{ P, S, roffset, high20, low12 });
                        debugPrint("  BEFORE: auipc=0x{x:0>8}, jalr=0x{x:0>8}\n", .{ auipc, jalr });

                        auipc &= ~@as(u32, 0xFFFFF000);
                        auipc |= @as(u32, @bitCast(high20)) << 12;

                        jalr &= ~@as(u32, 0xFFF00000);
                        jalr |= @as(u32, @bitCast(low12 & 0xFFF)) << 20;

                        debugPrint("  AFTER:  auipc=0x{x:0>8}, jalr=0x{x:0>8}\n", .{ auipc, jalr });

                        std.mem.writeInt(u32, memory.backing[P..][0..4], auipc, .little);
                        std.mem.writeInt(u32, memory.backing[P + 4 ..][0..4], jalr, .little);
                    },
                    23 => { // R_RISCV_PCREL_HI20
                        const roffset = @as(i64, S) + A - P;
                        const high20 = @as(i32, @truncate((roffset + 0x800) >> 12));
                        var inst = std.mem.readInt(u32, memory.backing[P..][0..4], .little);
                        debugPrint("RELOC 23: P=0x{x}, S=0x{x}, roffset={}, high20=0x{x}\n", .{ P, S, roffset, high20 });
                        debugPrint("  BEFORE: inst=0x{x:0>8}\n", .{ inst });
                        inst &= ~@as(u32, 0xFFFFF000);
                        inst |= @as(u32, @bitCast(high20)) << 12;
                        debugPrint("  AFTER:  inst=0x{x:0>8}\n", .{ inst });
                        std.mem.writeInt(u32, memory.backing[P..][0..4], inst, .little);
                    },
                    24 => { // R_RISCV_PCREL_LO12_I
                        const hi_addr = S;
                        var hi_rela: ?elf.Elf64_Rela = null;
                        for (relas) |r| {
                            const r_type_hi = r.r_info & 0xffffffff;
                            if (r_type_hi == 23) { // R_RISCV_PCREL_HI20
                                const r_P_hi = target_vaddr + @as(u32, @truncate(r.r_offset));
                                if (r_P_hi == hi_addr) {
                                    hi_rela = r;
                                    break;
                                }
                            }
                        }

                        if (hi_rela) |hr| {
                            const sym_idx_hi = hr.r_info >> 32;
                            const S_hi = sym_vaddrs[sym_idx_hi];
                            const A_hi = hr.r_addend;
                            const roffset = @as(i64, S_hi) + A_hi - hi_addr;
                            const high20 = @as(i32, @truncate((roffset + 0x800) >> 12));
                            const low12 = @as(i32, @truncate(roffset)) - (high20 << 12);

                            var inst = std.mem.readInt(u32, memory.backing[P..][0..4], .little);
                            debugPrint("RELOC 24: P=0x{x}, hi_addr=0x{x}, low12={}\n", .{ P, hi_addr, low12 });
                            debugPrint("  BEFORE: inst=0x{x:0>8}\n", .{ inst });
                            inst &= ~@as(u32, 0xFFF00000);
                            inst |= @as(u32, @bitCast(low12 & 0xFFF)) << 20;
                            debugPrint("  AFTER:  inst=0x{x:0>8}\n", .{ inst });
                            std.mem.writeInt(u32, memory.backing[P..][0..4], inst, .little);
                        }
                    },
                    25 => { // R_RISCV_PCREL_LO12_S
                        const hi_addr = S;
                        var hi_rela: ?elf.Elf64_Rela = null;
                        for (relas) |r| {
                            const r_type_hi = r.r_info & 0xffffffff;
                            if (r_type_hi == 23) { // R_RISCV_PCREL_HI20
                                const r_P_hi = target_vaddr + @as(u32, @truncate(r.r_offset));
                                if (r_P_hi == hi_addr) {
                                    hi_rela = r;
                                    break;
                                }
                            }
                        }

                        if (hi_rela) |hr| {
                            const sym_idx_hi = hr.r_info >> 32;
                            const S_hi = sym_vaddrs[sym_idx_hi];
                            const A_hi = hr.r_addend;
                            const roffset = @as(i64, S_hi) + A_hi - hi_addr;
                            const high20 = @as(i32, @truncate((roffset + 0x800) >> 12));
                            const low12 = @as(i32, @truncate(roffset)) - (high20 << 12);

                            var inst = std.mem.readInt(u32, memory.backing[P..][0..4], .little);
                            debugPrint("RELOC 25: P=0x{x}, hi_addr=0x{x}, low12={}\n", .{ P, hi_addr, low12 });
                            debugPrint("  BEFORE: inst=0x{x:0>8}\n", .{ inst });
                            inst &= ~@as(u32, 0xFE000F80);
                            const u_low12 = @as(u32, @bitCast(low12)) & 0xFFF;
                            const imm_lo = u_low12 & 0x1F;
                            const imm_hi = (u_low12 >> 5) & 0x7F;
                            inst |= (imm_hi << 25) | (imm_lo << 7);
                            debugPrint("  AFTER:  inst=0x{x:0>8}\n", .{ inst });
                            std.mem.writeInt(u32, memory.backing[P..][0..4], inst, .little);
                        }
                    },
                    44 => { // R_RISCV_RVC_BRANCH
                        const roffset = @as(i64, S) + A - P;
                        var inst = std.mem.readInt(u16, memory.backing[P..][0..2], .little);
                        inst &= ~@as(u16, 0x1C7C);
                        const u_offset = @as(u32, @truncate(@as(u64, @bitCast(roffset))));
                        const bit8 = (u_offset >> 8) & 1;
                        const bit7_6 = (u_offset >> 6) & 3;
                        const bit5 = (u_offset >> 5) & 1;
                        const bit4_3 = (u_offset >> 3) & 3;
                        const bit2_1 = (u_offset >> 1) & 3;
                        const encoded = (bit8 << 12) | (bit4_3 << 10) | (bit7_6 << 5) | (bit2_1 << 3) | (bit5 << 2);
                        inst |= @as(u16, @truncate(encoded));
                        std.mem.writeInt(u16, memory.backing[P..][0..2], inst, .little);
                    },
                    45 => { // R_RISCV_RVC_JUMP
                        const roffset = @as(i64, S) + A - P;
                        var inst = std.mem.readInt(u16, memory.backing[P..][0..2], .little);
                        inst &= ~@as(u16, 0x1FFC);
                        const u_offset = @as(u32, @truncate(@as(u64, @bitCast(roffset))));
                        const bit11 = (u_offset >> 11) & 1;
                        const bit10 = (u_offset >> 10) & 1;
                        const bit9_8 = (u_offset >> 8) & 3;
                        const bit7 = (u_offset >> 7) & 1;
                        const bit6 = (u_offset >> 6) & 1;
                        const bit5 = (u_offset >> 5) & 1;
                        const bit4 = (u_offset >> 4) & 1;
                        const bit3_1 = (u_offset >> 1) & 7;
                        const encoded = (bit11 << 12) | (bit4 << 11) | (bit9_8 << 9) | (bit10 << 8) | (bit6 << 7) | (bit7 << 6) | (bit3_1 << 3) | (bit5 << 2);
                        inst |= @as(u16, @truncate(encoded));
                        std.mem.writeInt(u16, memory.backing[P..][0..2], inst, .little);
                    },
                    else => {},
                }
            }
        }
    }

    // Determine entry point
    var call_addr: ?u32 = null;
    var deploy_addr: ?u32 = null;

    for (symtab, 0..) |sym, sym_idx| {
        const name_offset = sym.st_name;
        if (name_offset >= strtab.len) continue;
        var len: usize = 0;
        while (name_offset + len < strtab.len and strtab[name_offset + len] != 0) : (len += 1) {}
        const sym_name = strtab[name_offset .. name_offset + len];

        if (std.mem.eql(u8, sym_name, "call")) {
            call_addr = sym_vaddrs[sym_idx];
        } else if (std.mem.eql(u8, sym_name, "deploy")) {
            deploy_addr = sym_vaddrs[sym_idx];
        }
    }

    if (enable_debug_logging) {
        std.debug.print("POST-RELOCATION HEX DUMP OF MEMORY 0x280..0x2c0:\n", .{});
        var dump_idx: u32 = 0x280;
        while (dump_idx < 0x2c0) : (dump_idx += 4) {
            const word_val = std.mem.readInt(u32, memory.backing[dump_idx..][0..4], .little);
            std.debug.print("0x{x:0>4}: 0x{x:0>8}\n", .{ dump_idx, word_val });
        }
    }

    // Check if we are performing a deployment or call
    const is_deploy = env.balanceFn == null or env.selfAddress[0] == 0; // Simple heuristic for test vs run
    const entry = if (is_deploy) (deploy_addr orelse (call_addr orelse 0)) else (call_addr orelse (deploy_addr orelse 0));

    return entry;
}

/// Load and execute a contract using a pre-allocated sandbox memory.
pub fn executeWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    elfData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    const isPvm = elfData.len >= 4 and elfData[0] == 'P' and elfData[1] == 'V' and elfData[2] == 'M' and elfData[3] == 0;
    if (isPvm) {
        memory.reset();
        
        const pvm_loader = @import("pvm_loader.zig");
        const pvm_executor = @import("../core/pvm_executor.zig");
        
        var prog = try pvm_loader.parse(allocator, elfData);
        defer prog.deinit();
        
        if (prog.ro_data.len > 0) {
            @memcpy(memory.backing[0x10000 .. 0x10000 + prog.ro_data.len], prog.ro_data);
            memory.dirty_tracker.markDirty(0x10000, @intCast(prog.ro_data.len));
        }
        
        if (prog.rw_data.len > 0) {
            const rw_start = 0x10000 + prog.ro_data_size;
            @memcpy(memory.backing[rw_start .. rw_start + prog.rw_data.len], prog.rw_data);
            memory.dirty_tracker.markDirty(rw_start, @intCast(prog.rw_data.len));
        }
        
        const is_deploy = env.balanceFn == null or env.selfAddress[0] == 0;

        // In pallet-revive, code is uploaded separately. Calldata contains
        // only the ABI-encoded constructor arguments (deploy) or function
        // call data (call).  Do NOT prepend prog.code.
        const actual_calldata = calldata;

        if (actual_calldata.len > 0) {
            try memory.loadCalldata(actual_calldata);
        }

        const entry_pc = if (is_deploy) 
            (prog.findExport("deploy") orelse (prog.findExport("call") orelse 0)) 
        else 
            (prog.findExport("call") orelse (prog.findExport("deploy") orelse 0));
        std.debug.print("DEBUG PVM is_deploy: {}, exports count: {}, code len: {}, entry_pc: {}, stack_size: {}, ro_data_size: {}, rw_data_size: {}\n", .{is_deploy, prog.exports.len, prog.code.len, entry_pc, prog.stack_size, prog.ro_data_size, prog.rw_data_size});
        for (prog.exports) |exp| {
            std.debug.print("  export: name={s}, pc={}\n", .{exp.name, exp.pc});
        }
            
        const handler = syscallDispatch.createHandler(env);
        
        var pvm_vm = pvm_executor.PvmExecutor.init(memory, &prog, gasLimit, handler, env, @intCast(actual_calldata.len));
        pvm_vm.pc = entry_pc;
        
        const result = pvm_vm.execute();
        
        var returnData: []const u8 = &[_]u8{};
        if (result.returnDataLen > 0) {
            const rawReturn = memory.getReturnData(
                result.returnDataOffset,
                result.returnDataLen,
            ) catch &[_]u8{};
            if (rawReturn.len > 0) {
                returnData = allocator.dupe(u8, rawReturn) catch &[_]u8{};
            }
        }
        
        return .{
            .status = result.status,
            .gasUsed = result.gasUsed,
            .gasRemaining = result.gasRemaining,
            .returnData = returnData,
            .logs = env.logs.items,
            .faultPc = result.faultPc,
            .faultReason = result.faultReason,
        };
    }

    const isElf = elfData.len >= 4 and elfData[0] == 0x7F and elfData[1] == 'E' and elfData[2] == 'L' and elfData[3] == 'F';
    // No allocation here! We use the provided memory.
    memory.reset();

    var codeLen: usize = 0;
    var entryPoint: u32 = 0;
    var is_rel = false;

    if (isElf) {
        is_rel = elfData.len >= 18 and elfData[16] == 1 and elfData[17] == 0;
        if (is_rel) {
            codeLen = sandbox.codeSize;
            entryPoint = try loadRelocatableElf(allocator, memory, elfData, env);
        } else {
            // 1. Parse ELF
            const elf = forgeLoader.parse(elfData) catch return LoadError.InvalidElf;

            // 2. Validate code size
            if (elf.code.len > sandbox.codeSize) return LoadError.CodeTooLarge;

            // Give the VM the full Code Sandbox area so that execution inside .rodata or multiple segments doesn't trip the bounds restriction.
            codeLen = sandbox.codeSize;
            entryPoint = elf.entryPoint -| elf.codeVaddr;

            // 4. Load segments directly into memory at their vaddr
            if (elf.segmentCount > 0) {
                var i: usize = 0;
                while (i < elf.segmentCount) : (i += 1) {
                    const seg = elf.segments[i];
                    if (seg.vaddr + seg.data.len > sandbox.memorySize) return LoadError.InvalidElf;
                    if (seg.data.len > 0) {
                        @memcpy(memory.backing[seg.vaddr .. seg.vaddr + seg.data.len], seg.data);
                    }
                }
                try resolveSubstrateImports(memory, elfData, elf.codeVaddr);
            } else {
                // Fallback for flat binary
                memory.loadCode(elf.code) catch return LoadError.ExecutionFailed;
                if (elf.initData.len > 0) {
                    const max_data = sandbox.heapEnd - sandbox.heapStart + 1;
                    const data_len = @min(elf.initData.len, max_data);
                    if (elf.dataVaddr > 0 and elf.dataVaddr + data_len <= sandbox.memorySize) {
                        @memcpy(memory.backing[elf.dataVaddr .. elf.dataVaddr + data_len], elf.initData[0..data_len]);
                    } else {
                        @memcpy(memory.backing[sandbox.heapStart .. sandbox.heapStart + data_len], elf.initData[0..data_len]);
                    }
                }
            }
        }
    } else {
        // Raw RISC-V bytecode execution (EVM style)
        if (elfData.len > sandbox.codeSize) return LoadError.CodeTooLarge;
        memory.loadCode(elfData) catch return LoadError.ExecutionFailed;
        codeLen = elfData.len;
        entryPoint = 0;
    }

    // 6. Load calldata
    if (calldata.len > 0) {
        memory.loadCalldata(calldata) catch return LoadError.ExecutionFailed;
    }

    // 7. Create syscall handler
    const handler = syscallDispatch.createHandler(env);

    // 8. Initialize VM
    // 8. Initialize VM
    var vm = executor.ForgeVM.init(
        memory,
        @intCast(codeLen),
        gasLimit,
        handler,
    );
    if (isElf and is_rel) {
        vm.is_polkavm = true;
    }

    // Wire hostCtx so the thread-safe syscall dispatcher can retrieve HostEnv
    // without going through a shared static pointer.
    vm.hostCtx = env;

    // 9. Set entry point
    vm.pc = entryPoint;

    // 9b. Set actual calldata length
    vm.calldataLen = @intCast(calldata.len);

    // 10. Execute
    const result = vm.execute();

    // 11. Extract return data
    var returnData: []const u8 = &[_]u8{};
    if (result.returnDataLen > 0) {
        const rawReturn = memory.getReturnData(
            result.returnDataOffset,
            result.returnDataLen,
        ) catch &[_]u8{};
        if (rawReturn.len > 0) {
            returnData = allocator.dupe(u8, rawReturn) catch &[_]u8{};
        }
    }

    return .{
        .status = result.status,
        .gasUsed = result.gasUsed,
        .gasRemaining = result.gasRemaining,
        .returnData = returnData,
        .logs = env.logs.items,
        .faultPc = result.faultPc,
        .faultReason = result.faultReason,
    };
}

/// Load and execute a contract from a .fozbin or .forge package.
///
/// Detection order:
///   1. ZephBin v1 (magic "FORG", version=1) — emitted by the Forge compiler (codegen.zig)
///   2. ForgeHeader v2 (magic "FORG", version=2) — VM internal format
///   3. Falls back to executeFromElf for bare ELF or raw bytecode
pub fn executeFromZeph(
    allocator: std.mem.Allocator,
    forgeData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    if (env.vm_pool) |pool_ptr| {
        const pool: *@import("../vm_pool.zig").VMPool = @ptrCast(@alignCast(pool_ptr));
        const mem = pool.acquire() orelse {
            var legacy_mem = try sandbox.SandboxMemory.init(allocator);
            defer legacy_mem.deinit();
            return executeFromZephWithMemory(allocator, &legacy_mem, forgeData, calldata, gasLimit, env);
        };
        defer pool.release(mem);
        return executeFromZephWithMemory(allocator, mem, forgeData, calldata, gasLimit, env);
    }
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeFromZephWithMemory(allocator, &memory, forgeData, calldata, gasLimit, env);
}

/// Load and execute a contract from a .fozbin package using pre-allocated memory.
pub fn executeFromZephWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    forgeData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    if (zephbinLoader.isZephBin(forgeData)) {
        return executeFromZephBinWithMemory(allocator, memory, forgeData, calldata, gasLimit, env);
    }

    const pkg = forgeFormat.parse(forgeData) catch return LoadError.InvalidPackage;

    var computedHash: [32]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(pkg.bytecode);
    hasher.final(&computedHash);
    if (!std.mem.eql(u8, &computedHash, &pkg.header.code_hash)) {
        return LoadError.InvalidPackage;
    }

    const isElf = pkg.bytecode.len >= 4 and pkg.bytecode[0] == 0x7F and pkg.bytecode[1] == 'E' and pkg.bytecode[2] == 'L' and pkg.bytecode[3] == 'F';
    if (!isElf) return LoadError.InvalidElf;

    return executeWithMemory(allocator, memory, pkg.bytecode, calldata, gasLimit, env);
}

/// Execute a contract from a ZephBin v1 package (compiler output).
/// Selects the first action by default (selector = 0 = constructor, else action[0]).
/// Pass `calldata[0..4]` as the 4-byte selector to dispatch a specific action.
pub fn executeFromZephBin(
    allocator: std.mem.Allocator,
    binData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    var memory = try sandbox.SandboxMemory.init(allocator);
    defer memory.deinit();
    return executeFromZephBinWithMemory(allocator, &memory, binData, calldata, gasLimit, env);
}

fn aotSyscallHandler(vm_opaque: ?*anyopaque, syscall_id: u32) callconv(.c) i32 {
    _ = syscall_id;
    const vm: *executor.ForgeVM = @ptrCast(@alignCast(vm_opaque orelse return 5));
    if (vm.syscallHandler) |handler| {
        handler(vm) catch |err| {
            return switch (err) {
                error.ReturnData => @as(i32, 1),
                error.Revert => @as(i32, 2),
                error.SelfDestruct => @as(i32, 3),
                error.OutOfGas => @as(i32, 4),
                else => @as(i32, 5),
            };
        };
        return 0; // success
    }
    return 5; // fault
}

const AotLibEntry = struct {
    hash: [32]u8,
    lib: std.DynLib,
};

const AotFuncEntry = struct {
    hash: [32]u8,
    selector: u32,
    func: *const fn (*const aot.AotContext) callconv(.c) void,
};

var aot_cache_rwlock: std.Thread.RwLock = .{};
var aot_cache_entries: std.ArrayListUnmanaged(AotLibEntry) = .empty;
var aot_func_entries: std.ArrayListUnmanaged(AotFuncEntry) = .empty;

var no_aot_cached: bool = false;
var no_aot_initialized: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn isNoAotEnabled(allocator: std.mem.Allocator) bool {
    if (no_aot_initialized.load(.acquire)) {
        return no_aot_cached;
    }
    
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();
    
    if (no_aot_initialized.load(.unordered)) {
        return no_aot_cached;
    }
    
    var is_no_aot = false;
    if (std.process.getEnvVarOwned(allocator, "FORGE_NO_AOT")) |env_val| {
        defer allocator.free(env_val);
        if (std.mem.eql(u8, env_val, "1")) {
            is_no_aot = true;
        }
    } else |_| {}
    no_aot_cached = is_no_aot;
    no_aot_initialized.store(true, .release);
    return is_no_aot;
}

fn getCachedLib(hash: [32]u8) ?std.DynLib {
    aot_cache_rwlock.lockShared();
    defer aot_cache_rwlock.unlockShared();

    for (aot_cache_entries.items) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) {
            return entry.lib;
        }
    }
    return null;
}

fn putCachedLib(allocator: std.mem.Allocator, hash: [32]u8, lib: std.DynLib) !void {
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();

    for (aot_cache_entries.items) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) {
            return;
        }
    }

    try aot_cache_entries.append(allocator, .{ .hash = hash, .lib = lib });
}

fn getCachedFunc(hash: [32]u8, selector: u32) ?*const fn (*const aot.AotContext) callconv(.c) void {
    aot_cache_rwlock.lockShared();
    defer aot_cache_rwlock.unlockShared();

    for (aot_func_entries.items) |entry| {
        if (entry.selector == selector and std.mem.eql(u8, &entry.hash, &hash)) {
            return entry.func;
        }
    }
    return null;
}


fn putCachedFunc(allocator: std.mem.Allocator, hash: [32]u8, selector: u32, func: *const fn (*const aot.AotContext) callconv(.c) void) !void {
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();

    for (aot_func_entries.items) |entry| {
        if (entry.selector == selector and std.mem.eql(u8, &entry.hash, &hash)) {
            return;
        }
    }

    try aot_func_entries.append(allocator, .{ .hash = hash, .selector = selector, .func = func });
}

pub fn deinitAotCache(allocator: std.mem.Allocator) void {
    aot_cache_rwlock.lock();
    defer aot_cache_rwlock.unlock();

    for (aot_cache_entries.items) |*entry| {
        entry.lib.close();
    }
    aot_cache_entries.deinit(allocator);
    aot_func_entries.deinit(allocator);

    if (last_parsed_pkg) |*old_pkg| {
        old_pkg.deinit();
        last_parsed_pkg = null;
    }
    last_parsed_bin_ptr = null;
    last_parsed_bin_len = 0;
}

pub fn preWarmAot(allocator: std.mem.Allocator, binData: []const u8) !void {
    if (!zephbinLoader.isZephBin(binData)) return;

    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(binData, &hash, .{});

    // 1. Check/load dynamic library
    var lib: std.DynLib = undefined;
    var cached = false;

    aot_cache_rwlock.lockShared();
    for (aot_cache_entries.items) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) {
            lib = entry.lib;
            cached = true;
            break;
        }
    }
    aot_cache_rwlock.unlockShared();

    if (!cached) {
        // Compile the entire package
        const lib_path = try aot.compileAot(allocator, binData);
        defer allocator.free(lib_path);

        const abs_lib_path = try std.fs.cwd().realpathAlloc(allocator, lib_path);
        defer allocator.free(abs_lib_path);

        lib = try std.DynLib.open(abs_lib_path);
        try putCachedLib(allocator, hash, lib);
    }

    // 2. Parse the package to get the list of actions/selectors
    const pkg = try zephbinLoader.parse(allocator, binData);
    defer {
        var mutable_pkg = pkg;
        mutable_pkg.deinit();
    }

    // 3. Lookup and cache all action functions
    for (pkg.actions) |action| {
        var is_func_cached = false;
        aot_cache_rwlock.lockShared();
        for (aot_func_entries.items) |entry| {
            if (entry.selector == action.selector and std.mem.eql(u8, &entry.hash, &hash)) {
                is_func_cached = true;
                break;
            }
        }
        aot_cache_rwlock.unlockShared();

        if (!is_func_cached) {
            var sym_name_buf: [64]u8 = undefined;
            const sym_name = try std.fmt.bufPrintZ(&sym_name_buf, "action_{x:0>8}", .{action.selector});
            const action_fn = lib.lookup(*const fn (*const aot.AotContext) callconv(.c) void, sym_name) orelse continue;
            try putCachedFunc(allocator, hash, action.selector, action_fn);
        }
    }
}


threadlocal var last_action_fn: ?*const fn (*const aot.AotContext) callconv(.c) void = null;
threadlocal var last_action_selector: u32 = 0;
threadlocal var last_action_bin_ptr: ?[*]const u8 = null;
threadlocal var last_action_bin_len: usize = 0;

threadlocal var last_parsed_bin_ptr: ?[*]const u8 = null;
threadlocal var last_parsed_bin_len: usize = 0;
threadlocal var last_parsed_pkg: ?zephbinLoader.ZephBinPackage = null;

fn compileAndRunAot(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    binData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
    pkg: *const zephbinLoader.ZephBinPackage,
    action: *const zephbinLoader.ZephAction,
) !ContractResult {
    var action_fn: *const fn (*const aot.AotContext) callconv(.c) void = undefined;
    if (last_action_bin_ptr == binData.ptr and last_action_bin_len == binData.len and last_action_selector == action.selector and last_action_fn != null) {
        action_fn = last_action_fn.?;
    } else {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(binData, &hash, .{});

        if (getCachedFunc(hash, action.selector)) |f| {
            action_fn = f;
        } else {
            debugPrint("[AOT Cache Miss] hash[0]={d}, selector={x}\n", .{ hash[0], action.selector });
            var lib: std.DynLib = undefined;
            if (getCachedLib(hash)) |cached_lib| {
                debugPrint("[AOT Cache Lib Hit]\n", .{});
                lib = cached_lib;
            } else {
                debugPrint("[AOT Cache Lib Miss] Compiling...\n", .{});
                const lib_path = try aot.compileAot(allocator, binData);
                defer allocator.free(lib_path);

                const abs_lib_path = try std.fs.cwd().realpathAlloc(allocator, lib_path);
                defer allocator.free(abs_lib_path);

                lib = try std.DynLib.open(abs_lib_path);
                try putCachedLib(allocator, hash, lib);
            }

            var sym_name_buf: [64]u8 = undefined;
            const sym_name = try std.fmt.bufPrintZ(&sym_name_buf, "action_{x:0>8}", .{action.selector});
            action_fn = lib.lookup(*const fn (*const aot.AotContext) callconv(.c) void, sym_name) orelse return error.SymbolNotFound;
            try putCachedFunc(allocator, hash, action.selector, action_fn);
        }

        // Cache the lookup results thread-locally
        last_action_bin_ptr = binData.ptr;
        last_action_bin_len = binData.len;
        last_action_selector = action.selector;
        last_action_fn = action_fn;
    }


    // Load data section (string literals etc.) into heap at HEAP_START
    if (pkg.dataSection.len > 0) {
        const max_ds = sandbox.heapEnd - sandbox.heapStart + 1;
        const ds_len = @min(pkg.dataSection.len, max_ds);
        @memcpy(memory.backing[sandbox.heapStart .. sandbox.heapStart + ds_len], pkg.dataSection[0..ds_len]);
    }

    // Load calldata (skip the 4-byte selector if present)
    const actualCalldata = if (calldata.len >= 4) calldata[4..] else calldata;
    if (actualCalldata.len > 0) {
        try memory.loadCalldata(actualCalldata);
    }

    const handler = syscallDispatch.createHandler(env);

    const stubOffset: u32 = @intCast(action.code.len);
    const stubEnd = stubOffset + 8;
    if (stubEnd > sandbox.codeSize) return LoadError.CodeTooLarge;

    // Load the action bytecode into the code region so that code-relative data
    // references (e.g. error message bytes at small offsets) are readable.
    memory.loadCode(action.code) catch return LoadError.CodeTooLarge;

    // Write exit stub after the action code
    const addiReturn: u32 = 0x05000513;
    const ecall: u32 = 0x00000073;
    std.mem.writeInt(u32, memory.backing[stubOffset..][0..4], addiReturn, .little);
    std.mem.writeInt(u32, memory.backing[stubOffset + 4 ..][0..4], ecall, .little);

    var vm = executor.ForgeVM.init(
        memory,
        stubEnd,
        gasLimit,
        handler,
    );
    vm.hostCtx = env;
    vm.calldataLen = @intCast(actualCalldata.len);
    vm.regs[3] = sandbox.heapStart; // GP
    vm.regs[1] = stubOffset;        // RA

    var pc: u32 = 0;
    var status_val: u32 = 0;

    const ctx = aot.AotContext{
        .regs = &vm.regs,
        .pc = &pc,
        .memory_backing = memory.backing.ptr,
        .memory_size = @intCast(memory.backing.len),
        .gas_limit = &vm.gas.limit,
        .gas_used = &vm.gas.used,
        .status = &status_val,
        .syscall_handler = aotSyscallHandler,
        .vm_ctx = &vm,
        .dirty_tracker = &memory.dirty_tracker,
    };

    // Execute the action natively
    action_fn(&ctx);

    // Sync PC and status back to VM structure (gas.used is already synced via pointer)
    vm.pc = pc;
    vm.status = std.meta.intToEnum(executor.ExecutionStatus, status_val) catch .fault;

    // Extract return data — include both returned and reverted (matches interpreter behavior)
    var returnData: []const u8 = &[_]u8{};
    if (vm.returnDataLen > 0) {
        const raw = memory.getReturnData(
            vm.returnDataOffset,
            vm.returnDataLen,
        ) catch &[_]u8{};
        if (raw.len > 0) {
            returnData = try allocator.dupe(u8, raw);
        }
    }

    return ContractResult{
        .status = vm.status,
        .gasUsed = vm.gas.used,
        .gasRemaining = vm.gas.remaining(),
        .returnData = returnData,
        .logs = env.logs.items,
        .faultPc = vm.pc,
        .faultReason = vm.faultReason,
    };
}

/// Execute a contract from a ZephBin v1 package using pre-allocated memory.
pub fn executeFromZephBinWithMemory(
    allocator: std.mem.Allocator,
    memory: *sandbox.SandboxMemory,
    binData: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    env: *syscallDispatch.HostEnv,
) !ContractResult {
    // No allocation here!
    memory.reset();

    // 1. Parse ZephBin (with thread-local caching to eliminate heap contention)
    var pkg: zephbinLoader.ZephBinPackage = undefined;
    if (last_parsed_bin_ptr == binData.ptr and last_parsed_bin_len == binData.len and last_parsed_pkg != null) {
        pkg = last_parsed_pkg.?;
    } else {
        pkg = try zephbinLoader.parse(allocator, binData);
        if (last_parsed_pkg) |*old_pkg| {
            old_pkg.deinit();
        }
        last_parsed_bin_ptr = binData.ptr;
        last_parsed_bin_len = binData.len;
        last_parsed_pkg = pkg;
    }

    // 2. Pick action: use first 4 bytes of calldata as selector if present
    const selector: u32 = if (calldata.len >= 4)
        std.mem.readInt(u32, calldata[0..4], .little)
    else
        0;
    const action = pkg.pickAction(selector) orelse return LoadError.CodeTooLarge;
    if (action.code.len == 0) return LoadError.CodeTooLarge;

    const use_aot = !isNoAotEnabled(allocator);

    if (use_aot) {
        if (compileAndRunAot(allocator, memory, binData, calldata, gasLimit, env, &pkg, action)) |aot_res| {
            return aot_res;
        } else |err| {
            debugPrint("AOT compilation/execution failed: {}, falling back to interpreter\n", .{err});
        }
    }

    // Load action bytecode into code region
    memory.loadCode(action.code) catch return LoadError.CodeTooLarge;

    // ── Exit stub ─────────────────────────────────────────────────────────
    // The Forge compiler epilogue ends with JALR zero, ra, 0  (return through ra).
    // The VM initialises ra (x1) = 0, so without a stub the function returns to
    // PC=0 and loops forever until gas is exhausted.
    //
    // Fix: write two instructions immediately after the action code and set ra
    // to that address before execution.  When the epilogue returns, it hits:
    //   ADDI a0, zero, 0x50   ; a0 = RETURN_DATA syscall ID
    //   ECALL                 ; triggers clean halt with status=returned
    //
    // The stub is 8 bytes; verify it fits in the code region.
    const actionCodeLen = action.code.len;
    const stubOffset: u32 = @intCast(actionCodeLen);
    const stubEnd: u32 = stubOffset + 8;
    if (stubEnd > sandbox.codeSize) return LoadError.CodeTooLarge;

    // ADDI a0, zero, 0x50  (opcode=0x13, rd=10, funct3=0, rs1=0, imm=0x50)
    const addiReturn: u32 = 0x05000513;
    // ECALL
    const ecall: u32 = 0x00000073;

    std.mem.writeInt(u32, memory.backing[stubOffset..][0..4], addiReturn, .little);
    std.mem.writeInt(u32, memory.backing[stubOffset + 4 ..][0..4], ecall, .little);

    // Load data section (string literals etc.) into heap at HEAP_START
    if (pkg.dataSection.len > 0) {
        const max_ds = sandbox.heapEnd - sandbox.heapStart + 1;
        const ds_len = @min(pkg.dataSection.len, max_ds);
        @memcpy(memory.backing[sandbox.heapStart .. sandbox.heapStart + ds_len], pkg.dataSection[0..ds_len]);
    }

    // Load calldata (skip the 4-byte selector if present)
    const actualCalldata = if (calldata.len >= 4) calldata[4..] else calldata;
    if (actualCalldata.len > 0) {
        memory.loadCalldata(actualCalldata) catch return LoadError.ExecutionFailed;
    }

    // 4. Set up host env
    const handler = syscallDispatch.createHandler(env);

    var vm = executor.ForgeVM.init(
        memory,
        stubEnd, // codeLen includes the exit stub
        gasLimit,
        handler,
    );
    vm.hostCtx = env;
    vm.calldataLen = @intCast(actualCalldata.len);

    // Set GP (x3) = HEAP_START so gp-relative string loads work correctly.
    // The Forge compiler emits: dest = gp + string_offset
    vm.regs[3] = sandbox.heapStart;

    // Set RA (x1) = stubOffset so the compiler epilogue's JALR zero, ra, 0
    // lands on the exit stub instead of looping back to PC=0.
    vm.regs[1] = stubOffset;

    // 5. Execute (threaded if VMPool is available)
    const result = if (env.vm_pool) |pool_ptr| blk: {
        const pool: *@import("../vm_pool.zig").VMPool = @ptrCast(@alignCast(pool_ptr));
        const code_slice = memory.backing[0..stubEnd];
        var code_hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(code_slice, &code_hash, .{});

        if (pool.getDecodedCode(code_hash)) |cached| {
            break :blk threaded_executor.executeThreaded(&vm, cached.decoded_insns, null);
        }

        const decoded = try threaded_executor.preDecodeProgram(allocator, code_slice, stubEnd);
        const insn_count: u32 = @intCast(decoded.len);

        var analysis = try basic_block.analyze(allocator, code_slice, stubEnd);
        defer analysis.deinit();
        basic_block.resolveBranchTargets(&analysis, code_slice);

        pool.cacheDecodedCode(code_hash, decoded, insn_count, stubEnd);
        break :blk threaded_executor.executeThreaded(&vm, decoded, &analysis);
    } else vm.execute();

    // 6. Extract return data
    var returnData: []const u8 = &[_]u8{};
    if (result.returnDataLen > 0) {
        const raw = memory.getReturnData(
            result.returnDataOffset,
            result.returnDataLen,
        ) catch &[_]u8{};
        if (raw.len > 0) {
            returnData = allocator.dupe(u8, raw) catch &[_]u8{};
        }
    }

    return ContractResult{
        .status = result.status,
        .gasUsed = result.gasUsed,
        .gasRemaining = result.gasRemaining,
        .returnData = returnData,
        .logs = env.logs.items,
        .faultPc = result.faultPc,
        .faultReason = result.faultReason,
    };
}

/// Validate a bytecode blob (ELF) without executing it.
/// Returns true if the bytecode passes all validation checks.
pub fn validate(elfData: []const u8) bool {
    const isElf = elfData.len >= 4 and elfData[0] == 0x7F and elfData[1] == 'E' and elfData[2] == 'L' and elfData[3] == 'F';

    var codeToScan: []const u8 = undefined;

    if (isElf) {
        // 1. Must be a valid ELF
        const elf = forgeLoader.parse(elfData) catch return false;

        // 2. Code must fit in sandbox
        if (elf.code.len > sandbox.codeSize) return false;
        codeToScan = elf.code;
    } else {
        // Raw bytecode
        if (elfData.len > sandbox.codeSize) return false;
        codeToScan = elfData;
    }

    if (codeToScan.len == 0) return false;
    // Max deployed code size = CODE_SIZE (128 KB) for FORGE contracts.
    // (EVM's 24 576 B EIP-170 limit does NOT apply to the FORGE VM.)
    if (codeToScan.len > sandbox.codeSize) return false;

    // 3. Code must be 4-byte aligned (RISC-V instructions are 32-bit)
    if (codeToScan.len & 3 != 0) return false;

    // 4. Scan for basic instruction validity
    var i: usize = 0;
    while (i < codeToScan.len) : (i += 4) {
        const word = std.mem.readInt(u32, codeToScan[i..][0..4], .little);
        const opcode: u7 = @truncate(word & 0x7F);

        // Check opcode is a known RV64IM opcode (includes 64-bit word ops)
        const decoder = @import("../core/decoder.zig");
        switch (opcode) {
            decoder.Opcode.OP, // R-type 64-bit (ADD, SUB, MUL…)
            decoder.Opcode.OP_32, // R-type 32-bit word ops (ADDW, SUBW, MULW…)
            decoder.Opcode.OP_IMM, // I-type imm 64-bit (ADDI, SLTI…)
            decoder.Opcode.OP_IMM_32, // I-type imm 32-bit word ops (ADDIW, SLLIW…)
            decoder.Opcode.LOAD,
            decoder.Opcode.STORE,
            decoder.Opcode.BRANCH,
            decoder.Opcode.JAL,
            decoder.Opcode.JALR,
            decoder.Opcode.LUI,
            decoder.Opcode.AUIPC,
            decoder.Opcode.SYSTEM,
            // Forge compiler ZEPH custom instructions
            decoder.Opcode.CUSTOM_0,
            decoder.Opcode.CUSTOM_1,
            decoder.Opcode.CUSTOM_2,
            decoder.Opcode.CUSTOM_3,
            => {},
            else => return false, // Unknown opcode
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "validate rejects empty bytecode" {
    try testing.expect(!validate(&[_]u8{}));
}

test "validate rejects misaligned code" {
    // 3 bytes — not 4-byte aligned
    const badElf = [_]u8{ 0x13, 0x00, 0x00 };
    try testing.expect(!validate(&badElf));
}

test "executeFromZeph with built package" {
    // Build a minimal .forge package containing a simple EBREAK (halt) instruction
    // First, create a minimal ELF-like structure with just an EBREAK
    // For now we test the .forge parsing path
    const ebreak: u32 = 0x00100073;
    const raw_code = std.mem.asBytes(&ebreak);

    // Build .forge package
    const pkg = try forgeFormat.build(testing.allocator, raw_code, .{});
    defer testing.allocator.free(pkg);

    // This will fail at ELF parse (raw_code isn't a valid ELF) but tests the flow
    var env = syscallDispatch.HostEnv.init(testing.allocator);
    defer env.deinit();

    const result = executeFromZeph(testing.allocator, pkg, &[_]u8{}, 100_000, &env);
    // Expect InvalidElf since raw code bytes aren't a valid ELF binary
    try testing.expectError(LoadError.InvalidElf, result);
}

fn resolveSubstrateImports(
    memory: *sandbox.SandboxMemory,
    elfData: []const u8,
    codeVaddr: u32,
) !void {
    const isElf = elfData.len >= 4 and elfData[0] == 0x7F and elfData[1] == 'E' and elfData[2] == 'L' and elfData[3] == 'F';
    if (!isElf) return;

    const is64 = elfData[4] == 2;
    if (is64) {
        try resolveImports64(memory, elfData, codeVaddr);
    } else {
        try resolveImports32(memory, elfData, codeVaddr);
    }
}

fn resolveImports64(
    memory: *sandbox.SandboxMemory,
    elfData: []const u8,
    codeVaddr: u32,
) !void {
    const elf = std.elf;
    if (elfData.len < @sizeOf(elf.Elf64_Ehdr)) return;
    const hdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, elfData[0..@sizeOf(elf.Elf64_Ehdr)]);
    const shnum = hdr.e_shnum;
    const shoff = hdr.e_shoff;
    const shentsize = hdr.e_shentsize;

    var opt_symtab_sh: ?*align(1) const elf.Elf64_Shdr = null;
    var opt_strtab_sh: ?*align(1) const elf.Elf64_Shdr = null;
    
    var rela_offset: u64 = 0;
    var rela_size: u64 = 0;
    var rela_entsize: u64 = 0;

    var rel_offset: u64 = 0;
    var rel_size: u64 = 0;
    var rel_entsize: u64 = 0;

    var i: u16 = 0;
    while (i < shnum) : (i += 1) {
        const offset = shoff + @as(u64, i) * shentsize;
        if (offset + @sizeOf(elf.Elf64_Shdr) > elfData.len) break;
        const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elfData[offset..][0..@sizeOf(elf.Elf64_Shdr)]);

        if (sh.sh_type == elf.SHT_DYNSYM or sh.sh_type == elf.SHT_SYMTAB) {
            opt_symtab_sh = sh;
        } else if (sh.sh_type == elf.SHT_STRTAB) {
            // Usually there are multiple string tables (like .shstrtab, .strtab, .dynstr).
            // We want the one containing seal_ symbols. We'll check link references or try them.
            // If sh_name suggests .strtab or .dynstr, we pick it.
            // Let's get name if we can, or just keep the last one/dynstr.
            opt_strtab_sh = sh;
        } else if (sh.sh_type == elf.SHT_RELA) {
            rela_offset = sh.sh_offset;
            rela_size = sh.sh_size;
            rela_entsize = sh.sh_entsize;
        } else if (sh.sh_type == elf.SHT_REL) {
            rel_offset = sh.sh_offset;
            rel_size = sh.sh_size;
            rel_entsize = sh.sh_entsize;
        }
    }

    const symtab_sh = opt_symtab_sh orelse return;
    const strtab_sh = opt_strtab_sh orelse return;

    if (symtab_sh.sh_offset + symtab_sh.sh_size > elfData.len) return;
    if (strtab_sh.sh_offset + strtab_sh.sh_size > elfData.len) return;

    const syms_byte_len = symtab_sh.sh_size;
    const syms_count = syms_byte_len / @sizeOf(elf.Elf64_Sym);
    const syms_ptr = @as([*]align(1) const elf.Elf64_Sym, @ptrCast(elfData[symtab_sh.sh_offset..].ptr));
    const syms = syms_ptr[0..syms_count];
    const strtab = elfData[strtab_sh.sh_offset .. strtab_sh.sh_offset + strtab_sh.sh_size];

    var next_trampoline_addr: u32 = 0x0001_F000;

    // Process RELA relocations
    if (rela_size > 0 and rela_entsize > 0 and rela_offset + rela_size <= elfData.len) {
        const count = rela_size / rela_entsize;
        const ptr = @as([*]align(1) const elf.Elf64_Rela, @ptrCast(elfData[rela_offset..].ptr));
        const relas = ptr[0..count];
        for (relas) |rela| {
            const sym_idx = rela.r_info >> 32;
            if (sym_idx >= syms.len) continue;
            const sym = syms[sym_idx];
            const name_offset = sym.st_name;
            if (name_offset >= strtab.len) continue;

            const rest = strtab[name_offset..];
            var name_len: usize = 0;
            while (name_len < rest.len and rest[name_len] != 0) : (name_len += 1) {}
            const name = rest[0..name_len];

            if (mapNameToSyscallId(name) != null) {
                const syscall_id = mapNameToSyscallId(name).?;

                if (next_trampoline_addr + 12 > sandbox.memorySize) return;

                const word1 = (syscall_id << 20) | 0x513; // ADDI a0, zero, syscall_id
                const word2 = 0x00000073;                  // ECALL
                const word3 = 0x00008067;                  // JALR zero, ra, 0

                std.mem.writeInt(u32, memory.backing[next_trampoline_addr..][0..4], word1, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 4..][0..4], word2, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 8..][0..4], word3, .little);

                const got_offset = rela.r_offset - codeVaddr;
                if (got_offset + 8 > sandbox.memorySize) continue;

                std.mem.writeInt(u64, memory.backing[got_offset..][0..8], next_trampoline_addr, .little);
                next_trampoline_addr += 12;
            }
        }
    }

    // Process REL relocations
    if (rel_size > 0 and rel_entsize > 0 and rel_offset + rel_size <= elfData.len) {
        const count = rel_size / rel_entsize;
        const ptr = @as([*]align(1) const elf.Elf64_Rel, @ptrCast(elfData[rel_offset..].ptr));
        const rels = ptr[0..count];
        for (rels) |rel| {
            const sym_idx = rel.r_info >> 32;
            if (sym_idx >= syms.len) continue;
            const sym = syms[sym_idx];
            const name_offset = sym.st_name;
            if (name_offset >= strtab.len) continue;

            const rest = strtab[name_offset..];
            var name_len: usize = 0;
            while (name_len < rest.len and rest[name_len] != 0) : (name_len += 1) {}
            const name = rest[0..name_len];

            if (mapNameToSyscallId(name) != null) {
                const syscall_id = mapNameToSyscallId(name).?;

                if (next_trampoline_addr + 12 > sandbox.memorySize) return;

                const word1 = (syscall_id << 20) | 0x513; // ADDI a0, zero, syscall_id
                const word2 = 0x00000073;                  // ECALL
                const word3 = 0x00008067;                  // JALR zero, ra, 0

                std.mem.writeInt(u32, memory.backing[next_trampoline_addr..][0..4], word1, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 4..][0..4], word2, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 8..][0..4], word3, .little);

                const got_offset = rel.r_offset - codeVaddr;
                if (got_offset + 8 > sandbox.memorySize) continue;

                std.mem.writeInt(u64, memory.backing[got_offset..][0..8], next_trampoline_addr, .little);
                next_trampoline_addr += 12;
            }
        }
    }
}

fn resolveImports32(
    memory: *sandbox.SandboxMemory,
    elfData: []const u8,
    codeVaddr: u32,
) !void {
    const elf = std.elf;
    if (elfData.len < @sizeOf(elf.Elf32_Ehdr)) return;
    const hdr = std.mem.bytesAsValue(elf.Elf32_Ehdr, elfData[0..@sizeOf(elf.Elf32_Ehdr)]);
    const shnum = hdr.e_shnum;
    const shoff = hdr.e_shoff;
    const shentsize = hdr.e_shentsize;

    var opt_symtab_sh: ?*align(1) const elf.Elf32_Shdr = null;
    var opt_strtab_sh: ?*align(1) const elf.Elf32_Shdr = null;

    var rela_offset: u32 = 0;
    var rela_size: u32 = 0;
    var rela_entsize: u32 = 0;

    var rel_offset: u32 = 0;
    var rel_size: u32 = 0;
    var rel_entsize: u32 = 0;

    var i: u16 = 0;
    while (i < shnum) : (i += 1) {
        const offset = shoff + @as(u32, i) * shentsize;
        if (offset + @sizeOf(elf.Elf32_Shdr) > elfData.len) break;
        const sh = std.mem.bytesAsValue(elf.Elf32_Shdr, elfData[offset..][0..@sizeOf(elf.Elf32_Shdr)]);

        if (sh.sh_type == elf.SHT_DYNSYM or sh.sh_type == elf.SHT_SYMTAB) {
            opt_symtab_sh = sh;
        } else if (sh.sh_type == elf.SHT_STRTAB) {
            opt_strtab_sh = sh;
        } else if (sh.sh_type == elf.SHT_RELA) {
            rela_offset = sh.sh_offset;
            rela_size = sh.sh_size;
            rela_entsize = sh.sh_entsize;
        } else if (sh.sh_type == elf.SHT_REL) {
            rel_offset = sh.sh_offset;
            rel_size = sh.sh_size;
            rel_entsize = sh.sh_entsize;
        }
    }

    const symtab_sh = opt_symtab_sh orelse return;
    const strtab_sh = opt_strtab_sh orelse return;

    if (symtab_sh.sh_offset + symtab_sh.sh_size > elfData.len) return;
    if (strtab_sh.sh_offset + strtab_sh.sh_size > elfData.len) return;

    const syms_byte_len = symtab_sh.sh_size;
    const syms_count = syms_byte_len / @sizeOf(elf.Elf32_Sym);
    const syms_ptr = @as([*]align(1) const elf.Elf32_Sym, @ptrCast(elfData[symtab_sh.sh_offset..].ptr));
    const syms = syms_ptr[0..syms_count];
    const strtab = elfData[strtab_sh.sh_offset .. strtab_sh.sh_offset + strtab_sh.sh_size];

    var next_trampoline_addr: u32 = 0x0001_F000;

    // Process RELA relocations
    if (rela_size > 0 and rela_entsize > 0 and rela_offset + rela_size <= elfData.len) {
        const count = rela_size / rela_entsize;
        const ptr = @as([*]align(1) const elf.Elf32_Rela, @ptrCast(elfData[rela_offset..].ptr));
        const relas = ptr[0..count];
        for (relas) |rela| {
            const sym_idx = rela.r_info >> 8;
            if (sym_idx >= syms.len) continue;
            const sym = syms[sym_idx];
            const name_offset = sym.st_name;
            if (name_offset >= strtab.len) continue;

            const rest = strtab[name_offset..];
            var name_len: usize = 0;
            while (name_len < rest.len and rest[name_len] != 0) : (name_len += 1) {}
            const name = rest[0..name_len];

            if (mapNameToSyscallId(name) != null) {
                const syscall_id = mapNameToSyscallId(name).?;

                if (next_trampoline_addr + 12 > sandbox.memorySize) return;

                const word1 = (syscall_id << 20) | 0x513; // ADDI a0, zero, syscall_id
                const word2 = 0x00000073;                  // ECALL
                const word3 = 0x00008067;                  // JALR zero, ra, 0

                std.mem.writeInt(u32, memory.backing[next_trampoline_addr..][0..4], word1, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 4..][0..4], word2, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 8..][0..4], word3, .little);

                const got_offset = rela.r_offset - codeVaddr;
                if (got_offset + 4 > sandbox.memorySize) continue;

                std.mem.writeInt(u32, memory.backing[got_offset..][0..4], next_trampoline_addr, .little);
                next_trampoline_addr += 12;
            }
        }
    }

    // Process REL relocations
    if (rel_size > 0 and rel_entsize > 0 and rel_offset + rel_size <= elfData.len) {
        const count = rel_size / rel_entsize;
        const ptr = @as([*]align(1) const elf.Elf32_Rel, @ptrCast(elfData[rel_offset..].ptr));
        const rels = ptr[0..count];
        for (rels) |rel| {
            const sym_idx = rel.r_info >> 8;
            if (sym_idx >= syms.len) continue;
            const sym = syms[sym_idx];
            const name_offset = sym.st_name;
            if (name_offset >= strtab.len) continue;

            const rest = strtab[name_offset..];
            var name_len: usize = 0;
            while (name_len < rest.len and rest[name_len] != 0) : (name_len += 1) {}
            const name = rest[0..name_len];

            if (mapNameToSyscallId(name) != null) {
                const syscall_id = mapNameToSyscallId(name).?;

                if (next_trampoline_addr + 12 > sandbox.memorySize) return;

                const word1 = (syscall_id << 20) | 0x513; // ADDI a0, zero, syscall_id
                const word2 = 0x00000073;                  // ECALL
                const word3 = 0x00008067;                  // JALR zero, ra, 0

                std.mem.writeInt(u32, memory.backing[next_trampoline_addr..][0..4], word1, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 4..][0..4], word2, .little);
                std.mem.writeInt(u32, memory.backing[next_trampoline_addr + 8..][0..4], word3, .little);

                const got_offset = rel.r_offset - codeVaddr;
                if (got_offset + 4 > sandbox.memorySize) continue;

                std.mem.writeInt(u32, memory.backing[got_offset..][0..4], next_trampoline_addr, .little);
                next_trampoline_addr += 12;
            }
        }
    }
}

fn mapNameToSyscallId(name: []const u8) ?u32 {
    if (std.mem.eql(u8, name, "seal_get_storage")) return 0x101;
    if (std.mem.eql(u8, name, "seal_set_storage")) return 0x102;
    if (std.mem.eql(u8, name, "seal_clear_storage")) return 0x103;
    if (std.mem.eql(u8, name, "seal_contains_storage")) return 0x104;
    if (std.mem.eql(u8, name, "seal_transfer")) return 0x105;
    if (std.mem.eql(u8, name, "seal_call")) return 0x106;
    if (std.mem.eql(u8, name, "seal_delegate_call")) return 0x107;
    if (std.mem.eql(u8, name, "seal_caller")) return 0x108;
    if (std.mem.eql(u8, name, "seal_address")) return 0x109;
    if (std.mem.eql(u8, name, "seal_value_transferred")) return 0x10A;
    if (std.mem.eql(u8, name, "seal_gas_left")) return 0x10B;
    if (std.mem.eql(u8, name, "seal_balance")) return 0x10C;
    if (std.mem.eql(u8, name, "seal_hash_keccak_256")) return 0x10D;
    if (std.mem.eql(u8, name, "seal_hash_blake2_256")) return 0x10E;
    if (std.mem.eql(u8, name, "seal_hash_sha2_256")) return 0x10F;
    if (std.mem.eql(u8, name, "seal_hash_blake3")) return 0x110;
    if (std.mem.eql(u8, name, "seal_return")) return 0x111;
    if (std.mem.eql(u8, name, "seal_revert")) return 0x112;
    if (std.mem.eql(u8, name, "seal_instantiate")) return 0x113;
    if (std.mem.eql(u8, name, "seal_instantiate2")) return 0x114;
    if (std.mem.eql(u8, name, "seal_random")) return 0x115;
    if (std.mem.eql(u8, name, "seal_block_number")) return 0x116;
    if (std.mem.eql(u8, name, "seal_now")) return 0x117;
    if (std.mem.eql(u8, name, "seal_minimum_balance")) return 0x118;
    if (std.mem.eql(u8, name, "seal_weight_to_fee")) return 0x119;
    if (std.mem.eql(u8, name, "seal_gas_price")) return 0x11A;
    if (std.mem.eql(u8, name, "seal_terminate")) return 0x11B;

    // revive / modern PolkaVM host functions
    if (std.mem.eql(u8, name, "address")) return 0x201;
    if (std.mem.eql(u8, name, "balance")) return 0x202;
    if (std.mem.eql(u8, name, "balance_of")) return 0x203;
    if (std.mem.eql(u8, name, "base_fee")) return 0x204;
    if (std.mem.eql(u8, name, "block_author")) return 0x205;
    if (std.mem.eql(u8, name, "block_hash")) return 0x206;
    if (std.mem.eql(u8, name, "block_number")) return 0x207;
    if (std.mem.eql(u8, name, "call_data_copy")) return 0x208;
    if (std.mem.eql(u8, name, "call_data_load")) return 0x209;
    if (std.mem.eql(u8, name, "call_data_size")) return 0x20A;
    if (std.mem.eql(u8, name, "call_evm")) return 0x20B;
    if (std.mem.eql(u8, name, "caller")) return 0x20C;
    if (std.mem.eql(u8, name, "chain_id")) return 0x20D;
    if (std.mem.eql(u8, name, "code_hash")) return 0x20E;
    if (std.mem.eql(u8, name, "code_size")) return 0x20F;
    if (std.mem.eql(u8, name, "consume_all_gas")) return 0x210;
    if (std.mem.eql(u8, name, "delegate_call_evm")) return 0x211;
    if (std.mem.eql(u8, name, "deposit_event")) return 0x212;
    if (std.mem.eql(u8, name, "gas_limit")) return 0x213;
    if (std.mem.eql(u8, name, "gas_price")) return 0x214;
    if (std.mem.eql(u8, name, "get_immutable_data")) return 0x215;
    if (std.mem.eql(u8, name, "get_storage_or_zero")) return 0x216;
    if (std.mem.eql(u8, name, "hash_keccak_256")) return 0x217;
    if (std.mem.eql(u8, name, "instantiate")) return 0x218;
    if (std.mem.eql(u8, name, "now")) return 0x219;
    if (std.mem.eql(u8, name, "origin")) return 0x21A;
    if (std.mem.eql(u8, name, "ref_time_left")) return 0x21B;
    if (std.mem.eql(u8, name, "return_data_copy")) return 0x21C;
    if (std.mem.eql(u8, name, "return_data_size")) return 0x21D;
    if (std.mem.eql(u8, name, "set_immutable_data")) return 0x21F;
    if (std.mem.eql(u8, name, "set_storage_or_clear")) return 0x220;
    if (std.mem.eql(u8, name, "value_transferred")) return 0x222;

    return null;
}

