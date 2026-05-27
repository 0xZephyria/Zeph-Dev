// File: vm/vm.zig
// ForgeVM — Top-level RISC-V RV32EM Virtual Machine API.
// This is the primary public interface for embedding ForgeVM in the Zephyria blockchain node.
//
// Usage:
//   const vm_mod = @import("vm");
//   var host = vm_mod.HostEnv.init(allocator);
//   var vm = try vm_mod.ForgeVM.create(bytecode, calldata, gas_limit, &host);
//   const result = vm.run();

const std = @import("std");
pub const decoder = @import("core/decoder.zig");
pub const executor = @import("core/executor.zig");
pub const threaded_executor = @import("core/threaded_executor.zig");
pub const basicBlock = @import("core/basic_block.zig");
pub const sandbox = @import("memory/sandbox.zig");
pub const gasMeter = @import("gas/meter.zig");
pub const gasTable = @import("gas/table.zig");
pub const syscallDispatch = @import("syscall/dispatch.zig");
pub const forgeLoader = @import("loader/forge_loader.zig");
pub const forgeFormat = @import("loader/forge_format.zig");
pub const contractLoader = @import("loader/contract_loader.zig");
pub const zephbinLoader = @import("loader/zephbin_loader.zig");
pub const vmPool = @import("vm_pool.zig");
pub const aot = @import("compiler/aot.zig");

// Re-export key types
pub const Instruction = decoder.Instruction;
pub const DecodeError = decoder.DecodeError;
pub const SandboxMemory = sandbox.SandboxMemory;
pub const MemoryError = sandbox.MemoryError;
pub const GasMeter = gasMeter.GasMeter;
pub const ExecutionStatus = executor.ExecutionStatus;
pub const ExecutionResult = executor.ExecutionResult;
pub const HostEnv = syscallDispatch.HostEnv;
pub const StorageBackend = syscallDispatch.StorageBackend;
pub const LogEntry = syscallDispatch.LogEntry;
pub const SyscallId = syscallDispatch.SyscallId;
pub const CoreVM = executor.ForgeVM;
pub const DecodedInsn = threaded_executor.DecodedInsn;
pub const ProgramAnalysis = basicBlock.ProgramAnalysis;

/// High-level VM instance that owns its memory and manages lifecycle.
pub const ForgeVM = struct {
    core: CoreVM,
    memory: SandboxMemory,
    host: *HostEnv,
    allocator: std.mem.Allocator,

    /// Create a new VM instance, load bytecode and calldata, wire up syscalls.
    pub fn create(
        allocator: std.mem.Allocator,
        bytecode: []const u8,
        calldata: []const u8,
        gas_limit: u64,
        host: *HostEnv,
    ) !ForgeVM {
        // Allocate and initialize sandboxed memory
        var memory = try SandboxMemory.init(allocator);
        errdefer memory.deinit();

        // Load code into the code region
        try memory.loadCode(bytecode);

        // Load calldata into the calldata region
        if (calldata.len > 0) {
            try memory.loadCalldata(calldata);
        }

        // Create syscall handler
        const handler = syscallDispatch.createHandler(host);

        // Initialize core VM
        const core = CoreVM.init(
            &memory,
            @intCast(bytecode.len),
            gas_limit,
            handler,
        );

        var vm_instance = ForgeVM{
            .core = core,
            .memory = memory,
            .host = host,
            .allocator = allocator,
        };
        // Wire hostCtx for thread-safe syscall dispatch (no shared static pointer)
        vm_instance.core.hostCtx = host;

        return vm_instance;
    }

    /// Execute the contract until completion.
    pub fn run(self: *ForgeVM) ExecutionResult {
        // Fix pointers invalidated when this struct was moved after create().
        self.core.memory = &self.memory;
        self.core.hostCtx = self.host;
        return self.core.execute();
    }

    /// Execute the contract using the threaded interpreter with pre-decoded
    /// instructions and per-basic-block gas accounting.
    /// This is the high-performance path — 2-3x faster than the switch-based run().
    pub fn runThreaded(self: *ForgeVM, allocator: std.mem.Allocator) !ExecutionResult {
        self.core.memory = &self.memory;
        self.core.hostCtx = self.host;

        const codeLen = self.core.codeLen;
        if (codeLen == 0) return self.core.buildResult();

        // Pre-decode all instructions
        const code = self.memory.backing[0..codeLen];
        const decoded = try threaded_executor.preDecodeProgram(allocator, code, codeLen);
        defer allocator.free(decoded);

        // Analyze basic blocks
        var analysis = try basicBlock.analyze(allocator, code, codeLen);
        defer analysis.deinit();
        basicBlock.resolveBranchTargets(&analysis, code);

        // Execute using threaded path
        return threaded_executor.executeThreaded(&self.core, decoded, &analysis);
    }

    /// Execute a single instruction (for debugging/step-through).
    pub fn step(self: *ForgeVM) void {
        self.core.memory = &self.memory;
        self.core.hostCtx = self.host;
        self.core.step();
    }

    /// Get the current execution status.
    pub fn status(self: *const ForgeVM) ExecutionStatus {
        return self.core.status;
    }

    /// Read a register value.
    pub fn getReg(self: *const ForgeVM, reg: u5) u64 {
        return self.core.getReg(reg);
    }

    /// Write a register value.
    pub fn setReg(self: *ForgeVM, reg: u5, val: u64) void {
        self.core.setReg(reg, val);
    }

    /// Get return data after successful execution.
    pub fn getReturnData(self: *const ForgeVM) ![]const u8 {
        if (self.core.returnDataLen == 0) return &[_]u8{};
        return self.memory.getReturnData(
            self.core.returnDataOffset,
            self.core.returnDataLen,
        );
    }

    /// Get gas used.
    pub fn gasUsed(self: *const ForgeVM) u64 {
        return self.core.gas.used;
    }

    /// Get remaining gas.
    pub fn gasRemaining(self: *const ForgeVM) u64 {
        return self.core.gas.remaining();
    }

    /// Get accumulated logs.
    pub fn getLogs(self: *const ForgeVM) []const LogEntry {
        return self.host.logs.items;
    }

    /// Clean up resources.
    pub fn deinit(self: *ForgeVM) void {
        self.memory.deinit();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ForgeVM: simple ADDI program" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    // ADDI x1, x0, 42 → x1 = 42, then EBREAK to stop
    const code = [_]u32{
        0x02A00093, // ADDI x1, x0, 42
        0x00100073, // EBREAK
    };

    var vm = try ForgeVM.create(
        testing.allocator,
        std.mem.sliceAsBytes(&code),
        &[_]u8{},
        100_000,
        &host,
    );
    defer vm.deinit();

    const result = vm.run();
    try testing.expectEqual(ExecutionStatus.breakpoint, result.status);
    try testing.expectEqual(@as(u32, 42), vm.getReg(1));
}

test "ForgeVM: gas tracking" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    // 3 ADDI instructions + EBREAK
    const code = [_]u32{
        0x00100093, // ADDI x1, x0, 1
        0x00108093, // ADDI x1, x1, 1
        0x00108093, // ADDI x1, x1, 1
        0x00100073, // EBREAK
    };

    var vm = try ForgeVM.create(
        testing.allocator,
        std.mem.sliceAsBytes(&code),
        &[_]u8{},
        100_000,
        &host,
    );
    defer vm.deinit();

    const result = vm.run();
    try testing.expectEqual(ExecutionStatus.breakpoint, result.status);
    try testing.expect(result.gasUsed > 0);
    try testing.expectEqual(@as(u32, 3), vm.getReg(1));
}

test "PolkaVM: Address Translation" {
    // 20-byte guest address (e.g. EVM address)
    const guest_addr = [_]u8{0xaa} ** 20;
    
    // Translate to 32-byte host address
    const host_addr = syscallDispatch.translateAddrToHost(&guest_addr);
    
    for (host_addr[0..12]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
    try testing.expectEqualSlices(u8, &guest_addr, host_addr[12..32]);

    // Translate back to guest
    var out_guest: [20]u8 = undefined;
    syscallDispatch.translateAddrToGuest(host_addr, &out_guest);
    try testing.expectEqualSlices(u8, &guest_addr, &out_guest);

    // If host address is a native 32-byte address (not EVM)
    var native_host = [_]u8{0xff} ** 32;
    var out_guest2: [20]u8 = undefined;
    syscallDispatch.translateAddrToGuest(native_host, &out_guest2);
    try testing.expectEqualSlices(u8, native_host[12..32], &out_guest2);
}

test "PolkaVM: Blake2b256 Hashing via Syscall" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const input_data = "Hello PolkaVM!";
    const input_offset: u32 = 0x0002_0000;
    @memcpy(mem.backing[input_offset..input_offset + input_data.len], input_data);

    const output_offset = input_offset + 100;
    
    const handler = syscallDispatch.createHandler(&host);
    
    var vm = executor.ForgeVM.init(&mem, 0, 100_000, handler);
    vm.hostCtx = &host;
    vm.regs[10] = 0x10E; // seal_hash_blake2_256
    vm.regs[11] = input_offset;
    vm.regs[12] = input_data.len;
    vm.regs[13] = output_offset;

    try handler(&vm);

    var expected_hash: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2b256.hash(input_data, &expected_hash, .{});

    const actual_hash = mem.backing[output_offset .. output_offset + 32];
    try testing.expectEqualSlices(u8, &expected_hash, actual_hash);
}

test "PolkaVM: seal_caller Syscall" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const caller_addr = [_]u8{0x55} ** 32;
    host.caller = caller_addr;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const out_ptr: u32 = 0x0002_0000;
    const out_len_ptr: u32 = 0x0002_0100;

    std.mem.writeInt(u32, mem.backing[out_len_ptr..][0..4], 32, .little);

    const handler = syscallDispatch.createHandler(&host);

    var vm = executor.ForgeVM.init(&mem, 0, 100_000, handler);
    vm.hostCtx = &host;
    vm.regs[10] = 0x108; // seal_caller
    vm.regs[11] = out_ptr;
    vm.regs[12] = out_len_ptr;

    try handler(&vm);

    const returned_len = std.mem.readInt(u32, mem.backing[out_len_ptr..][0..4], .little);
    try testing.expectEqual(@as(u32, 32), returned_len);

    const actual_caller = mem.backing[out_ptr..][0..32];
    try testing.expectEqualSlices(u8, &caller_addr, actual_caller);
}

test "PolkaVM: Execute revive-transfer-example ELF" {
    const elf_data = @embedFile("revive-transfer-example.elf");
    std.debug.print("\n=== ELF RELOCATIONS ===\n", .{});
    const is64 = elf_data[4] == 2;
    const elf = std.elf;
    if (is64) {
        const hdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, elf_data[0..@sizeOf(elf.Elf64_Ehdr)]);
        const shoff = hdr.e_shoff;
        const shentsize = hdr.e_shentsize;
        const shstrndx = hdr.e_shstrndx;
        
        const str_sh_off = shoff + @as(u64, shstrndx) * shentsize;
        const str_sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elf_data[str_sh_off..][0..@sizeOf(elf.Elf64_Shdr)]);
        const shstrtab = elf_data[str_sh.sh_offset .. str_sh.sh_offset + str_sh.sh_size];

        var opt_symtab: ?[]align(1) const elf.Elf64_Sym = null;
        var opt_strtab: ?[]const u8 = null;
        var opt_text: ?[]const u8 = null;
        var opt_exports: ?[]const u8 = null;
        var opt_rela_exports: ?[]align(1) const elf.Elf64_Rela = null;
        var opt_rela: ?[]align(1) const elf.Elf64_Rela = null;

        var i: u16 = 0;
        while (i < hdr.e_shnum) : (i += 1) {
            const offset = shoff + @as(u64, i) * shentsize;
            const sh = std.mem.bytesAsValue(elf.Elf64_Shdr, elf_data[offset..][0..@sizeOf(elf.Elf64_Shdr)]);
            const name_offset = sh.sh_name;
            var name_len: usize = 0;
            while (name_offset + name_len < shstrtab.len and shstrtab[name_offset + name_len] != 0) : (name_len += 1) {}
            const name = shstrtab[name_offset .. name_offset + name_len];

            if (std.mem.eql(u8, name, ".symtab")) {
                const syms_count = sh.sh_size / @sizeOf(elf.Elf64_Sym);
                const syms_ptr = @as([*]align(1) const elf.Elf64_Sym, @ptrCast(elf_data[sh.sh_offset..].ptr));
                opt_symtab = syms_ptr[0..syms_count];
            } else if (std.mem.eql(u8, name, ".strtab")) {
                opt_strtab = elf_data[sh.sh_offset .. sh.sh_offset + sh.sh_size];
            } else if (std.mem.eql(u8, name, ".text")) {
                opt_text = elf_data[sh.sh_offset .. sh.sh_offset + sh.sh_size];
            } else if (std.mem.eql(u8, name, ".polkavm_exports")) {
                opt_exports = elf_data[sh.sh_offset .. sh.sh_offset + sh.sh_size];
            } else if (std.mem.eql(u8, name, ".rela.polkavm_exports")) {
                const rela_count = sh.sh_size / @sizeOf(elf.Elf64_Rela);
                const rela_ptr = @as([*]align(1) const elf.Elf64_Rela, @ptrCast(elf_data[sh.sh_offset..].ptr));
                opt_rela_exports = rela_ptr[0..rela_count];
            } else if (std.mem.eql(u8, name, ".rela.text")) {
                if (opt_rela == null) {
                    const rela_count = sh.sh_size / @sizeOf(elf.Elf64_Rela);
                    const rela_ptr = @as([*]align(1) const elf.Elf64_Rela, @ptrCast(elf_data[sh.sh_offset..].ptr));
                    opt_rela = rela_ptr[0..rela_count];
                }
            }
        }

        if (opt_exports) |exports| {
            std.debug.print("=== EXPORTS SECTION ===\n", .{});
            for (exports, 0..) |b, idx| {
                std.debug.print("{x:0>2} ", .{b});
                if ((idx + 1) % 16 == 0) std.debug.print("\n", .{});
            }
            std.debug.print("\n", .{});
        }

        if (opt_rela_exports) |relas| {
            const syms = opt_symtab.?;
            const strtab = opt_strtab.?;
            std.debug.print("=== EXPORTS RELOCATIONS ===\n", .{});
            for (relas, 0..) |rela, idx| {
                const sym_idx = rela.r_info >> 32;
                const r_type = rela.r_info & 0xffffffff;
                var sym_name: []const u8 = "<none>";
                var sym_val: u64 = 0;
                if (sym_idx < syms.len) {
                    const sym = syms[sym_idx];
                    sym_val = sym.st_value;
                    const st_name = sym.st_name;
                    if (st_name < strtab.len) {
                        var len: usize = 0;
                        while (st_name + len < strtab.len and strtab[st_name + len] != 0) : (len += 1) {}
                        sym_name = strtab[st_name .. st_name + len];
                    }
                }
                std.debug.print("Reloc {}: offset=0x{x} type={} sym='{s}' val=0x{x} addend=0x{x}\n", .{
                    idx, rela.r_offset, r_type, sym_name, sym_val, rela.r_addend,
                });
            }
        }

        if (opt_text) |text| {
            std.debug.print("=== RVC INSTRUCTION ANALYSIS FROM 0x2b4 ===\n", .{});
            var offset: usize = 0x2b4;
            var rvc_count: usize = 0;
            var total_count: usize = 0;
            while (offset < text.len) {
                const b0 = text[offset];
                const is_rvc = (b0 & 3) != 3;
                total_count += 1;
                if (is_rvc) {
                    if (offset + 2 > text.len) break;
                    const inst = std.mem.readInt(u16, text[offset..][0..2], .little);
                    std.debug.print("RVC at offset 0x{x}: 0x{x:0>4}\n", .{offset, inst});
                    rvc_count += 1;
                    offset += 2;
                } else {
                    offset += 4;
                }
            }
            std.debug.print("Total RVC instructions: {} out of {} total instructions\n", .{rvc_count, total_count});
        }
        if (opt_rela) |relas| {
            const syms = opt_symtab.?;
            const strtab = opt_strtab.?;
            var type_counts = [_]usize{0} ** 256;
            for (relas) |rela| {
                const r_type = rela.r_info & 0xffffffff;
                if (r_type < 256) {
                    type_counts[r_type] += 1;
                }
            }
            std.debug.print("=== TEXT RELOCATIONS SUMMARY ===\n", .{});
            for (type_counts, 0..) |count, r_type| {
                if (count > 0) {
                    std.debug.print("Type {}: {} relocations\n", .{r_type, count});
                }
            }

            std.debug.print("ALL relocations:\n", .{});
            var reloc_count: usize = 0;
            for (relas) |rela| {
                const r_type = rela.r_info & 0xffffffff;
                const sym_idx = rela.r_info >> 32;
                var sym_name: []const u8 = "<none>";
                var sym_val: u64 = 0;
                if (sym_idx < syms.len) {
                    const sym = syms[sym_idx];
                    sym_val = sym.st_value;
                    const st_name = sym.st_name;
                    if (st_name < strtab.len) {
                        var len: usize = 0;
                        while (st_name + len < strtab.len and strtab[st_name + len] != 0) : (len += 1) {}
                        sym_name = strtab[st_name .. st_name + len];
                    }
                }
                std.debug.print("Reloc: offset=0x{x} type={} sym='{s}' val=0x{x} addend=0x{x}\n", .{
                    rela.r_offset, r_type, sym_name, sym_val, rela.r_addend,
                });
                reloc_count += 1;
                if (reloc_count >= 100) break;
            }
        }

        if (opt_symtab) |syms| {
            const strtab = opt_strtab.?;
            std.debug.print("=== SYMBOL TABLE ===\n", .{});
            for (syms) |sym| {
                const name_offset = sym.st_name;
                var len: usize = 0;
                while (name_offset + len < strtab.len and strtab[name_offset + len] != 0) : (len += 1) {}
                const sym_name = strtab[name_offset .. name_offset + len];
                std.debug.print("Symbol: name='{s}' shndx={} val=0x{x} info={}\n", .{
                    sym_name, sym.st_shndx, sym.st_value, sym.st_info,
                });
            }
        }
    }

    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const result = try contractLoader.executeWithMemory(
        testing.allocator,
        &mem,
        elf_data,
        &[_]u8{},
        100_000,
        &host,
    );

    std.debug.print("revive-transfer-example status: {}, faultPc: 0x{x}, faultReason: {s}\n", .{
        result.status,
        result.faultPc,
        result.faultReason orelse "none",
    });
    try testing.expect(result.status != .fault);
}

// ── Helper functions for instruction encoding in tests ──
fn encodeLui(rd: u5, imm: u20) u32 {
    return ((@as(u32, imm) & 0xFFFFF) << 12) | (@as(u32, rd) << 7) | 0x37;
}

fn encodeAddi(rd: u5, rs1: u5, imm: i12) u32 {
    const imm_u: u12 = @bitCast(imm);
    return (@as(u32, imm_u) << 20) | (@as(u32, rs1) << 15) | (0 << 12) | (@as(u32, rd) << 7) | 0x13;
}

fn encodeEcall() u32 {
    return 0x00000073;
}

fn encodeEbreak() u32 {
    return 0x00100073;
}

test "PolkaVM Contract 1: Simple Storage" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    var storage_map = std.AutoHashMap([32]u8, [32]u8).init(testing.allocator);
    defer storage_map.deinit();
    var storage_backend = StorageBackend{
        .ctx = &storage_map,
        .loadFn = struct {
            fn load(ctx: *anyopaque, key: [32]u8) [32]u8 {
                const map: *std.AutoHashMap([32]u8, [32]u8) = @ptrCast(@alignCast(ctx));
                return map.get(key) orelse [_]u8{0} ** 32;
            }
        }.load,
        .storeFn = struct {
            fn store(ctx: *anyopaque, key: [32]u8, value: [32]u8) void {
                const map: *std.AutoHashMap([32]u8, [32]u8) = @ptrCast(@alignCast(ctx));
                map.put(key, value) catch {};
            }
        }.store,
    };
    host.storage = &storage_backend;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const key_addr: u32 = 0x0002_0000;
    const val_addr: u32 = 0x0002_0020;
    const out_addr: u32 = 0x0002_0040;

    const key_data = [_]u8{0x11} ** 32;
    const val_data = [_]u8{0x99} ** 32;

    @memcpy(mem.backing[key_addr .. key_addr + 32], &key_data);
    @memcpy(mem.backing[val_addr .. val_addr + 32], &val_data);

    const code = [_]u32{
        encodeLui(12, 0x20), // x12 = 0x20000
        encodeLui(13, 0x20),
        encodeAddi(13, 13, 32),   // x13 = 0x20020
        encodeAddi(10, 0, 0x220), // a0 = 0x220 (set storage)
        encodeAddi(11, 0, 0),     // a1 = 0
        encodeEcall(),

        encodeLui(13, 0x20),
        encodeAddi(13, 13, 64),   // x13 = 0x20040
        encodeAddi(10, 0, 0x216), // a0 = 0x216 (get storage)
        encodeAddi(11, 0, 0),     // a1 = 0
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    const loaded_val = mem.backing[out_addr .. out_addr + 32];
    try testing.expectEqualSlices(u8, &val_data, loaded_val);
}

test "PolkaVM Contract 2: ERC20 Token" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    host.balanceFn = struct {
        fn balance(addr: [32]u8) [32]u8 {
            _ = addr;
            var bal = [_]u8{0} ** 32;
            bal[0] = 232;
            bal[1] = 3;
            return bal;
        }
    }.balance;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const addr_ptr: u32 = 0x0002_0000;
    const balance_out_ptr: u32 = 0x0002_0020;
    const topics_ptr: u32 = 0x0002_0040;
    const data_ptr: u32 = 0x0002_0080;

    const guest_addr = [_]u8{0xaa} ** 20;
    @memcpy(mem.backing[addr_ptr .. addr_ptr + 20], &guest_addr);

    const topic1 = [_]u8{0x01} ** 32;
    const topic2 = [_]u8{0x02} ** 32;
    @memcpy(mem.backing[topics_ptr .. topics_ptr + 32], &topic1);
    @memcpy(mem.backing[topics_ptr + 32 .. topics_ptr + 64], &topic2);

    const event_data = [_]u8{0xff} ** 8;
    @memcpy(mem.backing[data_ptr .. data_ptr + 8], &event_data);

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeLui(12, 0x20),
        encodeAddi(12, 12, 32),
        encodeAddi(10, 0, 0x203),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 64),
        encodeAddi(12, 0, 2),
        encodeLui(13, 0x20),
        encodeAddi(13, 13, 128),
        encodeAddi(14, 0, 8),
        encodeAddi(10, 0, 0x212),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    const balance_out = mem.backing[balance_out_ptr .. balance_out_ptr + 32];
    try testing.expectEqual(@as(u8, 232), balance_out[0]);
    try testing.expectEqual(@as(u8, 3), balance_out[1]);

    try testing.expectEqual(@as(usize, 1), host.logs.items.len);
    const log = host.logs.items[0];
    try testing.expectEqual(@as(usize, 2), log.topics.items.len);
    try testing.expectEqualSlices(u8, &topic1, &log.topics.items[0]);
    try testing.expectEqualSlices(u8, &topic2, &log.topics.items[1]);
    try testing.expectEqualSlices(u8, &event_data, log.data.items);
}

test "PolkaVM Contract 3: Gas Burner" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const code = [_]u32{
        encodeAddi(10, 0, 0x213),
        encodeEcall(),

        encodeAddi(10, 0, 0x21B),
        encodeEcall(),

        encodeAddi(10, 0, 0x210),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 100_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.reverted, res.status);
    try testing.expectEqual(@as(u64, 0), vm.gas.remaining());
}

test "PolkaVM Contract 4: Block Inspector" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    host.blockNumber = 123456789;
    host.timestamp = 987654321;
    const author_addr = [_]u8{0x77} ** 32;
    host.coinbase = author_addr;
    const hash_val = [_]u8{0xbc} ** 32;
    host.prevrandao = hash_val;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const block_out: u32 = 0x0002_0000;
    const now_out: u32 = 0x0002_0008;
    const author_out: u32 = 0x0002_0010;
    const hash_out: u32 = 0x0002_0028;

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeAddi(10, 0, 0x207),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 8),
        encodeAddi(10, 0, 0x219),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 16),
        encodeAddi(10, 0, 0x205),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 36),
        encodeLui(12, 0x20),
        encodeAddi(12, 12, 40),
        encodeAddi(10, 0, 0x206),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    try testing.expectEqual(host.blockNumber, std.mem.readInt(u64, mem.backing[block_out..block_out+8][0..8], .little));
    try testing.expectEqual(host.timestamp, std.mem.readInt(u64, mem.backing[now_out..now_out+8][0..8], .little));

    var expected_guest_author = [_]u8{0} ** 20;
    syscallDispatch.translateAddrToGuest(author_addr, &expected_guest_author);
    try testing.expectEqualSlices(u8, &expected_guest_author, mem.backing[author_out..author_out+20]);
    try testing.expectEqualSlices(u8, &hash_val, mem.backing[hash_out..hash_out+32]);
}

test "PolkaVM Contract 5: Caller Authentication" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const caller_addr = [_]u8{0x12} ** 32;
    const origin_addr = [_]u8{0x34} ** 32;
    host.caller = caller_addr;
    host.txOrigin = origin_addr;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const caller_out: u32 = 0x0002_0000;
    const origin_out: u32 = 0x0002_0014;

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeAddi(10, 0, 0x20C),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 20),
        encodeAddi(10, 0, 0x21A),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    var expected_guest_caller = [_]u8{0} ** 20;
    syscallDispatch.translateAddrToGuest(caller_addr, &expected_guest_caller);
    try testing.expectEqualSlices(u8, &expected_guest_caller, mem.backing[caller_out..caller_out+20]);

    var expected_guest_origin = [_]u8{0} ** 20;
    syscallDispatch.translateAddrToGuest(origin_addr, &expected_guest_origin);
    try testing.expectEqualSlices(u8, &expected_guest_origin, mem.backing[origin_out..origin_out+20]);
}

test "PolkaVM Contract 6: Value Depositor & Balance" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const val_transferred = [_]u8{0x88} ** 32;
    const self_addr = [_]u8{0xde} ** 32;
    host.callValue = val_transferred;
    host.selfAddress = self_addr;

    host.balanceFn = struct {
        fn balance(addr: [32]u8) [32]u8 {
            _ = addr;
            var bal = [_]u8{0} ** 32;
            bal[0] = 0xaa;
            bal[31] = 0xff;
            return bal;
        }
    }.balance;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const val_out: u32 = 0x0002_0000;
    const bal_out: u32 = 0x0002_0020;
    const addr_out: u32 = 0x0002_0040;

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeAddi(10, 0, 0x222),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 32),
        encodeAddi(10, 0, 0x202),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 64),
        encodeAddi(10, 0, 0x201),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    try testing.expectEqualSlices(u8, &val_transferred, mem.backing[val_out .. val_out + 32]);

    var expected_bal = [_]u8{0} ** 32;
    expected_bal[0] = 0xaa;
    expected_bal[31] = 0xff;
    try testing.expectEqualSlices(u8, &expected_bal, mem.backing[bal_out .. bal_out + 32]);

    var expected_guest_self = [_]u8{0} ** 20;
    syscallDispatch.translateAddrToGuest(self_addr, &expected_guest_self);
    try testing.expectEqualSlices(u8, &expected_guest_self, mem.backing[addr_out .. addr_out + 20]);
}

test "PolkaVM Contract 7: Immutable Store" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const data_addr: u32 = 0x0002_0000;
    const out_addr: u32 = 0x0002_0020;
    const len_addr: u32 = 0x0002_0040;

    const mock_immutable = "ImmutableOwner12";
    @memcpy(mem.backing[data_addr .. data_addr + 16], mock_immutable);
    std.mem.writeInt(u32, mem.backing[len_addr .. len_addr + 4][0..4], 32, .little);

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeAddi(12, 0, 16),
        encodeAddi(10, 0, 0x21F),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(11, 11, 32),
        encodeLui(12, 0x20),
        encodeAddi(12, 12, 64),
        encodeAddi(10, 0, 0x215),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    const written_len = std.mem.readInt(u32, mem.backing[len_addr .. len_addr + 4][0..4], .little);
    try testing.expectEqual(@as(u32, 16), written_len);
    try testing.expectEqualSlices(u8, mock_immutable, mem.backing[out_addr .. out_addr + 16]);
}

test "PolkaVM Contract 8: Keccak Hasher" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const input_addr: u32 = 0x0002_0000;
    const output_addr: u32 = 0x0002_0020;

    const input_str = "Hello Keccak256";
    @memcpy(mem.backing[input_addr .. input_addr + input_str.len], input_str);

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeAddi(12, 0, @intCast(input_str.len)),
        encodeLui(13, 0x20),
        encodeAddi(13, 13, 32),
        encodeAddi(10, 0, 0x217),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    var expected_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(input_str, &expected_hash, .{});
    try testing.expectEqualSlices(u8, &expected_hash, mem.backing[output_addr .. output_addr + 32]);
}

test "PolkaVM Contract 9: Return Data Relayer" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const mock_ret = "RelayedReturnBytes";
    host.lastReturnData = mock_ret;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const out_addr: u32 = 0x0002_0000;
    const len_addr: u32 = 0x0002_0020;

    std.mem.writeInt(u32, mem.backing[len_addr .. len_addr + 4][0..4], 32, .little);

    const code = [_]u32{
        encodeAddi(10, 0, 0x21D),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeLui(12, 0x20),
        encodeAddi(12, 12, 32),
        encodeAddi(13, 0, 0),
        encodeAddi(10, 0, 0x21C),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    const written_len = std.mem.readInt(u32, mem.backing[len_addr .. len_addr + 4][0..4], .little);
    try testing.expectEqual(@as(u32, 18), written_len);
    try testing.expectEqualSlices(u8, mock_ret, mem.backing[out_addr .. out_addr + 18]);
}

test "PolkaVM Contract 10: Code Inspector" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const target_addr = [_]u8{0x99} ** 32;
    const mock_code_hash = [_]u8{0xaa} ** 32;
    const mock_code_size: u64 = 40960;

    host.codeHashFn = struct {
        fn hash(addr: [32]u8) [32]u8 {
            _ = addr;
            return [_]u8{0xaa} ** 32;
        }
    }.hash;
    host.codeSizeFn = struct {
        fn size(addr: [32]u8) u64 {
            _ = addr;
            return 40960;
        }
    }.size;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const addr_ptr: u32 = 0x0002_0000;
    const hash_out: u32 = 0x0002_0020;

    var target_guest = [_]u8{0} ** 20;
    syscallDispatch.translateAddrToGuest(target_addr, &target_guest);
    @memcpy(mem.backing[addr_ptr .. addr_ptr + 20], &target_guest);

    const code = [_]u32{
        encodeLui(11, 0x20),
        encodeLui(12, 0x20),
        encodeAddi(12, 12, 32),
        encodeAddi(10, 0, 0x20E),
        encodeEcall(),

        encodeLui(11, 0x20),
        encodeAddi(10, 0, 0x20F),
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);

    try testing.expectEqualSlices(u8, &mock_code_hash, mem.backing[hash_out .. hash_out + 32]);

    const returned_size = vm.regs[10] | (vm.regs[11] << 32);
    try testing.expectEqual(mock_code_size, returned_size);
}

test "PolkaVM Contract 11: Cross-Call Router" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const mock_out = "PoolSwapOutput!";
    host.callFn = struct {
        fn call(callType: syscallDispatch.CallType, to: [32]u8, value: [32]u8, data: []const u8, gas: u64) syscallDispatch.CallProviderResult {
            _ = callType;
            _ = to;
            _ = value;
            _ = data;
            _ = gas;
            return .{
                .success = true,
                .returnData = "PoolSwapOutput!",
                .gasUsed = 500,
            };
        }
    }.call;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const callee_addr: u32 = 0x0002_0000;
    const value_addr: u32 = 0x0002_0020;
    const input_addr: u32 = 0x0002_0040;
    const output_addr: u32 = 0x0002_0060;
    const len_addr: u32 = 0x0002_0080;

    const guest_callee = [_]u8{0x77} ** 20;
    @memcpy(mem.backing[callee_addr .. callee_addr + 20], &guest_callee);

    const call_val = [_]u8{0x10} ** 32;
    @memcpy(mem.backing[value_addr .. value_addr + 32], &call_val);

    const call_input = "SwapArgs";
    @memcpy(mem.backing[input_addr .. input_addr + 8], call_input);

    std.mem.writeInt(u32, mem.backing[len_addr .. len_addr + 4][0..4], 32, .little);

    const code = [_]u32{
        encodeLui(12, 0x20), // x12 = callee_ptr (0x20000)
        encodeLui(13, 0x20),
        encodeAddi(13, 13, 32),   // x13 = value_ptr (0x20020)
        encodeAddi(14, 0, 2000),  // x14 = gas_low
        encodeAddi(15, 0, 0),     // x15 = gas_high
        encodeLui(16, 0x20),
        encodeAddi(16, 16, 64),   // x16 = input_ptr (0x20040)
        encodeAddi(17, 0, 8),     // x17 = input_len
        encodeLui(18, 0x20),
        encodeAddi(18, 18, 96),   // x18 = output_ptr (0x20060)
        encodeLui(19, 0x20),
        encodeAddi(19, 19, 128),  // x19 = output_len_ptr (0x20080)
        encodeAddi(11, 0, 0),     // x11 = flags
        encodeAddi(10, 0, 0x20B), // a0 = 0x20B (call_evm)
        encodeEcall(),

        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.breakpoint, res.status);
    try testing.expectEqual(@as(u64, 0), vm.regs[10]);

    const written_len = std.mem.readInt(u32, mem.backing[len_addr .. len_addr + 4][0..4], .little);
    try testing.expectEqual(@as(u32, 15), written_len);
    try testing.expectEqualSlices(u8, mock_out, mem.backing[output_addr .. output_addr + 15]);
}

test "PolkaVM Contract 12: Terminating Contract" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const State = struct {
        var called: bool = false;
    };
    State.called = false;

    host.selfDestructFn = struct {
        fn selfDestruct(ben: [32]u8) bool {
            State.called = true;
            _ = ben;
            return true;
        }
    }.selfDestruct;

    var mem = try SandboxMemory.init(testing.allocator);
    defer mem.deinit();

    const ben_addr: u32 = 0x0002_0000;
    const beneficiary_addr = [_]u8{0xdd} ** 32;
    @memcpy(mem.backing[ben_addr .. ben_addr + 32], &beneficiary_addr);

    const code = [_]u32{
        encodeLui(11, 0x20), // x11 = 0x20000
        encodeAddi(10, 0, 0x11B), // a0 = 0x11B (seal_terminate)
        encodeEcall(),
        encodeEbreak(),
    };

    try mem.loadCode(std.mem.sliceAsBytes(&code));
    const handler = syscallDispatch.createHandler(&host);
    var vm = executor.ForgeVM.init(&mem, @intCast(code.len * 4), 1_000_000, handler);
    vm.hostCtx = &host;

    const res = vm.execute();
    try testing.expectEqual(ExecutionStatus.selfDestruct, res.status);
    try testing.expect(State.called);
}

test "PolkaVM Contract: Execute resolc compiled Counter.elf" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const file = try std.fs.cwd().openFile("contracts/out/counter/Counter.elf", .{});
    defer file.close();
    const elf_data = try file.readToEndAlloc(testing.allocator, 10 * 1024);
    defer testing.allocator.free(elf_data);

    std.debug.print("DEBUG Counter.elf hex bytes: ", .{});
    var h_idx: usize = 0;
    while (h_idx < @min(elf_data.len, @as(usize, 64))) : (h_idx += 1) {
        std.debug.print("{x:0>2} ", .{elf_data[h_idx]});
    }
    std.debug.print("\n", .{});

    const result = try contractLoader.executeFromElf(
        testing.allocator,
        elf_data,
        &[_]u8{},
        1_000_000,
        &host,
    );

    std.debug.print("Counter deploy result status: {}, returnData size: {}, faultPc: 0x{x}, faultReason: {s}\n", .{ result.status, result.returnData.len, result.faultPc, result.faultReason orelse "none" });
    try testing.expect(result.status != .fault);
}

test "PolkaVM Contract: Execute resolc compiled Storage.elf" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const file = try std.fs.cwd().openFile("contracts/out/storage/Storage.elf", .{});
    defer file.close();
    const elf_data = try file.readToEndAlloc(testing.allocator, 15 * 1024);
    defer testing.allocator.free(elf_data);

    const result = try contractLoader.executeFromElf(
        testing.allocator,
        elf_data,
        &[_]u8{},
        1_000_000,
        &host,
    );

    std.debug.print("Storage deploy result status: {}, returnData size: {}, faultPc: 0x{x}, faultReason: {s}\n", .{ result.status, result.returnData.len, result.faultPc, result.faultReason orelse "none" });
    try testing.expect(result.status != .fault);
}

test "PolkaVM Contract: Execute resolc compiled Fibonacci.elf" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const file = try std.fs.cwd().openFile("contracts/out/fibonacci/Fibonacci.elf", .{});
    defer file.close();
    const elf_data = try file.readToEndAlloc(testing.allocator, 10 * 1024);
    defer testing.allocator.free(elf_data);

    const result = try contractLoader.executeFromElf(
        testing.allocator,
        elf_data,
        &[_]u8{},
        1_000_000,
        &host,
    );

    std.debug.print("Fibonacci deploy result status: {}, returnData size: {}, faultPc: 0x{x}, faultReason: {s}\n", .{ result.status, result.returnData.len, result.faultPc, result.faultReason orelse "none" });
    try testing.expect(result.status != .fault);
}

test "PolkaVM Contract: Execute resolc compiled BlockInfo.elf" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const file = try std.fs.cwd().openFile("contracts/out/blockinfo/BlockInfo.elf", .{});
    defer file.close();
    const elf_data = try file.readToEndAlloc(testing.allocator, 15 * 1024);
    defer testing.allocator.free(elf_data);

    const result = try contractLoader.executeFromElf(
        testing.allocator,
        elf_data,
        &[_]u8{},
        1_000_000,
        &host,
    );

    std.debug.print("BlockInfo deploy result status: {}, returnData size: {}, faultPc: 0x{x}, faultReason: {s}\n", .{ result.status, result.returnData.len, result.faultPc, result.faultReason orelse "none" });
    try testing.expect(result.status != .fault);
}

test "PolkaVM Contract: Execute resolc compiled SimpleToken.elf" {
    var host = HostEnv.init(testing.allocator);
    defer host.deinit();

    const file = try std.fs.cwd().openFile("contracts/out/token/SimpleToken.elf", .{});
    defer file.close();
    const elf_data = try file.readToEndAlloc(testing.allocator, 30 * 1024);
    defer testing.allocator.free(elf_data);

    const initial_supply_calldata = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232
    };

    const result = try contractLoader.executeFromElf(
        testing.allocator,
        elf_data,
        &initial_supply_calldata,
        1_000_000,
        &host,
    );

    std.debug.print("SimpleToken deploy result status: {}, returnData size: {}, faultPc: 0x{x}, faultReason: {s}\n", .{ result.status, result.returnData.len, result.faultPc, result.faultReason orelse "none" });
    try testing.expect(result.status != .fault);
}

test {
    std.testing.refAllDecls(@This());
}
