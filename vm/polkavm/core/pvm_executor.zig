// File: vm/polkavm/core/pvm_executor.zig
// PVM Executor - Zero-dependency, modern revive/substrate compatible PVM native interpreter.

const std = @import("std");
const sandbox = @import("../memory/sandbox.zig");
const syscallDispatch = @import("../syscall/dispatch.zig");
const executor = @import("executor.zig");
const pvmLoader = @import("../loader/pvm_loader.zig");

pub const enable_pvm_step_logging = false;

pub const PvmExecutor = struct {
    // ---- PVM Register File ----
    // RA(0), SP(1), T0(2), T1(3), T2(4), S0(5), S1(6), A0(7), A1(8), A2(9), A3(10), A4(11), A5(12)
    regs: [13]u64 = [_]u64{0} ** 13,
    pc: u32 = 0,
    pc_updated: bool = false,

    // ---- VM State ----
    memory: *sandbox.SandboxMemory,
    program: *const pvmLoader.PvmProgram,
    gas_remaining: u64,
    gas_used: u64 = 0,
    status: executor.ExecutionStatus = .running,
    syscall_handler: ?executor.SyscallFn = null,
    host_ctx: ?*anyopaque = null,

    // ---- Return info ----
    return_data_offset: u32 = 0,
    return_data_len: u32 = 0,
    fault_pc: u32 = 0,
    fault_reason: ?[]const u8 = null,
    calldata_len: u32 = 0,

    pub fn init(
        memory: *sandbox.SandboxMemory,
        program: *const pvmLoader.PvmProgram,
        gas_limit: u64,
        syscall_handler: ?executor.SyscallFn,
        host_ctx: ?*anyopaque,
        calldata_len: u32,
    ) PvmExecutor {
        var exec = PvmExecutor{
            .memory = memory,
            .program = program,
            .gas_remaining = gas_limit,
            .syscall_handler = syscall_handler,
            .host_ctx = host_ctx,
            .calldata_len = calldata_len,
        };
        // SP initialized to top of sandboxed stack region
        exec.regs[1] = @as(u64, sandbox.stackTop);
        // RA initialized to VM_ADDR_RETURN_TO_HOST
        exec.regs[0] = 0xffff0000;
        // A0 (regs[7]) initialized to calldata length as per PolkaVM ABI
        exec.regs[7] = calldata_len;
        return exec;
    }

    pub fn execute(self: *PvmExecutor) executor.ExecutionResult {
        while (self.status == .running) {
            self.step();
        }
        if (self.status == .fault) {
            self.fault_pc = self.pc;
            std.debug.print("DEBUG PvmExecutor fault at PC=0x{x:0>4}, reason: {s}\n", .{self.pc, self.fault_reason orelse "none"});
            std.debug.print("  Registers: RA=0x{x}, SP=0x{x}, T0=0x{x}, T1=0x{x}, T2=0x{x}, S0=0x{x}, S1=0x{x}, A0=0x{x}, A1=0x{x}, A2=0x{x}, A3=0x{x}, A4=0x{x}, A5=0x{x}\n", .{
                self.regs[0], self.regs[1], self.regs[2], self.regs[3], self.regs[4],
                self.regs[5], self.regs[6], self.regs[7], self.regs[8], self.regs[9],
                self.regs[10], self.regs[11], self.regs[12]
            });
        }
        return .{
            .status = self.status,
            .gasUsed = self.gas_used,
            .gasRemaining = self.gas_remaining,
            .returnDataOffset = self.return_data_offset,
            .returnDataLen = self.return_data_len,
            .faultPc = self.fault_pc,
            .faultReason = self.fault_reason,
        };
    }

    fn checkPvmAccess(self: *const PvmExecutor, addr: u64, size: u64, is_write: bool) !usize {
        if (size == 0) return 0;
        
        // 1. Stack region: 0x0006_0000 .. 0x0006_FFFF
        if (addr >= 0x0006_0000 and addr + size <= 0x0007_0000) {
            return @intCast(addr);
        }
        // 2. Data region (RO + RW): 0x10000 .. 0x10000 + ro_data_size + rw_data_size
        const data_limit = 0x10000 + @as(u64, self.program.ro_data_size) + @as(u64, self.program.rw_data_size);
        if (addr >= 0x10000 and addr + size <= data_limit) {
            if (is_write and addr < 0x10000 + self.program.ro_data_size) {
                return error.PermissionDenied;
            }
            return @intCast(addr);
        }
        // 3. Heap region: heapStart (0x20000) .. heapEnd (0x5FFFF)
        if (addr >= 0x0002_0000 and addr + size <= 0x0006_0000) {
            return @intCast(addr);
        }
        // 4. Return region: returnStart .. returnEnd
        if (addr >= sandbox.returnStart and addr + size <= sandbox.returnEnd + 1) {
            return @intCast(addr);
        }
        // 5. Calldata region: calldataStart .. calldataEnd
        if (addr >= sandbox.calldataStart and addr + size <= sandbox.calldataEnd + 1) {
            if (is_write) return error.PermissionDenied;
            return @intCast(addr);
        }
        // 6. Scratch region: scratchStart .. scratchEnd
        if (addr >= sandbox.scratchStart and addr + size <= sandbox.scratchEnd + 1) {
            return @intCast(addr);
        }
        return error.SegFault;
    }

    fn loadByte(self: *const PvmExecutor, addr: u64) !u8 {
        const offset = try self.checkPvmAccess(addr, 1, false);
        return self.memory.backing[offset];
    }

    fn loadHalfword(self: *const PvmExecutor, addr: u64) !u16 {
        const offset = try self.checkPvmAccess(addr, 2, false);
        return std.mem.readInt(u16, self.memory.backing[offset..][0..2], .little);
    }

    fn loadWord(self: *const PvmExecutor, addr: u64) !u32 {
        const offset = try self.checkPvmAccess(addr, 4, false);
        return std.mem.readInt(u32, self.memory.backing[offset..][0..4], .little);
    }

    fn loadDoubleword(self: *const PvmExecutor, addr: u64) !u64 {
        const offset = try self.checkPvmAccess(addr, 8, false);
        return std.mem.readInt(u64, self.memory.backing[offset..][0..8], .little);
    }

    fn storeByte(self: *PvmExecutor, addr: u64, val: u8) !void {
        const offset = try self.checkPvmAccess(addr, 1, true);
        self.memory.backing[offset] = val;
        self.memory.dirty_tracker.markDirty(@intCast(offset), 1);
    }

    fn storeHalfword(self: *PvmExecutor, addr: u64, val: u16) !void {
        const offset = try self.checkPvmAccess(addr, 2, true);
        std.mem.writeInt(u16, self.memory.backing[offset..][0..2], val, .little);
        self.memory.dirty_tracker.markDirty(@intCast(offset), 2);
    }

    fn storeWord(self: *PvmExecutor, addr: u64, val: u32) !void {
        const offset = try self.checkPvmAccess(addr, 4, true);
        std.mem.writeInt(u32, self.memory.backing[offset..][0..4], val, .little);
        self.memory.dirty_tracker.markDirty(@intCast(offset), 4);
    }

    fn storeDoubleword(self: *PvmExecutor, addr: u64, val: u64) !void {
        const offset = try self.checkPvmAccess(addr, 8, true);
        std.mem.writeInt(u64, self.memory.backing[offset..][0..8], val, .little);
        self.memory.dirty_tracker.markDirty(@intCast(offset), 8);
    }

    inline fn get32(self: *const PvmExecutor, reg: u8) u32 {
        if (reg >= 13) return 0;
        return @truncate(self.regs[reg]);
    }

    inline fn get64(self: *const PvmExecutor, reg: u8) u64 {
        if (reg >= 13) return 0;
        return self.regs[reg];
    }

    inline fn set32(self: *PvmExecutor, reg: u8, val: u32) void {
        if (reg >= 13) return;
        const signed_val = @as(i32, @bitCast(val));
        const extended_val = @as(i64, signed_val);
        self.regs[reg] = @bitCast(extended_val);
    }

    inline fn set64(self: *PvmExecutor, reg: u8, val: u64) void {
        if (reg >= 13) return;
        self.regs[reg] = val;
    }

    fn consumeGas(self: *PvmExecutor, gas: u64) !void {
        if (self.gas_remaining < gas) {
            self.gas_used += self.gas_remaining;
            self.gas_remaining = 0;
            self.status = .outOfGas;
            return error.OutOfGas;
        }
        self.gas_remaining -= gas;
        self.gas_used += gas;
    }

    fn findNextPc(self: *const PvmExecutor, current_pc: u32) u32 {
        var test_pc = current_pc + 1;
        while (test_pc < self.program.code.len) : (test_pc += 1) {
            const byte_idx = test_pc >> 3;
            const bit_idx = test_pc & 7;
            if (byte_idx >= self.program.bitmask.len) break;
            const mask = self.program.bitmask[byte_idx];
            if (((mask >> @intCast(bit_idx)) & 1) == 1) {
                return test_pc;
            }
        }
        return @intCast(self.program.code.len);
    }

    pub fn step(self: *PvmExecutor) void {
        if (self.status != .running) return;

        if (self.pc >= self.program.code.len) {
            self.status = .fault;
            self.fault_reason = "PC out of bounds";
            return;
        }

        // Compute instruction skip bytes using bitmask
        const next_pc = self.findNextPc(self.pc);
        const skip = next_pc - self.pc - 1;

        const opcode = self.program.code[self.pc];
        const args = self.program.code[self.pc + 1 .. next_pc];

        if (comptime enable_pvm_step_logging) {
            std.debug.print("PVM STEP: pc=0x{x:0>4}, opcode={}, skip={}, args={any}\n", .{ self.pc, opcode, skip, args });
        }

        self.consumeGas(5) catch return;

        self.pc_updated = false;
        self.dispatch(opcode, args, skip);

        if (self.status == .running and !self.pc_updated) {
            self.pc = next_pc;
        }
    }

    fn dispatch(self: *PvmExecutor, opcode: u8, args: []const u8, skip: u32) void {
        switch (opcode) {
            0 => { // trap
                self.status = .fault;
                self.fault_reason = "Executed trap instruction";
            },
            1 => { // fallthrough
                // does nothing, sequential execution
            },
            10 => { // ecalli (import index)
                const import_idx = readSimpleVarint(args, skip);
                if (import_idx >= self.program.imports.len) {
                    self.status = .fault;
                    self.fault_reason = "Invalid ecalli import index";
                    return;
                }
                const name = self.program.imports[import_idx];
                std.debug.print("DEBUG ecalli: index={}, name={s}\n", .{import_idx, name});
                self.handleEcall(name) catch |err| {
                    if (err == error.ReturnData) {
                        self.status = .returned;
                    } else if (err == error.Revert) {
                        self.status = .reverted;
                    } else {
                        self.status = .fault;
                        self.fault_reason = "ecalli execution failed";
                    }
                };
            },
            20 => { // load_imm64 (reg, imm64)
                const parsed = readRegImm64(args, skip);
                self.set64(parsed.reg, parsed.imm);
            },
            40 => { // jump (offset)
                const offset = readSimpleVarint(args, skip);
                self.pc = self.pc +% offset;
                self.pc_updated = true;
            },
            50 => { // jump_indirect (reg, offset)
                const parsed = readArgsRegImm(args, skip);
                const target_addr = @as(u32, @truncate(self.get64(parsed.reg) +% parsed.imm));
                const resolved = self.resolveDynamicAddress(target_addr) orelse {
                    self.status = .fault;
                    self.fault_reason = "Indirect jump target resolution failed";
                    return;
                };
                if (resolved == 0xffff0000) {
                    self.status = .returned;
                    return;
                }
                self.pc = resolved;
                self.pc_updated = true;
            },
            51 => { // load_imm (reg, imm32)
                const parsed = readArgsRegImm(args, skip);
                self.set32(parsed.reg, parsed.imm);
            },
            52 => { // load_u8 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadByte(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_u8";
                    return;
                };
                self.set64(parsed.reg, val);
            },
            53 => { // load_i8 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadByte(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_i8";
                    return;
                };
                const signed_val = @as(i8, @bitCast(val));
                self.set32(parsed.reg, @bitCast(@as(i32, signed_val)));
            },
            54 => { // load_u16 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadHalfword(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_u16";
                    return;
                };
                self.set64(parsed.reg, val);
            },
            55 => { // load_i16 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadHalfword(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_i16";
                    return;
                };
                const signed_val = @as(i16, @bitCast(val));
                self.set32(parsed.reg, @bitCast(@as(i32, signed_val)));
            },
            56 => { // load_u32 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadWord(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_u32";
                    return;
                };
                self.set64(parsed.reg, val);
            },
            57 => { // load_i32 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadWord(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_i32";
                    return;
                };
                self.set32(parsed.reg, val);
            },
            58 => { // load_u64 (reg, ptr)
                const parsed = readArgsRegImm(args, skip);
                const val = self.loadDoubleword(parsed.imm) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_u64";
                    return;
                };
                self.set64(parsed.reg, val);
            },
            59 => { // store_u8 (src, offset)
                const parsed = readArgsRegImm(args, skip);
                self.storeByte(parsed.imm, @truncate(self.get64(parsed.reg))) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_u8";
                };
            },
            60 => { // store_u16 (src, offset)
                const parsed = readArgsRegImm(args, skip);
                self.storeHalfword(parsed.imm, @truncate(self.get64(parsed.reg))) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_u16";
                };
            },
            61 => { // store_u32 (src, offset)
                const parsed = readArgsRegImm(args, skip);
                self.storeWord(parsed.imm, @truncate(self.get64(parsed.reg))) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_u32";
                };
            },
            62 => { // store_u64 (src, offset)
                const parsed = readArgsRegImm(args, skip);
                self.storeDoubleword(parsed.imm, self.get64(parsed.reg)) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_u64";
                };
            },
            70 => { // store_imm_indirect_u8 (base, offset, value)
                const parsed = readArgsRegImm2(args, skip);
                const addr = self.get64(parsed.reg) +% parsed.imm1;
                self.storeByte(addr, @truncate(parsed.imm2)) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_imm_indirect_u8";
                };
            },
            71 => { // store_imm_indirect_u16 (base, offset, value)
                const parsed = readArgsRegImm2(args, skip);
                const addr = self.get64(parsed.reg) +% parsed.imm1;
                self.storeHalfword(addr, @truncate(parsed.imm2)) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_imm_indirect_u16";
                };
            },
            72 => { // store_imm_indirect_u32 (base, offset, value)
                const parsed = readArgsRegImm2(args, skip);
                const addr = self.get64(parsed.reg) +% parsed.imm1;
                self.storeWord(addr, parsed.imm2) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_imm_indirect_u32";
                };
            },
            73 => { // store_imm_indirect_u64 (base, offset, value)
                const parsed = readArgsRegImm2(args, skip);
                const addr = self.get64(parsed.reg) +% parsed.imm1;
                self.storeDoubleword(addr, parsed.imm2) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_imm_indirect_u64";
                };
            },
            80 => { // load_imm_and_jump (ra, value, target)
                const parsed = readArgsRegImm2(args, skip);
                self.set32(parsed.reg, parsed.imm1);
                self.pc = self.pc +% parsed.imm2;
                self.pc_updated = true;
            },
            81 => { // branch_eq_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (self.get64(parsed.reg) == parsed.imm1) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            82 => { // branch_not_eq_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (self.get64(parsed.reg) != parsed.imm1) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            83 => { // branch_less_unsigned_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (self.get64(parsed.reg) < parsed.imm1) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            84 => { // branch_less_or_equal_unsigned_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (self.get64(parsed.reg) <= parsed.imm1) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            85 => { // branch_greater_or_equal_unsigned_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (self.get64(parsed.reg) >= parsed.imm1) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            86 => { // branch_greater_unsigned_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (self.get64(parsed.reg) > parsed.imm1) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            87 => { // branch_less_signed_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (@as(i64, @bitCast(self.get64(parsed.reg))) < @as(i32, @bitCast(parsed.imm1))) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            88 => { // branch_less_or_equal_signed_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (@as(i64, @bitCast(self.get64(parsed.reg))) <= @as(i32, @bitCast(parsed.imm1))) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            89 => { // branch_greater_or_equal_signed_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (@as(i64, @bitCast(self.get64(parsed.reg))) >= @as(i32, @bitCast(parsed.imm1))) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            90 => { // branch_greater_signed_imm (reg, value, target)
                const parsed = readArgsRegImm2(args, skip);
                if (@as(i64, @bitCast(self.get64(parsed.reg))) > @as(i32, @bitCast(parsed.imm1))) {
                    self.pc = self.pc +% parsed.imm2;
                    self.pc_updated = true;
                }
            },
            100 => { // move_reg (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                self.set64(reg1, self.get64(reg2));
            },
            103 => { // count_set_bits_32 (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                self.set32(reg1, @popCount(self.get32(reg2)));
            },
            105 => { // count_leading_zero_bits_32 (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                self.set32(reg1, @clz(self.get32(reg2)));
            },
            107 => { // count_trailing_zero_bits_32 (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                self.set32(reg1, @ctz(self.get32(reg2)));
            },
            108 => { // sign_extend_8 (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const val = @as(i8, @bitCast(@as(u8, @truncate(self.get64(reg2)))));
                self.set32(reg1, @bitCast(@as(i32, val)));
            },
            109 => { // sign_extend_16 (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const val = @as(i16, @bitCast(@as(u16, @truncate(self.get64(reg2)))));
                self.set32(reg1, @bitCast(@as(i32, val)));
            },
            110 => { // zero_extend_16 (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                self.set64(reg1, @as(u16, @truncate(self.get64(reg2))));
            },
            111 => { // reverse_byte (d, s)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                self.set32(reg1, @byteSwap(self.get32(reg2)));
            },
            120 => { // store_indirect_u8 (src, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                self.storeByte(addr, @truncate(self.get64(reg1))) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_indirect_u8";
                };
            },
            121 => { // store_indirect_u16 (src, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                self.storeHalfword(addr, @truncate(self.get64(reg1))) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_indirect_u16";
                };
            },
            122 => { // store_indirect_u32 (src, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                self.storeWord(addr, @truncate(self.get64(reg1))) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_indirect_u32";
                };
            },
            123 => { // store_indirect_u64 (src, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                self.storeDoubleword(addr, self.get64(reg1)) catch |err| {
                    std.debug.print("DEBUG store_indirect_u64 fault: reg1={}, reg2={}, offset={}, addr=0x{x}, err={}\n", .{reg1, reg2, offset, addr, err});
                    self.status = .fault;
                    self.fault_reason = "Segfault on store_indirect_u64";
                };
            },
            124 => { // load_indirect_u8 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadByte(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_u8";
                    return;
                };
                self.set64(reg1, val);
            },
            125 => { // load_indirect_i8 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadByte(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_i8";
                    return;
                };
                const signed_val = @as(i8, @bitCast(val));
                self.set32(reg1, @bitCast(@as(i32, signed_val)));
            },
            126 => { // load_indirect_u16 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadHalfword(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_u16";
                    return;
                };
                self.set64(reg1, val);
            },
            127 => { // load_indirect_i16 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadHalfword(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_i16";
                    return;
                };
                const signed_val = @as(i16, @bitCast(val));
                self.set32(reg1, @bitCast(@as(i32, signed_val)));
            },
            128 => { // load_indirect_u32 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadWord(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_u32";
                    return;
                };
                self.set64(reg1, val);
            },
            129 => { // load_indirect_i32 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadWord(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_i32";
                    return;
                };
                self.set32(reg1, val);
            },
            130 => { // load_indirect_u64 (dst, base, offset)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                const addr = self.get64(reg2) +% offset;
                const val = self.loadDoubleword(addr) catch {
                    self.status = .fault;
                    self.fault_reason = "Segfault on load_indirect_u64";
                    return;
                };
                self.set64(reg1, val);
            },
            131 => { // add_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, self.get32(reg2) +% imm);
            },
            132 => { // and_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, self.get64(reg2) & imm);
            },
            133 => { // xor_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, self.get64(reg2) ^ imm);
            },
            134 => { // or_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, self.get64(reg2) | imm);
            },
            135 => { // mul_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, self.get32(reg2) *% imm);
            },
            136 => { // shift_logical_left_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, self.get32(reg2) << @truncate(imm & 31));
            },
            137 => { // shift_logical_right_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, self.get32(reg2) >> @truncate(imm & 31));
            },
            138 => { // shift_arithmetic_right_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, @bitCast(@as(i32, @bitCast(self.get32(reg2))) >> @truncate(imm & 31)));
            },
            139 => { // set_less_than_unsigned_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, if (self.get64(reg2) < imm) 1 else 0);
            },
            140 => { // set_less_than_signed_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, if (@as(i64, @bitCast(self.get64(reg2))) < @as(i32, @bitCast(imm))) 1 else 0);
            },
            141 => { // negate_and_add_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, imm -% self.get32(reg2));
            },
            142 => { // set_greater_than_unsigned_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, if (self.get64(reg2) > imm) 1 else 0);
            },
            143 => { // set_greater_than_signed_imm (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, if (@as(i64, @bitCast(self.get64(reg2))) > @as(i32, @bitCast(imm))) 1 else 0);
            },
            144 => { // shift_logical_left_imm_alt_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, imm << @truncate(self.get32(reg2) & 31));
            },
            145 => { // shift_logical_right_imm_alt_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, imm >> @truncate(self.get32(reg2) & 31));
            },
            146 => { // shift_arithmetic_right_imm_alt_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, @bitCast(@as(i32, @bitCast(imm)) >> @truncate(self.get32(reg2) & 31)));
            },
            147 => { // cmov_if_zero_imm (dst, ctrl, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                if (self.get64(reg2) == 0) {
                    self.set32(reg1, imm);
                }
            },
            148 => { // cmov_if_not_zero_imm (dst, ctrl, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                if (self.get64(reg2) != 0) {
                    self.set32(reg1, imm);
                }
            },
            149 => { // add_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                const extended_imm = @as(i64, @as(i32, @bitCast(imm)));
                self.set64(reg1, self.get64(reg2) +% @as(u64, @bitCast(extended_imm)));
            },
            150 => { // mul_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                const extended_imm = @as(i64, @as(i32, @bitCast(imm)));
                self.set64(reg1, self.get64(reg2) *% @as(u64, @bitCast(extended_imm)));
            },
            151 => { // shift_logical_left_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, self.get64(reg2) << @truncate(imm & 63));
            },
            152 => { // shift_logical_right_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, self.get64(reg2) >> @truncate(imm & 63));
            },
            153 => { // shift_arithmetic_right_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, @bitCast(@as(i64, @bitCast(self.get64(reg2))) >> @truncate(imm & 63)));
            },
            154 => { // negate_and_add_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                const extended_imm = @as(i64, @as(i32, @bitCast(imm)));
                self.set64(reg1, @bitCast(extended_imm -% @as(i64, @bitCast(self.get64(reg2)))));
            },
            155 => { // shift_logical_left_imm_alt_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, @as(u64, imm) << @truncate(self.get64(reg2) & 63));
            },
            156 => { // shift_logical_right_imm_alt_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, @as(u64, imm) >> @truncate(self.get64(reg2) & 63));
            },
            157 => { // shift_arithmetic_right_imm_alt_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, @bitCast(@as(i64, @bitCast(@as(u64, imm))) >> @truncate(self.get64(reg2) & 63)));
            },
            158 => { // rotate_right_imm_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, std.math.rotr(u64, self.get64(reg2), @as(u6, @truncate(imm & 63))));
            },
            159 => { // rotate_right_imm_alt_64 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set64(reg1, std.math.rotr(u64, imm, @as(u6, @truncate(self.get64(reg2) & 63))));
            },
            160 => { // rotate_right_imm_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, std.math.rotr(u32, self.get32(reg2), @as(u5, @truncate(imm & 31))));
            },
            161 => { // rotate_right_imm_alt_32 (dst, src, imm)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const imm = readSimpleVarint(args[1..], skip - 1);
                self.set32(reg1, std.math.rotr(u32, imm, @as(u5, @truncate(self.get32(reg2) & 31))));
            },
            170 => { // branch_eq (reg1, reg2, target)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                if (self.get64(reg1) == self.get64(reg2)) {
                    self.pc = self.pc +% offset;
                    self.pc_updated = true;
                }
            },
            171 => { // branch_not_eq (reg1, reg2, target)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                if (self.get64(reg1) != self.get64(reg2)) {
                    self.pc = self.pc +% offset;
                    self.pc_updated = true;
                }
            },
            172 => { // branch_less_unsigned (reg1, reg2, target)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                if (self.get64(reg1) < self.get64(reg2)) {
                    self.pc = self.pc +% offset;
                    self.pc_updated = true;
                }
            },
            173 => { // branch_less_signed (reg1, reg2, target)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                if (@as(i64, @bitCast(self.get64(reg1))) < @as(i64, @bitCast(self.get64(reg2)))) {
                    self.pc = self.pc +% offset;
                    self.pc_updated = true;
                }
            },
            174 => { // branch_greater_or_equal_unsigned (reg1, reg2, target)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                if (self.get64(reg1) >= self.get64(reg2)) {
                    self.pc = self.pc +% offset;
                    self.pc_updated = true;
                }
            },
            175 => { // branch_greater_or_equal_signed (reg1, reg2, target)
                const reg1 = args[0] & 0x0F;
                const reg2 = (args[0] >> 4) & 0x0F;
                const offset = readSimpleVarint(args[1..], skip - 1);
                if (@as(i64, @bitCast(self.get64(reg1))) >= @as(i64, @bitCast(self.get64(reg2)))) {
                    self.pc = self.pc +% offset;
                    self.pc_updated = true;
                }
            },
            180 => { // load_imm_and_jump_indirect (ra, base, value, offset)
                const parsed = readArgsRegs2Imm2(args, skip);
                self.set32(parsed.reg1, parsed.imm1);
                const target_addr = @as(u32, @truncate(self.get64(parsed.reg2) +% parsed.imm2));
                const resolved = self.resolveDynamicAddress(target_addr) orelse {
                    self.status = .fault;
                    self.fault_reason = "Indirect jump target resolution failed";
                    return;
                };
                if (resolved == 0xffff0000) {
                    self.status = .returned;
                    return;
                }
                self.pc = resolved;
                self.pc_updated = true;
            },
            190 => { // add_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, self.get32(s1) +% self.get32(s2));
            },
            191 => { // sub_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, self.get32(s1) -% self.get32(s2));
            },
            192 => { // mul_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, self.get32(s1) *% self.get32(s2));
            },
            193 => { // div_unsigned_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = self.get32(s2);
                self.set32(d, if (divisor == 0) 0 else self.get32(s1) / divisor);
            },
            194 => { // div_signed_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = @as(i32, @bitCast(self.get32(s2)));
                const dividend = @as(i32, @bitCast(self.get32(s1)));
                if (divisor == 0) {
                    self.set32(d, 0);
                } else if (dividend == -2147483648 and divisor == -1) {
                    self.set32(d, @bitCast(dividend));
                } else {
                    self.set32(d, @bitCast(@divTrunc(dividend, divisor)));
                }
            },
            195 => { // rem_unsigned_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = self.get32(s2);
                self.set32(d, if (divisor == 0) 0 else self.get32(s1) % divisor);
            },
            196 => { // rem_signed_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = @as(i32, @bitCast(self.get32(s2)));
                const dividend = @as(i32, @bitCast(self.get32(s1)));
                if (divisor == 0) {
                    self.set32(d, 0);
                } else if (dividend == -2147483648 and divisor == -1) {
                    self.set32(d, 0);
                } else {
                    self.set32(d, @bitCast(@rem(dividend, divisor)));
                }
            },
            197 => { // shift_logical_left_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, self.get32(s1) << @truncate(self.get32(s2) & 31));
            },
            198 => { // shift_logical_right_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, self.get32(s1) >> @truncate(self.get32(s2) & 31));
            },
            199 => { // shift_arithmetic_right_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, @bitCast(@as(i32, @bitCast(self.get32(s1))) >> @truncate(self.get32(s2) & 31)));
            },
            200 => { // add_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) +% self.get64(s2));
            },
            201 => { // sub_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) -% self.get64(s2));
            },
            202 => { // mul_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) *% self.get64(s2));
            },
            203 => { // div_unsigned_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = self.get64(s2);
                self.set64(d, if (divisor == 0) 0 else self.get64(s1) / divisor);
            },
            204 => { // div_signed_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = @as(i64, @bitCast(self.get64(s2)));
                const dividend = @as(i64, @bitCast(self.get64(s1)));
                if (divisor == 0) {
                    self.set64(d, 0);
                } else if (dividend == -9223372036854775808 and divisor == -1) {
                    self.set64(d, @bitCast(dividend));
                } else {
                    self.set64(d, @bitCast(@divTrunc(dividend, divisor)));
                }
            },
            205 => { // rem_unsigned_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = self.get64(s2);
                self.set64(d, if (divisor == 0) 0 else self.get64(s1) % divisor);
            },
            206 => { // rem_signed_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const divisor = @as(i64, @bitCast(self.get64(s2)));
                const dividend = @as(i64, @bitCast(self.get64(s1)));
                if (divisor == 0) {
                    self.set64(d, 0);
                } else if (dividend == -9223372036854775808 and divisor == -1) {
                    self.set64(d, 0);
                } else {
                    self.set64(d, @bitCast(@rem(dividend, divisor)));
                }
            },
            207 => { // shift_logical_left_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) << @truncate(self.get64(s2) & 63));
            },
            208 => { // shift_logical_right_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) >> @truncate(self.get64(s2) & 63));
            },
            209 => { // shift_arithmetic_right_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, @bitCast(@as(i64, @bitCast(self.get64(s1))) >> @truncate(self.get64(s2) & 63)));
            },
            210 => { // and (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) & self.get64(s2));
            },
            211 => { // xor (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) ^ self.get64(s2));
            },
            212 => { // or (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) | self.get64(s2));
            },
            216 => { // set_less_than_unsigned (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, if (self.get64(s1) < self.get64(s2)) 1 else 0);
            },
            217 => { // set_less_than_signed (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, if (@as(i64, @bitCast(self.get64(s1))) < @as(i64, @bitCast(self.get64(s2)))) 1 else 0);
            },
            218 => { // cmov_if_zero (d, s, c)
                const d = args[1] & 0x0F;
                const s = args[0] & 0x0F;
                const c = (args[0] >> 4) & 0x0F;
                if (self.get64(c) == 0) {
                    self.set64(d, self.get64(s));
                }
            },
            219 => { // cmov_if_not_zero (d, s, c)
                const d = args[1] & 0x0F;
                const s = args[0] & 0x0F;
                const c = (args[0] >> 4) & 0x0F;
                if (self.get64(c) != 0) {
                    self.set64(d, self.get64(s));
                }
            },
            222 => { // rotate_right_64 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, std.math.rotr(u64, self.get64(s1), @as(u6, @truncate(self.get64(s2) & 63))));
            },
            223 => { // rotate_right_32 (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set32(d, std.math.rotr(u32, self.get32(s1), @as(u5, @truncate(self.get32(s2) & 31))));
            },
            224 => { // and_inverted (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) & ~self.get64(s2));
            },
            225 => { // or_inverted (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, self.get64(s1) | ~self.get64(s2));
            },
            226 => { // xnor (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, ~(self.get64(s1) ^ self.get64(s2)));
            },
            227 => { // maximum (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const v1 = @as(i64, @bitCast(self.get64(s1)));
                const v2 = @as(i64, @bitCast(self.get64(s2)));
                self.set64(d, @bitCast(@max(v1, v2)));
            },
            228 => { // maximum_unsigned (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, @max(self.get64(s1), self.get64(s2)));
            },
            229 => { // minimum (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                const v1 = @as(i64, @bitCast(self.get64(s1)));
                const v2 = @as(i64, @bitCast(self.get64(s2)));
                self.set64(d, @bitCast(@min(v1, v2)));
            },
            230 => { // minimum_unsigned (d, s1, s2)
                const d = args[1] & 0x0F;
                const s1 = args[0] & 0x0F;
                const s2 = (args[0] >> 4) & 0x0F;
                self.set64(d, @min(self.get64(s1), self.get64(s2)));
            },
            else => {
                self.status = .fault;
                self.fault_reason = "Unrecognized PVM opcode";
            }
        }
    }

    fn handleEcall(self: *PvmExecutor, name: []const u8) !void {
        const syscall_id = mapNameToSyscallId(name) orelse {
            self.status = .fault;
            self.fault_reason = "Unrecognized syscall name";
            return error.UnknownSyscall;
        };

        if (self.syscall_handler) |handler| {
            // Create a fake RISC-V executor struct to pass registers to the syscall dispatcher.
            // PVM registers A0..A5 (regs[7..12]) map directly to RISC-V regs[11..16].
            // SyscallId maps to RISC-V regs[10].
            var riscv_vm = executor.ForgeVM{
                .regs = [_]u64{0} ** 32,
                .pc = self.pc,
                .pcUpdated = false,
                .memory = self.memory,
                .gas = executor.GasMeter.init(self.gas_remaining),
                .codeLen = @intCast(self.program.code.len),
                .calldataLen = self.calldata_len,
                .status = .running,
                .syscallHandler = self.syscall_handler,
                .returnDataOffset = self.return_data_offset,
                .returnDataLen = self.return_data_len,
                .faultReason = null,
                .callDepth = 0,
                .maxCallDepth = 1024,
                .stepCount = 0,
                .maxSteps = 10_000_000,
                .hostCtx = self.host_ctx,
            };

            // Copy PVM parameters to RISC-V registers
            riscv_vm.regs[10] = syscall_id;
            riscv_vm.regs[11] = self.get64(7);  // A0
            riscv_vm.regs[12] = self.get64(8);  // A1
            riscv_vm.regs[13] = self.get64(9);  // A2
            riscv_vm.regs[14] = self.get64(10); // A3
            riscv_vm.regs[15] = self.get64(11); // A4
            riscv_vm.regs[16] = self.get64(12); // A5

            handler(&riscv_vm) catch |err| {
                // Sync gas back
                self.gas_remaining = riscv_vm.gas.remaining();
                self.gas_used = riscv_vm.gas.limit - self.gas_remaining;
                
                // Copy return data offsets
                self.return_data_offset = riscv_vm.returnDataOffset;
                self.return_data_len = riscv_vm.returnDataLen;

                if (err == executor.SyscallError.ReturnData) {
                    return error.ReturnData;
                } else if (err == executor.SyscallError.Revert) {
                    return error.Revert;
                } else {
                    return err;
                }
            };

            // Sync gas back
            self.gas_remaining = riscv_vm.gas.remaining();
            self.gas_used = riscv_vm.gas.limit - self.gas_remaining;

            // Copy return register back to PVM register A0 (7)
            self.set64(7, riscv_vm.regs[10]);
        } else {
            return error.InternalError;
        }
    }

    fn resolveDynamicAddress(self: *const PvmExecutor, address: u32) ?u32 {
        if (address == 0xffff0000) {
            // Return to host
            return 0xffff0000;
        }
        if (address < 2 or (address & 1) != 0) return null;
        const index = (address - 2) / 2;
        const entry_size = self.program.jump_table_entry_size;
        if (entry_size == 0) return null;
        
        const start = @as(usize, index) * entry_size;
        const end = start + entry_size;
        if (end > self.program.jump_table.len) return null;
        
        const bytes = self.program.jump_table[start..end];
        switch (entry_size) {
            1 => return @as(u32, bytes[0]),
            2 => return @as(u32, std.mem.readInt(u16, bytes[0..2], .little)),
            3 => {
                const val = @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16);
                return val;
            },
            4 => return std.mem.readInt(u32, bytes[0..4], .little),
            else => return null,
        }
    }
};

// ─── Decoding Helpers ─────────────────────────────────────────────────────────

fn readSimpleVarint(bytes: []const u8, length: u32) u32 {
    if (length == 0) return 0;
    if (length == 1) {
        return @bitCast(@as(i32, @as(i8, @bitCast(bytes[0]))));
    } else if (length == 2) {
        const val = std.mem.readInt(u16, bytes[0..2], .little);
        return @bitCast(@as(i32, @as(i16, @bitCast(val))));
    } else if (length == 3) {
        const val = @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16);
        const sign_bit = (val >> 23) & 1;
        if (sign_bit == 1) {
            return val | 0xFF000000;
        } else {
            return val;
        }
    } else {
        return std.mem.readInt(u32, bytes[0..4], .little);
    }
}

const RegImm = struct {
    reg: u8,
    imm: u32,
};

fn readArgsRegImm(args: []const u8, skip: u32) RegImm {
    if (skip == 0) return .{ .reg = 0, .imm = 0 };
    const raw_reg = args[0] & 0x0F;
    const reg = if (raw_reg > 12) 12 else raw_reg;
    const imm = readSimpleVarint(args[1..], skip - 1);
    return .{ .reg = reg, .imm = imm };
}

const RegImm2 = struct {
    reg: u8,
    imm1: u32,
    imm2: u32,
};

fn readArgsRegImm2(args: []const u8, skip: u32) RegImm2 {
    if (skip == 0) return .{ .reg = 0, .imm1 = 0, .imm2 = 0 };
    const reg = args[0] & 0x0F;
    const aux = (args[0] >> 4) & 0x07;
    const imm1_length = @min(@as(u32, 4), aux);
    const imm2_length: u32 = if (skip >= imm1_length + 1)
        @min(@as(u32, 4), skip - imm1_length - 1)
    else
        0;

    const imm1 = readSimpleVarint(args[1..], imm1_length);
    const imm2 = readSimpleVarint(args[1 + imm1_length ..], imm2_length);
    return .{ .reg = reg, .imm1 = imm1, .imm2 = imm2 };
}

const Regs2Imm2 = struct {
    reg1: u8,
    reg2: u8,
    imm1: u32,
    imm2: u32,
};

fn readArgsRegs2Imm2(args: []const u8, skip: u32) Regs2Imm2 {
    if (skip == 0) return .{ .reg1 = 0, .reg2 = 0, .imm1 = 0, .imm2 = 0 };
    const reg1 = args[0] & 0x0F;
    const reg2 = (args[0] >> 4) & 0x0F;
    const aux = args[1] & 0x07;
    const imm1_length = @min(@as(u32, 4), aux);
    const imm2_length: u32 = if (skip >= imm1_length + 2)
        @min(@as(u32, 4), skip - imm1_length - 2)
    else
        0;

    const imm1 = readSimpleVarint(args[2..], imm1_length);
    const imm2 = readSimpleVarint(args[2 + imm1_length ..], imm2_length);
    return .{ .reg1 = reg1, .reg2 = reg2, .imm1 = imm1, .imm2 = imm2 };
}

const RegImm64 = struct {
    reg: u8,
    imm: u64,
};

fn readRegImm64(args: []const u8, skip: u32) RegImm64 {
    if (skip == 0) return .{ .reg = 0, .imm = 0 };
    const raw_reg = args[0] & 0x0F;
    const reg = if (raw_reg > 12) 12 else raw_reg;
    var val: u64 = 0;
    const len = skip - 1;
    var i: usize = 0;
    while (i < len and i < 8) : (i += 1) {
        val |= @as(u64, args[1 + i]) << @intCast(i * 8);
    }
    return .{ .reg = reg, .imm = val };
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
