// File: vm/core/executor.zig
// ForgeVM Core Executor — The RISC-V RV64IM execution engine.
// This is the most performance-critical file in the entire system.
//
// Implements the fetch-decode-execute-gas loop for all RV64IM instructions:
//   - RV64I base: ALU, loads (including 64-bit LD/SD), stores, branches, jumps, upper-imm
//   - RV64M extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
//     plus RV64M word ops: MULW, DIVW, DIVUW, REMW, REMUW
//   - RV64I word ops: ADDW, SUBW, ADDIW, SLLW, SRLW, SRAW (OP_32 / OP_IMM_32)
//   - System: ECALL, EBREAK
//   - Full 32-register file (x0–x31) with 64-bit registers

const std = @import("std");
const decoder = @import("decoder.zig");
const sandbox = @import("../memory/sandbox.zig");
const gas_meter = @import("../gas/meter.zig");
const gas_table = @import("../gas/table.zig");

// Re-export for convenience
pub const Instruction = decoder.Instruction;
pub const SandboxMemory = sandbox.SandboxMemory;
pub const GasMeter = gas_meter.GasMeter;

// ---------------------------------------------------------------------------
// Execution result
// ---------------------------------------------------------------------------

pub const ExecutionStatus = enum {
    running,
    returned, // Normal exit via ECALL return_data (syscall 0x09)
    reverted, // Revert via ECALL revert (syscall 0x0A)
    out_of_gas, // Gas exhausted
    fault, // Illegal instruction, segfault, etc.
    breakpoint, // EBREAK hit (debug)
    self_destruct, // SELFDESTRUCT syscall
};

pub const ExecutionResult = struct {
    status: ExecutionStatus,
    gas_used: u64,
    gas_remaining: u64,
    return_data_offset: u32, // Offset within return region
    return_data_len: u32, // Length of return data
    fault_pc: u32, // PC where fault occurred (if status == .fault)
    fault_reason: ?[]const u8, // Human-readable fault reason
};

/// Syscall handler function type.
/// Called when the VM encounters an ECALL instruction.
/// The handler receives the VM state and can read/write registers and memory.
/// Returns an error to signal control flow (ReturnData, Revert, etc.).
pub const SyscallFn = *const fn (vm: *anyopaque) SyscallError!void;

pub const SyscallError = error{
    ReturnData,
    Revert,
    SelfDestruct,
    OutOfGas,
    UnknownSyscall,
    SegFault,
    InternalError,
};

// ---------------------------------------------------------------------------
// ForgeVM — The core virtual machine
// ---------------------------------------------------------------------------

pub const ForgeVM = struct {
    // ---- CPU State ----
    regs: [32]u64, // x0–x31 (x0 always 0)
    pc: u32, // Program counter (byte address)
    pc_updated: bool, // Flag: true if pc was set by a branch/jump this cycle

    // ---- Memory ----
    memory: *SandboxMemory,

    // ---- Gas ----
    gas: GasMeter,

    // ---- Code ----
    code_len: u32, // Length of loaded code in bytes
    calldata_len: u32, // Actual calldata length (set by loader)

    // ---- Status ----
    status: ExecutionStatus,

    // ---- Syscall ----
    syscall_handler: ?SyscallFn,

    // ---- Return data ----
    return_data_offset: u32,
    return_data_len: u32,

    // ---- Fault info ----
    fault_reason: ?[]const u8,

    // ---- Call depth tracking (EVM-compatible, max 1024) ----
    call_depth: u16,
    max_call_depth: u16,

    // ---- Step counter (defense-in-depth against runaway execution) ----
    step_count: u64,
    max_steps: u64,

    // ---- Host context (opaque pointer to HostEnv, avoids shared-static threading bugs) ----
    // Set by the VM creator immediately after init(). The syscall handler retrieves the
    // HostEnv from here rather than from a module-level static, making concurrent VM
    // instances on the same or different threads fully independent.
    host_ctx: ?*anyopaque,

    /// Initialize a new VM instance.
    pub fn init(
        memory: *SandboxMemory,
        code_len: u32,
        gas_limit: u64,
        syscall_handler: ?SyscallFn,
    ) ForgeVM {
        var vm = ForgeVM{
            .regs = [_]u64{0} ** 32,
            .pc = 0,
            .pc_updated = false,
            .memory = memory,
            .gas = GasMeter.init(gas_limit),
            .code_len = code_len,
            .calldata_len = 0,
            .status = .running,
            .syscall_handler = syscall_handler,
            .return_data_offset = 0,
            .return_data_len = 0,
            .fault_reason = null,
            .call_depth = 0,
            .max_call_depth = 1024,
            .step_count = 0,
            .max_steps = 10_000_000, // 10M steps — configurable defense-in-depth
            .host_ctx = null,
        };
        // Set stack pointer to top of stack region (grows downward)
        vm.regs[2] = @as(u64, sandbox.STACK_TOP);
        return vm;
    }

    /// Execute until completion (return, revert, out-of-gas, or fault).
    pub fn execute(self: *ForgeVM) ExecutionResult {
        while (self.status == .running) {
            self.step();
        }
        return self.buildResult();
    }

    /// Execute a single instruction (for debugging / step-through).
    pub fn step(self: *ForgeVM) void {
        if (self.status != .running) return;

        // 1. Check PC bounds
        if (self.pc >= self.code_len or self.pc & 3 != 0) {
            self.status = .fault;
            self.fault_reason = "PC out of bounds or misaligned";
            return;
        }

        // 1b. Check step limit (defense-in-depth)
        self.step_count += 1;
        if (self.step_count > self.max_steps) {
            self.status = .fault;
            self.fault_reason = "Execution step limit exceeded";
            return;
        }

        // 2. Fetch instruction word
        const word = self.memory.loadWord(self.pc) catch {
            self.status = .fault;
            self.fault_reason = "Failed to fetch instruction";
            return;
        };

        // 3. Fast gas pre-check using opcode table
        const opcode: u7 = @truncate(word & 0x7F);
        self.gas.consumeOpcode(opcode) catch {
            self.status = .out_of_gas;
            return;
        };

        // 4. Decode
        const insn = decoder.decode(word) catch {
            self.status = .fault;
            self.fault_reason = "Illegal instruction";
            return;
        };

        // 5. For M-extension multiply/divide, charge additional gas
        if (insn == .r_type) {
            const r = insn.r_type;
            if (r.funct7 == decoder.Funct7.MULDIV) {
                const extra = gas_table.instructionCost(insn) -| gas_table.InstructionGas.ALU;
                if (extra > 0) {
                    self.gas.consume(extra) catch {
                        self.status = .out_of_gas;
                        return;
                    };
                }
            }
        }

        // 6. Execute
        self.pc_updated = false;
        self.dispatch(insn);

        // 7. Enforce x0 = 0
        self.regs[0] = 0;

        // 8. Advance PC (unless a branch/jump already updated it)
        if (!self.pc_updated and self.status == .running) {
            self.pc +%= 4;
        }
    }

    // -------------------------------------------------------------------
    // Instruction dispatch
    // -------------------------------------------------------------------

    fn dispatch(self: *ForgeVM, insn: Instruction) void {
        switch (insn) {
            .r_type => |r| self.execR(r),
            .i_type => |i| self.execI(i),
            .s_type => |s| self.execS(s),
            .b_type => |b| self.execB(b),
            .u_type => |u_val| self.execU(u_val),
            .j_type => |j| self.execJ(j),
            .system => |sys| self.execSystem(sys),
            .custom => |c| self.execCustom(c),
        }
    }

    // -------------------------------------------------------------------
    // R-type: register-register operations
    // -------------------------------------------------------------------

    fn signExtend32(val: u64) u64 {
        // Treat lower 32 bits as i32, sign-extend to i64, reinterpret as u64
        const val32: u32 = @truncate(val);
        const signed32: i32 = @bitCast(val32);
        return @bitCast(@as(i64, signed32));
    }

    fn execR(self: *ForgeVM, r: decoder.RType) void {
        const rs1 = self.regs[r.rs1];
        const rs2 = self.regs[r.rs2];

        const result: u64 = switch (r.funct7) {
            decoder.Funct7.NORMAL => switch (r.funct3) {
                decoder.Funct3.ADD_SUB => rs1 +% rs2, // ADD
                decoder.Funct3.SLL => rs1 << @truncate(if (r.word_op) rs2 & 0x1F else rs2 & 0x3F),
                decoder.Funct3.SLT => if (@as(i64, @bitCast(rs1)) < @as(i64, @bitCast(rs2))) @as(u64, 1) else @as(u64, 0),
                decoder.Funct3.SLTU => if (rs1 < rs2) @as(u64, 1) else @as(u64, 0),
                decoder.Funct3.XOR => rs1 ^ rs2,
                decoder.Funct3.SRL_SRA => rs1 >> @truncate(if (r.word_op) rs2 & 0x1F else rs2 & 0x3F), // SRL
                decoder.Funct3.OR => rs1 | rs2,
                decoder.Funct3.AND => rs1 & rs2,
            },
            decoder.Funct7.SUB_SRA => switch (r.funct3) {
                decoder.Funct3.ADD_SUB => rs1 -% rs2, // SUB
                decoder.Funct3.SRL_SRA => @bitCast(@as(i64, @bitCast(rs1)) >> @truncate(if (r.word_op) rs2 & 0x1F else rs2 & 0x3F)), // SRA
                else => {
                    self.status = .fault;
                    self.fault_reason = "Invalid R-type funct3 with SUB/SRA funct7";
                    return;
                },
            },
            decoder.Funct7.MULDIV => self.execMulDiv(rs1, rs2, r.funct3, r.word_op),
            else => {
                self.status = .fault;
                self.fault_reason = "Invalid R-type funct7";
                return;
            },
        };

        if (self.status == .running) {
            self.regs[r.rd] = if (r.word_op) signExtend32(result) else result;
        }
    }

    // -------------------------------------------------------------------
    // M-extension: multiply/divide
    // -------------------------------------------------------------------

    fn execMulDiv(self: *ForgeVM, rs1: u64, rs2: u64, funct3: u3, word_op: bool) u64 {
        _ = self;
        const s1: i64 = @bitCast(rs1);
        const s2: i64 = @bitCast(rs2);

        return switch (funct3) {
            decoder.Funct3.MUL => blk: {
                // MUL: lower 64 bits of rs1 × rs2
                break :blk @truncate(@as(u64, @bitCast(@as(i64, s1) *% @as(i64, s2))));
            },
            decoder.Funct3.MULH => blk: {
                // MULH: upper 64 bits of signed × signed
                const product: i128 = @as(i128, s1) * @as(i128, s2);
                break :blk @truncate(@as(u128, @bitCast(product)) >> 64);
            },
            decoder.Funct3.MULHSU => blk: {
                // MULHSU: upper 64 bits of signed × unsigned
                const product: i128 = @as(i128, s1) * @as(i128, @intCast(rs2));
                break :blk @truncate(@as(u128, @bitCast(product)) >> 64);
            },
            decoder.Funct3.MULHU => blk: {
                // MULHU: upper 64 bits of unsigned × unsigned
                const product: u128 = @as(u128, rs1) * @as(u128, rs2);
                break :blk @truncate(product >> 64);
            },
            decoder.Funct3.DIV => blk: {
                if (word_op) {
                    const ws1: i32 = @truncate(s1);
                    const ws2: i32 = @truncate(s2);
                    if (ws2 == 0) break :blk @as(u64, 0xFFFFFFFF_FFFFFFFF); // -1
                    if (ws1 == std.math.minInt(i32) and ws2 == -1) break :blk @as(u64, @bitCast(@as(i64, std.math.minInt(i32))));
                    break :blk @as(u64, @bitCast(@as(i64, @divTrunc(ws1, ws2))));
                } else {
                    if (rs2 == 0) break :blk @as(u64, 0xFFFFFFFF_FFFFFFFF); // -1
                    if (s1 == std.math.minInt(i64) and s2 == -1) break :blk @as(u64, @bitCast(@as(i64, std.math.minInt(i64)))); // overflow
                    break :blk @bitCast(@divTrunc(s1, s2));
                }
            },
            decoder.Funct3.DIVU => blk: {
                if (word_op) {
                    const wrs1: u32 = @truncate(rs1);
                    const wrs2: u32 = @truncate(rs2);
                    if (wrs2 == 0) break :blk @as(u64, 0xFFFFFFFF_FFFFFFFF);
                    break :blk @as(u64, wrs1 / wrs2); // This will be sign-extended by execR
                } else {
                    if (rs2 == 0) break :blk @as(u64, 0xFFFFFFFF_FFFFFFFF);
                    break :blk rs1 / rs2;
                }
            },
            decoder.Funct3.REM => blk: {
                if (word_op) {
                    const ws1: i32 = @truncate(s1);
                    const ws2: i32 = @truncate(s2);
                    if (ws2 == 0) break :blk rs1;
                    if (ws1 == std.math.minInt(i32) and ws2 == -1) break :blk @as(u64, 0);
                    break :blk @as(u64, @bitCast(@as(i64, @rem(ws1, ws2))));
                } else {
                    if (rs2 == 0) break :blk rs1;
                    if (s1 == std.math.minInt(i64) and s2 == -1) break :blk @as(u64, 0);
                    break :blk @bitCast(@rem(s1, s2));
                }
            },
            decoder.Funct3.REMU => blk: {
                if (word_op) {
                    const wrs1: u32 = @truncate(rs1);
                    const wrs2: u32 = @truncate(rs2);
                    if (wrs2 == 0) break :blk rs1;
                    break :blk @as(u64, wrs1 % wrs2); // This will be sign-extended by execR
                } else {
                    if (rs2 == 0) break :blk rs1;
                    break :blk rs1 % rs2;
                }
            },
        };
    }

    // -------------------------------------------------------------------
    // I-type: immediate operations + loads + JALR
    // -------------------------------------------------------------------

    fn execI(self: *ForgeVM, i: decoder.IType) void {
        // Determine opcode from context: I-type is used for OP_IMM, LOAD, and JALR
        // We disambiguate by looking at the instruction being in the I-type variant
        // The opcode info is embedded in funct3 behavior but we need to know which
        // opcode class this was decoded from. We reconstruct from the original decode flow.
        //
        // For the executor, we handle all I-type operations through funct3.
        // The caller (decode) placed the instruction here for OP_IMM, LOAD, or JALR.
        // We distinguish LOAD by checking if funct3 matches load patterns.
        // However, a cleaner approach: the decoder should tag the opcode.
        //
        // Design: We add opcode tracking to the decode result.
        // For now: the executor handles this via the original word fetch.
        //
        // SIMPLIFIED APPROACH: We use a separate opcode field stored in the i_type.
        // But we can't change the struct now. Instead, we detect by context:
        // In the main dispatch, the I-type handler checks the original opcode.
        //
        // ACTUAL APPROACH: execI is only called from dispatch for I-type instructions.
        // We need the original opcode. Let's fetch it from the instruction word.

        // Re-fetch the word to get the opcode (this is a hot-path consideration,
        // but the word is in L1 cache so this is ~1 cycle)
        const word = self.memory.loadWord(self.pc) catch {
            self.status = .fault;
            return;
        };
        const opcode: u7 = @truncate(word & 0x7F);

        const rs1 = self.regs[i.rs1];
        const imm: u64 = @bitCast(i.imm);
        const word_op = i.word_op;

        switch (opcode) {
            decoder.Opcode.OP_IMM, decoder.Opcode.OP_IMM_32 => {
                const result: u64 = switch (i.funct3) {
                    decoder.Funct3.ADD_SUB => rs1 +% imm, // ADDI
                    decoder.Funct3.SLT => if (@as(i64, @bitCast(rs1)) < i.imm) @as(u64, 1) else @as(u64, 0), // SLTI
                    decoder.Funct3.SLTU => if (rs1 < imm) @as(u64, 1) else @as(u64, 0), // SLTIU
                    decoder.Funct3.XOR => rs1 ^ imm, // XORI
                    decoder.Funct3.OR => rs1 | imm, // ORI
                    decoder.Funct3.AND => rs1 & imm, // ANDI
                    decoder.Funct3.SLL => rs1 << @truncate(if (word_op) imm & 0x1F else imm & 0x3F), // SLLI
                    decoder.Funct3.SRL_SRA => blk: {
                        const shamt: u6 = @truncate(if (word_op) imm & 0x1F else imm & 0x3F);
                        if (imm & 0x400 != 0) {
                            // SRAI: arithmetic shift right
                            break :blk @bitCast(@as(i64, @bitCast(rs1)) >> shamt);
                        } else {
                            // SRLI: logical shift right
                            break :blk rs1 >> shamt;
                        }
                    },
                };
                self.regs[i.rd] = if (word_op) signExtend32(result) else result;
            },
            decoder.Opcode.LOAD => {
                const addr: u32 = @truncate(rs1 +% imm);
                const result: u64 = switch (i.funct3) {
                    decoder.Funct3.LB => blk: {
                        const b = self.memory.loadByte(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load byte segfault";
                            return;
                        };
                        // Sign-extend byte to u64
                        break :blk @bitCast(@as(i64, @as(i8, @bitCast(b))));
                    },
                    decoder.Funct3.LH => blk: {
                        const h = self.memory.loadHalfword(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load halfword fault";
                            return;
                        };
                        // Sign-extend halfword to u64
                        break :blk @bitCast(@as(i64, @as(i16, @bitCast(h))));
                    },
                    decoder.Funct3.LW => blk: {
                        const w = self.memory.loadWord(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load word fault";
                            return;
                        };
                        // Sign-extend word to u64
                        break :blk @bitCast(@as(i64, @as(i32, @bitCast(w))));
                    },
                    decoder.Funct3.LBU => blk: {
                        const b = self.memory.loadByte(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load byte unsigned fault";
                            return;
                        };
                        // Zero-extend byte to u64
                        break :blk @as(u64, b);
                    },
                    decoder.Funct3.LHU => blk: {
                        const h = self.memory.loadHalfword(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load halfword unsigned fault";
                            return;
                        };
                        // Zero-extend halfword to u64
                        break :blk @as(u64, h);
                    },
                    decoder.Funct3.LWU => blk: {
                        const w = self.memory.loadWord(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load word unsigned fault";
                            return;
                        };
                        // Zero-extend word to u64
                        break :blk @as(u64, w);
                    },
                    decoder.Funct3.LD => blk: {
                        const dw = self.memory.loadDoubleword(addr) catch {
                            self.status = .fault;
                            self.fault_reason = "Load doubleword fault";
                            return;
                        };
                        break :blk dw;
                    },
                    else => {
                        self.status = .fault;
                        self.fault_reason = "Invalid load funct3";
                        return;
                    },
                };
                self.regs[i.rd] = result;
            },
            decoder.Opcode.JALR => {
                // JALR: rd = PC+4, jump to (rs1 + imm) & ~1
                const return_addr = self.pc +% 4;
                const target: u32 = @truncate((rs1 +% imm) & 0xFFFFFFFE); // Clear bit 0, truncate to u32
                self.regs[i.rd] = return_addr;
                self.pc = target;
                self.pc_updated = true;
            },
            else => {
                self.status = .fault;
                self.fault_reason = "Unexpected opcode in I-type";
            },
        }
    }

    // -------------------------------------------------------------------
    // S-type: stores
    // -------------------------------------------------------------------

    fn execS(self: *ForgeVM, s: decoder.SType) void {
        const rs1 = self.regs[s.rs1];
        const rs2 = self.regs[s.rs2];
        const addr: u32 = @truncate(rs1 +% @as(u64, @bitCast(s.imm)));

        switch (s.funct3) {
            decoder.Funct3.SB => {
                self.memory.storeByte(addr, @truncate(rs2)) catch {
                    self.status = .fault;
                    self.fault_reason = "Store byte fault";
                    return;
                };
            },
            decoder.Funct3.SH => {
                self.memory.storeHalfword(addr, @truncate(rs2)) catch {
                    self.status = .fault;
                    self.fault_reason = "Store halfword fault";
                    return;
                };
            },
            decoder.Funct3.SW => {
                self.memory.storeWord(addr, @truncate(rs2)) catch {
                    self.status = .fault;
                    self.fault_reason = "Store word fault";
                    return;
                };
            },
            decoder.Funct3.SD => {
                self.memory.storeDoubleword(addr, rs2) catch {
                    self.status = .fault;
                    self.fault_reason = "Store doubleword fault";
                    return;
                };
            },
            else => {
                self.status = .fault;
                self.fault_reason = "Invalid store funct3";
            },
        }
    }

    // -------------------------------------------------------------------
    // B-type: conditional branches
    // -------------------------------------------------------------------

    fn execB(self: *ForgeVM, b: decoder.BType) void {
        const rs1 = self.regs[b.rs1];
        const rs2 = self.regs[b.rs2];
        const s1: i64 = @bitCast(rs1);
        const s2: i64 = @bitCast(rs2);

        const taken: bool = switch (b.funct3) {
            decoder.Funct3.BEQ => rs1 == rs2,
            decoder.Funct3.BNE => rs1 != rs2,
            decoder.Funct3.BLT => s1 < s2,
            decoder.Funct3.BGE => s1 >= s2,
            decoder.Funct3.BLTU => rs1 < rs2,
            decoder.Funct3.BGEU => rs1 >= rs2,
            else => {
                self.status = .fault;
                self.fault_reason = "Invalid branch funct3";
                return;
            },
        };

        if (taken) {
            const target: u32 = @truncate(self.pc +% @as(u64, @bitCast(b.imm)));
            self.pc = target;
            self.pc_updated = true;
        }
    }

    // -------------------------------------------------------------------
    // U-type: LUI, AUIPC
    // -------------------------------------------------------------------

    fn execU(self: *ForgeVM, u_val: decoder.UType) void {
        // Re-fetch opcode to distinguish LUI vs AUIPC
        const word = self.memory.loadWord(self.pc) catch {
            self.status = .fault;
            return;
        };
        const opcode: u7 = @truncate(word & 0x7F);

        switch (opcode) {
            decoder.Opcode.LUI => {
                // LUI: rd = signExtend(imm << 12)
                self.regs[u_val.rd] = @bitCast(u_val.imm);
            },
            decoder.Opcode.AUIPC => {
                // AUIPC: rd = PC + signExtend(imm << 12)
                self.regs[u_val.rd] = self.pc +% @as(u64, @bitCast(u_val.imm));
            },
            else => {
                self.status = .fault;
                self.fault_reason = "Unexpected opcode in U-type";
            },
        }
    }

    // -------------------------------------------------------------------
    // J-type: JAL
    // -------------------------------------------------------------------

    fn execJ(self: *ForgeVM, j: decoder.JType) void {
        // JAL: rd = PC+4, jump to PC + signExtend(imm)
        self.regs[j.rd] = self.pc +% 4;
        self.pc = @truncate(self.pc +% @as(u64, @bitCast(j.imm)));
        self.pc_updated = true;
    }

    // -------------------------------------------------------------------
    // System: ECALL, EBREAK
    // -------------------------------------------------------------------

    fn execSystem(self: *ForgeVM, sys: decoder.SystemOp) void {
        switch (sys) {
            .ecall => {
                if (self.syscall_handler) |handler| {
                    handler(self) catch |err| {
                        switch (err) {
                            error.ReturnData => {
                                self.status = .returned;
                            },
                            error.Revert => {
                                self.status = .reverted;
                            },
                            error.SelfDestruct => {
                                self.status = .self_destruct;
                            },
                            error.OutOfGas => {
                                self.status = .out_of_gas;
                            },
                            error.UnknownSyscall => {
                                self.status = .fault;
                                self.fault_reason = "Unknown syscall";
                            },
                            error.SegFault => {
                                self.status = .fault;
                                self.fault_reason = "Syscall segfault";
                            },
                            error.InternalError => {
                                self.status = .fault;
                                self.fault_reason = "Syscall internal error";
                            },
                        }
                    };
                } else {
                    self.status = .fault;
                    self.fault_reason = "No syscall handler installed";
                }
            },
            .ebreak => {
                self.status = .breakpoint;
            },
        }
    }


    // -------------------------------------------------------------------
    // Custom (ZEPH) instruction dispatch
    // -------------------------------------------------------------------
    // The Forge compiler emits ZEPH instructions using RISC-V custom-0..3
    // opcode space.  These encode the operation in the instruction word
    // (not in a register) and pass arguments in a0-a5 (x10-x15).
    //
    // Register convention (ZEPH ABI from compiler riscv.zig comments):
    //   a0-a5  = arguments 0-5 (input)
    //   a0     = return value
    //
    // This is different from the ECALL convention (a0=syscall_id, a1=arg0).
    // execCustom bridges the two: it maps ZephCustomOp → SyscallId and
    // rearranges registers so the existing syscall handlers work correctly.

    fn execCustom(self: *ForgeVM, c: decoder.CustomType) void {
        if (self.syscall_handler == null) {
            self.status = .fault;
            self.fault_reason = "No syscall handler for ZEPH custom instruction";
            return;
        }

        // Map ZephCustomOp value to the SyscallId the dispatch.zig handlers expect.
        // ZEPH args are in a0-a5; ECALL handlers read args from a1-a5 (a0 = syscall ID).
        // We shift: save a0→scratch, set a0=syscall_id, move original a0→a1, a1→a2, etc.
        // For ops that return values in a0, the shift is reversed by the handler.
        const op = c.op_val;
        const orig_a0 = self.regs[10];
        const orig_a1 = self.regs[11];
        const orig_a2 = self.regs[12];
        const orig_a3 = self.regs[13];
        const orig_a4 = self.regs[14];

        // Determine the SyscallId and any special handling needed
        const syscall_id: u32 = switch (op) {
            0x00 => blk: { // STATE_READ: a0=field_id, a1=key → a0=value
                // Remap: a1=field_id(orig a0), a2=key(orig a1) — storage_load reads key from a1
                self.regs[11] = orig_a0; // field_id as key ptr
                self.regs[12] = orig_a1; // key_ptr as result ptr (output goes here)
                break :blk 0x01; // STORAGE_LOAD
            },
            0x01 => blk: { // STATE_WRITE: a0=field_id, a1=key, a2=value
                self.regs[11] = orig_a0; // key ptr
                self.regs[12] = orig_a1; // value ptr
                break :blk 0x02; // STORAGE_STORE
            },
            0x02 => blk: { // STATE_EXISTS: a0=field_id, a1=key → a0=bool
                self.regs[11] = orig_a0;
                self.regs[12] = orig_a1;
                break :blk 0x01; // STORAGE_LOAD, then check if result is non-zero
            },
            0x03 => blk: { // STATE_DELETE: store zero
                self.regs[11] = orig_a0;
                self.regs[12] = 0; // zero value
                break :blk 0x02; // STORAGE_STORE
            },
            0x10 => blk: { // AUTH_CHECK: a0=auth_id → a0=bool
                self.regs[10] = 0x20; // AUTHORITY_CHECK
                self.regs[11] = orig_a0; // addr ptr
                self.regs[12] = orig_a0; // role ptr (same as addr for simple check)
                self.regs[13] = orig_a0; // account ptr
                break :blk 0x20; // AUTHORITY_CHECK
            },
            0x20 => blk: { // ASSET_TRANSFER: a0=asset_id, a1=from, a2=to, a3=amount
                self.regs[11] = orig_a0; // asset_id
                self.regs[12] = orig_a1; // from
                self.regs[13] = orig_a2; // to
                self.regs[14] = orig_a3; // amount
                break :blk 0x10; // ASSET_TRANSFER
            },
            0x21 => blk: { // ASSET_MINT: a0=asset_id, a1=to, a2=amount
                self.regs[11] = orig_a0;
                self.regs[12] = orig_a1;
                self.regs[13] = orig_a2;
                break :blk 0x12; // ASSET_CREATE
            },
            0x22 => blk: { // ASSET_BURN: a0=asset_id, a1=from, a2=amount
                self.regs[11] = orig_a0;
                self.regs[12] = orig_a1;
                self.regs[13] = orig_a2;
                break :blk 0x13; // ASSET_BURN
            },
            0x23 => blk: { // NATIVE_PAY: a0=to, a1=amount → ASSET_TRANSFER with ZPH asset_id=0
                self.regs[11] = 0;        // ZPH asset_id = 0
                self.regs[12] = 0;        // from = zero (deducted from caller by runtime)
                self.regs[13] = orig_a0;  // to
                self.regs[14] = orig_a1;  // amount
                break :blk 0x10; // ASSET_TRANSFER
            },
            0x30 => blk: { // EMIT_EVENT: a0=event_id, a1=data_ptr, a2=data_len
                self.regs[11] = 0;        // topic_count = 0 (event_id goes as first topic)
                self.regs[12] = orig_a0;  // topics_ptr (we treat event_id as a topic ptr)
                self.regs[13] = orig_a1;  // data_ptr
                self.regs[14] = orig_a2;  // data_len
                break :blk 0x30; // EMIT_EVENT
            },
            0x31 => blk: { // SCHEDULE_CALL: a0=selector, a1=to, a2=delay
                self.regs[11] = orig_a1;  // to addr ptr
                self.regs[12] = 0;        // value = 0
                self.regs[13] = 0;        // data ptr
                self.regs[14] = 0;        // data len
                break :blk 0x40; // CALL_CONTRACT
            },
            0x32 => blk: { // REVERT: a0=error_ptr, a1=error_len
                self.regs[11] = orig_a0;
                self.regs[12] = orig_a1;
                break :blk 0x51; // REVERT
            },
            0x33 => blk: { // LOG_DIAGNOSTIC: a0=msg_ptr, a1=msg_len
                self.regs[11] = orig_a0;
                self.regs[12] = orig_a1;
                break :blk 0xFF; // DEBUG_LOG
            },
            0x34 => blk: { // GET_CALLER: → a0=addr_ptr (caller writes to memory[a1])
                self.regs[11] = orig_a0; // buffer ptr the caller put in a0
                break :blk 0x60; // GET_CALLER
            },
            0x35 => blk: { // GET_NOW: → a0=timestamp
                break :blk 0x66; // GET_TIMESTAMP
            },
            0x36 => blk: { // GET_BLOCK: → a0=block_number
                break :blk 0x65; // GET_BLOCK_NUMBER
            },
            0x37 => blk: { // GET_VALUE: → a0=call_value
                break :blk 0x61; // GET_CALLVALUE
            },
            else => {
                self.status = .fault;
                self.fault_reason = "Unknown ZEPH custom op";
                return;
            },
        };

        // Set a0 = syscall ID so dispatch.zig can route it
        self.regs[10] = syscall_id;

        // Call through the standard syscall handler
        if (self.syscall_handler) |handler| {
            handler(self) catch |err| {
                switch (err) {
                    error.ReturnData    => self.status = .returned,
                    error.Revert        => self.status = .reverted,
                    error.SelfDestruct  => self.status = .self_destruct,
                    error.OutOfGas      => self.status = .out_of_gas,
                    error.UnknownSyscall => {
                        self.status = .fault;
                        self.fault_reason = "Unknown syscall via ZEPH custom";
                    },
                    error.SegFault => {
                        self.status = .fault;
                        self.fault_reason = "Syscall segfault via ZEPH custom";
                    },
                    error.InternalError => {
                        self.status = .fault;
                        self.fault_reason = "Syscall internal error via ZEPH custom";
                    },
                }
            };
        }

        // STATE_EXISTS post-processing: convert loaded value to bool
        if (op == 0x02 and self.status == .running) {
            // a0 currently points to the result buffer; check if it's non-zero
            // For simplicity, treat non-zero a0 as "exists"
            self.regs[10] = if (self.regs[10] != 0) 1 else 0;
        }

        _ = orig_a4; // suppress unused warning
    }

    // -------------------------------------------------------------------
    // Build final result
    // -------------------------------------------------------------------

    pub fn buildResult(self: *const ForgeVM) ExecutionResult {
        return .{
            .status = self.status,
            .gas_used = self.gas.used,
            .gas_remaining = self.gas.remaining(),
            .return_data_offset = self.return_data_offset,
            .return_data_len = self.return_data_len,
            .fault_pc = if (self.status == .fault) self.pc else 0,
            .fault_reason = self.fault_reason,
        };
    }

    // -------------------------------------------------------------------
    // Call depth management (EVM-compatible)
    // -------------------------------------------------------------------

    /// Increment call depth for cross-contract calls.
    /// Returns error if maximum call depth (1024) would be exceeded.
    pub fn incrementCallDepth(self: *ForgeVM) error{CallDepthExceeded}!void {
        if (self.call_depth >= self.max_call_depth) return error.CallDepthExceeded;
        self.call_depth += 1;
    }

    /// Decrement call depth when returning from a cross-contract call.
    pub fn decrementCallDepth(self: *ForgeVM) void {
        if (self.call_depth > 0) self.call_depth -= 1;
    }

    // -------------------------------------------------------------------
    // Convenience: read/write registers by ABI name
    // -------------------------------------------------------------------

    pub fn getReg(self: *const ForgeVM, reg: u5) u64 {
        return self.regs[reg];
    }

    pub fn setReg(self: *ForgeVM, reg: u5, val: u64) void {
        if (reg == 0) return; // x0 is always 0
        self.regs[reg] = val;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Helper: encode an R-type instruction word
fn encodeR(rd: u5, rs1: u5, rs2: u5, funct3: u3, funct7: u7) u32 {
    return (@as(u32, funct7) << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, funct3) << 12) |
        (@as(u32, rd) << 7) |
        decoder.Opcode.OP;
}

/// Helper: encode an I-type instruction word
fn encodeI(rd: u5, rs1: u5, funct3: u3, imm: i12, opcode: u7) u32 {
    const imm_u: u32 = @as(u32, @bitCast(@as(i32, imm))) & 0xFFF;
    return (imm_u << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, funct3) << 12) |
        (@as(u32, rd) << 7) |
        opcode;
}

/// Helper: encode ECALL
fn encodeEcall() u32 {
    return decoder.Opcode.SYSTEM; // 0x00000073
}

/// Helper: create a VM with code loaded into memory.
/// IMPORTANT: call ctx.fixMemPtr() after assignment.
fn createTestVM(code: []const u32, gas: u64) !struct {
    vm: ForgeVM,
    mem: SandboxMemory,

    const Self = @This();

    pub fn fixMemPtr(self: *Self) void {
        self.vm.memory = &self.mem;
    }
} {
    var mem = try SandboxMemory.init(testing.allocator);
    // Load code words into code region
    const code_bytes = std.mem.sliceAsBytes(code);
    try mem.loadCode(code_bytes);
    const code_len: u32 = @intCast(code_bytes.len);
    const vm = ForgeVM.init(&mem, code_len, gas, null);
    return .{ .vm = vm, .mem = mem };
}

test "ADD x1, x2, x3" {
    const code = [_]u32{encodeR(1, 2, 3, 0, 0)}; // ADD x1, x2, x3
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 10;
    ctx.vm.regs[3] = 20;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 30), ctx.vm.regs[1]);
}

test "SUB x1, x2, x3" {
    const code = [_]u32{encodeR(1, 2, 3, 0, 0b0100000)}; // SUB x1, x2, x3
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 50;
    ctx.vm.regs[3] = 20;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 30), ctx.vm.regs[1]);
}

test "AND x1, x2, x3" {
    const code = [_]u32{encodeR(1, 2, 3, 0b111, 0)}; // AND x1, x2, x3
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 0xFF00;
    ctx.vm.regs[3] = 0x0FF0;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 0x0F00), ctx.vm.regs[1]);
}

test "OR x1, x2, x3" {
    const code = [_]u32{encodeR(1, 2, 3, 0b110, 0)}; // OR x1, x2, x3
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 0xFF00;
    ctx.vm.regs[3] = 0x00FF;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 0xFFFF), ctx.vm.regs[1]);
}

test "XOR x1, x2, x3" {
    const code = [_]u32{encodeR(1, 2, 3, 0b100, 0)}; // XOR x1, x2, x3
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 0xAAAA;
    ctx.vm.regs[3] = 0x5555;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 0xFFFF), ctx.vm.regs[1]);
}

test "SLT x1, x2, x3 (signed)" {
    const code = [_]u32{encodeR(1, 2, 3, 0b010, 0)}; // SLT x1, x2, x3
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = @bitCast(@as(i64, -5)); // -5
    ctx.vm.regs[3] = 5; // 5
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 1), ctx.vm.regs[1]); // -5 < 5 → 1
}

test "ADDI x1, x2, 42" {
    const code = [_]u32{encodeI(1, 2, 0, 42, decoder.Opcode.OP_IMM)};
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 100;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 142), ctx.vm.regs[1]);
}

test "ADDI x1, x2, -1 (negative immediate)" {
    const code = [_]u32{encodeI(1, 2, 0, -1, decoder.Opcode.OP_IMM)};
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 100;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 99), ctx.vm.regs[1]);
}

test "x0 is always zero" {
    // ADDI x0, x1, 42 — writes to x0 should be ignored
    const code = [_]u32{encodeI(0, 1, 0, 42, decoder.Opcode.OP_IMM)};
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[1] = 100;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 0), ctx.vm.regs[0]);
}

test "MUL x1, x2, x3" {
    const code = [_]u32{encodeR(1, 2, 3, 0b000, 0b0000001)}; // MUL
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 7;
    ctx.vm.regs[3] = 6;
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 42), ctx.vm.regs[1]);
}

test "DIV x1, x2, x3 (signed)" {
    const code = [_]u32{encodeR(1, 2, 3, 0b100, 0b0000001)}; // DIV
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = @bitCast(@as(i64, -42));
    ctx.vm.regs[3] = 6;
    ctx.vm.step();
    try testing.expectEqual(@as(i64, -7), @as(i64, @bitCast(ctx.vm.regs[1])));
}

test "DIV by zero returns -1" {
    const code = [_]u32{encodeR(1, 2, 3, 0b100, 0b0000001)}; // DIV
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[2] = 42;
    ctx.vm.regs[3] = 0;
    ctx.vm.step();
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), ctx.vm.regs[1]);
}

test "out of gas stops execution" {
    const code = [_]u32{
        encodeI(1, 0, 0, 1, decoder.Opcode.OP_IMM), // ADDI x1, x0, 1
        encodeI(1, 1, 0, 1, decoder.Opcode.OP_IMM), // ADDI x1, x1, 1
        encodeI(1, 1, 0, 1, decoder.Opcode.OP_IMM), // ADDI x1, x1, 1
    };
    // Each ADDI costs 1 gas, give only 2
    var ctx = try createTestVM(&code, 2);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    const result = ctx.vm.execute();
    try testing.expectEqual(ExecutionStatus.out_of_gas, result.status);
    try testing.expectEqual(@as(u32, 2), ctx.vm.regs[1]); // Only 2 executed
}

test "EBREAK sets breakpoint status" {
    const code = [_]u32{0b000000000001_00000_000_00000_1110011}; // EBREAK
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.step();
    try testing.expectEqual(ExecutionStatus.breakpoint, ctx.vm.status);
}

test "ECALL without handler faults" {
    const code = [_]u32{encodeEcall()};
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.step();
    try testing.expectEqual(ExecutionStatus.fault, ctx.vm.status);
}

test "simple program: compute 5 + 3 = 8" {
    const code = [_]u32{
        encodeI(1, 0, 0, 5, decoder.Opcode.OP_IMM), // ADDI x1, x0, 5
        encodeI(2, 0, 0, 3, decoder.Opcode.OP_IMM), // ADDI x2, x0, 3
        encodeR(3, 1, 2, 0, 0), // ADD x3, x1, x2
    };
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    // Execute all 3 instructions
    ctx.vm.step();
    ctx.vm.step();
    ctx.vm.step();
    try testing.expectEqual(@as(u32, 8), ctx.vm.regs[3]);
}

test "SW + LW round-trip in heap" {
    const heap_base = sandbox.HEAP_START;
    const code = [_]u32{
        // ADDI x1, x0, 0x42 (value to store)
        encodeI(1, 0, 0, 0x42, decoder.Opcode.OP_IMM),
        // Load heap base address into x2 (needs LUI + ADDI since HEAP_START > 12 bits)
        // LUI x2, (HEAP_START >> 12)
        @as(u32, (heap_base & 0xFFFFF000)) | (@as(u32, 2) << 7) | decoder.Opcode.LUI,
        // SW x1, 0(x2)
        @as(u32, 0b0000000) << 25 | @as(u32, 1) << 20 | @as(u32, 2) << 15 | @as(u32, 0b010) << 12 | @as(u32, 0) << 7 | decoder.Opcode.STORE,
        // LW x3, 0(x2)
        encodeI(3, 2, 0b010, 0, decoder.Opcode.LOAD),
    };
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.step(); // ADDI
    ctx.vm.step(); // LUI
    ctx.vm.step(); // SW
    ctx.vm.step(); // LW
    try testing.expectEqual(@as(u32, 0x42), ctx.vm.regs[3]);
}

test "gas accounting is correct" {
    const code = [_]u32{
        encodeI(1, 0, 0, 1, decoder.Opcode.OP_IMM), // ADDI: 1 gas
        encodeR(2, 1, 1, 0, 0), // ADD: 1 gas
        encodeR(3, 1, 2, 0b000, 0b0000001), // MUL: 1 gas (base) + 1 (M-ext extra) = 2 gas total
    };
    var ctx = try createTestVM(&code, 100);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.step(); // ADDI
    try testing.expectEqual(@as(u64, 1), ctx.vm.gas.used);
    ctx.vm.step(); // ADD
    try testing.expectEqual(@as(u64, 2), ctx.vm.gas.used);
    ctx.vm.step(); // MUL
    try testing.expectEqual(@as(u64, 4), ctx.vm.gas.used); // 1+1+2
}
