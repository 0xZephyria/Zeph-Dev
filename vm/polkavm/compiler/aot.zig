// File: vm/compiler/aot.zig
// Ahead-of-Time (AOT) C-Transpiling Compiler for ZephBin (.fozbin) packages.

const std = @import("std");
const builtin = @import("builtin");
const decoder = @import("../core/decoder.zig");
const zephbinLoader = @import("../loader/zephbin_loader.zig");
const sandbox = @import("../memory/sandbox.zig");

/// AOT context passed to compiled dynamic library functions.
/// Must match the C declaration layout exactly.
pub const AotContext = extern struct {
    regs: [*]u64,
    pc: *u32,
    memory_backing: [*]u8,
    memory_size: u32,
    budget_limit: *u64,
    budget_used: *u64,
    status: *u32,
    syscall_handler: *const fn (vm_ctx: ?*anyopaque, syscall_id: u32) callconv(.c) i32,
    vm_ctx: ?*anyopaque,
    dirty_tracker: ?*anyopaque,
};

/// Transpile a parsed ZephBin package into standalone C source code.
pub fn generateCSource(allocator: std.mem.Allocator, pkg: *const zephbinLoader.ZephBinPackage) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    // 1. Write header declarations
    try writer.writeAll(
        \\#include <stdint.h>
        \\#include <stdbool.h>
        \\#include <stddef.h>
        \\
        \\typedef struct {
        \\    uint32_t start;
        \\    uint32_t len;
        \\} DirtyRange;
        \\
        \\typedef struct {
        \\    DirtyRange ranges[256];
        \\    size_t count;
        \\    bool fully_dirty;
        \\} DirtyTracker;
        \\
        \\typedef struct {
        \\    uint64_t* regs;
        \\    uint32_t* pc;
        \\    uint8_t* memory;
        \\    uint32_t memory_size;
        \\    uint64_t* budget_limit;
        \\    uint64_t* budget_used;
        \\    uint32_t* status;
        \\    int32_t (*syscall_handler)(void* vm_ctx, uint32_t syscall_id);
        \\    void* vm_ctx;
        \\    DirtyTracker* dirty_tracker;
        \\} AotContext;
        \\
        \\static inline uint64_t sign_extend_32(uint64_t val) {
        \\    return (uint64_t)(int64_t)(int32_t)val;
        \\}
        \\
        \\static inline void mark_dirty(DirtyTracker* tracker, uint32_t addr, uint32_t size) {
        \\    if (tracker->fully_dirty) return;
        \\    if (size == 0) return;
        \\
        \\    if (tracker->count > 0) {
        \\        DirtyRange* last = &tracker->ranges[tracker->count - 1];
        \\        uint32_t last_end = last->start + last->len;
        \\        if (addr >= last->start && addr <= last_end + 64) {
        \\            uint32_t new_end = last_end > (addr + size) ? last_end : (addr + size);
        \\            last->len = new_end - last->start;
        \\            return;
        \\        }
        \\    }
        \\
        \\    if (tracker->count >= 256) {
        \\        tracker->fully_dirty = true;
        \\        return;
        \\    }
        \\
        \\    tracker->ranges[tracker->count].start = addr;
        \\    tracker->ranges[tracker->count].len = size;
        \\    tracker->count += 1;
        \\}
        \\
        \\// Memory load helpers
        \\static inline uint8_t load_byte_u(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr >= ctx->memory_size) { *fault = 1; return 0; }
        \\    return ctx->memory[addr];
        \\}
        \\static inline int8_t load_byte_s(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr >= ctx->memory_size) { *fault = 1; return 0; }
        \\    return (int8_t)ctx->memory[addr];
        \\}
        \\static inline uint16_t load_halfword_u(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr & 1) { *fault = 2; return 0; }
        \\    if (addr + 2 > ctx->memory_size) { *fault = 1; return 0; }
        \\    return *(uint16_t*)(ctx->memory + addr);
        \\}
        \\static inline int16_t load_halfword_s(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr & 1) { *fault = 2; return 0; }
        \\    if (addr + 2 > ctx->memory_size) { *fault = 1; return 0; }
        \\    return *(int16_t*)(ctx->memory + addr);
        \\}
        \\static inline uint32_t load_word_u(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr & 3) { *fault = 2; return 0; }
        \\    if (addr + 4 > ctx->memory_size) { *fault = 1; return 0; }
        \\    return *(uint32_t*)(ctx->memory + addr);
        \\}
        \\static inline int32_t load_word_s(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr & 3) { *fault = 2; return 0; }
        \\    if (addr + 4 > ctx->memory_size) { *fault = 1; return 0; }
        \\    return *(int32_t*)(ctx->memory + addr);
        \\}
        \\static inline uint64_t load_doubleword(AotContext* ctx, uint64_t addr, uint32_t* fault) {
        \\    if (addr & 7) { *fault = 2; return 0; }
        \\    if (addr + 8 > ctx->memory_size) { *fault = 1; return 0; }
        \\    return *(uint64_t*)(ctx->memory + addr);
        \\}
        \\
        \\// Memory store helpers
        \\static inline void store_byte(AotContext* ctx, uint64_t addr, uint8_t val, uint32_t* fault) {
        \\    if (addr >= ctx->memory_size) { *fault = 1; return; }
        \\    if (addr < 0x20000 || (addr < 0x74000 && addr >= 0x70000)) { *fault = 3; return; }
        \\    ctx->memory[addr] = val;
        \\    mark_dirty(ctx->dirty_tracker, (uint32_t)addr, 1);
        \\}
        \\static inline void store_halfword(AotContext* ctx, uint64_t addr, uint16_t val, uint32_t* fault) {
        \\    if (addr & 1) { *fault = 2; return; }
        \\    if (addr + 2 > ctx->memory_size) { *fault = 1; return; }
        \\    if (addr < 0x20000 || (addr < 0x74000 && (addr + 1) >= 0x70000)) { *fault = 3; return; }
        \\    *(uint16_t*)(ctx->memory + addr) = val;
        \\    mark_dirty(ctx->dirty_tracker, (uint32_t)addr, 2);
        \\}
        \\static inline void store_word(AotContext* ctx, uint64_t addr, uint32_t val, uint32_t* fault) {
        \\    if (addr & 3) { *fault = 2; return; }
        \\    if (addr + 4 > ctx->memory_size) { *fault = 1; return; }
        \\    if (addr < 0x20000 || (addr < 0x74000 && (addr + 3) >= 0x70000)) { *fault = 3; return; }
        \\    *(uint32_t*)(ctx->memory + addr) = val;
        \\    mark_dirty(ctx->dirty_tracker, (uint32_t)addr, 4);
        \\}
        \\static inline void store_doubleword(AotContext* ctx, uint64_t addr, uint64_t val, uint32_t* fault) {
        \\    if (addr & 7) { *fault = 2; return; }
        \\    if (addr + 8 > ctx->memory_size) { *fault = 1; return; }
        \\    if (addr < 0x20000 || (addr < 0x74000 && (addr + 7) >= 0x70000)) { *fault = 3; return; }
        \\    *(uint64_t*)(ctx->memory + addr) = val;
        \\    mark_dirty(ctx->dirty_tracker, (uint32_t)addr, 8);
        \\}
        \\
        \\
    );

    // 2. Transpile each action
    for (pkg.actions) |action| {
        try transpileAction(allocator, writer, action);
    }

    return try out.toOwnedSlice(allocator);
}

fn getInstructionbudgetCost(word: u32) u64 {
    const opcode: u7 = @truncate(word & 0x7F);
    const insn = decoder.decode(word) catch return 0;
    // Use the same OPCODE_budget_TABLE as the interpreter fast path
    const base = switch (opcode) {
        decoder.Opcode.OP, decoder.Opcode.OP_32 => blk: {
            // R-type: M-extension gets extra on top of base ALU cost
            if (insn == .rType and insn.rType.funct7 == decoder.Funct7.MULDIV) {
                break :blk switch (insn.rType.funct3) {
                    decoder.Funct3.MUL, decoder.Funct3.MULH, decoder.Funct3.MULHSU, decoder.Funct3.MULHU => @as(u64, 2),
                    decoder.Funct3.DIV, decoder.Funct3.DIVU, decoder.Funct3.REM, decoder.Funct3.REMU => @as(u64, 5),
                };
            }
            break :blk @as(u64, 1); // ALU
        },
        decoder.Opcode.OP_IMM, decoder.Opcode.OP_IMM_32 => @as(u64, 1), // ALU_IMM
        decoder.Opcode.LOAD => @as(u64, 2), // LOAD_WORD (matches OPCODE_budget_TABLE[LOAD])
        decoder.Opcode.STORE => @as(u64, 2), // STORE
        decoder.Opcode.BRANCH => @as(u64, 1), // BRANCH
        decoder.Opcode.JAL => @as(u64, 2), // JAL
        decoder.Opcode.JALR => @as(u64, 2), // JALR
        decoder.Opcode.LUI, decoder.Opcode.AUIPC => @as(u64, 1), // LUI / AUIPC
        decoder.Opcode.SYSTEM => @as(u64, 3), // ECALL_BASE
        decoder.Opcode.CUSTOM_0, decoder.Opcode.CUSTOM_1,
        decoder.Opcode.CUSTOM_2, decoder.Opcode.CUSTOM_3 => @as(u64, 3), // ECALL_BASE
        else => @as(u64, 1),
    };
    return base;
}

fn transpileAction(allocator: std.mem.Allocator, writer: anytype, action: zephbinLoader.ZephAction) !void {
    const code = action.code;
    const stubOffset: u32 = @intCast(code.len);
    const num_insns = code.len / 4;

    // Scan the code to identify basic block entry points
    const starts = try allocator.alloc(bool, num_insns);
    defer allocator.free(starts);
    @memset(starts, false);

    if (num_insns > 0) {
        starts[0] = true; // start of action is always a block start
        var offset: u32 = 0;
        while (offset < code.len) : (offset += 4) {
            const word = std.mem.readInt(u32, code[offset..][0..4], .little);
            const insn = decoder.decode(word) catch continue;
            const pc = offset;
            const next_pc = pc + 4;

            switch (insn) {
                .bType => |b| {
                    const imm = b.imm;
                    const target_pc: u32 = @bitCast(@as(i32, @intCast(pc)) +% @as(i32, @truncate(imm)));
                    if (target_pc % 4 == 0 and target_pc < code.len) {
                        starts[target_pc / 4] = true;
                    }
                    if (next_pc < code.len) {
                        starts[next_pc / 4] = true;
                    }
                },
                .jType => |j| {
                    const imm = j.imm;
                    const target_pc: u32 = @bitCast(@as(i32, @intCast(pc)) +% @as(i32, @truncate(imm)));
                    if (target_pc % 4 == 0 and target_pc < code.len) {
                        starts[target_pc / 4] = true;
                    }
                    if (next_pc < code.len) {
                        starts[next_pc / 4] = true;
                    }
                },
                .iType => {
                    const opcode: u7 = @truncate(word & 0x7F);
                    if (opcode == decoder.Opcode.JALR) {
                        if (next_pc < code.len) {
                            starts[next_pc / 4] = true;
                        }
                    }
                },
                .system => {
                    // SYSTEM instruction itself starts a new block (matching basic_block.zig)
                    starts[offset / 4] = true;
                    if (next_pc < code.len) {
                        starts[next_pc / 4] = true;
                    }
                },
                .custom => {
                    // CUSTOM instruction itself starts a new block
                    starts[offset / 4] = true;
                    if (next_pc < code.len) {
                        starts[next_pc / 4] = true;
                    }
                },
                else => {},
            }
        }
    }

    // Precompute basic block budget costs
    const block_costs = try allocator.alloc(u64, num_insns);
    defer allocator.free(block_costs);
    @memset(block_costs, 0);

    if (num_insns > 0) {
        var i: usize = 0;
        while (i < num_insns) {
            if (starts[i]) {
                var cost: u64 = 0;
                var j = i;
                while (j < num_insns) {
                    if (j > i and starts[j]) {
                        break;
                    }
                    const word = std.mem.readInt(u32, code[j * 4 ..][0..4], .little);
                    cost += getInstructionbudgetCost(word);
                    const insn = decoder.decode(word) catch break;
                    const is_control = switch (insn) {
                        .bType, .jType, .system, .custom => true,
                        .iType => blk: {
                            const opcode: u7 = @truncate(word & 0x7F);
                            break :blk (opcode == decoder.Opcode.JALR);
                        },
                        else => false,
                    };
                    if (is_control) {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                block_costs[i] = cost;
                i = j;
            } else {
                i += 1;
            }
        }
    }

    try writer.print(
        \\
        \\void action_{0x:0>8}(AotContext* ctx) {{
        \\    uint32_t pc = *ctx->pc;
        \\    uint32_t fault = 0;
        \\    uint64_t budget_used = *ctx->budget_used;
        \\    uint64_t budget_limit = *ctx->budget_limit;
        \\    int32_t sys_err = 0;
        \\    bool taken = false;
        \\
        \\    dispatch:
        \\    switch (pc) {{
        \\
    , .{action.selector});

    // Populate switch case targets for all 4-byte boundaries
    var offset: u32 = 0;
    while (offset < code.len) : (offset += 4) {
        try writer.print("        case {d}: goto pc_{d};\n", .{ offset, offset });
    }
    // Stub boundaries
    try writer.print("        case {d}: goto pc_stub;\n", .{stubOffset});
    try writer.print("        case {d}: goto pc_stub_ecall;\n", .{stubOffset + 4});

    try writer.writeAll(
        \\        default:
        \\            *ctx->status = 4; // fault
        \\            goto end;
        \\    }
        \\
    );

    // Decode and emit C code for each instruction
    offset = 0;
    while (offset < code.len) : (offset += 4) {
        const word = std.mem.readInt(u32, code[offset..][0..4], .little);
        const insn = decoder.decode(word) catch {
            // Emitting illegal instruction block in C
            try writer.print(
                \\    pc_{d}:
                \\        *ctx->status = 4;
                \\        goto end;
                \\
            , .{offset});
            continue;
        };

        try writer.print("    pc_{d}: // Word: 0x{X:0>8}\n", .{ offset, word });

        // Emit block budget check if this is a block start
        if (starts[offset / 4]) {
            try emitbudgetCheck(writer, block_costs[offset / 4]);
        }

        // Translate the instruction
        try translateInstruction(writer, insn, offset, stubOffset, code);
    }

    // Emit stub exit handlers
    try writer.print(
        \\    pc_stub:
        \\        ctx->regs[10] = 0x50; // a0 = RETURN_DATA
        \\        pc = {d};
        \\        goto dispatch;
        \\
        \\    pc_stub_ecall:
        \\        // Charge budget for stub instructions (ADDI a0,0,0x50 = 1 + ECALL = 3)
        \\        budget_used += 4;
        \\        if (budget_used > budget_limit) {{
        \\            *ctx->budget_used = budget_limit;
        \\            *ctx->status = 3; // outOfbudget
        \\            goto end;
        \\        }}
        \\        *ctx->pc = {d};
        \\        *ctx->budget_used = budget_used;
        \\        sys_err = ctx->syscall_handler(ctx->vm_ctx, 0x50);
        \\        ctx->regs[0] = 0;
        \\        if (sys_err != 0) {{
        \\            if (sys_err == 1) *ctx->status = 1;
        \\            else if (sys_err == 2) *ctx->status = 2;
        \\            else if (sys_err == 3) *ctx->status = 6;
        \\            else if (sys_err == 4) *ctx->status = 3;
        \\            else *ctx->status = 4;
        \\        }} else {{
        \\            *ctx->status = 1; // returned
        \\        }}
        \\        goto end;
        \\
    , .{ stubOffset + 4, stubOffset + 4 });

    // End function block
    try writer.writeAll(
        \\    end:
        \\        *ctx->budget_used = budget_used;
        \\        *ctx->pc = pc;
        \\        if (fault != 0) {
        \\            *ctx->status = 4; // fault
        \\        }
        \\}
        \\
    );
}

fn translateInstruction(writer: anytype, insn: decoder.Instruction, pc: u32, stubOffset: u32, code: []const u8) !void {
    const next_pc = pc + 4;

    switch (insn) {
        .rType => |r| {
            if (r.rd != 0) {
                const is_muldiv = (r.funct7 == decoder.Funct7.MULDIV);

                if (is_muldiv) {
                    // MUL / DIV operations
                    const rs1 = r.rs1;
                    const rs2 = r.rs2;
                    const rd = r.rd;

                    switch (r.funct3) {
                        decoder.Funct3.MUL => {
                            try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] * ctx->regs[{d}];\n", .{ rd, rs1, rs2 });
                        },
                        decoder.Funct3.MULH => {
                            try writer.print("        ctx->regs[{d}] = (uint64_t)((((__int128)(int64_t)ctx->regs[{d}]) * ((__int128)(int64_t)ctx->regs[{d}])) >> 64);\n", .{ rd, rs1, rs2 });
                        },
                        decoder.Funct3.MULHSU => {
                            try writer.print("        ctx->regs[{d}] = (uint64_t)((((__int128)(int64_t)ctx->regs[{d}]) * ((__int128)ctx->regs[{d}])) >> 64);\n", .{ rd, rs1, rs2 });
                        },
                        decoder.Funct3.MULHU => {
                            try writer.print("        ctx->regs[{d}] = (uint64_t)((((unsigned __int128)ctx->regs[{d}]) * ((unsigned __int128)ctx->regs[{d}])) >> 64);\n", .{ rd, rs1, rs2 });
                        },
                        decoder.Funct3.DIV => {
                            if (r.wordOp) {
                                try writer.print(
                                    \\        {{
                                    \\            int32_t ws1 = (int32_t)ctx->regs[{d}];
                                    \\            int32_t ws2 = (int32_t)ctx->regs[{d}];
                                    \\            if (ws2 == 0) ctx->regs[{d}] = 0xFFFFFFFFFFFFFFFFULL;
                                    \\            else if (ws1 == (-2147483647 - 1) && ws2 == -1) ctx->regs[{d}] = (uint64_t)(int64_t)ws1;
                                    \\            else ctx->regs[{d}] = (uint64_t)(int64_t)(ws1 / ws2);
                                    \\        }}
                                    \\
                                , .{ rs1, rs2, rd, rd, rd });
                            } else {
                                try writer.print(
                                    \\        {{
                                    \\            int64_t s1 = (int64_t)ctx->regs[{d}];
                                    \\            int64_t s2 = (int64_t)ctx->regs[{d}];
                                    \\            if (s2 == 0) ctx->regs[{d}] = 0xFFFFFFFFFFFFFFFFULL;
                                    \\            else if (s1 == INT64_MIN && s2 == -1) ctx->regs[{d}] = (uint64_t)s1;
                                    \\            else ctx->regs[{d}] = (uint64_t)(s1 / s2);
                                    \\        }}
                                    \\
                                , .{ rs1, rs2, rd, rd, rd });
                            }
                        },
                        decoder.Funct3.DIVU => {
                            if (r.wordOp) {
                                try writer.print(
                                    \\        {{
                                    \\            uint32_t wrs1 = (uint32_t)ctx->regs[{d}];
                                    \\            uint32_t wrs2 = (uint32_t)ctx->regs[{d}];
                                    \\            ctx->regs[{d}] = (wrs2 == 0) ? 0xFFFFFFFFFFFFFFFFULL : (uint64_t)(wrs1 / wrs2);
                                    \\        }}
                                    \\
                                , .{ rs1, rs2, rd });
                            } else {
                                try writer.print(
                                    \\        ctx->regs[{d}] = (ctx->regs[{d}] == 0) ? 0xFFFFFFFFFFFFFFFFULL : (ctx->regs[{d}] / ctx->regs[{d}]);
                                    \\
                                , .{ rd, rs2, rs1, rs2 });
                            }
                        },
                        decoder.Funct3.REM => {
                            if (r.wordOp) {
                                try writer.print(
                                    \\        {{
                                    \\            int32_t ws1 = (int32_t)ctx->regs[{d}];
                                    \\            int32_t ws2 = (int32_t)ctx->regs[{d}];
                                    \\            if (ws2 == 0) ctx->regs[{d}] = (uint64_t)(int64_t)ws1;
                                    \\            else if (ws1 == (-2147483647 - 1) && ws2 == -1) ctx->regs[{d}] = 0;
                                    \\            else ctx->regs[{d}] = (uint64_t)(int64_t)(ws1 % ws2);
                                    \\        }}
                                    \\
                                , .{ rs1, rs2, rd, rd, rd });
                            } else {
                                try writer.print(
                                    \\        {{
                                    \\            int64_t s1 = (int64_t)ctx->regs[{d}];
                                    \\            int64_t s2 = (int64_t)ctx->regs[{d}];
                                    \\            if (s2 == 0) ctx->regs[{d}] = (uint64_t)s1;
                                    \\            else if (s1 == INT64_MIN && s2 == -1) ctx->regs[{d}] = 0;
                                    \\            else ctx->regs[{d}] = (uint64_t)(s1 % s2);
                                    \\        }}
                                    \\
                                , .{ rs1, rs2, rd, rd, rd });
                            }
                        },
                        decoder.Funct3.REMU => {
                            if (r.wordOp) {
                                try writer.print(
                                    \\        {{
                                    \\            uint32_t wrs1 = (uint32_t)ctx->regs[{d}];
                                    \\            uint32_t wrs2 = (uint32_t)ctx->regs[{d}];
                                    \\            ctx->regs[{d}] = (wrs2 == 0) ? (uint64_t)wrs1 : (uint64_t)(wrs1 % wrs2);
                                    \\        }}
                                    \\
                                , .{ rs1, rs2, rd });
                            } else {
                                try writer.print(
                                    \\        ctx->regs[{d}] = (ctx->regs[{d}] == 0) ? ctx->regs[{d}] : (ctx->regs[{d}] % ctx->regs[{d}]);
                                    \\
                                , .{ rd, rs2, rs1, rs1, rs2 });
                            }
                        },
                    }
                } else {
                    // NORMAL R-type
                    const rd = r.rd;
                    const rs1 = r.rs1;
                    const rs2 = r.rs2;
                    const shamt_mask = if (r.wordOp) @as(u32, 0x1F) else @as(u32, 0x3F);

                    switch (r.funct7) {
                        decoder.Funct7.NORMAL => {
                            switch (r.funct3) {
                                decoder.Funct3.ADD_SUB => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] + ctx->regs[{d}];\n", .{ rd, rs1, rs2 });
                                },
                                decoder.Funct3.SLL => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] << (ctx->regs[{d}] & 0x{X});\n", .{ rd, rs1, rs2, shamt_mask });
                                },
                                decoder.Funct3.SLT => {
                                    try writer.print("        ctx->regs[{d}] = ((int64_t)ctx->regs[{d}] < (int64_t)ctx->regs[{d}]) ? 1 : 0;\n", .{ rd, rs1, rs2 });
                                },
                                decoder.Funct3.SLTU => {
                                    try writer.print("        ctx->regs[{d}] = (ctx->regs[{d}] < ctx->regs[{d}]) ? 1 : 0;\n", .{ rd, rs1, rs2 });
                                },
                                decoder.Funct3.XOR => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] ^ ctx->regs[{d}];\n", .{ rd, rs1, rs2 });
                                },
                                decoder.Funct3.SRL_SRA => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] >> (ctx->regs[{d}] & 0x{X});\n", .{ rd, rs1, rs2, shamt_mask });
                                },
                                decoder.Funct3.OR => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] | ctx->regs[{d}];\n", .{ rd, rs1, rs2 });
                                },
                                decoder.Funct3.AND => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] & ctx->regs[{d}];\n", .{ rd, rs1, rs2 });
                                },
                            }
                        },
                        decoder.Funct7.SUB_SRA => {
                            switch (r.funct3) {
                                decoder.Funct3.ADD_SUB => {
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] - ctx->regs[{d}];\n", .{ rd, rs1, rs2 });
                                },
                                decoder.Funct3.SRL_SRA => {
                                    try writer.print("        ctx->regs[{d}] = (uint64_t)((int64_t)ctx->regs[{d}] >> (ctx->regs[{d}] & 0x{X}));\n", .{ rd, rs1, rs2, shamt_mask });
                                },
                                else => {
                                    try writer.writeAll("        fault = 4; goto end;\n");
                                },
                            }
                        },
                        else => {
                            try writer.writeAll("        fault = 4; goto end;\n");
                        },
                    }
                }

                if (r.wordOp) {
                    try writer.print("        ctx->regs[{d}] = sign_extend_32(ctx->regs[{d}]);\n", .{ r.rd, r.rd });
                }
            }
            try writer.print("        pc = {d};\n\n", .{next_pc});
        },

        .iType => |i| {
            const word = std.mem.readInt(u32, code[pc..][0..4], .little);
            const opcode: u7 = @truncate(word & 0x7F);

            const rd = i.rd;
            const rs1 = i.rs1;
            const imm = i.imm;
            const wordOp = i.wordOp;

            switch (opcode) {
                decoder.Opcode.OP_IMM, decoder.Opcode.OP_IMM_32 => {
                    if (rd != 0) {
                        const shamt_mask = if (wordOp) @as(u32, 0x1F) else @as(u32, 0x3F);

                        switch (i.funct3) {
                            decoder.Funct3.ADD_SUB => {
                                try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] + {d}ULL;\n", .{ rd, rs1, imm });
                            },
                            decoder.Funct3.SLT => {
                                try writer.print("        ctx->regs[{d}] = ((int64_t)ctx->regs[{d}] < (int64_t){d}) ? 1 : 0;\n", .{ rd, rs1, imm });
                            },
                            decoder.Funct3.SLTU => {
                                try writer.print("        ctx->regs[{d}] = (ctx->regs[{d}] < {d}ULL) ? 1 : 0;\n", .{ rd, rs1, @as(u64, @bitCast(imm)) });
                            },
                            decoder.Funct3.XOR => {
                                try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] ^ {d}ULL;\n", .{ rd, rs1, @as(u64, @bitCast(imm)) });
                            },
                            decoder.Funct3.OR => {
                                try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] | {d}ULL;\n", .{ rd, rs1, @as(u64, @bitCast(imm)) });
                            },
                            decoder.Funct3.AND => {
                                try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] & {d}ULL;\n", .{ rd, rs1, @as(u64, @bitCast(imm)) });
                            },
                            decoder.Funct3.SLL => {
                                try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] << ({d} & 0x{X});\n", .{ rd, rs1, imm, shamt_mask });
                            },
                            decoder.Funct3.SRL_SRA => {
                                if (imm & 0x400 != 0) { // SRAI
                                    try writer.print("        ctx->regs[{d}] = (uint64_t)((int64_t)ctx->regs[{d}] >> ({d} & 0x{X}));\n", .{ rd, rs1, imm, shamt_mask });
                                } else { // SRLI
                                    try writer.print("        ctx->regs[{d}] = ctx->regs[{d}] >> ({d} & 0x{X});\n", .{ rd, rs1, imm, shamt_mask });
                                }
                            },
                        }

                        if (wordOp) {
                            try writer.print("        ctx->regs[{d}] = sign_extend_32(ctx->regs[{d}]);\n", .{ rd, rd });
                        }
                    }
                    try writer.print("        pc = {d};\n\n", .{next_pc});
                },

                decoder.Opcode.LOAD => {
                    switch (i.funct3) {
                        decoder.Funct3.LB => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = (uint64_t)load_byte_s(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_byte_s(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        decoder.Funct3.LH => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = (uint64_t)load_halfword_s(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_halfword_s(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        decoder.Funct3.LW => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = (uint64_t)load_word_s(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_word_s(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        decoder.Funct3.LBU => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = (uint64_t)load_byte_u(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_byte_u(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        decoder.Funct3.LHU => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = (uint64_t)load_halfword_u(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_halfword_u(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        decoder.Funct3.LWU => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = (uint64_t)load_word_u(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_word_u(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        decoder.Funct3.LD => {
                            if (rd != 0) {
                                try writer.print("        ctx->regs[{d}] = load_doubleword(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rd, rs1, imm });
                            } else {
                                try writer.print("        (void)load_doubleword(ctx, ctx->regs[{d}] + {d}ULL, &fault);\n", .{ rs1, imm });
                            }
                        },
                        else => {
                            try writer.writeAll("        fault = 4; goto end;\n");
                        },
                    }
                    try writer.writeAll("        if (fault != 0) goto end;\n");
                    try writer.print("        pc = {d};\n\n", .{next_pc});
                },

                decoder.Opcode.JALR => {
                    // JALR: rd = PC+4, jump to (rs1 + imm) & ~1
                    if (rd != 0) {
                        try writer.print("        ctx->regs[{d}] = {d};\n", .{ rd, pc + 4 });
                    }
                    try writer.print("        pc = (uint32_t)((ctx->regs[{d}] + {d}ULL) & 0xFFFFFFFEULL);\n", .{ rs1, imm });
                    try writer.writeAll("        goto dispatch;\n\n");
                },

                else => {
                    try writer.writeAll("        fault = 4; goto end;\n");
                },
            }
        },

        .sType => |s| {
            const rs1 = s.rs1;
            const rs2 = s.rs2;
            const imm = s.imm;

            switch (s.funct3) {
                decoder.Funct3.SB => {
                    try writer.print("        store_byte(ctx, ctx->regs[{d}] + {d}ULL, (uint8_t)ctx->regs[{d}], &fault);\n", .{ rs1, imm, rs2 });
                },
                decoder.Funct3.SH => {
                    try writer.print("        store_halfword(ctx, ctx->regs[{d}] + {d}ULL, (uint16_t)ctx->regs[{d}], &fault);\n", .{ rs1, imm, rs2 });
                },
                decoder.Funct3.SW => {
                    try writer.print("        store_word(ctx, ctx->regs[{d}] + {d}ULL, (uint32_t)ctx->regs[{d}], &fault);\n", .{ rs1, imm, rs2 });
                },
                decoder.Funct3.SD => {
                    try writer.print("        store_doubleword(ctx, ctx->regs[{d}] + {d}ULL, ctx->regs[{d}], &fault);\n", .{ rs1, imm, rs2 });
                },
                else => {
                    try writer.writeAll("        fault = 4; goto end;\n");
                },
            }
            try writer.writeAll("        if (fault != 0) goto end;\n");
            try writer.print("        pc = {d};\n\n", .{next_pc});
        },

        .bType => |b| {
            const rs1 = b.rs1;
            const rs2 = b.rs2;
            const imm = b.imm;
            const target_pc: u32 = @bitCast(@as(i32, @intCast(pc)) +% @as(i32, @truncate(imm)));

            try writer.writeAll("        taken = false;\n");
            switch (b.funct3) {
                decoder.Funct3.BEQ => {
                    try writer.print("        taken = (ctx->regs[{d}] == ctx->regs[{d}]);\n", .{ rs1, rs2 });
                },
                decoder.Funct3.BNE => {
                    try writer.print("        taken = (ctx->regs[{d}] != ctx->regs[{d}]);\n", .{ rs1, rs2 });
                },
                decoder.Funct3.BLT => {
                    try writer.print("        taken = ((int64_t)ctx->regs[{d}] < (int64_t)ctx->regs[{d}]);\n", .{ rs1, rs2 });
                },
                decoder.Funct3.BGE => {
                    try writer.print("        taken = ((int64_t)ctx->regs[{d}] >= (int64_t)ctx->regs[{d}]);\n", .{ rs1, rs2 });
                },
                decoder.Funct3.BLTU => {
                    try writer.print("        taken = (ctx->regs[{d}] < ctx->regs[{d}]);\n", .{ rs1, rs2 });
                },
                decoder.Funct3.BGEU => {
                    try writer.print("        taken = (ctx->regs[{d}] >= ctx->regs[{d}]);\n", .{ rs1, rs2 });
                },
                else => {
                    try writer.writeAll("        fault = 4; goto end;\n");
                },
            }

            // Verify target_pc validity
            const is_valid_target = (target_pc % 4 == 0 and target_pc < stubOffset) or
                target_pc == stubOffset or target_pc == stubOffset + 4;

            if (is_valid_target) {
                try writer.print(
                    \\        if (taken) {{
                    \\            pc = {d};
                    \\            goto pc_{d};
                    \\        }}
                    \\
                , .{ target_pc, target_pc });
            } else {
                try writer.writeAll(
                    \\        if (taken) {
                    \\            fault = 4;
                    \\            goto end;
                    \\        }
                    \\
                );
            }
            try writer.print("        pc = {d};\n\n", .{next_pc});
        },

        .uType => |u_val| {
            const word = std.mem.readInt(u32, code[pc..][0..4], .little);
            const opcode: u7 = @truncate(word & 0x7F);
            const rd = u_val.rd;
            const imm = u_val.imm;

            if (rd != 0) {
                switch (opcode) {
                    decoder.Opcode.LUI => {
                        try writer.print("        ctx->regs[{d}] = {d}ULL;\n", .{ rd, @as(u64, @bitCast(imm)) });
                    },
                    decoder.Opcode.AUIPC => {
                        try writer.print("        ctx->regs[{d}] = {d}ULL + {d}ULL;\n", .{ rd, pc, @as(u64, @bitCast(imm)) });
                    },
                    else => {
                        try writer.writeAll("        fault = 4; goto end;\n");
                    },
                }
            } else {
                switch (opcode) {
                    decoder.Opcode.LUI, decoder.Opcode.AUIPC => {},
                    else => {
                        try writer.writeAll("        fault = 4; goto end;\n");
                    },
                }
            }
            try writer.print("        pc = {d};\n\n", .{next_pc});
        },

        .jType => |j| {
            const rd = j.rd;
            const imm = j.imm;
            const target_pc: u32 = @bitCast(@as(i32, @intCast(pc)) +% @as(i32, @truncate(imm)));

            if (rd != 0) {
                try writer.print("        ctx->regs[{d}] = {d};\n", .{ rd, pc + 4 });
            }

            // Verify target_pc validity
            const is_valid_target = (target_pc % 4 == 0 and target_pc < stubOffset) or
                target_pc == stubOffset or target_pc == stubOffset + 4;

            if (is_valid_target) {
                try writer.print("        pc = {d};\n", .{target_pc});
                try writer.print("        goto pc_{d};\n\n", .{target_pc});
            } else {
                try writer.writeAll("        fault = 4;\n        goto end;\n\n");
            }
        },

        .system => |sys| {
            switch (sys) {
                .ecall => {
                    try writer.print("        *ctx->pc = {d};\n", .{pc});
                    try writer.writeAll(
                        \\        *ctx->budget_used = budget_used;
                        \\        sys_err = ctx->syscall_handler(ctx->vm_ctx, (uint32_t)ctx->regs[10]);
                        \\        ctx->regs[0] = 0;
                        \\        budget_used = *ctx->budget_used;
                        \\        if (sys_err != 0) {
                        \\            if (sys_err == 1) *ctx->status = 1; // returned
                        \\            else if (sys_err == 2) *ctx->status = 2; // reverted
                        \\            else if (sys_err == 3) *ctx->status = 6; // selfDestruct
                        \\            else if (sys_err == 4) *ctx->status = 3; // outOfbudget
                        \\            else *ctx->status = 4; // fault
                        \\            goto end;
                        \\        }
                        \\
                    );
                    try writer.print("        pc = {d};\n\n", .{next_pc});
                },
                .ebreak => {
                    try writer.writeAll(
                        \\        *ctx->status = 5; // breakpoint
                        \\        goto end;
                        \\
                    );
                },
            }
        },

        .custom => |c| {
            try writer.print("        *ctx->pc = {d};\n", .{pc});

            // Implement register shuffle and call syscall handler
            const op = c.opVal;
            try writer.print("        // ZEPH Custom Opcode 0x{X:0>2}\n", .{op});
            try writer.writeAll(
                \\        {
                \\            uint64_t origA0 = ctx->regs[10];
                \\            uint64_t origA1 = ctx->regs[11];
                \\            uint64_t origA2 = ctx->regs[12];
                \\            uint64_t origA3 = ctx->regs[13];
                \\            uint32_t syscallId = 0;
                \\
            );

            // Shuffling logic per execCustom mapping
            switch (op) {
                0x00 => { // STATE_READ
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            syscallId = 0x01;
                    );
                },
                0x01 => { // STATE_WRITE
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            syscallId = 0x02;
                    );
                },
                0x02 => { // STATE_EXISTS
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            syscallId = 0x01;
                    );
                },
                0x03 => { // STATE_DELETE
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = 0;
                        \\            syscallId = 0x02;
                    );
                },
                0x10 => { // AUTH_CHECK
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA0;
                        \\            ctx->regs[13] = origA0;
                        \\            syscallId = 0x20;
                    );
                },
                0x20 => { // ASSET_TRANSFER
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            ctx->regs[13] = origA2;
                        \\            ctx->regs[14] = origA3;
                        \\            syscallId = 0x10;
                    );
                },
                0x21 => { // ASSET_MINT
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            ctx->regs[13] = origA2;
                        \\            syscallId = 0x12;
                    );
                },
                0x22 => { // ASSET_BURN
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            ctx->regs[13] = origA2;
                        \\            syscallId = 0x13;
                    );
                },
                0x23 => { // NATIVE_PAY
                    try writer.writeAll(
                        \\            ctx->regs[11] = 0;
                        \\            ctx->regs[12] = 0;
                        \\            ctx->regs[13] = origA0;
                        \\            ctx->regs[14] = origA1;
                        \\            syscallId = 0x10;
                    );
                },
                0x30 => { // EMIT_EVENT
                    try writer.writeAll(
                        \\            ctx->regs[11] = 0;
                        \\            ctx->regs[12] = origA0;
                        \\            ctx->regs[13] = origA1;
                        \\            ctx->regs[14] = origA2;
                        \\            syscallId = 0x30;
                    );
                },
                0x31 => { // SCHEDULE_CALL
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA1;
                        \\            ctx->regs[12] = 0;
                        \\            ctx->regs[13] = 0;
                        \\            ctx->regs[14] = 0;
                        \\            syscallId = 0x40;
                    );
                },
                0x32 => { // REVERT
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            syscallId = 0x51;
                    );
                },
                0x33 => { // LOG_DIAGNOSTIC
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            ctx->regs[12] = origA1;
                        \\            syscallId = 0xFF;
                    );
                },
                0x34 => { // GET_CALLER
                    try writer.writeAll(
                        \\            ctx->regs[11] = origA0;
                        \\            syscallId = 0x60;
                    );
                },
                0x35 => { // GET_NOW
                    try writer.writeAll("            syscallId = 0x66;\n");
                },
                0x36 => { // GET_BLOCK
                    try writer.writeAll("            syscallId = 0x65;\n");
                },
                0x37 => { // GET_VALUE
                    try writer.writeAll("            syscallId = 0x61;\n");
                },
                else => {
                    try writer.writeAll("            fault = 4; goto end;\n");
                },
            }

            try writer.writeAll(
                \\            ctx->regs[10] = syscallId;
                \\            *ctx->budget_used = budget_used;
                \\            sys_err = ctx->syscall_handler(ctx->vm_ctx, syscallId);
                \\            ctx->regs[0] = 0;
                \\            budget_used = *ctx->budget_used;
                \\            if (sys_err != 0) {
                \\                if (sys_err == 1) *ctx->status = 1;
                \\                else if (sys_err == 2) *ctx->status = 2;
                \\                else if (sys_err == 3) *ctx->status = 6;
                \\                else if (sys_err == 4) *ctx->status = 3;
                \\                else *ctx->status = 4;
                \\                goto end;
                \\            }
                \\
            );

            if (op == 0x02) { // STATE_EXISTS post-processing
                try writer.writeAll("            ctx->regs[10] = (ctx->regs[10] != 0) ? 1 : 0;\n");
            }

            try writer.writeAll("        }\n        ctx->regs[0] = 0;\n");
            try writer.print("        pc = {d};\n\n", .{next_pc});

        },
    }
}

fn emitbudgetCheck(writer: anytype, cost: u64) !void {
    try writer.print(
        \\        budget_used += {d};
        \\        if (budget_used > budget_limit) {{
        \\            *ctx->budget_used = budget_limit;
        \\            *ctx->status = 3; // outOfbudget
        \\            goto end;
        \\        }}
        \\
    , .{cost});
}

/// Compiles the ZephBin package to a native dynamic library and returns the file path.
/// The returned slice is heap-allocated and must be freed by the caller.
pub fn compileAot(allocator: std.mem.Allocator, binData: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(binData, &hash, .{});
    const hash_hex = std.fmt.bytesToHex(hash, .lower);

    const cache_dir = "node_data/aot_cache";
    std.fs.cwd().makePath(cache_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const ext = comptime switch (builtin.os.tag) {
        .windows => ".dll",
        .macos, .ios, .watchos, .tvos => ".dylib",
        else => ".so",
    };

    const lib_filename = try std.fmt.allocPrint(allocator, "{s}{s}", .{ &hash_hex, ext });
    defer allocator.free(lib_filename);
    const lib_path = try std.fs.path.join(allocator, &.{ cache_dir, lib_filename });
    errdefer allocator.free(lib_path);

    var exists = true;
    std.fs.cwd().access(lib_path, .{}) catch {
        exists = false;
    };

    if (!exists) {
        var pkg = try zephbinLoader.parse(allocator, binData);
        defer pkg.deinit();

        const c_source = try generateCSource(allocator, &pkg);
        defer allocator.free(c_source);

        const c_filename = try std.fmt.allocPrint(allocator, "{s}.c", .{&hash_hex});
        defer allocator.free(c_filename);
        const c_path = try std.fs.path.join(allocator, &.{ cache_dir, c_filename });
        defer allocator.free(c_path);

        const c_file = try std.fs.cwd().createFile(c_path, .{});
        defer c_file.close();
        try c_file.writeAll(c_source);

        // Run zig cc -shared -O3 -o lib_path c_path
        var child = std.process.Child.init(&.{
            "zig",
            "cc",
            "-shared",
            "-O3",
            "-o",
            lib_path,
            c_path,
        }, allocator);

        const term = try child.spawnAndWait();
        switch (term) {
            .Exited => |code| {
                if (code != 0) return error.CompilationFailed;
            },
            else => return error.CompilationFailed,
        }
    }

    return lib_path;
}

// ---------------------------------------------------------------------------
// AOT Unit Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const contractLoader = @import("../loader/contract_loader.zig");
const syscallDispatch = @import("../syscall/dispatch.zig");

extern "c" fn setenv(envname: [*:0]const u8, envval: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "AOT compiler: TokenTest.fozbin AOT vs Interpreter compatibility" {
    const allocator = testing.allocator;

    // 1. Read TokenTest.fozbin
    const file = try std.fs.cwd().openFile("./TokenTest.fozbin", .{});
    defer file.close();
    const size = (try file.stat()).size;
    const binData = try allocator.alloc(u8, size);
    defer allocator.free(binData);
    _ = try file.readAll(binData);

    // Parse the package to get selectors
    var pkg = try zephbinLoader.parse(allocator, binData);
    defer pkg.deinit();

    // Selectors to test
    const selectors = [_]u32{
        0x6f91d85a,
        0xba4d2440,
        0x1ce900f6,
        0x25b04e4e,
        0x47779aaa,
        0x0dc9e26b,
        0xa0873bbc,
    };

    for (selectors) |sel| {
        // Run AOT
        _ = unsetenv("FORGE_NO_AOT");
        var env_aot = syscallDispatch.HostEnv.init(allocator);
        defer env_aot.deinit();
        env_aot.executionBudget = 10_000_000;
        env_aot.chainId = 99999;
        env_aot.blockNumber = 1;
        env_aot.timestamp = 1716422400;

        var calldata: [4]u8 = undefined;
        std.mem.writeInt(u32, &calldata, sel, .little);

        const aot_res = try contractLoader.executeFromZephBin(
            allocator,
            binData,
            &calldata,
            10_000_000,
            &env_aot,
        );
        defer allocator.free(aot_res.returnData);

        // Run Interpreter
        _ = setenv("FORGE_NO_AOT", "1", 1);
        var env_interp = syscallDispatch.HostEnv.init(allocator);
        defer env_interp.deinit();
        env_interp.executionBudget = 10_000_000;
        env_interp.chainId = 99999;
        env_interp.blockNumber = 1;
        env_interp.timestamp = 1716422400;

        const interp_res = try contractLoader.executeFromZephBin(
            allocator,
            binData,
            &calldata,
            10_000_000,
            &env_interp,
        );
        defer allocator.free(interp_res.returnData);

        // Assert compatibility
        try testing.expectEqual(interp_res.status, aot_res.status);
        try testing.expectEqual(interp_res.budgetUsed, aot_res.budgetUsed);
        try testing.expectEqualSlices(u8, interp_res.returnData, aot_res.returnData);
    }
    _ = unsetenv("FORGE_NO_AOT");
    // Release global AOT cache (DynLib handles + function pointers)
    contractLoader.deinitAotCache(allocator);
}

