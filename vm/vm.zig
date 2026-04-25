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
