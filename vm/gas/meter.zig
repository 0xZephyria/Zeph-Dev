// File: vm/gas/meter.zig
// Gas metering engine for ForgeVM.
// Tracks gas consumption per instruction and per syscall.

const gasTable = @import("table.zig");
const decoder = @import("../core/decoder.zig");

/// Gas metering state for a single contract execution.
pub const GasMeter = struct {
    limit: u64, // Total gas budget
    used: u64, // Gas consumed so far
    refund: u64, // Gas refund accumulator (e.g., SSTORE clear refund)

    /// Initialize with a gas budget.
    pub fn init(limit: u64) GasMeter {
        return .{ .limit = limit, .used = 0, .refund = 0 };
    }

    /// Remaining gas available.
    pub fn remaining(self: *const GasMeter) u64 {
        if (self.used >= self.limit) return 0;
        return self.limit - self.used;
    }

    /// Consume gas for a decoded instruction.
    /// Returns error.OutOfGas if insufficient gas.
    pub fn consumeInstruction(self: *GasMeter, insn: decoder.Instruction) error{OutOfGas}!void {
        const cost = gasTable.instructionCost(insn);
        return self.consume(cost);
    }

    /// Consume gas for a raw opcode (fast path using lookup table).
    pub fn consumeOpcode(self: *GasMeter, opcode: u7) error{OutOfGas}!void {
        const cost = gasTable.OPCODE_GAS_TABLE[opcode];
        return self.consume(cost);
    }

    /// Consume arbitrary gas amount (for syscalls, dynamic costs).
    pub fn consume(self: *GasMeter, amount: u64) error{OutOfGas}!void {
        if (self.remaining() < amount) return error.OutOfGas;
        self.used += amount;
    }

    /// Add gas refund (e.g., clearing a storage slot).
    pub fn addRefund(self: *GasMeter, amount: u64) void {
        _ = self;
        _ = amount;
        // No-op: EIP-3529 refunds are completely deprecated.
    }

    /// Compute effective gas used after refund.
    pub fn effectiveGasUsed(self: *const GasMeter) u64 {
        return self.used;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = @import("std").testing;

test "init and remaining" {
    const meter = GasMeter.init(1000);
    try testing.expectEqual(@as(u64, 1000), meter.remaining());
    try testing.expectEqual(@as(u64, 0), meter.used);
}

test "consume reduces remaining" {
    var meter = GasMeter.init(100);
    try meter.consume(30);
    try testing.expectEqual(@as(u64, 70), meter.remaining());
    try testing.expectEqual(@as(u64, 30), meter.used);
}

test "consume exact limit succeeds" {
    var meter = GasMeter.init(10);
    try meter.consume(10);
    try testing.expectEqual(@as(u64, 0), meter.remaining());
}

test "consume over limit returns OutOfGas" {
    var meter = GasMeter.init(10);
    try meter.consume(5);
    const result = meter.consume(6);
    try testing.expectError(error.OutOfGas, result);
    // Gas used should not have changed from the failed attempt
    try testing.expectEqual(@as(u64, 5), meter.used);
}

test "consumeOpcode uses lookup table" {
    var meter = GasMeter.init(1000);
    try meter.consumeOpcode(decoder.Opcode.OP); // ALU = 1
    try testing.expectEqual(@as(u64, 1), meter.used);
    try meter.consumeOpcode(decoder.Opcode.LOAD); // LOAD = 2
    try testing.expectEqual(@as(u64, 3), meter.used);
}

test "refund is a no-op" {
    var meter = GasMeter.init(1000);
    try meter.consume(100);
    meter.addRefund(50); // Request 50 refund
    try testing.expectEqual(@as(u64, 100), meter.effectiveGasUsed());
}
