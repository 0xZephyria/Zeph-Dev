// File: vm/budget/meter.zig
// budget metering engine for ForgeVM.
// Tracks budget consumption per instruction and per syscall.

const budgetTable = @import("table.zig");
const decoder = @import("../core/decoder.zig");

/// budget metering state for a single contract execution.
pub const budgetMeter = struct {
    limit: u64, // Total budget budget
    used: u64, // budget consumed so far
    refund: u64, // budget refund accumulator (e.g., SSTORE clear refund)

    /// Initialize with a budget budget.
    pub fn init(limit: u64) budgetMeter {
        return .{ .limit = limit, .used = 0, .refund = 0 };
    }

    /// Remaining budget available.
    pub fn remaining(self: *const budgetMeter) u64 {
        if (self.used >= self.limit) return 0;
        return self.limit - self.used;
    }

    /// Consume budget for a decoded instruction.
    /// Returns error.OutOfbudget if insufficient budget.
    pub fn consumeInstruction(self: *budgetMeter, insn: decoder.Instruction) error{OutOfbudget}!void {
        const cost = budgetTable.instructionCost(insn);
        return self.consume(cost);
    }

    /// Consume budget for a raw opcode (fast path using lookup table).
    pub fn consumeOpcode(self: *budgetMeter, opcode: u7) error{OutOfbudget}!void {
        const cost = budgetTable.OPCODE_budget_TABLE[opcode];
        return self.consume(cost);
    }

    /// Consume arbitrary budget amount (for syscalls, dynamic costs).
    pub fn consume(self: *budgetMeter, amount: u64) error{OutOfbudget}!void {
        if (self.remaining() < amount) return error.OutOfbudget;
        self.used += amount;
    }

    /// Add budget refund (e.g., clearing a storage slot).
    pub fn addRefund(self: *budgetMeter, amount: u64) void {
        _ = self;
        _ = amount;
        // No-op: EIP-3529 refunds are completely deprecated.
    }

    /// Compute effective budget used after refund.
    pub fn effectivebudgetUsed(self: *const budgetMeter) u64 {
        return self.used;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = @import("std").testing;

test "init and remaining" {
    const meter = budgetMeter.init(1000);
    try testing.expectEqual(@as(u64, 1000), meter.remaining());
    try testing.expectEqual(@as(u64, 0), meter.used);
}

test "consume reduces remaining" {
    var meter = budgetMeter.init(100);
    try meter.consume(30);
    try testing.expectEqual(@as(u64, 70), meter.remaining());
    try testing.expectEqual(@as(u64, 30), meter.used);
}

test "consume exact limit succeeds" {
    var meter = budgetMeter.init(10);
    try meter.consume(10);
    try testing.expectEqual(@as(u64, 0), meter.remaining());
}

test "consume over limit returns OutOfbudget" {
    var meter = budgetMeter.init(10);
    try meter.consume(5);
    const result = meter.consume(6);
    try testing.expectError(error.OutOfbudget, result);
    // budget used should not have changed from the failed attempt
    try testing.expectEqual(@as(u64, 5), meter.used);
}

test "consumeOpcode uses lookup table" {
    var meter = budgetMeter.init(1000);
    try meter.consumeOpcode(decoder.Opcode.OP); // ALU = 1
    try testing.expectEqual(@as(u64, 1), meter.used);
    try meter.consumeOpcode(decoder.Opcode.LOAD); // LOAD = 2
    try testing.expectEqual(@as(u64, 3), meter.used);
}

test "refund is a no-op" {
    var meter = budgetMeter.init(1000);
    try meter.consume(100);
    meter.addRefund(50); // Request 50 refund
    try testing.expectEqual(@as(u64, 100), meter.effectivebudgetUsed());
}
