const budgetTable = @import("table.zig");
const decoder = @import("../core/decoder.zig");

pub const BudgetMeter = struct {
    budget: u64,
    consumed: u64,

    pub fn init(budget: u64) BudgetMeter {
        return .{ .budget = budget, .consumed = 0 };
    }

    pub fn remaining(self: *const BudgetMeter) u64 {
        if (self.consumed >= self.budget) return 0;
        return self.budget - self.consumed;
    }

    pub fn consumeInstruction(self: *BudgetMeter, insn: decoder.Instruction) error{OutOfBudget}!void {
        const cost = budgetTable.instructionCost(insn);
        return self.consume(cost);
    }

    pub fn consumeOpcode(self: *BudgetMeter, opcode: u7) error{OutOfBudget}!void {
        const cost = budgetTable.OPCODE_budget_TABLE[opcode];
        return self.consume(cost);
    }

    pub fn consume(self: *BudgetMeter, amount: u64) error{OutOfBudget}!void {
        if (self.remaining() < amount) return error.OutOfBudget;
        self.consumed += amount;
    }

    pub fn effective(self: *const BudgetMeter) u64 {
        return self.consumed;
    }

    pub fn addRefund(self: *BudgetMeter, amount: u64) void {
        _ = self;
        _ = amount;
    }
};

const testing = @import("std").testing;

test "init and remaining" {
    const meter = BudgetMeter.init(1000);
    try testing.expectEqual(@as(u64, 1000), meter.remaining());
    try testing.expectEqual(@as(u64, 0), meter.consumed);
}

test "consume reduces remaining" {
    var meter = BudgetMeter.init(100);
    try meter.consume(30);
    try testing.expectEqual(@as(u64, 70), meter.remaining());
    try testing.expectEqual(@as(u64, 30), meter.consumed);
}

test "consume exact budget succeeds" {
    var meter = BudgetMeter.init(10);
    try meter.consume(10);
    try testing.expectEqual(@as(u64, 0), meter.remaining());
}

test "consume over limit returns OutOfBudget" {
    var meter = BudgetMeter.init(10);
    try meter.consume(5);
    const result = meter.consume(6);
    try testing.expectError(error.OutOfBudget, result);
    try testing.expectEqual(@as(u64, 5), meter.consumed);
}

test "consumeOpcode uses lookup table" {
    var meter = BudgetMeter.init(1000);
    try meter.consumeOpcode(decoder.Opcode.OP);
    try testing.expectEqual(@as(u64, 1), meter.consumed);
    try meter.consumeOpcode(decoder.Opcode.LOAD);
    try testing.expectEqual(@as(u64, 3), meter.consumed);
}
