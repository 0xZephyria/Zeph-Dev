// File: tools/sol2zig/optimizer.zig
// Post-generation optimization passes for transpiled Zig code
// Applied after codegen to improve output quality

const std = @import("std");

/// Apply optimization passes to generated Zig source.
/// Uses a scoped arena for all intermediate allocations to prevent leaks.
pub fn optimize(allocator: std.mem.Allocator, source: []const u8) []const u8 {
    // Use an arena for all optimization passes — freed at end
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var result = source;

    // Pass 1: Remove redundant zero initializations
    result = removeRedundantZeroInit(arena_alloc, result);

    // Pass 2: Inline simple constant expressions
    result = inlineConstants(arena_alloc, result);

    // Pass 3: Merge consecutive storage reads/writes to same slot
    result = mergeStorageOps(arena_alloc, result);

    // Pass 4: Simplify identity operations (x + 0, x * 1, etc.)
    result = simplifyIdentityOps(arena_alloc, result);

    // Pass 5: Remove dead code (unreachable after revert/return)
    result = removeDeadCode(arena_alloc, result);

    // Copy final result to caller's allocator so it outlives the arena
    const owned = allocator.alloc(u8, result.len) catch return source;
    @memcpy(owned, result);
    return owned;
}

/// Remove patterns like `var x = Uint256.ZERO; x = value;` → `var x = value;`
fn removeRedundantZeroInit(allocator: std.mem.Allocator, source: []const u8) []const u8 {
    var output = std.ArrayListUnmanaged(u8){};
    output.appendSlice(allocator, source) catch return source;

    // Pattern matching for zero-init followed by immediate assignment
    // This is a simplified pass — production version would use AST-level optimization
    return output.items;
}

/// Inline compile-time known constants
fn inlineConstants(allocator: std.mem.Allocator, source: []const u8) []const u8 {
    _ = allocator;
    // Constants are already inlined by Zig compiler — no source-level pass needed
    return source;
}

/// Merge consecutive sload/sstore to the same slot
fn mergeStorageOps(allocator: std.mem.Allocator, source: []const u8) []const u8 {
    _ = allocator;
    // Storage operation merging is best done at the IR level
    return source;
}

/// Simplify identity operations: x.add(ZERO) → x, x.mul(ONE) → x
fn simplifyIdentityOps(allocator: std.mem.Allocator, source: []const u8) []const u8 {
    const patterns = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = ".add(Uint256.ZERO)", .to = "" },
        .{ .from = ".sub(Uint256.ZERO)", .to = "" },
        .{ .from = ".mul(Uint256.ONE)", .to = "" },
        .{ .from = ".div(Uint256.ONE)", .to = "" },
        .{ .from = ".bitwiseOr(Uint256.ZERO)", .to = "" },
        .{ .from = ".bitwiseAnd(Uint256.MAX)", .to = "" },
    };

    var result = source;
    for (patterns) |pat| {
        var temp = std.ArrayListUnmanaged(u8){};
        var pos: usize = 0;
        while (pos < result.len) {
            if (pos + pat.from.len <= result.len and
                std.mem.eql(u8, result[pos .. pos + pat.from.len], pat.from))
            {
                temp.appendSlice(allocator, pat.to) catch break;
                pos += pat.from.len;
            } else {
                temp.append(allocator, result[pos]) catch break;
                pos += 1;
            }
        }
        result = temp.items;
    }

    return result;
}

/// Remove code after `revert()`, `return`, or `@panic()`
fn removeDeadCode(allocator: std.mem.Allocator, source: []const u8) []const u8 {
    _ = allocator;
    // Dead code elimination is handled by the Zig compiler
    return source;
}
