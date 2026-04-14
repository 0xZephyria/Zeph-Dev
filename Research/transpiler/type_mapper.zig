// File: tools/sol2zig/type_mapper.zig
// Maps Solidity types to Zephyria Zig SDK types
// Complete coverage of all Solidity primitive types, arrays, mappings, and user-defined types

const std = @import("std");

pub const TypeMapping = struct {
    sol_type: []const u8,
    zig_type: []const u8,
    is_value_type: bool,
    storage_wrapper: []const u8,
};

/// Default type mapping table — covers all standard Solidity types
pub const DEFAULT_TYPE_MAP = [_]TypeMapping{
    // Unsigned integers — all widths (multiples of 8)
    .{ .sol_type = "uint256", .zig_type = "sdk.Uint256", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Uint256)" },
    .{ .sol_type = "uint", .zig_type = "sdk.Uint256", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Uint256)" },
    .{ .sol_type = "uint8", .zig_type = "u8", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(u8)" },
    .{ .sol_type = "uint16", .zig_type = "u16", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(u16)" },
    .{ .sol_type = "uint24", .zig_type = "sdk.UintN(24)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(24))" },
    .{ .sol_type = "uint32", .zig_type = "u32", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(u32)" },
    .{ .sol_type = "uint40", .zig_type = "sdk.UintN(40)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(40))" },
    .{ .sol_type = "uint48", .zig_type = "sdk.UintN(48)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(48))" },
    .{ .sol_type = "uint56", .zig_type = "sdk.UintN(56)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(56))" },
    .{ .sol_type = "uint64", .zig_type = "u64", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(u64)" },
    .{ .sol_type = "uint72", .zig_type = "sdk.UintN(72)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(72))" },
    .{ .sol_type = "uint80", .zig_type = "sdk.UintN(80)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(80))" },
    .{ .sol_type = "uint88", .zig_type = "sdk.UintN(88)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(88))" },
    .{ .sol_type = "uint96", .zig_type = "sdk.UintN(96)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(96))" },
    .{ .sol_type = "uint104", .zig_type = "sdk.UintN(104)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(104))" },
    .{ .sol_type = "uint112", .zig_type = "sdk.UintN(112)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(112))" },
    .{ .sol_type = "uint120", .zig_type = "sdk.UintN(120)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(120))" },
    .{ .sol_type = "uint128", .zig_type = "u128", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(u128)" },
    .{ .sol_type = "uint136", .zig_type = "sdk.UintN(136)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(136))" },
    .{ .sol_type = "uint144", .zig_type = "sdk.UintN(144)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(144))" },
    .{ .sol_type = "uint152", .zig_type = "sdk.UintN(152)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(152))" },
    .{ .sol_type = "uint160", .zig_type = "sdk.UintN(160)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(160))" },
    .{ .sol_type = "uint168", .zig_type = "sdk.UintN(168)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(168))" },
    .{ .sol_type = "uint176", .zig_type = "sdk.UintN(176)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(176))" },
    .{ .sol_type = "uint184", .zig_type = "sdk.UintN(184)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(184))" },
    .{ .sol_type = "uint192", .zig_type = "sdk.UintN(192)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(192))" },
    .{ .sol_type = "uint200", .zig_type = "sdk.UintN(200)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(200))" },
    .{ .sol_type = "uint208", .zig_type = "sdk.UintN(208)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(208))" },
    .{ .sol_type = "uint216", .zig_type = "sdk.UintN(216)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(216))" },
    .{ .sol_type = "uint224", .zig_type = "sdk.UintN(224)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(224))" },
    .{ .sol_type = "uint232", .zig_type = "sdk.UintN(232)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(232))" },
    .{ .sol_type = "uint240", .zig_type = "sdk.UintN(240)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(240))" },
    .{ .sol_type = "uint248", .zig_type = "sdk.UintN(248)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.UintN(248))" },
    // Signed integers — all widths (multiples of 8)
    .{ .sol_type = "int256", .zig_type = "sdk.Int256", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Int256)" },
    .{ .sol_type = "int", .zig_type = "sdk.Int256", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Int256)" },
    .{ .sol_type = "int8", .zig_type = "i8", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(i8)" },
    .{ .sol_type = "int16", .zig_type = "i16", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(i16)" },
    .{ .sol_type = "int24", .zig_type = "sdk.IntN(24)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(24))" },
    .{ .sol_type = "int32", .zig_type = "i32", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(i32)" },
    .{ .sol_type = "int40", .zig_type = "sdk.IntN(40)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(40))" },
    .{ .sol_type = "int48", .zig_type = "sdk.IntN(48)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(48))" },
    .{ .sol_type = "int56", .zig_type = "sdk.IntN(56)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(56))" },
    .{ .sol_type = "int64", .zig_type = "i64", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(i64)" },
    .{ .sol_type = "int72", .zig_type = "sdk.IntN(72)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(72))" },
    .{ .sol_type = "int80", .zig_type = "sdk.IntN(80)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(80))" },
    .{ .sol_type = "int88", .zig_type = "sdk.IntN(88)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(88))" },
    .{ .sol_type = "int96", .zig_type = "sdk.IntN(96)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(96))" },
    .{ .sol_type = "int104", .zig_type = "sdk.IntN(104)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(104))" },
    .{ .sol_type = "int112", .zig_type = "sdk.IntN(112)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(112))" },
    .{ .sol_type = "int120", .zig_type = "sdk.IntN(120)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(120))" },
    .{ .sol_type = "int128", .zig_type = "i128", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(i128)" },
    .{ .sol_type = "int136", .zig_type = "sdk.IntN(136)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(136))" },
    .{ .sol_type = "int144", .zig_type = "sdk.IntN(144)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(144))" },
    .{ .sol_type = "int152", .zig_type = "sdk.IntN(152)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(152))" },
    .{ .sol_type = "int160", .zig_type = "sdk.IntN(160)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(160))" },
    .{ .sol_type = "int168", .zig_type = "sdk.IntN(168)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(168))" },
    .{ .sol_type = "int176", .zig_type = "sdk.IntN(176)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(176))" },
    .{ .sol_type = "int184", .zig_type = "sdk.IntN(184)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(184))" },
    .{ .sol_type = "int192", .zig_type = "sdk.IntN(192)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(192))" },
    .{ .sol_type = "int200", .zig_type = "sdk.IntN(200)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(200))" },
    .{ .sol_type = "int208", .zig_type = "sdk.IntN(208)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(208))" },
    .{ .sol_type = "int216", .zig_type = "sdk.IntN(216)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(216))" },
    .{ .sol_type = "int224", .zig_type = "sdk.IntN(224)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(224))" },
    .{ .sol_type = "int232", .zig_type = "sdk.IntN(232)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(232))" },
    .{ .sol_type = "int240", .zig_type = "sdk.IntN(240)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(240))" },
    .{ .sol_type = "int248", .zig_type = "sdk.IntN(248)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.IntN(248))" },
    // Address
    .{ .sol_type = "address", .zig_type = "sdk.Address", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Address)" },
    .{ .sol_type = "address payable", .zig_type = "sdk.Address", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Address)" },
    // Boolean
    .{ .sol_type = "bool", .zig_type = "bool", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(bool)" },
    // Fixed-size bytes — all widths 1..32
    .{ .sol_type = "bytes1", .zig_type = "sdk.BytesN(1)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(1))" },
    .{ .sol_type = "bytes2", .zig_type = "sdk.BytesN(2)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(2))" },
    .{ .sol_type = "bytes3", .zig_type = "sdk.BytesN(3)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(3))" },
    .{ .sol_type = "bytes4", .zig_type = "sdk.BytesN(4)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(4))" },
    .{ .sol_type = "bytes5", .zig_type = "sdk.BytesN(5)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(5))" },
    .{ .sol_type = "bytes6", .zig_type = "sdk.BytesN(6)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(6))" },
    .{ .sol_type = "bytes7", .zig_type = "sdk.BytesN(7)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(7))" },
    .{ .sol_type = "bytes8", .zig_type = "sdk.BytesN(8)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(8))" },
    .{ .sol_type = "bytes9", .zig_type = "sdk.BytesN(9)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(9))" },
    .{ .sol_type = "bytes10", .zig_type = "sdk.BytesN(10)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(10))" },
    .{ .sol_type = "bytes11", .zig_type = "sdk.BytesN(11)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(11))" },
    .{ .sol_type = "bytes12", .zig_type = "sdk.BytesN(12)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(12))" },
    .{ .sol_type = "bytes13", .zig_type = "sdk.BytesN(13)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(13))" },
    .{ .sol_type = "bytes14", .zig_type = "sdk.BytesN(14)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(14))" },
    .{ .sol_type = "bytes15", .zig_type = "sdk.BytesN(15)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(15))" },
    .{ .sol_type = "bytes16", .zig_type = "sdk.BytesN(16)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(16))" },
    .{ .sol_type = "bytes17", .zig_type = "sdk.BytesN(17)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(17))" },
    .{ .sol_type = "bytes18", .zig_type = "sdk.BytesN(18)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(18))" },
    .{ .sol_type = "bytes19", .zig_type = "sdk.BytesN(19)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(19))" },
    .{ .sol_type = "bytes20", .zig_type = "sdk.BytesN(20)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(20))" },
    .{ .sol_type = "bytes21", .zig_type = "sdk.BytesN(21)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(21))" },
    .{ .sol_type = "bytes22", .zig_type = "sdk.BytesN(22)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(22))" },
    .{ .sol_type = "bytes23", .zig_type = "sdk.BytesN(23)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(23))" },
    .{ .sol_type = "bytes24", .zig_type = "sdk.BytesN(24)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(24))" },
    .{ .sol_type = "bytes25", .zig_type = "sdk.BytesN(25)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(25))" },
    .{ .sol_type = "bytes26", .zig_type = "sdk.BytesN(26)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(26))" },
    .{ .sol_type = "bytes27", .zig_type = "sdk.BytesN(27)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(27))" },
    .{ .sol_type = "bytes28", .zig_type = "sdk.BytesN(28)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(28))" },
    .{ .sol_type = "bytes29", .zig_type = "sdk.BytesN(29)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(29))" },
    .{ .sol_type = "bytes30", .zig_type = "sdk.BytesN(30)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(30))" },
    .{ .sol_type = "bytes31", .zig_type = "sdk.BytesN(31)", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.BytesN(31))" },
    .{ .sol_type = "bytes32", .zig_type = "sdk.Bytes32", .is_value_type = true, .storage_wrapper = "sdk.StorageSlot(sdk.Bytes32)" },
    // Dynamic types
    .{ .sol_type = "string", .zig_type = "[]const u8", .is_value_type = false, .storage_wrapper = "sdk.StorageString" },
    .{ .sol_type = "bytes", .zig_type = "[]const u8", .is_value_type = false, .storage_wrapper = "sdk.StorageBytes" },
};

// ============================================================================
// Type Resolution Functions
// ============================================================================

/// Map a Solidity type name string to its Zig equivalent
/// Handles primitives, mappings, arrays, and user-defined types
pub fn mapType(type_name: []const u8) []const u8 {
    // Strip whitespace
    const trimmed = std.mem.trim(u8, type_name, " \t\n\r");

    // Check for mapping(K => V)
    if (std.mem.startsWith(u8, trimmed, "mapping(") or std.mem.startsWith(u8, trimmed, "mapping ")) {
        return "Mapping"; // Resolved by codegen with allocator
    }

    // Check for array types: T[] (dynamic) or T[N] (fixed)
    if (std.mem.indexOf(u8, trimmed, "[") != null) {
        return "StorageArray"; // Handled by codegen
    }

    // Check for function type
    if (std.mem.startsWith(u8, trimmed, "function(") or std.mem.startsWith(u8, trimmed, "function ")) {
        return "sdk.BytesN(24)"; // Function pointers are 24 bytes (address + selector)
    }

    // Look up in type table
    for (&DEFAULT_TYPE_MAP) |*entry| {
        if (std.mem.eql(u8, trimmed, entry.sol_type)) {
            return entry.zig_type;
        }
    }

    // Unknown type — user-defined struct, enum, contract, or interface
    return trimmed;
}

/// Map a Solidity type to its storage wrapper type
pub fn mapStorageType(type_name: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, type_name, " \t\n\r");

    if (std.mem.startsWith(u8, trimmed, "mapping(") or std.mem.startsWith(u8, trimmed, "mapping ")) {
        return "Mapping"; // Resolved by codegen with allocator
    }

    if (std.mem.indexOf(u8, trimmed, "[") != null) {
        return "StorageArray";
    }

    for (&DEFAULT_TYPE_MAP) |*entry| {
        if (std.mem.eql(u8, trimmed, entry.sol_type)) {
            return entry.storage_wrapper;
        }
    }

    // User-defined type → wrap in StorageSlot
    return "sdk.StorageSlot(sdk.Uint256)";
}

/// Resolve a mapping type string into structured key/value type strings
/// Input: "mapping(address => uint256)" → key="address", value="uint256"
/// Handles nested: "mapping(address => mapping(address => uint256))"
pub fn parseMappingTypes(type_name: []const u8) ?struct { key: []const u8, value: []const u8 } {
    const trimmed = std.mem.trim(u8, type_name, " \t\n\r");
    if (!std.mem.startsWith(u8, trimmed, "mapping(")) return null;

    // Find the matching closing paren
    var depth: usize = 0;
    var arrow_pos: ?usize = null;
    var end_pos: usize = trimmed.len;

    for (trimmed, 0..) |c, i| {
        if (c == '(') depth += 1;
        if (c == ')') {
            depth -= 1;
            if (depth == 0) {
                end_pos = i;
                break;
            }
        }
        if (depth == 1 and i + 1 < trimmed.len and c == '=' and trimmed[i + 1] == '>') {
            arrow_pos = i;
        }
    }

    const ap = arrow_pos orelse return null;
    const open = std.mem.indexOfScalar(u8, trimmed, '(') orelse return null;
    const key = std.mem.trim(u8, trimmed[open + 1 .. ap], " \t\n\r");
    const value = std.mem.trim(u8, trimmed[ap + 2 .. end_pos], " \t\n\r");

    return .{ .key = key, .value = value };
}

/// Resolve array element type. Input: "uint256[]" → "uint256", "address[10]" → "address"
pub fn parseArrayBaseType(type_name: []const u8) ?[]const u8 {
    const bracket_pos = std.mem.lastIndexOfScalar(u8, type_name, '[') orelse return null;
    if (bracket_pos == 0) return null;
    return std.mem.trim(u8, type_name[0..bracket_pos], " \t\n\r");
}

/// Check if a type is a value type (fits in a single slot)
pub fn isValueType(type_name: []const u8) bool {
    for (&DEFAULT_TYPE_MAP) |*entry| {
        if (std.mem.eql(u8, type_name, entry.sol_type)) {
            return entry.is_value_type;
        }
    }
    return false;
}

// ============================================================================
// Operator Mapping
// ============================================================================

/// Map Solidity operator to Zig SDK method call
pub fn mapOperator(op: []const u8, checked: bool) []const u8 {
    if (checked) {
        if (std.mem.eql(u8, op, "+")) return ".checkedAdd";
        if (std.mem.eql(u8, op, "-")) return ".checkedSub";
        if (std.mem.eql(u8, op, "*")) return ".checkedMul";
        if (std.mem.eql(u8, op, "/")) return ".checkedDiv";
    } else {
        if (std.mem.eql(u8, op, "+")) return ".add";
        if (std.mem.eql(u8, op, "-")) return ".sub";
        if (std.mem.eql(u8, op, "*")) return ".mul";
        if (std.mem.eql(u8, op, "/")) return ".div";
    }
    if (std.mem.eql(u8, op, "%")) return ".mod";
    if (std.mem.eql(u8, op, "**")) return "sdk.Uint256.exp";
    if (std.mem.eql(u8, op, "==")) return ".eql";
    if (std.mem.eql(u8, op, "!=")) return "!.eql";
    if (std.mem.eql(u8, op, "<")) return ".lt";
    if (std.mem.eql(u8, op, ">")) return ".gt";
    if (std.mem.eql(u8, op, "<=")) return ".lte";
    if (std.mem.eql(u8, op, ">=")) return ".gte";
    if (std.mem.eql(u8, op, "&")) return ".bitwiseAnd";
    if (std.mem.eql(u8, op, "|")) return ".bitwiseOr";
    if (std.mem.eql(u8, op, "^")) return ".bitwiseXor";
    if (std.mem.eql(u8, op, "<<")) return ".shl";
    if (std.mem.eql(u8, op, ">>")) return ".shr";
    if (std.mem.eql(u8, op, "&&")) return "and";
    if (std.mem.eql(u8, op, "||")) return "or";
    return op;
}

// ============================================================================
// Global / Built-in / Member Mapping
// ============================================================================

/// Map Solidity global variable to SDK equivalent
pub fn mapGlobal(global: []const u8) []const u8 {
    if (std.mem.eql(u8, global, "msg.sender")) return "ctx.msg_sender";
    if (std.mem.eql(u8, global, "msg.value")) return "ctx.msg_value";
    if (std.mem.eql(u8, global, "msg.data")) return "ctx.msg_data";
    if (std.mem.eql(u8, global, "msg.sig")) return "ctx.msg_sig";
    if (std.mem.eql(u8, global, "tx.origin")) return "ctx.tx_origin";
    if (std.mem.eql(u8, global, "tx.gasprice")) return "ctx.tx_gasprice";
    if (std.mem.eql(u8, global, "block.number")) return "ctx.block_number";
    if (std.mem.eql(u8, global, "block.timestamp")) return "ctx.block_timestamp";
    if (std.mem.eql(u8, global, "block.coinbase")) return "ctx.block_coinbase";
    if (std.mem.eql(u8, global, "block.gaslimit")) return "ctx.block_gaslimit";
    if (std.mem.eql(u8, global, "block.basefee")) return "ctx.block_basefee";
    if (std.mem.eql(u8, global, "block.chainid")) return "ctx.block_chainid";
    if (std.mem.eql(u8, global, "block.prevrandao")) return "ctx.block_prevrandao";
    if (std.mem.eql(u8, global, "block.difficulty")) return "ctx.block_prevrandao";
    if (std.mem.eql(u8, global, "now")) return "ctx.block_timestamp"; // Deprecated alias
    return global;
}

/// Map Solidity built-in function to SDK equivalent
pub fn mapBuiltin(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "keccak256")) return "sdk.keccak256";
    if (std.mem.eql(u8, name, "sha256")) return "sdk.sha256";
    if (std.mem.eql(u8, name, "ripemd160")) return "sdk.ripemd160";
    if (std.mem.eql(u8, name, "ecrecover")) return "sdk.ecrecover";
    if (std.mem.eql(u8, name, "addmod")) return "sdk.addmod";
    if (std.mem.eql(u8, name, "mulmod")) return "sdk.mulmod_fn";
    if (std.mem.eql(u8, name, "require")) return "sdk.require";
    if (std.mem.eql(u8, name, "revert")) return "sdk.revert";
    if (std.mem.eql(u8, name, "assert")) return "sdk.assert_";
    if (std.mem.eql(u8, name, "gasleft")) return "ctx.gasLeft";
    if (std.mem.eql(u8, name, "selfdestruct")) return "ctx.selfDestruct";
    if (std.mem.eql(u8, name, "this")) return "ctx.self_address";
    if (std.mem.eql(u8, name, "blockhash")) return "ctx.blockHash";
    if (std.mem.eql(u8, name, "type")) return "sdk.typeInfo";
    return name;
}

/// Map Solidity address member to SDK equivalent
pub fn mapAddressMember(member: []const u8) []const u8 {
    if (std.mem.eql(u8, member, "balance")) return "sdk.context.getBalance";
    if (std.mem.eql(u8, member, "code")) return "sdk.context.getCode";
    if (std.mem.eql(u8, member, "codehash")) return "sdk.context.getCodeHash";
    if (std.mem.eql(u8, member, "transfer")) return "sdk.transfer";
    if (std.mem.eql(u8, member, "send")) return "sdk.send";
    if (std.mem.eql(u8, member, "call")) return "ctx.call";
    if (std.mem.eql(u8, member, "delegatecall")) return "ctx.delegatecall";
    if (std.mem.eql(u8, member, "staticcall")) return "ctx.staticcall";
    return member;
}

/// Map abi.X functions
pub fn mapAbiFunction(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "encode")) return "sdk.abi.encode";
    if (std.mem.eql(u8, name, "decode")) return "sdk.abi.decode";
    if (std.mem.eql(u8, name, "encodePacked")) return "sdk.abi.encodePacked";
    if (std.mem.eql(u8, name, "encodeWithSelector")) return "sdk.abi.encodeWithSelector";
    if (std.mem.eql(u8, name, "encodeWithSignature")) return "sdk.abi.encodeWithSignature";
    if (std.mem.eql(u8, name, "encodeCall")) return "sdk.abi.encodeCall";
    return name;
}

/// Map type(X).member access
pub fn mapTypeInfo(member: []const u8) []const u8 {
    if (std.mem.eql(u8, member, "min")) return "MIN";
    if (std.mem.eql(u8, member, "max")) return "MAX";
    if (std.mem.eql(u8, member, "interfaceId")) return "INTERFACE_ID";
    if (std.mem.eql(u8, member, "name")) return "NAME";
    if (std.mem.eql(u8, member, "creationCode")) return "CREATION_CODE";
    if (std.mem.eql(u8, member, "runtimeCode")) return "RUNTIME_CODE";
    return member;
}

/// Map string/bytes member functions
pub fn mapStringMember(member: []const u8) []const u8 {
    if (std.mem.eql(u8, member, "length")) return "len";
    if (std.mem.eql(u8, member, "concat")) return "sdk.bytes.concat";
    return member;
}

/// Map array member functions
pub fn mapArrayMember(member: []const u8) []const u8 {
    if (std.mem.eql(u8, member, "length")) return "length";
    if (std.mem.eql(u8, member, "push")) return "push";
    if (std.mem.eql(u8, member, "pop")) return "pop";
    return member;
}
