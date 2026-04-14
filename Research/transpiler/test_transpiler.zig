// File: tests/test_transpiler.zig
// Comprehensive test suite for the sol2zig transpiler
// Tests parser, codegen, type mapper, selector, and end-to-end transpilation

const std = @import("std");
const parser = @import("parser.zig");
const codegen = @import("codegen.zig");
const type_mapper = @import("type_mapper.zig");
const selector = @import("selector.zig");
const validation = @import("validation.zig");
const inheritance = @import("inheritance.zig");
const abi_gen = @import("abi_gen.zig");

// ============================================================================
// Type Mapper Tests
// ============================================================================

test "mapType: all standard uint widths" {
    try std.testing.expectEqualStrings("sdk.Uint256", type_mapper.mapType("uint256"));
    try std.testing.expectEqualStrings("sdk.Uint256", type_mapper.mapType("uint"));
    try std.testing.expectEqualStrings("u8", type_mapper.mapType("uint8"));
    try std.testing.expectEqualStrings("u16", type_mapper.mapType("uint16"));
    try std.testing.expectEqualStrings("sdk.UintN(24)", type_mapper.mapType("uint24"));
    try std.testing.expectEqualStrings("u32", type_mapper.mapType("uint32"));
    try std.testing.expectEqualStrings("u64", type_mapper.mapType("uint64"));
    try std.testing.expectEqualStrings("u128", type_mapper.mapType("uint128"));
    try std.testing.expectEqualStrings("sdk.UintN(160)", type_mapper.mapType("uint160"));
    try std.testing.expectEqualStrings("sdk.UintN(248)", type_mapper.mapType("uint248"));
}

test "mapType: all standard int widths" {
    try std.testing.expectEqualStrings("sdk.Int256", type_mapper.mapType("int256"));
    try std.testing.expectEqualStrings("sdk.Int256", type_mapper.mapType("int"));
    try std.testing.expectEqualStrings("i8", type_mapper.mapType("int8"));
    try std.testing.expectEqualStrings("i16", type_mapper.mapType("int16"));
    try std.testing.expectEqualStrings("sdk.IntN(24)", type_mapper.mapType("int24"));
    try std.testing.expectEqualStrings("i64", type_mapper.mapType("int64"));
    try std.testing.expectEqualStrings("i128", type_mapper.mapType("int128"));
}

test "mapType: all bytesN widths" {
    try std.testing.expectEqualStrings("sdk.BytesN(1)", type_mapper.mapType("bytes1"));
    try std.testing.expectEqualStrings("sdk.BytesN(4)", type_mapper.mapType("bytes4"));
    try std.testing.expectEqualStrings("sdk.BytesN(20)", type_mapper.mapType("bytes20"));
    try std.testing.expectEqualStrings("sdk.Bytes32", type_mapper.mapType("bytes32"));
}

test "mapType: address and bool" {
    try std.testing.expectEqualStrings("sdk.Address", type_mapper.mapType("address"));
    try std.testing.expectEqualStrings("sdk.Address", type_mapper.mapType("address payable"));
    try std.testing.expectEqualStrings("bool", type_mapper.mapType("bool"));
}

test "mapType: dynamic types" {
    try std.testing.expectEqualStrings("[]const u8", type_mapper.mapType("string"));
    try std.testing.expectEqualStrings("[]const u8", type_mapper.mapType("bytes"));
}

test "mapType: mapping and array types" {
    try std.testing.expectEqualStrings("Mapping", type_mapper.mapType("mapping(address => uint256)"));
    try std.testing.expectEqualStrings("StorageArray", type_mapper.mapType("uint256[]"));
    try std.testing.expectEqualStrings("StorageArray", type_mapper.mapType("address[10]"));
}

test "mapType: unknown user-defined type passthrough" {
    try std.testing.expectEqualStrings("MyStruct", type_mapper.mapType("MyStruct"));
    try std.testing.expectEqualStrings("IERC20", type_mapper.mapType("IERC20"));
}

test "parseMappingTypes: simple mapping" {
    const result = type_mapper.parseMappingTypes("mapping(address => uint256)");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("address", result.?.key);
    try std.testing.expectEqualStrings("uint256", result.?.value);
}

test "parseMappingTypes: nested mapping" {
    const result = type_mapper.parseMappingTypes("mapping(address => mapping(address => uint256))");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("address", result.?.key);
    // Value contains the nested mapping
    try std.testing.expect(std.mem.startsWith(u8, result.?.value, "mapping("));
}

test "parseMappingTypes: non-mapping returns null" {
    const result = type_mapper.parseMappingTypes("uint256");
    try std.testing.expect(result == null);
}

test "parseArrayBaseType: dynamic array" {
    const result = type_mapper.parseArrayBaseType("uint256[]");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("uint256", result.?);
}

test "parseArrayBaseType: fixed-size array" {
    const result = type_mapper.parseArrayBaseType("address[10]");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("address", result.?);
}

test "isValueType: standard value types" {
    try std.testing.expect(type_mapper.isValueType("uint256"));
    try std.testing.expect(type_mapper.isValueType("address"));
    try std.testing.expect(type_mapper.isValueType("bool"));
    try std.testing.expect(type_mapper.isValueType("bytes32"));
    try std.testing.expect(!type_mapper.isValueType("string"));
    try std.testing.expect(!type_mapper.isValueType("bytes"));
    try std.testing.expect(!type_mapper.isValueType("MyStruct"));
}

// ============================================================================
// Operator Mapping Tests
// ============================================================================

test "mapOperator: checked arithmetic" {
    try std.testing.expectEqualStrings(".checkedAdd", type_mapper.mapOperator("+", true));
    try std.testing.expectEqualStrings(".checkedSub", type_mapper.mapOperator("-", true));
    try std.testing.expectEqualStrings(".checkedMul", type_mapper.mapOperator("*", true));
    try std.testing.expectEqualStrings(".checkedDiv", type_mapper.mapOperator("/", true));
}

test "mapOperator: unchecked arithmetic" {
    try std.testing.expectEqualStrings(".add", type_mapper.mapOperator("+", false));
    try std.testing.expectEqualStrings(".sub", type_mapper.mapOperator("-", false));
    try std.testing.expectEqualStrings(".mul", type_mapper.mapOperator("*", false));
    try std.testing.expectEqualStrings(".div", type_mapper.mapOperator("/", false));
}

test "mapOperator: comparison operators" {
    try std.testing.expectEqualStrings(".eql", type_mapper.mapOperator("==", false));
    try std.testing.expectEqualStrings("!.eql", type_mapper.mapOperator("!=", false));
    try std.testing.expectEqualStrings(".lt", type_mapper.mapOperator("<", false));
    try std.testing.expectEqualStrings(".gt", type_mapper.mapOperator(">", false));
    try std.testing.expectEqualStrings(".lte", type_mapper.mapOperator("<=", false));
    try std.testing.expectEqualStrings(".gte", type_mapper.mapOperator(">=", false));
}

test "mapOperator: bitwise operators" {
    try std.testing.expectEqualStrings(".bitwiseAnd", type_mapper.mapOperator("&", false));
    try std.testing.expectEqualStrings(".bitwiseOr", type_mapper.mapOperator("|", false));
    try std.testing.expectEqualStrings(".bitwiseXor", type_mapper.mapOperator("^", false));
    try std.testing.expectEqualStrings(".shl", type_mapper.mapOperator("<<", false));
    try std.testing.expectEqualStrings(".shr", type_mapper.mapOperator(">>", false));
}

test "mapOperator: logical operators" {
    try std.testing.expectEqualStrings("and", type_mapper.mapOperator("&&", false));
    try std.testing.expectEqualStrings("or", type_mapper.mapOperator("||", false));
}

// ============================================================================
// Global / Builtin Mapping Tests
// ============================================================================

test "mapGlobal: msg members" {
    try std.testing.expectEqualStrings("ctx.msg_sender", type_mapper.mapGlobal("msg.sender"));
    try std.testing.expectEqualStrings("ctx.msg_value", type_mapper.mapGlobal("msg.value"));
    try std.testing.expectEqualStrings("ctx.msg_data", type_mapper.mapGlobal("msg.data"));
    try std.testing.expectEqualStrings("ctx.msg_sig", type_mapper.mapGlobal("msg.sig"));
}

test "mapGlobal: block members" {
    try std.testing.expectEqualStrings("ctx.block_number", type_mapper.mapGlobal("block.number"));
    try std.testing.expectEqualStrings("ctx.block_timestamp", type_mapper.mapGlobal("block.timestamp"));
    try std.testing.expectEqualStrings("ctx.block_coinbase", type_mapper.mapGlobal("block.coinbase"));
    try std.testing.expectEqualStrings("ctx.block_prevrandao", type_mapper.mapGlobal("block.prevrandao"));
    try std.testing.expectEqualStrings("ctx.block_prevrandao", type_mapper.mapGlobal("block.difficulty"));
}

test "mapGlobal: tx members" {
    try std.testing.expectEqualStrings("ctx.tx_origin", type_mapper.mapGlobal("tx.origin"));
    try std.testing.expectEqualStrings("ctx.tx_gasprice", type_mapper.mapGlobal("tx.gasprice"));
}

test "mapGlobal: deprecated now alias" {
    try std.testing.expectEqualStrings("ctx.block_timestamp", type_mapper.mapGlobal("now"));
}

test "mapBuiltin: require/revert/assert" {
    try std.testing.expectEqualStrings("sdk.require", type_mapper.mapBuiltin("require"));
    try std.testing.expectEqualStrings("sdk.revert", type_mapper.mapBuiltin("revert"));
    try std.testing.expectEqualStrings("sdk.assert_", type_mapper.mapBuiltin("assert"));
}

test "mapBuiltin: crypto functions" {
    try std.testing.expectEqualStrings("sdk.keccak256", type_mapper.mapBuiltin("keccak256"));
    try std.testing.expectEqualStrings("sdk.sha256", type_mapper.mapBuiltin("sha256"));
    try std.testing.expectEqualStrings("sdk.ecrecover", type_mapper.mapBuiltin("ecrecover"));
}

test "mapAddressMember: all address operations" {
    try std.testing.expectEqualStrings("sdk.context.getBalance", type_mapper.mapAddressMember("balance"));
    try std.testing.expectEqualStrings("sdk.transfer", type_mapper.mapAddressMember("transfer"));
    try std.testing.expectEqualStrings("sdk.send", type_mapper.mapAddressMember("send"));
    try std.testing.expectEqualStrings("ctx.call", type_mapper.mapAddressMember("call"));
    try std.testing.expectEqualStrings("ctx.delegatecall", type_mapper.mapAddressMember("delegatecall"));
    try std.testing.expectEqualStrings("ctx.staticcall", type_mapper.mapAddressMember("staticcall"));
}

test "mapAbiFunction: all abi functions" {
    try std.testing.expectEqualStrings("sdk.abi.encode", type_mapper.mapAbiFunction("encode"));
    try std.testing.expectEqualStrings("sdk.abi.decode", type_mapper.mapAbiFunction("decode"));
    try std.testing.expectEqualStrings("sdk.abi.encodePacked", type_mapper.mapAbiFunction("encodePacked"));
    try std.testing.expectEqualStrings("sdk.abi.encodeCall", type_mapper.mapAbiFunction("encodeCall"));
}

test "mapTypeInfo: type info members" {
    try std.testing.expectEqualStrings("MIN", type_mapper.mapTypeInfo("min"));
    try std.testing.expectEqualStrings("MAX", type_mapper.mapTypeInfo("max"));
    try std.testing.expectEqualStrings("INTERFACE_ID", type_mapper.mapTypeInfo("interfaceId"));
}

// ============================================================================
// Selector Computation Tests
// ============================================================================

test "computeSelector: known ERC20 selectors" {
    // transfer(address,uint256) → 0xa9059cbb
    const transfer_sel = selector.computeSelector("transfer(address,uint256)");
    try std.testing.expectEqual(@as(u8, 0xa9), transfer_sel[0]);
    try std.testing.expectEqual(@as(u8, 0x05), transfer_sel[1]);
    try std.testing.expectEqual(@as(u8, 0x9c), transfer_sel[2]);
    try std.testing.expectEqual(@as(u8, 0xbb), transfer_sel[3]);

    // approve(address,uint256) → 0x095ea7b3
    const approve_sel = selector.computeSelector("approve(address,uint256)");
    try std.testing.expectEqual(@as(u8, 0x09), approve_sel[0]);
    try std.testing.expectEqual(@as(u8, 0x5e), approve_sel[1]);
    try std.testing.expectEqual(@as(u8, 0xa7), approve_sel[2]);
    try std.testing.expectEqual(@as(u8, 0xb3), approve_sel[3]);

    // balanceOf(address) → 0x70a08231
    const balance_sel = selector.computeSelector("balanceOf(address)");
    try std.testing.expectEqual(@as(u8, 0x70), balance_sel[0]);
    try std.testing.expectEqual(@as(u8, 0xa0), balance_sel[1]);
    try std.testing.expectEqual(@as(u8, 0x82), balance_sel[2]);
    try std.testing.expectEqual(@as(u8, 0x31), balance_sel[3]);
}

test "computeSelector: totalSupply()" {
    // totalSupply() → 0x18160ddd
    const sel = selector.computeSelector("totalSupply()");
    try std.testing.expectEqual(@as(u8, 0x18), sel[0]);
    try std.testing.expectEqual(@as(u8, 0x16), sel[1]);
    try std.testing.expectEqual(@as(u8, 0x0d), sel[2]);
    try std.testing.expectEqual(@as(u8, 0xdd), sel[3]);
}

test "selectorToHex: formatting" {
    const sel = [4]u8{ 0xa9, 0x05, 0x9c, 0xbb };
    const hex = selector.selectorToHex(sel);
    try std.testing.expectEqualStrings("0xa9059cbb", &hex);
}

// ============================================================================
// Parser Tests — verify parsing doesn't error on valid Solidity
// ============================================================================

test "parser: minimal contract" {
    const source = "contract Foo { }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items.len);
    try std.testing.expectEqualStrings("Foo", ast.contracts.items[0].name);
}

test "parser: contract with state variable" {
    const source = "contract Token { uint256 public totalSupply; }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items.len);
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items[0].state_variables.items.len);
    try std.testing.expectEqualStrings("totalSupply", ast.contracts.items[0].state_variables.items[0].name);
}

test "parser: contract with function" {
    const source =
        \\contract Token {
        \\    function transfer(address to, uint256 amount) public returns (bool) {
        \\        return true;
        \\    }
        \\}
    ;
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items.len);
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items[0].functions.items.len);
    try std.testing.expectEqualStrings("transfer", ast.contracts.items[0].functions.items[0].name);
}

test "parser: contract with event" {
    const source = "contract Token { event Transfer(address indexed from, address indexed to, uint256 value); }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items[0].events.items.len);
    try std.testing.expectEqualStrings("Transfer", ast.contracts.items[0].events.items[0].name);
}

test "parser: contract with enum" {
    const source = "contract Token { enum Status { Active, Paused, Stopped } }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items[0].enums.items.len);
    try std.testing.expectEqualStrings("Status", ast.contracts.items[0].enums.items[0].name);
}

test "parser: contract with struct" {
    const source = "contract Token { struct Order { address buyer; uint256 amount; } }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items[0].structs.items.len);
    try std.testing.expectEqualStrings("Order", ast.contracts.items[0].structs.items[0].name);
}

test "parser: pragma is skipped" {
    const source = "pragma solidity ^0.8.0; contract Foo { }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.contracts.items.len);
}

test "parser: multiple contracts" {
    const source = "contract A { } contract B { }";
    var ast = try parser.parse(std.testing.allocator, source);
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 2), ast.contracts.items.len);
    try std.testing.expectEqualStrings("A", ast.contracts.items[0].name);
    try std.testing.expectEqualStrings("B", ast.contracts.items[1].name);
}

// ============================================================================
// Codegen Tests — verify output contains expected Zig patterns
// ============================================================================

test "codegen: minimal contract produces struct" {
    const source = "contract Foo { }";
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var gen = codegen.CodeGenerator.init(std.testing.allocator, &ast_result, &type_mapper.DEFAULT_TYPE_MAP);
    defer gen.deinit();
    const output = try gen.generate();

    try std.testing.expect(std.mem.indexOf(u8, output, "pub const Foo = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "};") != null);
}

test "codegen: state variable becomes struct field" {
    const source = "contract Token { uint256 totalSupply; }";
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var gen = codegen.CodeGenerator.init(std.testing.allocator, &ast_result, &type_mapper.DEFAULT_TYPE_MAP);
    defer gen.deinit();
    const output = try gen.generate();

    try std.testing.expect(std.mem.indexOf(u8, output, "totalSupply") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sdk.StorageSlot(sdk.Uint256)") != null);
}

test "codegen: event emits SDK Event type" {
    const source = "contract Token { event Transfer(address indexed from, address indexed to, uint256 value); }";
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var gen = codegen.CodeGenerator.init(std.testing.allocator, &ast_result, &type_mapper.DEFAULT_TYPE_MAP);
    defer gen.deinit();
    const output = try gen.generate();

    try std.testing.expect(std.mem.indexOf(u8, output, "pub const Transfer = sdk.Event(\"Transfer\"") != null);
}

test "codegen: function generates pub fn" {
    const source =
        \\contract Token {
        \\    function name() public view returns (string memory) {
        \\        return "Token";
        \\    }
        \\}
    ;
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var gen = codegen.CodeGenerator.init(std.testing.allocator, &ast_result, &type_mapper.DEFAULT_TYPE_MAP);
    defer gen.deinit();
    const output = try gen.generate();

    try std.testing.expect(std.mem.indexOf(u8, output, "pub fn name(") != null);
}

test "codegen: SDK import is present" {
    const source = "contract Foo { }";
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var gen = codegen.CodeGenerator.init(std.testing.allocator, &ast_result, &type_mapper.DEFAULT_TYPE_MAP);
    defer gen.deinit();
    const output = try gen.generate();

    try std.testing.expect(std.mem.indexOf(u8, output, "@import(\"zephyria-sdk\")") != null);
}

// ============================================================================
// Validation Tests
// ============================================================================

test "validation: fixed-point type error" {
    const source = "contract Foo { fixed x; }";
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var diags = try validation.validate(std.testing.allocator, &ast_result);
    defer diags.deinit();

    try std.testing.expect(diags.hasErrors());
}

test "validation: clean contract has no errors" {
    const source = "contract Foo { uint256 x; }";
    var ast_result = try parser.parse(std.testing.allocator, source);
    defer ast_result.deinit();

    var diags = try validation.validate(std.testing.allocator, &ast_result);
    defer diags.deinit();

    try std.testing.expect(!diags.hasErrors());
}

// ============================================================================
// Storage Type Mapping Tests
// ============================================================================

test "mapStorageType: value types" {
    try std.testing.expectEqualStrings("sdk.StorageSlot(sdk.Uint256)", type_mapper.mapStorageType("uint256"));
    try std.testing.expectEqualStrings("sdk.StorageSlot(sdk.Address)", type_mapper.mapStorageType("address"));
    try std.testing.expectEqualStrings("sdk.StorageSlot(bool)", type_mapper.mapStorageType("bool"));
}

test "mapStorageType: dynamic types" {
    try std.testing.expectEqualStrings("sdk.StorageString", type_mapper.mapStorageType("string"));
    try std.testing.expectEqualStrings("sdk.StorageBytes", type_mapper.mapStorageType("bytes"));
}

test "mapStorageType: mapping" {
    try std.testing.expectEqualStrings("Mapping", type_mapper.mapStorageType("mapping(address => uint256)"));
}
