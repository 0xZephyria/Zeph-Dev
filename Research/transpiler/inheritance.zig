// File: tools/sol2zig/inheritance.zig
// Solidity inheritance resolution for the transpiler
// Implements C3 linearization, diamond resolution, super calls, constructor chaining

const std = @import("std");
const parser = @import("parser.zig");

/// Resolve inheritance for all contracts in the AST
/// This modifies contracts in-place, merging inherited members
pub fn resolveInheritance(allocator: std.mem.Allocator, ast: *parser.SolidityAST) void {
    // Build name → contract index map
    var name_map = std.StringHashMap(usize).init(allocator);
    defer name_map.deinit();

    for (ast.contracts.items, 0..) |contract, i| {
        name_map.put(contract.name, i) catch continue;
    }

    // Process each contract in topological order (bases first)
    const order = topologicalSort(allocator, ast, &name_map);
    defer allocator.free(order);

    for (order) |idx| {
        const contract = &ast.contracts.items[idx];
        if (contract.base_contracts.items.len == 0) continue;

        // C3 linearization order
        const linearized = linearize(allocator, contract.*, ast, &name_map);
        defer allocator.free(linearized);

        // Merge inherited members in linearization order (most-base-first)
        for (linearized) |base_idx| {
            const base = ast.contracts.items[base_idx];
            mergeStateVariables(allocator, contract, base);
            mergeFunctions(allocator, contract, base);
            mergeEvents(allocator, contract, base);
            mergeModifiers(allocator, contract, base);
            mergeErrors(allocator, contract, base);
            mergeStructs(allocator, contract, base);
            mergeEnums(allocator, contract, base);
        }
    }
}

/// Get the C3 linearization (Method Resolution Order) for a contract
pub fn getMRO(
    allocator: std.mem.Allocator,
    contract: parser.ContractDef,
    ast: *const parser.SolidityAST,
    name_map: *const std.StringHashMap(usize),
) []usize {
    return linearize(allocator, contract, ast, name_map);
}

/// Get the next contract in MRO for super call resolution
/// Returns the contract name that `super.funcName()` should dispatch to
pub fn resolveSuperCall(
    allocator: std.mem.Allocator,
    current_contract: parser.ContractDef,
    func_name: []const u8,
    ast: *const parser.SolidityAST,
    name_map: *const std.StringHashMap(usize),
) ?[]const u8 {
    const mro = linearize(allocator, current_contract, ast, name_map);
    defer allocator.free(mro);

    // Find the next contract in MRO that has this function
    for (mro) |base_idx| {
        const base = ast.contracts.items[base_idx];
        for (base.functions.items) |func| {
            if (std.mem.eql(u8, func.name, func_name) and func.visibility != .private) {
                return base.name;
            }
        }
    }
    return null;
}

/// Resolve constructor chaining order
/// Returns list of (contract_name, constructor_args?) pairs
pub fn resolveConstructorChain(
    allocator: std.mem.Allocator,
    contract: parser.ContractDef,
    ast: *const parser.SolidityAST,
    name_map: *const std.StringHashMap(usize),
) []ConstructorCall {
    var calls = std.ArrayListUnmanaged(ConstructorCall){};

    const mro = linearize(allocator, contract, ast, name_map);
    defer allocator.free(mro);

    // Walk MRO in reverse (most-base-first for constructor calls)
    var i: usize = mro.len;
    while (i > 0) {
        i -= 1;
        const base = ast.contracts.items[mro[i]];
        // Check if the base has a constructor
        for (base.functions.items) |func| {
            if (func.kind == .constructor) {
                calls.append(allocator, .{
                    .contract_name = base.name,
                    .has_constructor = true,
                }) catch continue;
                break;
            }
        }
    }

    return calls.toOwnedSlice(allocator) catch &[_]ConstructorCall{};
}

pub const ConstructorCall = struct {
    contract_name: []const u8,
    has_constructor: bool,
};

/// Check if contract satisfies an interface (has all required functions)
pub fn checkInterfaceCompliance(
    allocator: std.mem.Allocator,
    contract: parser.ContractDef,
    interface: parser.ContractDef,
) []const []const u8 {
    var missing = std.ArrayListUnmanaged([]const u8){};

    for (interface.functions.items) |iface_fn| {
        if (iface_fn.kind == .constructor) continue;
        var found = false;
        for (contract.functions.items) |impl_fn| {
            if (std.mem.eql(u8, impl_fn.name, iface_fn.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            missing.append(allocator, iface_fn.name) catch continue;
        }
    }

    return missing.toOwnedSlice(allocator) catch &[_][]const u8{};
}

// ============================================================================
// Topological Sort — process bases before derived
// ============================================================================

fn topologicalSort(
    allocator: std.mem.Allocator,
    ast: *const parser.SolidityAST,
    name_map: *const std.StringHashMap(usize),
) []usize {
    const n = ast.contracts.items.len;
    const visited = allocator.alloc(bool, n) catch return &[_]usize{};
    defer allocator.free(visited);
    @memset(visited, false);

    var result = std.ArrayListUnmanaged(usize){};

    for (0..n) |i| {
        if (!visited[i]) {
            topoVisit(allocator, i, ast, name_map, visited, &result);
        }
    }

    return result.toOwnedSlice(allocator) catch &[_]usize{};
}

fn topoVisit(
    allocator: std.mem.Allocator,
    idx: usize,
    ast: *const parser.SolidityAST,
    name_map: *const std.StringHashMap(usize),
    visited: []bool,
    result: *std.ArrayListUnmanaged(usize),
) void {
    if (visited[idx]) return;
    visited[idx] = true;

    const contract = ast.contracts.items[idx];
    for (contract.base_contracts.items) |base_name| {
        if (name_map.get(base_name)) |base_idx| {
            topoVisit(allocator, base_idx, ast, name_map, visited, result);
        }
    }

    result.append(allocator, idx) catch {};
}

// ============================================================================
// C3 Linearization
// ============================================================================

/// C3 linearization algorithm
/// Returns indices of base contracts in MRO order
fn linearize(
    allocator: std.mem.Allocator,
    contract: parser.ContractDef,
    ast: *const parser.SolidityAST,
    name_map: *const std.StringHashMap(usize),
) []usize {
    var result = std.ArrayListUnmanaged(usize){};

    // Iterate base contracts in declared order
    for (contract.base_contracts.items) |base_name| {
        if (name_map.get(base_name)) |base_idx| {
            // Recursively linearize base
            const base = ast.contracts.items[base_idx];
            const base_linear = linearize(allocator, base, ast, name_map);
            defer allocator.free(base_linear);

            // Add bases that aren't already in result (preserving order)
            for (base_linear) |idx| {
                if (!containsValue(result.items, idx)) {
                    result.append(allocator, idx) catch continue;
                }
            }

            // Add the base itself
            if (!containsValue(result.items, base_idx)) {
                result.append(allocator, base_idx) catch continue;
            }
        }
    }

    return result.toOwnedSlice(allocator) catch &[_]usize{};
}

fn containsValue(slice: []const usize, value: usize) bool {
    for (slice) |item| {
        if (item == value) return true;
    }
    return false;
}

// ============================================================================
// Member Merging
// ============================================================================

/// Merge state variables from base into derived (if not already present)
fn mergeStateVariables(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.state_variables.items) |base_sv| {
        var found = false;
        for (derived.state_variables.items) |sv| {
            if (std.mem.eql(u8, sv.name, base_sv.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            // Prepend base variable (inherited variables come first in storage layout)
            derived.state_variables.insert(allocator, 0, base_sv) catch continue;
        }
    }
}

/// Merge functions from base into derived (virtual/override handling)
fn mergeFunctions(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.functions.items) |base_fn| {
        var found = false;
        var found_idx: usize = 0;
        for (derived.functions.items, 0..) |func, i| {
            if (std.mem.eql(u8, func.name, base_fn.name)) {
                found = true;
                found_idx = i;
                break;
            }
        }
        if (found) {
            // If the existing function is a stub (no body) but the base has
            // an implementation, replace the stub with the real implementation.
            // This handles: IERC20 (interface, no body) vs ERC20 (concrete, has body).
            if (derived.functions.items[found_idx].body == null and base_fn.body != null) {
                derived.functions.items[found_idx] = base_fn;
            }
        } else if (base_fn.visibility != .private) {
            derived.functions.append(allocator, base_fn) catch continue;
        }
    }
}

/// Merge events from base into derived
fn mergeEvents(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.events.items) |base_event| {
        var found = false;
        for (derived.events.items) |event| {
            if (std.mem.eql(u8, event.name, base_event.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            derived.events.append(allocator, base_event) catch continue;
        }
    }
}

/// Merge modifiers from base into derived
fn mergeModifiers(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.modifiers.items) |base_mod| {
        const found = blk: {
            for (derived.modifiers.items) |mod| {
                if (std.mem.eql(u8, mod.name, base_mod.name)) break :blk true;
            }
            break :blk false;
        };
        if (!found) {
            derived.modifiers.append(allocator, base_mod) catch continue;
        }
    }
}

/// Merge custom errors from base into derived
fn mergeErrors(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.errors_list.items) |base_err| {
        const found = blk: {
            for (derived.errors_list.items) |err| {
                if (std.mem.eql(u8, err.name, base_err.name)) break :blk true;
            }
            break :blk false;
        };
        if (!found) {
            derived.errors_list.append(allocator, base_err) catch continue;
        }
    }
}

/// Merge struct definitions from base into derived
fn mergeStructs(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.structs.items) |base_s| {
        var found = false;
        for (derived.structs.items) |s| {
            if (std.mem.eql(u8, s.name, base_s.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            derived.structs.append(allocator, base_s) catch continue;
        }
    }
}

/// Merge enum definitions from base into derived
fn mergeEnums(
    allocator: std.mem.Allocator,
    derived: *parser.ContractDef,
    base: parser.ContractDef,
) void {
    for (base.enums.items) |base_e| {
        var found = false;
        for (derived.enums.items) |e| {
            if (std.mem.eql(u8, e.name, base_e.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            derived.enums.append(allocator, base_e) catch continue;
        }
    }
}
