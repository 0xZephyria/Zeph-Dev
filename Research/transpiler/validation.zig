// File: tools/sol2zig/validation.zig
// Validates Solidity AST for transpiler compatibility
// Reports errors and warnings for unsupported features
// Enhanced with expression-level checks, modifier existence, type compatibility

const std = @import("std");
const parser = @import("parser.zig");
const type_mapper = @import("type_mapper.zig");

pub const Diagnostic = struct {
    level: Level,
    message: []const u8,
    context: ?[]const u8,
};

pub const Level = enum {
    @"error",
    warning,
    info,
};

pub const DiagnosticList = struct {
    allocator: std.mem.Allocator,
    errors: std.ArrayListUnmanaged(Diagnostic),
    warnings: std.ArrayListUnmanaged(Diagnostic),

    pub fn hasErrors(self: DiagnosticList) bool {
        return self.errors.items.len > 0;
    }

    pub fn deinit(self: *DiagnosticList) void {
        self.errors.deinit(self.allocator);
        self.warnings.deinit(self.allocator);
    }
};

/// Validate the AST for transpiler compatibility
pub fn validate(allocator: std.mem.Allocator, ast: *const parser.SolidityAST) !DiagnosticList {
    var diags = DiagnosticList{
        .allocator = allocator,
        .errors = .{},
        .warnings = .{},
    };

    for (ast.contracts.items) |contract| {
        try validateContract(allocator, &diags, contract, ast);
    }

    return diags;
}

fn validateContract(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    contract: parser.ContractDef,
    ast: *const parser.SolidityAST,
) !void {
    // Check for unsupported contract types
    if (contract.kind == .library) {
        try diags.warnings.append(allocator, .{
            .level = .warning,
            .message = "Libraries are transpiled as standalone modules — library linking may need manual adjustment",
            .context = contract.name,
        });
    }

    // Validate state variables
    for (contract.state_variables.items) |sv| {
        try validateStateVariable(allocator, diags, sv, contract.name);
    }

    // Validate functions
    for (contract.functions.items) |func| {
        try validateFunction(allocator, diags, func, contract.name, contract);
    }

    // Validate events (max 3 indexed for non-anonymous, max 4 for anonymous)
    for (contract.events.items) |event| {
        try validateEvent(allocator, diags, event, contract.name);
    }

    // Validate base contract references
    try validateBaseContracts(allocator, diags, contract, ast);

    // Validate modifier references in functions
    try validateModifierReferences(allocator, diags, contract);

    // Check for diamond inheritance conflicts
    try validateInheritanceConflicts(allocator, diags, contract, ast);
}

fn validateStateVariable(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    sv: parser.StateVarDef,
    contract_name: []const u8,
) !void {
    // Check for unsupported types
    if (std.mem.eql(u8, sv.type_name, "fixed") or
        std.mem.eql(u8, sv.type_name, "ufixed"))
    {
        try diags.errors.append(allocator, .{
            .level = .@"error",
            .message = "Fixed-point types (fixed/ufixed) are not supported",
            .context = contract_name,
        });
    }

    // Check for fixed-point with precision (e.g. fixed128x18)
    if (std.mem.startsWith(u8, sv.type_name, "fixed") or
        std.mem.startsWith(u8, sv.type_name, "ufixed"))
    {
        if (std.mem.indexOf(u8, sv.type_name, "x") != null) {
            try diags.errors.append(allocator, .{
                .level = .@"error",
                .message = "Fixed-point types with precision are not supported",
                .context = contract_name,
            });
        }
    }

    // Validate mapping types
    if (std.mem.startsWith(u8, sv.type_name, "mapping(")) {
        const parsed = type_mapper.parseMappingTypes(sv.type_name);
        if (parsed == null) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "Could not parse mapping type — codegen may produce incorrect output",
                .context = contract_name,
            });
        }
    }
}

fn validateFunction(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    func: parser.FunctionDef,
    contract_name: []const u8,
    contract: parser.ContractDef,
) !void {
    // Check for assembly blocks
    if (func.body) |body| {
        if (std.mem.indexOf(u8, body, "assembly") != null) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "Inline assembly detected — manual transpilation required",
                .context = contract_name,
            });
        }

        // Check for try/catch
        if (std.mem.indexOf(u8, body, "try ") != null) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "Solidity try/catch — will be mapped to SDK error handling",
                .context = contract_name,
            });
        }

        // Check for unchecked blocks
        if (std.mem.indexOf(u8, body, "unchecked {") != null) {
            try diags.warnings.append(allocator, .{
                .level = .info,
                .message = "unchecked block — will use wrapping arithmetic",
                .context = contract_name,
            });
        }

        // Check for delegatecall (security concern)
        if (std.mem.indexOf(u8, body, "delegatecall") != null) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "delegatecall detected — ensure storage layout compatibility",
                .context = contract_name,
            });
        }

        // Check for selfdestruct (deprecated in newer Solidity)
        if (std.mem.indexOf(u8, body, "selfdestruct") != null) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "selfdestruct is deprecated — behavior may change in future versions",
                .context = contract_name,
            });
        }
    }

    // Functions with > 16 params (stack depth)
    if (func.params.items.len > 16) {
        try diags.warnings.append(allocator, .{
            .level = .warning,
            .message = "Function has >16 parameters — consider using a struct parameter",
            .context = contract_name,
        });
    }

    // Validate return type mappings
    for (func.returns.items) |ret| {
        if (std.mem.eql(u8, ret.type_name, "fixed") or std.mem.eql(u8, ret.type_name, "ufixed")) {
            try diags.errors.append(allocator, .{
                .level = .@"error",
                .message = "Fixed-point return types are not supported",
                .context = contract_name,
            });
        }
    }

    // Validate parameter type mappings
    for (func.params.items) |param| {
        if (std.mem.eql(u8, param.type_name, "fixed") or std.mem.eql(u8, param.type_name, "ufixed")) {
            try diags.errors.append(allocator, .{
                .level = .@"error",
                .message = "Fixed-point parameter types are not supported",
                .context = contract_name,
            });
        }
    }

    // Validate modifier references
    for (func.modifiers_applied.items) |mod_call| {
        if (!isKnownModifier(mod_call.name) and !contractHasModifier(contract, mod_call.name)) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "Modifier not found in contract — may be inherited",
                .context = mod_call.name,
            });
        }
    }
}

fn validateEvent(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    event: parser.EventDef,
    contract_name: []const u8,
) !void {
    var indexed_count: usize = 0;
    for (event.params.items) |param| {
        if (param.is_indexed) indexed_count += 1;
    }

    const max_indexed: usize = if (event.is_anonymous) 4 else 3;
    if (indexed_count > max_indexed) {
        try diags.errors.append(allocator, .{
            .level = .@"error",
            .message = "Too many indexed parameters in event",
            .context = contract_name,
        });
    }
}

// ============================================================================
// Phase 4 Enhancements — Advanced Validation
// ============================================================================

/// Validate that all base contract references resolve to known contracts
fn validateBaseContracts(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    contract: parser.ContractDef,
    ast: *const parser.SolidityAST,
) !void {
    for (contract.base_contracts.items) |base_name| {
        const found = blk: {
            for (ast.contracts.items) |c| {
                if (std.mem.eql(u8, c.name, base_name)) break :blk true;
            }
            break :blk false;
        };
        if (!found) {
            try diags.warnings.append(allocator, .{
                .level = .warning,
                .message = "Base contract not found — may need to be imported",
                .context = base_name,
            });
        }
    }
}

/// Validate that all modifier references in functions exist in the contract
fn validateModifierReferences(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    contract: parser.ContractDef,
) !void {
    for (contract.functions.items) |func| {
        for (func.modifiers_applied.items) |mod_call| {
            if (!isKnownModifier(mod_call.name) and !contractHasModifier(contract, mod_call.name)) {
                try diags.warnings.append(allocator, .{
                    .level = .warning,
                    .message = "Referenced modifier not defined in this contract",
                    .context = mod_call.name,
                });
            }
        }
    }
}

/// Check for diamond inheritance conflicts
fn validateInheritanceConflicts(
    allocator: std.mem.Allocator,
    diags: *DiagnosticList,
    contract: parser.ContractDef,
    ast: *const parser.SolidityAST,
) !void {
    if (contract.base_contracts.items.len < 2) return;

    // Check for functions defined in multiple base contracts with different implementations
    var seen_fns = std.StringHashMap([]const u8).init(allocator);
    defer seen_fns.deinit();

    for (contract.base_contracts.items) |base_name| {
        for (ast.contracts.items) |c| {
            if (!std.mem.eql(u8, c.name, base_name)) continue;
            for (c.functions.items) |func| {
                if (func.visibility == .private) continue;
                if (seen_fns.get(func.name)) |prev_contract| {
                    // Function exists in multiple bases — check if contract overrides it
                    var overridden = false;
                    for (contract.functions.items) |own_fn| {
                        if (std.mem.eql(u8, own_fn.name, func.name)) {
                            overridden = true;
                            break;
                        }
                    }
                    if (!overridden) {
                        _ = prev_contract;
                        try diags.warnings.append(allocator, .{
                            .level = .warning,
                            .message = "Diamond inheritance: function defined in multiple bases — should be overridden",
                            .context = func.name,
                        });
                    }
                } else {
                    seen_fns.put(func.name, base_name) catch continue;
                }
            }
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn isKnownModifier(name: []const u8) bool {
    const known = [_][]const u8{
        "onlyOwner",
        "whenNotPaused",
        "whenPaused",
        "nonReentrant",
        "initializer",
        "onlyRole",
    };
    for (&known) |known_name| {
        if (std.mem.eql(u8, name, known_name)) return true;
    }
    return false;
}

fn contractHasModifier(contract: parser.ContractDef, name: []const u8) bool {
    for (contract.modifiers.items) |mod| {
        if (std.mem.eql(u8, mod.name, name)) return true;
    }
    return false;
}
