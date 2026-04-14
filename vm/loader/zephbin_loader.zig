// File: vm/loader/zephbin_loader.zig
// Parser for the ZephBin binary format emitted by the Forge compiler (codegen.zig).
//
// ZephBin layout (version 1):
//   [64-byte ZephBinHeader]
//   [access_list section   — access_list_len bytes]
//   [bytecode section      — bytecode_len bytes]
//   [data section          — data_section_len bytes]
//
// Bytecode section layout:
//   [u16 action_count]
//   per action:
//     [u32 selector]  — SHA256(name)[0..4] little-endian, 0x00000000 = constructor
//     [u32 code_len]
//     [code_len bytes of RISC-V instructions]
//
// The VM executes a single action's bytecode.  The caller must provide either
// a 4-byte selector to pick the action, or 0x00000000 to pick the constructor.
// If no matching selector is found, action index 0 is used as a fallback.

const std = @import("std");
const sandbox = @import("../memory/sandbox.zig");

// ─── ZephBin header (must match codegen.zig ZephBinHeader exactly) ────────────

pub const ZEPHBIN_MAGIC: [4]u8 = .{ 'F', 'O', 'R', 'G' };
pub const ZEPHBIN_VERSION: u16 = 1;

pub const ZephBinHeader = extern struct {
    magic:            [4]u8,
    version:          u16,
    flags:            u16,
    contract_name:    [32]u8,
    action_count:     u16,
    _pad0:            u16,
    access_list_len:  u32,
    bytecode_len:     u32,
    checksum:         u32,
    data_section_len: u32,
    _reserved:        [4]u8,
};
comptime {
    // Must match compiler layout exactly
    std.debug.assert(@sizeOf(ZephBinHeader) == 64);
}

pub const ParseError = error{
    InvalidMagic,
    UnsupportedVersion,
    InvalidFormat,
    NoActions,
    CodeTooLarge,
    DataTooLarge,
    OutOfMemory, // allocator.alloc inside parse()
};

/// A single action extracted from a ZephBin binary.
pub const ZephAction = struct {
    selector: u32,
    code:     []const u8, // slice into the original binary — zero-copy
};

/// Fully parsed ZephBin package.
pub const ZephBinPackage = struct {
    header:       ZephBinHeader,
    actions:      []ZephAction,   // heap-allocated, caller must free
    data_section: []const u8,     // slice into original binary — zero-copy
    allocator:    std.mem.Allocator,

    pub fn deinit(self: *ZephBinPackage) void {
        self.allocator.free(self.actions);
    }

    /// Find an action by selector.  Returns null if not found.
    pub fn findAction(self: *const ZephBinPackage, selector: u32) ?*const ZephAction {
        for (self.actions) |*a| {
            if (a.selector == selector) return a;
        }
        return null;
    }

    /// Return the action to execute:
    ///   • If selector != 0, find by selector (fallback to index 0 if missing).
    ///   • If selector == 0, pick the constructor (selector=0) or index 0.
    pub fn pickAction(self: *const ZephBinPackage, selector: u32) ?*const ZephAction {
        if (self.actions.len == 0) return null;
        if (selector != 0) {
            if (self.findAction(selector)) |a| return a;
        } else {
            // Look for explicit constructor (selector = 0x00000000)
            for (self.actions) |*a| {
                if (a.selector == 0) return a;
            }
        }
        // Fallback: first action
        return &self.actions[0];
    }
};

/// Check whether `data` begins with the ZephBin magic bytes and has at least
/// a full header.  Does NOT validate the version — use `parse` for that.
pub fn isZephBin(data: []const u8) bool {
    if (data.len < @sizeOf(ZephBinHeader)) return false;
    return std.mem.eql(u8, data[0..4], &ZEPHBIN_MAGIC);
}

/// Parse a ZephBin binary.  Returns a ZephBinPackage whose `actions` slice is
/// heap-allocated (owned by the package, freed by `package.deinit()`).
/// All other slices point into `data` — the caller must keep `data` alive.
pub fn parse(allocator: std.mem.Allocator, data: []const u8) ParseError!ZephBinPackage {
    if (data.len < @sizeOf(ZephBinHeader)) return ParseError.InvalidFormat;

    const hdr: *align(1) const ZephBinHeader =
        @ptrCast(data[0..@sizeOf(ZephBinHeader)].ptr);

    if (!std.mem.eql(u8, &hdr.magic, &ZEPHBIN_MAGIC)) return ParseError.InvalidMagic;
    if (hdr.version != ZEPHBIN_VERSION)                return ParseError.UnsupportedVersion;

    // Locate sections
    const al_start: usize = @sizeOf(ZephBinHeader);
    const bc_start: usize = al_start + hdr.access_list_len;
    const ds_start: usize = bc_start + hdr.bytecode_len;
    const expected_len:usize = ds_start + hdr.data_section_len;

    if (data.len < expected_len) return ParseError.InvalidFormat;

    const bc_data = data[bc_start .. bc_start + hdr.bytecode_len];
    const data_section = if (hdr.data_section_len > 0)
        data[ds_start .. ds_start + hdr.data_section_len]
    else
        &[_]u8{};

    // Parse bytecode section: [u16 action_count] [actions...]
    if (bc_data.len < 2) return ParseError.InvalidFormat;
    const action_count = std.mem.readInt(u16, bc_data[0..2], .little);

    const actions = try allocator.alloc(ZephAction, action_count);
    errdefer allocator.free(actions);

    var pos: usize = 2;
    for (actions) |*action| {
        if (pos + 8 > bc_data.len) return ParseError.InvalidFormat;
        const sel     = std.mem.readInt(u32, bc_data[pos..][0..4], .little);
        const code_len = std.mem.readInt(u32, bc_data[pos+4..][0..4], .little);
        pos += 8;
        if (pos + code_len > bc_data.len) return ParseError.InvalidFormat;
        if (code_len > sandbox.CODE_SIZE)  return ParseError.CodeTooLarge;
        action.* = .{
            .selector = sel,
            .code     = bc_data[pos .. pos + code_len],
        };
        pos += code_len;
    }

    return ZephBinPackage{
        .header       = hdr.*,
        .actions      = actions,
        .data_section = data_section,
        .allocator    = allocator,
    };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "isZephBin rejects non-FORG data" {
    try testing.expect(!isZephBin("ELF\x7f" ** 16));
    try testing.expect(!isZephBin(&[_]u8{0x7F, 'E', 'L', 'F'}));
}

test "isZephBin recognises FORG magic" {
    var data = [_]u8{0} ** 64;
    @memcpy(data[0..4], "FORG");
    try testing.expect(isZephBin(&data));
}

test "parse rejects wrong version" {
    var data = [_]u8{0} ** 200;
    @memcpy(data[0..4], "FORG");
    std.mem.writeInt(u16, data[4..6], 99, .little); // bad version
    try testing.expectError(ParseError.UnsupportedVersion, parse(testing.allocator, &data));
}

test "parse empty contract (0 actions)" {
    var data = [_]u8{0} ** 70;
    @memcpy(data[0..4], "FORG");
    std.mem.writeInt(u16, data[4..6],  ZEPHBIN_VERSION, .little);
    // access_list_len = 0, bytecode_len = 2 (just the u16 action_count=0), data_section_len = 0
    std.mem.writeInt(u32, data[52..56], 0, .little); // access_list_len
    std.mem.writeInt(u32, data[56..60], 2, .little); // bytecode_len
    std.mem.writeInt(u32, data[64..68], 0, .little); // data_section_len
    // bytecode section starts at byte 64, contains [0x00, 0x00] (action_count=0)
    // data[64] = 0x00, data[65] = 0x00

    var pkg = try parse(testing.allocator, &data);
    defer pkg.deinit();
    try testing.expectEqual(@as(usize, 0), pkg.actions.len);
    try testing.expect(pkg.pickAction(0) == null);
}

test "pickAction falls back to index 0 on unknown selector" {
    // Build a minimal ZephBin with one action (selector = 0xDEADBEEF)
    const nop: u32 = 0x00000013; // ADDI x0, x0, 0
    const code_bytes = std.mem.asBytes(&nop);
    const code_len: u32 = 4;

    // Bytecode section: [2B count=1][4B selector][4B code_len][4B code]
    var bc_section: [14]u8 = undefined;
    std.mem.writeInt(u16, bc_section[0..2], 1, .little);
    std.mem.writeInt(u32, bc_section[2..6], 0xDEADBEEF, .little);
    std.mem.writeInt(u32, bc_section[6..10], code_len, .little);
    @memcpy(bc_section[10..14], code_bytes);

    var data = [_]u8{0} ** (64 + 14);
    @memcpy(data[0..4], "FORG");
    std.mem.writeInt(u16, data[4..6], ZEPHBIN_VERSION, .little);
    std.mem.writeInt(u32, data[52..56], 0,  .little); // access_list_len
    std.mem.writeInt(u32, data[56..60], 14, .little); // bytecode_len
    @memcpy(data[64..78], &bc_section);

    var pkg = try parse(testing.allocator, &data);
    defer pkg.deinit();
    try testing.expectEqual(@as(usize, 1), pkg.actions.len);

    // Unknown selector → fallback to index 0
    const action = pkg.pickAction(0x12345678);
    try testing.expect(action != null);
    try testing.expectEqual(@as(u32, 0xDEADBEEF), action.?.selector);
}
