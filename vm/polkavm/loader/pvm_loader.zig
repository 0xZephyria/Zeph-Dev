// File: vm/polkavm/loader/pvm_loader.zig
// Parser for PolkaVM (PVM\0) native bytecode blobs.

const std = @import("std");

pub const SECTION_MEMORY_CONFIG: u8 = 1;
pub const SECTION_RO_DATA: u8 = 2;
pub const SECTION_RW_DATA: u8 = 3;
pub const SECTION_IMPORTS: u8 = 4;
pub const SECTION_EXPORTS: u8 = 5;
pub const SECTION_CODE_AND_JUMP_TABLE: u8 = 6;
pub const SECTION_OPT_DEBUG_STRINGS: u8 = 128;
pub const SECTION_OPT_DEBUG_LINE_PROGRAMS: u8 = 129;
pub const SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES: u8 = 130;
pub const SECTION_END_OF_FILE: u8 = 0;

pub const PvmExport = struct {
    pc: u32,
    name: []const u8,
};

pub const PvmProgram = struct {
    allocator: std.mem.Allocator,
    ro_data_size: u32 = 0,
    rw_data_size: u32 = 0,
    stack_size: u32 = 0,
    ro_data: []const u8 = &[_]u8{},
    rw_data: []const u8 = &[_]u8{},
    imports: [][]const u8 = &[_][]const u8{},
    exports: []PvmExport = &[_]PvmExport{},
    code: []const u8 = &[_]u8{},
    bitmask: []const u8 = &[_]u8{},
    jump_table: []const u8 = &[_]u8{},
    jump_table_entry_size: u8 = 0,

    pub fn deinit(self: *PvmProgram) void {
        for (self.imports) |name| {
            self.allocator.free(name);
        }
        self.allocator.free(self.imports);
        for (self.exports) |exp| {
            self.allocator.free(exp.name);
        }
        self.allocator.free(self.exports);
    }

    /// Find an export by name. Returns the PC or null if not found.
    pub fn findExport(self: *const PvmProgram, name: []const u8) ?u32 {
        for (self.exports) |exp| {
            if (std.mem.eql(u8, exp.name, name)) {
                return exp.pc;
            }
        }
        return null;
    }
};

pub fn readVarint(data: []const u8, offset: *usize) !u32 {
    if (offset.* >= data.len) return error.UnexpectedEof;
    const first_byte = data[offset.*];
    offset.* += 1;

    const length: u8 = if ((first_byte & 0x80) == 0)
        0
    else if ((first_byte & 0xC0) == 0x80)
        1
    else if ((first_byte & 0xE0) == 0xC0)
        2
    else if ((first_byte & 0xF0) == 0xE0)
        3
    else if ((first_byte & 0xF8) == 0xF0)
        4
    else
        return error.InvalidVarint;

    switch (length) {
        0 => {
            return @as(u32, first_byte);
        },
        1 => {
            if (offset.* + 1 > data.len) return error.UnexpectedEof;
            const b1 = data[offset.*];
            offset.* += 1;
            const upper = @as(u32, first_byte & 0x7F) << 8;
            return upper | b1;
        },
        2 => {
            if (offset.* + 2 > data.len) return error.UnexpectedEof;
            const val = std.mem.readInt(u16, data[offset.* .. offset.* + 2][0..2], .little);
            offset.* += 2;
            const upper = @as(u32, first_byte & 0x3F) << 16;
            return upper | val;
        },
        3 => {
            if (offset.* + 3 > data.len) return error.UnexpectedEof;
            const b1 = data[offset.*];
            const b2 = data[offset.* + 1];
            const b3 = data[offset.* + 2];
            offset.* += 3;
            const upper = @as(u32, first_byte & 0x1F) << 24;
            const val = @as(u32, b1) | (@as(u32, b2) << 8) | (@as(u32, b3) << 16);
            return upper | val;
        },
        4 => {
            if (offset.* + 4 > data.len) return error.UnexpectedEof;
            const val = std.mem.readInt(u32, data[offset.* .. offset.* + 4][0..4], .little);
            offset.* += 4;
            return val;
        },
        else => return error.InvalidVarint,
    }
}

pub fn parse(allocator: std.mem.Allocator, data: []const u8) !PvmProgram {
    if (data.len < 13) return error.InvalidFormat;
    if (!std.mem.eql(u8, data[0..4], "PVM\x00")) return error.InvalidMagic;
    const version = data[4];
    if (version != 0) return error.UnsupportedVersion;
    const blob_total_len = std.mem.readInt(u64, data[5..13], .little);
    if (blob_total_len != data.len) return error.LengthMismatch;

    var program = PvmProgram{ .allocator = allocator };
    errdefer program.deinit();

    var offset: usize = 13;
    while (offset < data.len) {
        const section_id = data[offset];
        offset += 1;
        if (section_id == SECTION_END_OF_FILE) {
            break;
        }

        const section_len = try readVarint(data, &offset);
        if (offset + section_len > data.len) return error.UnexpectedEof;
        const section_data = data[offset .. offset + section_len];
        offset += section_len;

        switch (section_id) {
            SECTION_MEMORY_CONFIG => {
                var sec_offset: usize = 0;
                program.ro_data_size = try readVarint(section_data, &sec_offset);
                program.rw_data_size = try readVarint(section_data, &sec_offset);
                program.stack_size = try readVarint(section_data, &sec_offset);
            },
            SECTION_RO_DATA => {
                program.ro_data = section_data;
            },
            SECTION_RW_DATA => {
                program.rw_data = section_data;
            },
            SECTION_IMPORTS => {
                var sec_offset: usize = 0;
                const import_count = try readVarint(section_data, &sec_offset);
                const import_offsets_len = import_count * 4;
                if (sec_offset + import_offsets_len > section_data.len) return error.InvalidFormat;
                const import_offsets_raw = section_data[sec_offset .. sec_offset + import_offsets_len];
                sec_offset += import_offsets_len;
                const symbols_raw = section_data[sec_offset..];

                var imports_list = std.ArrayList([]const u8).empty;
                errdefer {
                    for (imports_list.items) |name| allocator.free(name);
                    imports_list.deinit(allocator);
                }

                var i: usize = 0;
                while (i < import_count) : (i += 1) {
                    const start = std.mem.readInt(u32, import_offsets_raw[i * 4 ..][0..4], .little);
                    const end = if (i + 1 < import_count)
                        std.mem.readInt(u32, import_offsets_raw[(i + 1) * 4 ..][0..4], .little)
                    else
                        @as(u32, @intCast(symbols_raw.len));
                    
                    if (start > end or end > symbols_raw.len) return error.InvalidFormat;
                    const name = try allocator.dupe(u8, symbols_raw[start..end]);
                    try imports_list.append(allocator, name);
                }
                program.imports = try imports_list.toOwnedSlice(allocator);
            },
            SECTION_EXPORTS => {
                var sec_offset: usize = 0;
                const export_count = try readVarint(section_data, &sec_offset);
                var exports_list = std.ArrayList(PvmExport).empty;
                errdefer {
                    for (exports_list.items) |exp| allocator.free(exp.name);
                    exports_list.deinit(allocator);
                }

                var i: usize = 0;
                while (i < export_count) : (i += 1) {
                    const pc = try readVarint(section_data, &sec_offset);
                    const name_len = try readVarint(section_data, &sec_offset);
                    if (sec_offset + name_len > section_data.len) return error.InvalidFormat;
                    const name_raw = section_data[sec_offset .. sec_offset + name_len];
                    sec_offset += name_len;
                    const name = try allocator.dupe(u8, name_raw);
                    try exports_list.append(allocator, .{ .pc = pc, .name = name });
                }
                program.exports = try exports_list.toOwnedSlice(allocator);
            },
            SECTION_CODE_AND_JUMP_TABLE => {
                var sec_offset: usize = 0;
                const jump_table_entry_count = try readVarint(section_data, &sec_offset);
                const jump_table_entry_size = section_data[sec_offset];
                sec_offset += 1;
                const code_len = try readVarint(section_data, &sec_offset);
                
                const jump_table_len = jump_table_entry_count * jump_table_entry_size;
                if (sec_offset + jump_table_len + code_len > section_data.len) return error.InvalidFormat;
                
                program.jump_table_entry_size = jump_table_entry_size;
                program.jump_table = section_data[sec_offset .. sec_offset + jump_table_len];
                sec_offset += jump_table_len;
                
                program.code = section_data[sec_offset .. sec_offset + code_len];
                sec_offset += code_len;
                
                program.bitmask = section_data[sec_offset..];
            },
            else => {
                // Ignore optional or debug sections
            }
        }
    }

    return program;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "PVM Varint parsing" {
    // 1. One-byte varints (value < 0x80)
    var offset: usize = 0;
    try testing.expectEqual(@as(u32, 0x45), try readVarint(&[_]u8{0x45}, &offset));
    try testing.expectEqual(@as(usize, 1), offset);

    // 2. Multi-byte varints
    offset = 0;
    try testing.expectEqual(@as(u32, 0x520), try readVarint(&[_]u8{ 0x85, 0x20 }, &offset));
    try testing.expectEqual(@as(usize, 2), offset);
}
