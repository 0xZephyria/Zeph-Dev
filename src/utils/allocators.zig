const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

/// very similar to RecycleFBA but with a few differences:
/// - this uses an explicit T type and only returns slices of that type (instead of a generic u8)
/// - additional memory blocks are supported (instead of using a fixed-buffer-allocator approach)
pub fn RecycleBuffer(comptime T: type, default_init: T, config: struct {
    /// If enabled, all operations will require an exclusive lock.
    thread_safe: bool = !builtin.single_threaded,
    max_collapse_tries: u32 = 5,
    collapse_sleep_ms: u32 = 100,
    min_split_size: u64 = 128,
}) type {
    std.debug.assert(config.min_split_size > 0);

    return struct {
        records_allocator: Allocator,
        /// records are used to keep track of the memory blocks
        records: std.ArrayListUnmanaged(Record),
        /// allocator used to alloc the memory blocks
        memory_allocator: Allocator,
        /// memory holds blocks of memory ([]T) that can be allocated/deallocated
        memory: std.ArrayListUnmanaged([]T),
        /// total number of T elements we have in memory
        capacity: u64,
        /// the maximum contiguous capacity we have in memory
        max_continguous_capacity: u64,
        /// for thread safety
        mux: std.Thread.Mutex = .{},
        const Self = @This();

        pub const Record = struct {
            is_free: bool,
            buf: []T,
            len: u64,
            // NOTE: this is tracked for correct usage of collapse()
            memory_index: u64,
        };

        const AllocatorConfig = struct {
            records_allocator: Allocator,
            memory_allocator: Allocator,
        };

        pub fn init(allocator_config: AllocatorConfig) Self {
            return .{
                .records_allocator = allocator_config.records_allocator,
                .records = .{},
                .memory_allocator = allocator_config.memory_allocator,
                .memory = .{},
                .capacity = 0,
                .max_continguous_capacity = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (self.memory.items) |block| {
                self.memory_allocator.free(block);
            }
            self.memory.deinit(self.memory_allocator);
            self.records.deinit(self.records_allocator);
        }

        /// append a block of N elements to the manager
        pub fn expandCapacity(self: *Self, n: u64) Allocator.Error!void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            return self.expandCapacityUnsafe(n);
        }

        pub fn expandCapacityUnsafe(self: *Self, n: u64) Allocator.Error!void {
            if (n == 0) return;

            try self.records.ensureUnusedCapacity(self.records_allocator, 1);
            try self.memory.ensureUnusedCapacity(self.memory_allocator, 1);

            const buf = try self.memory_allocator.alloc(T, n);
            @memset(buf, default_init);

            self.records.appendAssumeCapacity(.{
                .is_free = true,
                .buf = buf,
                .len = buf.len,
                .memory_index = self.memory.items.len,
            });
            self.memory.appendAssumeCapacity(buf);
            self.capacity += buf.len;
            self.max_continguous_capacity = @max(self.max_continguous_capacity, buf.len);
        }

        const AllocError = error{
            AllocTooBig,
            AllocFailed,
            CollapseFailed,
        } || Allocator.Error;

        pub fn alloc(self: *Self, n: u64) AllocError![]T {
            if (n == 0) return &.{};

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (0..config.max_collapse_tries) |_| {
                return self.allocUnsafe(n) catch |err| {
                    switch (err) {
                        error.CollapseFailed => {
                            if (config.thread_safe) self.mux.unlock();
                            defer if (config.thread_safe) self.mux.lock();
                            std.Thread.sleep(std.time.ns_per_ms * config.collapse_sleep_ms);
                            continue;
                        },
                        else => return err,
                    }
                };
            }
            @panic("not enough memory and collapse failed max times");
        }

        pub fn allocUnsafe(self: *Self, n: u64) AllocError![]T {
            if (n == 0) return &.{};
            if (n > self.max_continguous_capacity) return error.AllocTooBig;

            var is_possible_to_recycle = false;
            for (self.records.items) |*record| {
                if (record.buf.len >= n) {
                    if (record.is_free) {
                        record.is_free = false;
                        const buf = record.buf[0..n];
                        _ = self.tryRecycleUnusedSpaceWithRecordUnsafe(record, n);
                        return buf;
                    } else {
                        is_possible_to_recycle = true;
                    }
                }
            }

            if (is_possible_to_recycle) {
                return error.AllocFailed;
            } else {
                self.collapseUnsafe();
                const collapse_succeed = self.isPossibleToAllocateUnsafe(n);
                if (collapse_succeed) {
                    return self.allocUnsafe(n);
                } else {
                    return error.CollapseFailed;
                }
            }
        }

        pub fn free(self: *Self, buf_ptr: [*]T) void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (self.records.items) |*record| {
                if (record.buf.ptr == buf_ptr) {
                    record.is_free = true;
                    return;
                }
            }
            @panic("attempt to free invalid buf");
        }

        fn tryRecycleUnusedSpaceWithRecordUnsafe(
            self: *Self,
            record: *Record,
            used_len: u64,
        ) bool {
            const unused_len = record.buf.len -| used_len;
            if (unused_len > config.min_split_size) {
                const split_buf = record.buf[used_len..];
                record.buf = record.buf[0..used_len];
                record.len = used_len;
                self.records.append(self.records_allocator, .{
                    .is_free = true,
                    .buf = split_buf,
                    .len = split_buf.len,
                    .memory_index = record.memory_index,
                }) catch unreachable;
                return true;
            } else {
                return false;
            }
        }

        pub fn collapseUnsafe(self: *Self) void {
            const records = &self.records;
            var i: usize = 1;
            while (i < records.items.len) {
                const prev = records.items[i - 1];
                const curr = records.items[i];

                const both_free = prev.is_free and curr.is_free;
                const shared_memory_index = prev.memory_index == curr.memory_index;

                if (both_free and shared_memory_index) {
                    records.items[i - 1].buf.len += curr.buf.len;
                    _ = records.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        pub fn isPossibleToAllocateUnsafe(self: *Self, n: u64) bool {
            for (self.records.items) |*record| {
                if (record.buf.len >= n) {
                    return true;
                }
            }
            return false;
        }
    };
}
