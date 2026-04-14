const std = @import("std");
const builtin = @import("builtin");

const Mutex = std.Thread.Mutex;
const RwLock = std.Thread.RwLock;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;
const assert = std.debug.assert;

/// Mux is a `Mutex` wrapper which enforces proper access to a protected value.
pub fn Mux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        private: Inner,

        const Self = @This();

        /// `init` will initialize self with `val`
        pub fn init(val: T) Self {
            return Self{
                .private = .{
                    .m = Mutex{},
                    .v = val,
                },
            };
        }

        const Inner = struct {
            m: Mutex,
            v: T,
        };

        /// LockGuard represents a currently held lock on `Mux(T)`. It is not thread-safe.
        pub const LockGuard = struct {
            /// Do not use! Private field.
            private: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns `Const(T)`
            pub fn get(self: *LockGuard) *const T {
                assert(self.valid == true);
                return &self.private.v;
            }

            /// `mut` func returns a `Mutable(T)`
            pub fn mut(self: *LockGuard) *T {
                assert(self.valid == true);
                return &self.private.v;
            }

            /// `replace` sets the val in place of current `T`
            pub fn replace(self: *LockGuard, val: T) void {
                assert(self.valid == true);
                self.private.v = val;
            }

            /// `unlock` releases the held `Mutex` lock and invalidates this `LockGuard`
            pub fn unlock(self: *LockGuard) void {
                assert(self.valid == true);
                if (builtin.mode == .Debug) self.valid = false;

                self.private.m.unlock();
            }
        };

        pub fn readWithLock(self: *Self) struct { *const T, LockGuard } {
            var lock_guard = self.lock();
            const t = lock_guard.get();
            return .{ t, lock_guard };
        }

        pub fn writeWithLock(self: *Self) struct { *T, LockGuard } {
            var lock_guard = self.lock();
            const t = lock_guard.mut();
            return .{ t, lock_guard };
        }

        /// `lock` returns a `LockGuard` after acquiring `Mutex` lock
        pub fn lock(self: *Self) LockGuard {
            self.private.m.lock();
            return LockGuard{
                .private = &self.private,
                .valid = true,
            };
        }
    };
}

/// RwMux is a `RwLock` wrapper which enforces proper access to a protected value.
pub fn RwMux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        private: Inner,

        const Self = @This();

        const Inner = struct {
            r: DefaultRwLock,
            v: T,
        };

        /// `init` will initialize self with `val`
        pub fn init(val: T) Self {
            return Self{
                .private = .{
                    .r = DefaultRwLock{},
                    .v = val,
                },
            };
        }

        /// RLockGuard represents a currently held read lock on `RwMux(T)`. It is not thread-safe.
        pub const RLockGuard = struct {
            /// Do not use! Private field.
            private: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns a `Const(T)`
            pub fn get(self: *const RLockGuard) *const T {
                assert(self.valid == true);
                return &self.private.v;
            }

            /// `unlock` releases the held read lock and invalidates this `RLockGuard`
            pub fn unlock(self: *RLockGuard) void {
                assert(self.valid == true);
                if (builtin.mode == .Debug) self.valid = false;
                self.private.r.unlockShared();
            }
        };

        /// WLockGuard represents a currently held write lock on `RwMux(T)`. It is not thread-safe.
        pub const WLockGuard = struct {
            /// Do not use! Private field.
            private: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// `get` func returns `Const(T)`
            pub fn get(self: *WLockGuard) *const T {
                assert(self.valid == true);
                return &self.private.v;
            }

            /// `mut` func returns a `Mutable(T)`
            pub fn mut(self: *WLockGuard) *T {
                assert(self.valid == true);
                return &self.private.v;
            }

            /// `unlock` releases the held write lock and invalidates this `WLockGuard`
            pub fn unlock(self: *WLockGuard) void {
                self.valid = false;
                self.private.r.unlock();
            }
        };

        /// `write` returns a `WLockGuard` after acquiring a `write` lock
        pub fn write(self: *Self) WLockGuard {
            self.private.r.lock();
            return WLockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        /// `read` returns a `RLockGuard` after acquiring a `read` lock
        pub fn read(self: *Self) RLockGuard {
            self.private.r.lockShared();
            return RLockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        pub fn writeWithLock(self: *Self) struct { *T, WLockGuard } {
            var lock_guard = self.write();
            const t = lock_guard.mut();
            return .{ t, lock_guard };
        }
    };
}
