const std = @import("std");
const core = @import("core");

/// VDF implements a Verifiable Delay Function using sequential SHA-256 hashing.
pub const VDF = struct {
    /// Compute performs sequential hashing on the input for 'iterations' count.
    /// Output = SHA256^iterations(Input)
    pub fn compute(allocator: std.mem.Allocator, input: []const u8, iterations: u64) ![]u8 {
        if (iterations == 0) {
            return allocator.dupe(u8, input);
        }

        var buf: [32]u8 = undefined;
        // First iteration processes 'input' which can be any size
        std.crypto.hash.sha2.Sha256.hash(input, &buf, .{});

        var i: u64 = 1;
        while (i < iterations) : (i += 1) {
            var next_buf: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&buf, &next_buf, .{});
            buf = next_buf;
        }

        return allocator.dupe(u8, &buf);
    }

    /// ComputeWithCheckpoints returns checkpoints every 'interval' iterations.
    /// results[k] = SHA256^(interval * (k+1)) (Input)
    pub fn compute_checkpoints(allocator: std.mem.Allocator, input: []const u8, iterations: u64, interval: u64) ![][]u8 {
        if (interval == 0) return error.InvalidInterval;

        const count = iterations / interval;
        var results = try allocator.alloc([]u8, count);
        errdefer allocator.free(results); // Note: this only frees the slice of pointers, not contents if partially filled.

        var current_idx: usize = 0;

        // Handle Iteration 0 (if valid?) or just start loop
        // If iterations < interval, returns empty list.

        var buf: [32]u8 = undefined;
        if (iterations > 0) {
            std.crypto.hash.sha2.Sha256.hash(input, &buf, .{});
        }

        // Iter 1 is done (in buf).
        // If interval == 1, we save it.
        if (interval == 1 and iterations >= 1) {
            if (current_idx < count) {
                results[current_idx] = try allocator.dupe(u8, &buf);
                current_idx += 1;
            }
        }

        var i: u64 = 1;
        while (i < iterations) : (i += 1) {
            var next_buf: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&buf, &next_buf, .{});
            buf = next_buf;

            // Current iter is i+1
            if ((i + 1) % interval == 0) {
                if (current_idx < count) {
                    results[current_idx] = try allocator.dupe(u8, &buf);
                    current_idx += 1;
                }
            }
        }

        return results;
    }

    /// Verify checks if the output matches the input after 'iterations' hashes.
    pub fn verify(allocator: std.mem.Allocator, input: []const u8, output: []const u8, iterations: u64) !bool {
        const computed = try compute(allocator, input, iterations);
        defer allocator.free(computed);
        return std.mem.eql(u8, computed, output);
    }

    /// VerifyStep used for parallel verification of segments
    pub fn verify_step(allocator: std.mem.Allocator, start: []const u8, end: []const u8, iterations: u64) !bool {
        return verify(allocator, start, end, iterations);
    }

    // Parallel verification in Zig would typically use std.Thread
    // For simplicity in this initial port, we will implement it sequentially
    // but structure it such that threads can be added easily.
    pub fn verify_parallel(allocator: std.mem.Allocator, input: []const u8, checkpoints: []const []const u8, interval: u64) !bool {
        if (checkpoints.len == 0) return false;

        // Verify first segment: input -> checkpoints[0]
        if (!try verify_step(allocator, input, checkpoints[0], interval)) {
            return false;
        }

        // Verify remaining segments
        var i: usize = 1;
        while (i < checkpoints.len) : (i += 1) {
            const start = checkpoints[i - 1];
            const end = checkpoints[i];
            if (!try verify_step(allocator, start, end, interval)) {
                return false;
            }
        }

        return true;
    }
};
