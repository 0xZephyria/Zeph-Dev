// ============================================================================
// Zephyria — Parallel Wave Executor
// ============================================================================
//
// Executes transactions in parallel wavefronts produced by the Scheduler.
// Each TX in a wave gets its own Overlay (per-TX state), and all overlays
// are committed sequentially to the base state after the wave completes.
//
// Execution flow per wave:
//   1. Spawn N threads (one per TX in the wave)
//   2. Each thread creates an Overlay, executes the TX via VMCallback
//   3. After all threads complete, commit overlays in TX-index order
//   4. Apply accumulator deltas + credit receipts
//
// No sequential fallback — the scheduler guarantees zero conflicts.

const std = @import("std");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const scheduler_mod = @import("scheduler.zig");
const accounts = @import("accounts/mod.zig");
const log = @import("logger.zig");

/// Backward-compatible VMTransaction struct for RPC layer.
/// The executor itself uses individual args, but RPC constructs this struct
/// for VM simulation (eth_call, eth_estimateGas).
pub const VMTransaction = struct {
    from: [20]u8,
    to: ?[20]u8,
    value: u256,
    data: []const u8,
    gas_limit: u64,
    gas_price: u256,
    nonce: u64,
};

/// VM callback interface — avoids circular dependency between executor and VM.
/// The RISC-V VM implements this interface.
pub const VMCallback = struct {
    ctx: *anyopaque,
    exec_fn: *const fn (ctx: *anyopaque, code: []const u8, input: []const u8, gas: u64, overlay: *state_mod.Overlay, caller: types.Address, value: u256) VMResult,

    pub fn execute(self: VMCallback, code: []const u8, input: []const u8, gas: u64, overlay: *state_mod.Overlay, caller: types.Address, value: u256) VMResult {
        return self.exec_fn(self.ctx, code, input, gas, overlay, caller, value);
    }
};

pub const VMResult = struct {
    success: bool,
    gas_used: u64,
    output: []const u8,
    error_msg: ?[]const u8,
    revert_data: ?[]const u8 = null,
};

/// Executor configuration
pub const ExecutorConfig = struct {
    max_threads: u32 = 16,
    block_gas_limit: u64 = 60_000_000,
    base_fee: u256 = 1_000_000_000,
    coinbase: types.Address = types.Address.zero(),
};

/// Execution result for a single block
pub const BlockResult = struct {
    gas_used: u64,
    tx_results: []TxResult,
    state_root: types.Hash,
    receipts_root: types.Hash,

    pub fn deinit(self: *BlockResult, allocator: std.mem.Allocator) void {
        allocator.free(self.tx_results);
    }
};

pub const TxResult = struct {
    success: bool,
    gas_used: u64,
    fee: u256,
    error_message: ?[]const u8 = null,
    /// Contract return data (for eth_call / contract output)
    output: []const u8 = &[_]u8{},
    /// Logs emitted during execution (for transaction receipts)
    logs: []const state_mod.Overlay.Log = &[_]state_mod.Overlay.Log{},
};

pub const Executor = struct {
    allocator: std.mem.Allocator,
    config: ExecutorConfig,
    vm_callback: ?VMCallback,
    metadata_registry: ?*const accounts.MetadataRegistry,

    pub fn init(allocator: std.mem.Allocator, config: ExecutorConfig) Executor {
        return Executor{
            .allocator = allocator,
            .config = config,
            .vm_callback = null,
            .metadata_registry = null,
        };
    }

    pub fn setVMCallback(self: *Executor, callback: VMCallback) void {
        self.vm_callback = callback;
    }

    pub fn setMetadataRegistry(self: *Executor, registry: *const accounts.MetadataRegistry) void {
        self.metadata_registry = registry;
    }

    /// Execute an entire block worth of transactions.
    /// Returns the aggregate result including state root.
    pub fn apply_block(
        self: *Executor,
        world_state: *state_mod.State,
        transactions: []const types.Transaction,
    ) !BlockResult {
        // 1. Schedule into parallel wavefronts
        var sched = try scheduler_mod.schedule(
            self.allocator,
            transactions,
            self.metadata_registry,
        );
        defer sched.deinit();

        log.debug("Scheduled {d} TXs into {d} waves", .{ transactions.len, sched.wave_count() });

        // 2. Execute each wave
        const tx_results = try self.allocator.alloc(TxResult, transactions.len);
        @memset(tx_results, TxResult{ .success = false, .gas_used = 0, .fee = 0, .output = &[_]u8{}, .logs = &[_]state_mod.Overlay.Log{} });

        var total_gas: u64 = 0;

        for (sched.waves.items) |wave| {
            try self.executeWave(world_state, transactions, wave, tx_results, &total_gas);
        }

        // NOTE: Block rewards are NOT applied here — the miner handles rewards
        // separately via block_rewards.applyRewards() after production.
        // This avoids double-reward and ensures a single commit point.

        // 4. Compute state root
        try world_state.trie.commit();
        const root_arr = world_state.trie.rootHash();

        return BlockResult{
            .gas_used = total_gas,
            .tx_results = tx_results,
            .state_root = types.Hash{ .bytes = root_arr },
            .receipts_root = types.Hash.zero(),
        };
    }

    /// Execute a single wavefront of parallel transactions.
    fn executeWave(
        self: *Executor,
        world_state: *state_mod.State,
        transactions: []const types.Transaction,
        wave: scheduler_mod.Wave,
        tx_results: []TxResult,
        total_gas: *u64,
    ) !void {
        if (wave.tx_indices.items.len == 0) return;

        // For small waves, execute sequentially to avoid thread overhead
        if (wave.tx_indices.items.len == 1) {
            const idx = wave.tx_indices.items[0];
            tx_results[idx] = try self.executeSingleTx(world_state, transactions[idx]);
            total_gas.* += tx_results[idx].gas_used;
            return;
        }

        // Parallel execution: each TX gets its own Overlay
        const overlays = try self.allocator.alloc(state_mod.Overlay, wave.tx_indices.items.len);
        defer self.allocator.free(overlays);

        const results_buf = try self.allocator.alloc(TxResult, wave.tx_indices.items.len);
        defer self.allocator.free(results_buf);

        // Initialize overlays
        for (0..wave.tx_indices.items.len) |i| {
            overlays[i] = state_mod.Overlay.init(self.allocator, world_state);
        }

        // Execute in parallel using thread pool
        var threads = std.ArrayListUnmanaged(std.Thread){};
        defer threads.deinit(self.allocator);

        for (wave.tx_indices.items, 0..) |tx_idx, i| {
            const ctx = ThreadContext{
                .executor = self,
                .tx = &transactions[tx_idx],
                .overlay = &overlays[i],
                .result = &results_buf[i],
            };
            const thread = std.Thread.spawn(.{}, executeTxThread, .{ctx}) catch {
                // Fallback to sequential if thread spawn fails
                results_buf[i] = self.executeTxInOverlay(&overlays[i], transactions[tx_idx]);
                continue;
            };
            try threads.append(self.allocator, thread);
        }

        // Wait for all threads
        for (threads.items) |thread| {
            thread.join();
        }

        // Commit overlays in TX-index order (deterministic)
        for (wave.tx_indices.items, 0..) |tx_idx, i| {
            if (results_buf[i].success) {
                overlays[i].commit() catch |err| {
                    log.err("Overlay commit failed for TX {d}: {}", .{ tx_idx, err });
                    results_buf[i].success = false;
                };
            }
            tx_results[tx_idx] = results_buf[i];
            total_gas.* += results_buf[i].gas_used;
            overlays[i].deinit();
        }
    }

    const ThreadContext = struct {
        executor: *Executor,
        tx: *const types.Transaction,
        overlay: *state_mod.Overlay,
        result: *TxResult,
    };

    fn executeTxThread(ctx: ThreadContext) void {
        ctx.result.* = ctx.executor.executeTxInOverlay(ctx.overlay, ctx.tx.*);
    }

    /// Execute a single TX on a base state (no overlay needed — direct commit).
    fn executeSingleTx(self: *Executor, world_state: *state_mod.State, tx: types.Transaction) !TxResult {
        var overlay = state_mod.Overlay.init(self.allocator, world_state);
        defer overlay.deinit();

        const result = self.executeTxInOverlay(&overlay, tx);
        if (result.success) {
            try overlay.commit();
        }
        return result;
    }

    /// Core TX execution logic within an Overlay.
    fn executeTxInOverlay(self: *Executor, overlay: *state_mod.Overlay, tx: types.Transaction) TxResult {
        // 1. Verify nonce
        const current_nonce = overlay.get_nonce(tx.from);
        if (tx.nonce != current_nonce) {
            return TxResult{
                .success = false,
                .gas_used = 0,
                .fee = 0,
                .error_message = "nonce mismatch",
            };
        }

        // 2. Calculate intrinsic gas
        const intrinsic = calcIntrinsicGas(tx.data, tx.to == null);
        if (tx.gas_limit < intrinsic) {
            return TxResult{
                .success = false,
                .gas_used = 0,
                .fee = 0,
                .error_message = "intrinsic gas too low",
            };
        }

        // 3. Check balance covers gas + value
        const max_fee = tx.gas_price * @as(u256, tx.gas_limit);
        const total_cost = max_fee + tx.value;
        const sender_balance = overlay.get_balance(tx.from);
        if (sender_balance < total_cost) {
            return TxResult{
                .success = false,
                .gas_used = 0,
                .fee = 0,
                .error_message = "insufficient balance",
            };
        }

        // 4. Deduct max gas and increment nonce
        overlay.set_balance(tx.from, sender_balance - max_fee) catch
            return TxResult{ .success = false, .gas_used = 0, .fee = 0, .error_message = "state error" };
        overlay.set_nonce(tx.from, current_nonce + 1) catch
            return TxResult{ .success = false, .gas_used = 0, .fee = 0, .error_message = "state error" };

        // 5. Execute
        var gas_used: u64 = intrinsic;
        var success = true;
        var remaining_gas = tx.gas_limit - intrinsic;
        var tx_output: []const u8 = &[_]u8{};

        if (tx.to) |to_addr| {
            // Transfer value
            if (tx.value > 0) {
                overlay.add_balance(to_addr, @intCast(tx.value)) catch {
                    success = false;
                };
            }

            // Contract call — executes within this TX's Overlay
            // The VM operates on isolated per-TX state; the scheduler
            // guarantees zero conflicts between TXs in the same wave.
            if (success and tx.data.len > 0 and overlay.is_program_account(to_addr)) {
                if (self.vm_callback) |vm_cb| {
                    const code_bytes = overlay.get_code(to_addr) catch &[_]u8{};
                    if (code_bytes.len > 0) {
                        const vm_result = vm_cb.execute(code_bytes, tx.data, remaining_gas, overlay, tx.from, tx.value);
                        gas_used += vm_result.gas_used;
                        success = vm_result.success;
                        remaining_gas -|= vm_result.gas_used;
                        tx_output = vm_result.output;
                    }
                }
            }
        } else {
            // Contract creation — isolated per-TX via Overlay
            const new_addr = tx.deriveContractAddress();
            overlay.mark_created(new_addr) catch {};

            // Transfer value to new contract
            if (tx.value > 0) {
                overlay.add_balance(new_addr, @intCast(tx.value)) catch {
                    success = false;
                };
            }

            // Deploy code via VM
            if (success and tx.data.len > 0) {
                if (self.vm_callback) |vm_cb| {
                    const vm_result = vm_cb.execute(tx.data, &[_]u8{}, remaining_gas, overlay, tx.from, tx.value);
                    gas_used += vm_result.gas_used;
                    success = vm_result.success;
                    remaining_gas -|= vm_result.gas_used;
                    if (success and vm_result.output.len > 0) {
                        overlay.set_code(new_addr, vm_result.output) catch {
                            success = false;
                        };
                    }
                } else {
                    // No VM — deploy data directly as code
                    overlay.set_code(new_addr, tx.data) catch {
                        success = false;
                    };
                }
            }
        }

        // 6. Refund unused gas
        const gas_refund = @min(overlay.refund, gas_used / 5); // Max 20% refund
        gas_used -|= gas_refund;
        const actual_fee = tx.gas_price * @as(u256, gas_used);
        const refund_amount = max_fee - actual_fee;
        if (refund_amount > 0) {
            overlay.add_balance(tx.from, @intCast(refund_amount)) catch {};
        }

        // 7. Pay fee to coinbase
        if (!self.config.coinbase.eql(types.Address.zero())) {
            overlay.add_balance(self.config.coinbase, @intCast(actual_fee)) catch {};
        }

        return TxResult{
            .success = success,
            .gas_used = gas_used,
            .fee = actual_fee,
            .error_message = if (success) null else "execution failed",
            .output = tx_output,
            .logs = overlay.logs.items,
        };
    }
};

/// Calculate intrinsic gas for a transaction
fn calcIntrinsicGas(data: []const u8, is_create: bool) u64 {
    var gas: u64 = 21000;
    if (is_create) gas += 32000;

    for (data) |byte| {
        if (byte == 0) {
            gas += 4;
        } else {
            gas += 16;
        }
    }

    return gas;
}
