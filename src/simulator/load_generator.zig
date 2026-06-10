const std = @import("std");
const core = @import("core");
const consensus = @import("consensus");
const p2p = @import("p2p");
const node_runner = @import("node_runner.zig");

const Address = core.types.Address;
const Transaction = core.types.Transaction;

pub const LoadGenerator = struct {
    pub const CLIENT_COUNT: usize = 200;

    allocator: std.mem.Allocator,
    node: *node_runner.VirtualNode,
    tx_rate: u32, // target TPS (e.g. 100)
    running: std.atomic.Value(bool),
    thread: ?std.Thread = null,

    // Statistics
    tx_sent: std.atomic.Value(u64),
    tx_failed: std.atomic.Value(u64),

    // Client Accounts (for parallel lanes)
    seeds: [CLIENT_COUNT][32]u8,
    addresses: [CLIENT_COUNT]Address,
    keypairs: [CLIENT_COUNT]std.crypto.sign.Ed25519.KeyPair,
    nonces: [CLIENT_COUNT]u64,

    pub fn init(allocator: std.mem.Allocator, node: *node_runner.VirtualNode, tx_rate: u32) !*LoadGenerator {
        const self = try allocator.create(LoadGenerator);
        self.* = .{
            .allocator = allocator,
            .node = node,
            .tx_rate = tx_rate,
            .running = std.atomic.Value(bool).init(false),
            .tx_sent = std.atomic.Value(u64).init(0),
            .tx_failed = std.atomic.Value(u64).init(0),
            .seeds = undefined,
            .addresses = undefined,
            .keypairs = undefined,
            .nonces = undefined,
        };

        // Generate client keys
        var i: usize = 0;
        while (i < CLIENT_COUNT) : (i += 1) {
            std.crypto.random.bytes(&self.seeds[i]);
            self.keypairs[i] = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.seeds[i]);
            self.addresses[i] = core.types.Address.fromPubKey(&self.keypairs[i].public_key.bytes);
            self.nonces[i] = 0;
        }

        return self;
    }

    pub fn deinit(self: *LoadGenerator) void {
        self.stop();
        self.allocator.destroy(self);
    }

    pub fn start(self: *LoadGenerator) !void {
        self.running.store(true, .seq_cst);
        try self.fundAccounts();
        self.thread = try std.Thread.spawn(.{}, generatorLoop, .{self});
    }

    pub fn stop(self: *LoadGenerator) void {
        self.running.store(false, .seq_cst);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn fundAccounts(self: *LoadGenerator) !void {
        // Dev seed 0
        const dev_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        var seed_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&seed_bytes, dev_hex);
        const dev_keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed_bytes);
        const dev_addr = core.types.Address.fromPubKey(&dev_keypair.public_key.bytes);

        // Fetch current sequence from state
        const dev_seq = self.node.world_state.getSequence(dev_addr);

        std.debug.print("LoadGenerator: Funding {d} client accounts from dev account...\n", .{CLIENT_COUNT});

        var i: usize = 0;
        while (i < CLIENT_COUNT) : (i += 1) {
            var tx = Transaction{
                .pub_key = dev_keypair.public_key.bytes,
                .to = self.addresses[i],
                .value = 100 * 1_000_000_000_000_000_000, // 100 ZEE
                .executionBudget = 21000,
                .computePrice = 10_000_000_000,
                .sequence = dev_seq + i,
                .data = &[_]u8{},
                .from = dev_addr,
            };

            const msg = try tx.getSigningMessage(self.allocator);
            defer self.allocator.free(msg);
            const sig = try dev_keypair.sign(msg, null);
            tx.signature = sig.toBytes();

            self.node.dag_pool.add(&tx) catch |err| {
                std.debug.print("Failed to add fund TX: {}\n", .{err});
            };
        }

        // Wait for next block to mine funding transactions
        std.debug.print("LoadGenerator: Waiting for client accounts to be funded in world state...\n", .{});
        var funded = false;
        while (!funded) {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            funded = true;
            for (self.addresses) |addr| {
                if (self.node.world_state.getBalance(addr) == 0) {
                    funded = false;
                    break;
                }
            }
        }
        std.debug.print("LoadGenerator: All client accounts funded. Starting transaction generation.\n", .{});
    }

    fn generatorLoop(self: *LoadGenerator) void {
        var s: usize = 0;
        while (s < CLIENT_COUNT) : (s += 1) {
            self.nonces[s] = self.node.world_state.getSequence(self.addresses[s]);
        }

        var rand = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
        const r = rand.random();

        const start_generator_ns = std.time.nanoTimestamp();
        var sent_count: u64 = 0;

        while (self.running.load(.seq_cst)) {
            const now_ns = std.time.nanoTimestamp();
            const elapsed_ns = @as(u64, @intCast(@max(@as(i128, 0), now_ns - start_generator_ns)));
            const expected_sent = (elapsed_ns * self.tx_rate) / std.time.ns_per_s;

            if (sent_count < expected_sent) {
                const sender_idx = r.intRangeLessThan(usize, 0, CLIENT_COUNT);
                var dest_buf: [32]u8 = undefined;
                r.bytes(&dest_buf);
                const recipient = Address{ .bytes = dest_buf };

                var tx = Transaction{
                    .pub_key = self.keypairs[sender_idx].public_key.bytes,
                    .to = recipient,
                    .value = 1_000_000,
                    .executionBudget = 21000,
                .computePrice = 10_000_000_000,
                    .sequence = self.nonces[sender_idx],
                    .data = &[_]u8{},
                    .from = self.addresses[sender_idx],
                };

                const msg = tx.getSigningMessage(self.allocator) catch continue;
                defer self.allocator.free(msg);
                const sig = self.keypairs[sender_idx].sign(msg, null) catch continue;
                tx.signature = sig.toBytes();

                self.node.dag_pool.add(&tx) catch |err| {
                    _ = self.tx_failed.fetchAdd(1, .seq_cst);
                    const count = self.tx_failed.load(.seq_cst);
                    if (count % 1000 == 0) {
                        std.debug.print("LoadGenerator: Transaction validation failed: {}\n", .{err});
                    }
                    continue;
                };

                self.nonces[sender_idx] += 1;
                _ = self.tx_sent.fetchAdd(1, .seq_cst);
                sent_count += 1;
            } else {
                std.Thread.sleep(1 * std.time.ns_per_ms);
            }
        }
    }
};
