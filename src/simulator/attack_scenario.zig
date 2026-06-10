const std = @import("std");
const core = @import("core");
const consensus = @import("consensus");
const p2p = @import("p2p");
const node_runner = @import("node_runner.zig");

const Transaction = core.types.Transaction;
const Block = core.types.Block;
const Header = core.types.Header;
const Hash = core.types.Hash;

pub fn runDoubleSign(nodes: []const *node_runner.VirtualNode) !void {
    if (nodes.len == 0) return;
    const n = nodes[0];

    const parent = n.chain.currentBlock orelse return error.NoGenesis;
    const next_num = parent.header.number + 1;
    const proposer_addr = parent.header.producer;

    var header_a = Header{
        .number = next_num,
        .parentId = parent.id(),
        .time = parent.header.time + 10,
        .stateRoot = parent.header.stateRoot,
        .txMerkleRoot = Hash.zero(),
        .producer = proposer_addr,
        .executionBudget = 60_000_000,
        .budgetUsed = 0,
        .extraData = &[_]u8{},
    };
    const block_a_id = Block.blockId(&header_a);

    var header_b = Header{
        .number = next_num,
        .parentId = parent.id(),
        .time = parent.header.time + 20,
        .stateRoot = parent.header.stateRoot,
        .txMerkleRoot = Hash.zero(),
        .producer = proposer_addr,
        .executionBudget = 60_000_000,
        .budgetUsed = 0,
        .extraData = &[_]u8{},
    };
    const block_b_id = Block.blockId(&header_b);

    std.debug.print("\x1b[31m[ATTACK] Simulating Double-Signing on Node 0 at block #{d}...\x1b[0m\n", .{next_num});
    
    _ = try n.engine.recordProposal(next_num, block_a_id, proposer_addr);
    _ = try n.engine.recordProposal(next_num, block_b_id, proposer_addr);
    
    std.Thread.sleep(1000 * std.time.ns_per_ms);
}

pub fn runReplay(nodes: []const *node_runner.VirtualNode) !void {
    if (nodes.len == 0) return;
    const n = nodes[0];

    const dev_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    var seed_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed_bytes, dev_hex);
    const dev_keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed_bytes);
    const dev_addr = core.types.Address.fromPubKey(&dev_keypair.public_key.bytes);

    var tx = Transaction{
        .pub_key = dev_keypair.public_key.bytes,
        .to = dev_addr,
        .value = 1_000_000,
        .executionBudget = 21000,
        .computePrice = 1_000_000_000,
        .sequence = 0,
        .data = &[_]u8{},
        .from = dev_addr,
    };

    const msg = try tx.getSigningMessage(n.allocator);
    defer n.allocator.free(msg);
    const sig = try dev_keypair.sign(msg, null);
    tx.signature = sig.toBytes();

    std.debug.print("\x1b[31m[ATTACK] Injecting Replay Transaction (seq=0) to Node 0...\x1b[0m\n", .{});

    n.dag_pool.add(&tx) catch |err| {
        std.debug.print("\x1b[32m[SUCCESS] Replay rejected by mempool: {}\x1b[0m\n", .{err});
        return;
    };
    std.debug.print("\x1b[31m[WARNING] Replay transaction accepted (vulnerability!)\x1b[0m\n", .{});
}

pub fn runSpam(nodes: []const *node_runner.VirtualNode) !void {
    if (nodes.len == 0) return;
    const n = nodes[0];

    std.debug.print("\x1b[31m[ATTACK] Simulating P2P Spam/Eclipse flood on Node 0 P2P port {d}...\x1b[0m\n", .{n.p2p_port});

    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, n.p2p_port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    var garbage: [100]u8 = undefined;
    std.crypto.random.bytes(&garbage);

    var i: usize = 0;
    while (i < 200) : (i += 1) {
        _ = std.posix.sendto(sock, &garbage, 0, @ptrCast(&address.in.sa), @sizeOf(std.posix.sockaddr.in)) catch {};
    }
    std.debug.print("\x1b[32m[SUCCESS] Dispatched 200 spam packets to Node 0 P2P port. Firewall will filter.\x1b[0m\n", .{});
}

pub fn runDowntime(nodes: []const *node_runner.VirtualNode) !void {
    for (nodes) |n| {
        if (n.is_miner and n.running.load(.seq_cst)) {
            std.debug.print("\x1b[31m[ATTACK] Forcing Miner Node v{d} offline (Downtime simulation)...\x1b[0m\n", .{n.node_index});
            n.stop();
            break;
        }
    }
}
