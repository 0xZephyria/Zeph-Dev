// Zephyria Blockchain Node — Main Entry Point
// Production-grade L1 blockchain powered by RISC-V VM and ZephyrDB storage.

const std = @import("std");
const vm_bridge = @import("vm_bridge");
const core = @import("core");
const storage = @import("storage");
const consensus = @import("consensus");
const rpc = @import("rpc");
const p2p = @import("p2p");
const node = @import("node");
const log = core.logger;

const types = core.types;
const Block = types.Block;
const Header = types.Header;
const Address = types.Address;
const Hash = types.Hash;

// ── Version Info ─────────────────────────────────────────────────────────
const VERSION = "1.0.0";
const BUILD_TARGET = "native";
const VM_BACKEND = "RISC-V RV32EM";
const STORAGE_ENGINE = "ZephyrDB";
const CONSENSUS = "Loom Genesis Adaptive PoS";

// ── ANSI Escape Codes ────────────────────────────────────────────────────
// Using raw escape sequences directly in strings for zero-overhead output.
const RST = "\x1b[0m";
const BOLD = "\x1b[1m";
// Brand palette
const C_CYAN = "\x1b[38;5;87m";
const C_CYAN2 = "\x1b[38;5;123m";
const C_TEAL = "\x1b[38;5;43m";
const C_MAG = "\x1b[38;5;205m";
const C_PUR = "\x1b[38;5;141m";
const C_VIO = "\x1b[38;5;183m";
const C_BLUE = "\x1b[38;5;75m";
// Status
const C_GRN = "\x1b[38;5;84m";
const C_YEL = "\x1b[38;5;221m";
const C_RED = "\x1b[38;5;203m";
// Neutral
const C_DIM = "\x1b[38;5;245m";
const C_WHT = "\x1b[38;5;255m";
const C_GLW = "\x1b[38;5;51m";
const C_BOX = "\x1b[38;5;240m";

// ── Entry Point ──────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "start")) {
        try startNode(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "account")) {
        try handleAccountCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version")) {
        printVersion();
    } else if (std.mem.eql(u8, command, "status")) {
        printStatus();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        std.debug.print("\n  " ++ C_RED ++ "✗" ++ RST ++ " Unknown command: '" ++ BOLD ++ "{s}" ++ RST ++ "'\n\n", .{command});
        printUsage();
    }
}

// ── Banner ───────────────────────────────────────────────────────────────

fn printBanner() void {
    std.debug.print(
        \\
    ++ C_GLW ++ "    ╔══════════════════════════════════════════════════════════╗\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "                                                          " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "   " ++ BOLD ++ C_CYAN ++ "⚡" ++ RST ++ " " ++ BOLD ++ C_MAG ++ "Z E P H Y R I A" ++ RST ++ "                                  " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "   " ++ C_VIO ++ "High-Performance L1 Blockchain" ++ RST ++ "                        " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "   " ++ C_DIM ++ "v" ++ VERSION ++ "   │  " ++ C_GRN ++ "1M+ TPS" ++ RST ++ C_DIM ++ "  │  " ++ C_PUR ++ "Zero-Conflict DAG" ++ RST ++ "           " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "                                                          " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ╚══════════════════════════════════════════════════════════╝" ++ RST ++
        "\n", .{});
}

// ── CLI Output ───────────────────────────────────────────────────────────

fn printUsage() void {
    printBanner();
    // USAGE header
    std.debug.print("  " ++ BOLD ++ C_CYAN ++ "USAGE" ++ RST ++ "\n" ++
        "    " ++ BOLD ++ "zephyria" ++ RST ++ " " ++ C_PUR ++ "<command>" ++ RST ++ " " ++ C_DIM ++ "[options]" ++ RST ++ "\n\n", .{});
    // COMMANDS
    std.debug.print("  " ++ BOLD ++ C_CYAN ++ "COMMANDS" ++ RST ++ "\n" ++
        "    " ++ C_GRN ++ "start" ++ RST ++ "             " ++ C_DIM ++ "Start the blockchain node" ++ RST ++ "\n" ++
        "    " ++ C_GRN ++ "account new" ++ RST ++ "       " ++ C_DIM ++ "Generate a new validator account" ++ RST ++ "\n" ++
        "    " ++ C_GRN ++ "account list" ++ RST ++ "      " ++ C_DIM ++ "List all local accounts" ++ RST ++ "\n" ++
        "    " ++ C_GRN ++ "version" ++ RST ++ "           " ++ C_DIM ++ "Show version and build information" ++ RST ++ "\n" ++
        "    " ++ C_GRN ++ "status" ++ RST ++ "            " ++ C_DIM ++ "Check node status" ++ RST ++ "\n" ++
        "    " ++ C_GRN ++ "help" ++ RST ++ "              " ++ C_DIM ++ "Show this help message" ++ RST ++ "\n\n", .{});
    // NODE OPTIONS
    std.debug.print("  " ++ BOLD ++ C_CYAN ++ "NODE OPTIONS" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--port" ++ RST ++ " " ++ C_DIM ++ "<port>     P2P listening port        (default: 30303)" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--http.port" ++ RST ++ " " ++ C_DIM ++ "<p>   JSON-RPC HTTP port        (default: 8545)" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--datadir" ++ RST ++ " " ++ C_DIM ++ "<path>  Data directory             (default: ./node_data)" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--network" ++ RST ++ " " ++ C_DIM ++ "<name>  Network: devnet|testnet   (default: devnet)" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--mine" ++ RST ++ "            " ++ C_DIM ++ "Enable block production" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--miner.key" ++ RST ++ " " ++ C_DIM ++ "<hex> Validator private key (hex)" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--keystore" ++ RST ++ " " ++ C_DIM ++ "<path> Keystore file for validator" ++ RST ++ "\n" ++
        "    " ++ C_YEL ++ "--password" ++ RST ++ " " ++ C_DIM ++ "<pw>   Keystore password" ++ RST ++ "\n\n", .{});
    // QUICK START & COMPATIBILITY
    std.debug.print("  " ++ BOLD ++ C_CYAN ++ "QUICK START" ++ RST ++ "\n" ++
        "    " ++ C_DIM ++ "$" ++ RST ++ " " ++ BOLD ++ C_WHT ++ "zephyria start --network devnet --mine" ++ RST ++ "\n\n" ++
        "  " ++ BOLD ++ C_CYAN ++ "ETHEREUM COMPATIBILITY" ++ RST ++ "\n" ++
        "    " ++ C_TEAL ++ "JSON-RPC" ++ RST ++ "    " ++ C_BLUE ++ "http://127.0.0.1:8545" ++ RST ++ "\n" ++
        "    " ++ C_TEAL ++ "Compatible" ++ RST ++ "  " ++ C_DIM ++ "ethers.js  •  web3.js  •  MetaMask  •  Hardhat" ++ RST ++ "\n\n", .{});
}

fn printVersion() void {
    printBanner();
    // BUILD INFO
    std.debug.print("  " ++ BOLD ++ C_CYAN ++ "◆ BUILD INFO" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_TEAL ++ "VM Engine" ++ RST ++ "       " ++ C_WHT ++ VM_BACKEND ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_TEAL ++ "Storage" ++ RST ++ "         " ++ C_WHT ++ STORAGE_ENGINE ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_TEAL ++ "Consensus" ++ RST ++ "       " ++ C_WHT ++ CONSENSUS ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_TEAL ++ "Target" ++ RST ++ "          " ++ C_WHT ++ BUILD_TARGET ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_DIM ++ "└─" ++ RST ++ " " ++ C_TEAL ++ "Zig Version" ++ RST ++ "     " ++ C_WHT ++ "{s}" ++ RST ++ "\n\n", .{@import("builtin").zig_version_string});
    // FEATURES
    std.debug.print("  " ++ BOLD ++ C_MAG ++ "◆ FEATURES" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_PUR ++ "DAG Mempool" ++ RST ++ "     " ++ C_DIM ++ "256-shard, zero-conflict lanes" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_PUR ++ "Execution" ++ RST ++ "       " ++ C_DIM ++ "Parallel isolated accounts" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "├─" ++ RST ++ " " ++ C_PUR ++ "State" ++ RST ++ "           " ++ C_DIM ++ "Verkle Trie (IPA commitments)" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "└─" ++ RST ++ " " ++ C_PUR ++ "EVM Compatible" ++ RST ++ "  " ++ C_DIM ++ "ethers.js • web3.js • Hardhat" ++ RST ++ "\n\n", .{});
}

fn printStatus() void {
    std.debug.print("\n" ++
        "  " ++ BOLD ++ C_CYAN ++ "◉ NODE STATUS" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "────────────────────────────────" ++ RST ++ "\n" ++
        "  " ++ C_TEAL ++ "Status" ++ RST ++ "     " ++ C_YEL ++ "● Offline" ++ RST ++ "\n" ++
        "  " ++ C_TEAL ++ "Hint" ++ RST ++ "       " ++ C_DIM ++ "Run '" ++ C_GRN ++ "zephyria start" ++ RST ++ C_DIM ++ "' to launch" ++ RST ++ "\n\n", .{});
}

// ── Account Management ───────────────────────────────────────────────────

fn handleAccountCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("\n" ++
            "  " ++ BOLD ++ C_CYAN ++ "USAGE" ++ RST ++ "\n" ++
            "    " ++ BOLD ++ "zephyria account" ++ RST ++ " " ++ C_PUR ++ "<subcommand>" ++ RST ++ "\n\n" ++
            "  " ++ BOLD ++ C_CYAN ++ "SUBCOMMANDS" ++ RST ++ "\n" ++
            "    " ++ C_GRN ++ "new" ++ RST ++ "     " ++ C_DIM ++ "Generate a new validator keypair" ++ RST ++ "\n" ++
            "    " ++ C_GRN ++ "list" ++ RST ++ "    " ++ C_DIM ++ "List all accounts in the keystore" ++ RST ++ "\n\n", .{});
        return;
    }

    const sub = args[0];
    var data_dir: []const u8 = "./node_data";

    // Parse --datadir option
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--datadir")) {
            if (i + 1 < args.len) {
                data_dir = args[i + 1];
                i += 1;
            }
        }
    }

    const keystore_dir_path = try std.fs.path.join(allocator, &[_][]const u8{ data_dir, "keystore" });
    defer allocator.free(keystore_dir_path);
    try std.fs.cwd().makePath(keystore_dir_path);

    if (std.mem.eql(u8, sub, "new")) {
        std.debug.print("\n  " ++ C_CYAN ++ "◆" ++ RST ++ " Generating new account...\n", .{});
        var priv_key: [32]u8 = undefined;
        std.crypto.random.bytes(&priv_key);

        // Derive address from private key
        var addr: [20]u8 = undefined;
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&priv_key, &hash_buf, .{});
        @memcpy(&addr, hash_buf[12..]);

        var addr_buf: [42]u8 = undefined;
        const addr_hex = try @import("utils").hex.encodeBuffer(&addr_buf, &addr);

        // Save to keystore
        const json = try std.fmt.allocPrint(allocator, "{{\"address\":\"{s}\",\"version\":3}}", .{addr_hex});
        defer allocator.free(json);

        const filename = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ keystore_dir_path, addr_hex });
        defer allocator.free(filename);

        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();
        try file.writeAll(json);

        std.debug.print("  " ++ C_GRN ++ "✓" ++ RST ++ " Created account: " ++ BOLD ++ C_CYAN ++ "0x{s}" ++ RST ++ "\n", .{addr_hex});
        std.debug.print("  " ++ C_GRN ++ "✓" ++ RST ++ " Saved to: " ++ C_DIM ++ "{s}" ++ RST ++ "\n\n", .{filename});
    } else if (std.mem.eql(u8, sub, "list")) {
        std.debug.print("\n  " ++ BOLD ++ C_CYAN ++ "◆ Local Accounts" ++ RST ++ "\n  " ++ C_DIM ++ "────────────────────────────────" ++ RST ++ "\n", .{});
        var dir = try std.fs.cwd().openDir(keystore_dir_path, .{ .iterate = true });
        defer dir.close();

        var it = dir.iterate();
        var count: u32 = 0;
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".json")) {
                const full_path = try std.fs.path.join(allocator, &[_][]const u8{ keystore_dir_path, entry.name });
                defer allocator.free(full_path);

                const content = try std.fs.cwd().readFileAlloc(allocator, full_path, 4096);
                defer allocator.free(content);

                const parsed = try std.json.parseFromSlice(struct { address: []const u8 }, allocator, content, .{});
                defer parsed.deinit();

                count += 1;
                std.debug.print("  " ++ C_DIM ++ "{d}." ++ RST ++ " " ++ C_CYAN ++ "0x{s}" ++ RST ++ "\n", .{ count, parsed.value.address });
            }
        }
        if (count == 0) {
            std.debug.print("  " ++ C_DIM ++ "(no accounts found)" ++ RST ++ "\n", .{});
            std.debug.print("  Run '" ++ C_GRN ++ "zephyria account new" ++ RST ++ "' to create one\n", .{});
        }
        std.debug.print("\n", .{});
    } else {
        std.debug.print("  " ++ C_RED ++ "✗" ++ RST ++ " Unknown subcommand: '" ++ BOLD ++ "{s}" ++ RST ++ "'\n", .{sub});
    }
}

// ── Signal Handling ──────────────────────────────────────────────────────

var running = std.atomic.Value(bool).init(true);

fn sigHandler(sig: c_int) callconv(.c) void {
    _ = sig;
    running.store(false, .seq_cst);
    log.info("Shutting down gracefully...", .{});
}

// ── Helper: component status line ────────────────────────────────────────
fn printComponentLine(comptime connector: []const u8, comptime name: []const u8, detail: []const u8) void {
    std.debug.print("  " ++ C_DIM ++ connector ++ RST ++ " " ++ C_TEAL ++ "▸" ++ RST ++ " " ++ C_WHT ++ name ++ RST ++ " " ++ C_DIM ++ "{s}" ++ RST ++ " " ++ C_GRN ++ "✓" ++ RST ++ "\n", .{detail});
}

fn printComponentFmt(comptime connector: []const u8, comptime name: []const u8, comptime fmt: []const u8, value: anytype) void {
    std.debug.print("  " ++ C_DIM ++ connector ++ RST ++ " " ++ C_TEAL ++ "▸" ++ RST ++ " " ++ C_WHT ++ name ++ RST ++ " " ++ C_DIM ++ fmt ++ RST ++ " " ++ C_GRN ++ "✓" ++ RST ++ "\n", .{value});
}

// ── Node Startup ─────────────────────────────────────────────────────────

fn startNode(allocator: std.mem.Allocator, args: []const []const u8) !void {
    // ── Parse Arguments ──
    var p2p_port: u16 = 30303;
    var http_port: u16 = 8545;
    var data_dir: []const u8 = "./node_data";
    var network_name: []const u8 = "devnet";
    var should_mine: bool = false;
    var miner_key_hex: ?[]const u8 = null;
    var miner_keystore_path: ?[]const u8 = null;
    var password: []const u8 = "password";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port")) {
            if (i + 1 < args.len) {
                p2p_port = try std.fmt.parseInt(u16, args[i + 1], 10);
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--http.port")) {
            if (i + 1 < args.len) {
                http_port = try std.fmt.parseInt(u16, args[i + 1], 10);
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--datadir")) {
            if (i + 1 < args.len) {
                data_dir = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--network")) {
            if (i + 1 < args.len) {
                network_name = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--mine")) {
            should_mine = true;
        } else if (std.mem.eql(u8, args[i], "--miner.key")) {
            if (i + 1 < args.len) {
                miner_key_hex = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--keystore")) {
            if (i + 1 < args.len) {
                miner_keystore_path = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--password")) {
            if (i + 1 < args.len) {
                password = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--log-level")) {
            if (i + 1 < args.len) {
                if (log.Level.fromString(args[i + 1])) |level| {
                    log.setLevel(level);
                }
                i += 1;
            }
        }
    }

    // ── Startup Banner ──
    printBanner();
    std.debug.print("  " ++ BOLD ++ C_CYAN ++ "◆ INITIALIZING" ++ RST ++ "\n", .{});

    // Auto-enable mining for devnet
    if (std.mem.eql(u8, network_name, "devnet") and !should_mine) {
        should_mine = true;
    }

    // ── Initialize Components ──

    // Install signal handler
    const act = std.posix.Sigaction{
        .handler = .{ .handler = &sigHandler },
        .mask = 0,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    // 1. Storage
    try std.fs.cwd().makePath(data_dir);
    var db = try storage.lsm.db.DB.init(allocator, data_dir);
    defer db.deinit();
    printComponentLine("├─", "Storage       ", "ZephyrDB + LSM engine");

    var trie = try storage.verkle.trie.VerkleTrie.init(allocator, db.asAbstractDB());
    defer trie.deinit();
    printComponentLine("├─", "Verkle Trie   ", "IPA commitments");

    var world_state = core.state.State.init(allocator, trie);
    defer world_state.deinit();

    // 2. Network config + Genesis
    const network = core.genesis.getNetworkConfig(network_name);

    // Determine Miner Identity
    var miner_priv_key: [32]u8 = undefined;
    var validator_addr: Address = undefined;

    if (miner_key_hex) |hex_str| {
        const trimmed = if (hex_str.len >= 2 and hex_str[0] == '0' and hex_str[1] == 'x')
            hex_str[2..]
        else
            hex_str;
        _ = std.fmt.hexToBytes(&miner_priv_key, trimmed) catch |err| {
            log.err("Invalid --miner.key: {}", .{err});
            return error.InvalidMinerKey;
        };
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&miner_priv_key, &hash_buf, .{});
        @memcpy(&validator_addr.bytes, hash_buf[12..]);
    } else if (miner_keystore_path) |ks_path| {
        const ks_data = try std.fs.cwd().readFileAlloc(allocator, ks_path, 4096);
        defer allocator.free(ks_data);
        const parsed = try std.json.parseFromSlice(struct { address: []const u8 }, allocator, ks_data, .{});
        defer parsed.deinit();
        // NOTE: Keystore decryption not yet implemented — generating random key
        log.warn("Keystore decryption not implemented, using random key", .{});
        std.crypto.random.bytes(&miner_priv_key);
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&miner_priv_key, &hash_buf, .{});
        @memcpy(&validator_addr.bytes, hash_buf[12..]);
    } else if (should_mine) {
        std.crypto.random.bytes(&miner_priv_key);
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&miner_priv_key, &hash_buf, .{});
        @memcpy(&validator_addr.bytes, hash_buf[12..]);
    } else {
        log.err("Mining requested but no key provided. Use --miner.key <hex> or --keystore <path>", .{});
        return error.MinerKeyRequired;
    }

    // 3. Blockchain
    var chain = try core.blockchain.Blockchain.init(allocator, db.asAbstractDB(), @as(u64, @intCast(network.chain_id)));
    defer chain.deinit();

    var genesis_hash: Hash = Hash.zero();
    if (chain.get_head()) |head| {
        genesis_hash = head.hash();
        printComponentFmt("├─", "Chain         ", "Block #{d}", head.header.number);
    } else {
        const alloc = core.genesis.getDefaultAlloc();
        const sys_contracts = core.genesis.getDefaultSystemContracts();
        const genesis = core.genesis.Genesis{
            .config = network,
            .alloc = &alloc,
            .system_contracts = &sys_contracts,
        };
        const genesis_block = core.genesis.applyGenesis(allocator, trie, genesis) catch {
            log.err("Failed to create genesis block", .{});
            return;
        };
        try chain.add_block(genesis_block);
        genesis_hash = genesis_block.hash();
        printComponentLine("├─", "Genesis       ", "New chain created");
    }

    // 4. Consensus Engine (Zelius PoS)
    const validator_info = consensus.types.ValidatorInfo{
        .address = validator_addr,
        .stake = 100_000_000_000_000_000_000_000, // 100k ZEE
        .status = .Active,
        .bls_pub_key = [_]u8{0} ** 48,
        .commission = 500, // 5%
        .activation_block = 0,
        .slash_count = 0,
        .total_rewards = 0,
        .name = "validator-0",
        .website = "",
    };
    const validators = [_]consensus.types.ValidatorInfo{validator_info};
    const engine = try consensus.ZeliusEngine.init(allocator, &validators);
    defer engine.deinit();
    engine.set_priv_key(miner_priv_key);
    engine.set_bls_priv_key(&miner_priv_key);
    printComponentLine("├─", "Consensus     ", "Loom Genesis Adaptive PoS");

    // Initial epoch rotation to seed adaptive consensus
    {
        const initial_stakes = [_]u64{100_000_000_000};
        engine.rotateEpoch(0, genesis_hash.bytes, &initial_stakes) catch |err| {
            log.err("Initial epoch rotation failed: {}", .{err});
        };
    }

    // 5. Legacy Components (backward compatibility for RPC and fallback)
    var pool = core.tx_pool.TxPool.init(allocator, &world_state);
    defer pool.deinit();

    var exec = core.executor.Executor.init(allocator, .{
        .max_threads = 16,
        .block_gas_limit = @as(u64, @intCast(network.gas_limit)),
        .base_fee = network.base_fee orelse 1_000_000_000,
        .coinbase = validator_addr,
    });

    // 5a. DAG Pipeline (primary execution path for 1M+ TPS)
    var dag_pool = try core.dag_mempool.DAGMempool.init(allocator, &world_state, .{});
    defer dag_pool.deinit();

    var dag_exec = core.dag_executor.DAGExecutor.init(allocator, &world_state, .{
        .num_threads = 8,
        .block_gas_limit = @as(u64, @intCast(network.gas_limit)),
        .coinbase = validator_addr,
        .base_fee = network.base_fee orelse 1_000_000_000,
        .transfer_fast_path = true,
    });

    // ── Performance Optimization Modules (P0-P2) ────────────────────

    // P0: Async State Root — background Verkle trie commitment
    var async_root = core.async_state_root.AsyncStateRootComputer.init(
        allocator,
        &world_state,
        .{ .root_lag = 2, .max_queue_depth = 8 },
    );
    defer async_root.deinit();
    // NOTE: Do NOT start the async root background thread here.
    // The miner already calls trie.commit() + rootHash() directly in
    // its block production loop. Starting the bg thread causes a race
    // where it clears dirty_count before the miner can commit, resulting
    // in stale (unchanging) state roots. The async root computer object
    // is still registered with DAGExecutor for future use when the DAG
    // path handles its own commits independently.
    dag_exec.setAsyncRoot(&async_root);

    // P1: State Prefetcher — trie cache warming before lane execution
    var state_pf = core.state_prefetcher.StatePrefetcher.init(
        allocator,
        &world_state,
        .{ .max_addresses = 1_000_000, .prefetch_code = true },
    );
    defer state_pf.deinit();
    dag_exec.setPrefetcher(&state_pf);

    // P1: Lock-Free Delta Merger — parallel merge of lane deltas
    var delta_merger = core.delta_merge.DeltaMerger.init(allocator);
    defer delta_merger.deinit();
    dag_exec.setDeltaMerger(&delta_merger);

    printComponentLine("├─", "DAG Pipeline  ", "256-shard mempool + parallel executor");
    printComponentLine("├─", "Optimizations ", "AsyncRoot + Prefetch + DeltaMerge");

    // 5b. BlockProducer — unified production interface (DAG primary, legacy fallback)
    var producer = core.block_producer.BlockProducer.init(
        allocator,
        chain,
        &world_state,
        validator_addr,
        @as(u64, @intCast(network.gas_limit)),
    );
    producer.setDAGPipeline(dag_pool, &dag_exec);
    producer.setLegacyPipeline(&pool, &exec);
    producer.setAsyncRoot(&async_root);
    printComponentLine("├─", "BlockProducer ", "DAG + legacy fallback + async root");

    // 5c. Consensus subsystems
    var pipeline = consensus.Pipeline.init(allocator, .{
        .validator_count = 1,
        .our_index = 0,
        .our_address = validator_addr,
        .thread_count = engine.getThreadCount(),
        .tier = engine.getCurrentTier(),
    });
    defer pipeline.deinit();

    var staking = consensus.Staking.init(allocator, .{});
    defer staking.deinit();

    // Register initial validator in staking
    staking.registerValidator(
        validator_addr,
        100_000_000_000_000_000_000_000, // 100k ZEE self-stake
        500, // 5% commission
        0, // registered at genesis
    ) catch {};

    // Loom Genesis Adaptive Consensus subsystems
    var thread_attest_pool = consensus.ThreadAttestationPool.init(allocator);
    defer thread_attest_pool.deinit();

    var snowball_inst = consensus.Snowball.init(allocator, .{});
    defer snowball_inst.deinit();
    printComponentLine("├─", "Adaptive      ", "ThreadPool + Snowball ready");

    // 6. VM Bridge (thread-safe, wired to both executors)
    var riscv_bridge = vm_bridge.VMBridge.init(allocator, .{
        .enable_jit = true,
        .optimization_level = .Fast,
        .trace_execution = false,
    });
    defer riscv_bridge.deinit();

    // Wire execution context for contracts (block env + chain config)
    riscv_bridge.setExecutionContext(.{
        .timestamp = @intCast(@max(0, std.time.timestamp())),
        .block_number = 0,
        .chain_id = 99999,
        .coinbase = validator_addr.bytes,
        .prevrandao = genesis_hash.bytes,
    });

    // Wire VM callback to BOTH executors (DAG primary, legacy fallback)
    dag_exec.setVMCallback(riscv_bridge.getCallback());
    exec.setVMCallback(riscv_bridge.getLegacyCallback());
    printComponentLine("├─", "VM Engine     ", "RISC-V RV32EM (thread-safe)");

    // 7. Miner (uses BlockProducer for unified DAG/legacy production)
    var node_miner = try node.Miner.init(
        allocator,
        chain,
        &pool,
        engine,
        &exec,
        &world_state,
        validator_addr,
        &running,
        &producer,
    );
    defer node_miner.deinit();

    node_miner.setPipeline(&pipeline);
    node_miner.setStaking(&staking);
    node_miner.setValidatorIndex(0);

    // 8. Epoch Integration
    const epoch_integration = try node.EpochIntegration.init(
        allocator,
        db.asAbstractDB(),
        100,
    );
    defer epoch_integration.deinit();
    node_miner.setEpochIntegration(epoch_integration);

    // 9. Historical State
    const historical_state = try core.historical_state.HistoricalState.init(
        allocator,
        db.asAbstractDB(),
        &world_state,
    );
    defer historical_state.deinit();
    historical_state.setHead(chain.get_head_number());

    // 10. P2P Server
    var p2p_server = try p2p.Server.init(allocator, chain, engine, &pool, .{ .listen_port = p2p_port });
    defer p2p_server.deinit();
    node_miner.set_p2p(p2p_server);
    p2p_server.setThreadAttestPool(&thread_attest_pool);
    p2p_server.setSnowballEngine(&snowball_inst);

    // P2: Shred Signature Verifier — Ed25519 + 10% sampling
    var shred_verifier = p2p.shred_verifier.ShredVerifier.init(allocator, .{
        .sample_rate = 0.10,
        .enabled = true,
    });
    defer shred_verifier.deinit();

    // Register our own validator for self-verification
    try shred_verifier.addValidator(.{
        .address = validator_addr,
        .pubkey = [_]u8{0} ** 32, // Populated from BLS/Ed25519 key in production
        .stake = 100_000_000_000, // 100K ZEE (in gwei units)
        .active = true,
    });
    p2p_server.setShredVerifier(&shred_verifier);

    try p2p_server.start();
    printComponentFmt("├─", "P2P           ", "Port {d} + shred verification", p2p_port);

    // 11. JSON-RPC Server
    const rpc_server = try rpc.Server.init(allocator, http_port, chain, &pool, &exec, &world_state);
    defer rpc_server.deinit();
    rpc_server.set_p2p(p2p_server);
    rpc_server.setHistoricalState(historical_state);
    rpc_server.setDAGPool(dag_pool);
    try rpc_server.start();
    printComponentFmt("└─", "JSON-RPC      ", "Port {d}", http_port);

    // ── Node Dashboard ──
    var addr_buf: [42]u8 = undefined;
    const addr_hex = try @import("utils").hex.encodeBuffer(&addr_buf, &validator_addr.bytes);

    // Top border
    std.debug.print("\n  " ++ C_GLW ++ "╔══════════════════════════════════════════════════════════╗" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ BOLD ++ C_GRN ++ "◉ NODE ACTIVE" ++ RST ++ "                                           " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "╠══════════════════════════════════════════════════════════╣" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "                                                          " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    // Network, Chain ID, Validator — each as its own print call
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Network" ++ RST ++ "       " ++ C_WHT ++ "{s: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{network_name});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Chain ID" ++ RST ++ "      " ++ C_WHT ++ "{d: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{network.chain_id});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Validator" ++ RST ++ "     " ++ C_CYAN ++ "0x{s: <38}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{addr_hex});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Mining" ++ RST ++ "        " ++ C_WHT ++ "{s: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{if (should_mine) "● Active" else "○ Standby"});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Consensus" ++ RST ++ "     " ++ C_MAG ++ "{s: <38}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{@tagName(engine.getCurrentTier())});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Threads" ++ RST ++ "       " ++ C_WHT ++ "{d: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{engine.getThreadCount()});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "                                                          " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    // Endpoints section
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ BOLD ++ C_PUR ++ "ENDPOINTS" ++ RST ++ "                                              " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "P2P" ++ RST ++ "           " ++ C_BLUE ++ ":{d: <39}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{p2p_port});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "JSON-RPC" ++ RST ++ "      " ++ C_BLUE ++ "http://127.0.0.1:{d: <23}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{http_port});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Data Dir" ++ RST ++ "      " ++ C_DIM ++ "{s: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{data_dir});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "                                                          " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    // Bottom border
    std.debug.print("  " ++ C_GLW ++ "╚══════════════════════════════════════════════════════════╝" ++ RST ++ "\n\n", .{});

    // ── Start Block Production ──
    if (should_mine) {
        std.debug.print("  " ++ C_CYAN ++ "⚡" ++ RST ++ " Block production started. Press " ++ BOLD ++ "Ctrl+C" ++ RST ++ " to stop.\n\n", .{});
        try node_miner.start();
    } else {
        std.debug.print("  " ++ C_GRN ++ "◉" ++ RST ++ " Node ready (standby). Press " ++ BOLD ++ "Ctrl+C" ++ RST ++ " to stop.\n\n", .{});
        while (running.load(.seq_cst)) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }

    std.debug.print("\n  " ++ C_YEL ++ "●" ++ RST ++ " Node stopped.\n\n", .{});
}
