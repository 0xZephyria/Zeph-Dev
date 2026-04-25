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
const VM_BACKEND = "RISC-V RV64IM";
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

/// Main entry point for the Zephyria blockchain node.
/// Parses CLI commands and dispatches to the appropriate handlers.
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

/// Prints the Zephyria ASCII brand banner to stdout.
fn printBanner() void {
    std.debug.print(
        \\
    ++ C_GLW ++ "    ╔══════════════════════════════════════════════════════════╗\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "                                                          " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "      " ++ BOLD ++ C_CYAN ++ "⚡" ++ RST ++ " " ++ BOLD ++ C_MAG ++ "Z E P H Y R I A" ++ RST ++ "                                  " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "    " ++ C_VIO ++ "High-Performance L1 Blockchain" ++ RST ++ "                        " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "      " ++ C_DIM ++ "v" ++ VERSION ++ "   │  " ++ C_GRN ++ "1M+ TPS" ++ RST ++ C_DIM ++ "  │  " ++ C_PUR ++ "Zero-Conflict DAG" ++ RST ++ "           " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ║" ++ RST ++ "                                                          " ++ C_GLW ++ "║\n" ++ RST ++
        C_GLW ++ "    ╚══════════════════════════════════════════════════════════╝" ++ RST ++
        "\n", .{});
}

// ── CLI Output ───────────────────────────────────────────────────────────

/// Prints CLI usage instructions, including available commands and node options.
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

/// Prints detailed version, build, and feature information.
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

/// Prints the current status of the node (e.g., Online/Offline).
fn printStatus() void {
    std.debug.print("\n" ++
        "  " ++ BOLD ++ C_CYAN ++ "◉ NODE STATUS" ++ RST ++ "\n" ++
        "  " ++ C_DIM ++ "────────────────────────────────" ++ RST ++ "\n" ++
        "  " ++ C_TEAL ++ "Status" ++ RST ++ "     " ++ C_YEL ++ "● Offline" ++ RST ++ "\n" ++
        "  " ++ C_TEAL ++ "Hint" ++ RST ++ "       " ++ C_DIM ++ "Run '" ++ C_GRN ++ "zephyria start" ++ RST ++ C_DIM ++ "' to launch" ++ RST ++ "\n\n", .{});
}

// ── Account Management ───────────────────────────────────────────────────

/// Handles account management subcommands (new, list).
/// Creates and manages validator keypairs in the local keystore.
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
    var dataDir: []const u8 = "./node_data";

    // Parse --datadir option
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--datadir")) {
            if (i + 1 < args.len) {
                dataDir = args[i + 1];
                i += 1;
            }
        }
    }

    const keystoreDirPath = try std.fs.path.join(allocator, &[_][]const u8{ dataDir, "keystore" });
    defer allocator.free(keystoreDirPath);
    try std.fs.cwd().makePath(keystoreDirPath);

    if (std.mem.eql(u8, sub, "new")) {
        std.debug.print("\n  " ++ C_CYAN ++ "◆" ++ RST ++ " Generating new account...\n", .{});
        var priv_key: [32]u8 = undefined;
        std.crypto.random.bytes(&priv_key);

        // Derive address from private key
        var addr: [20]u8 = undefined;
        var hashBuf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&priv_key, &hashBuf, .{});
        @memcpy(&addr, hashBuf[12..]);

        var addr_buf: [42]u8 = undefined;
        const addr_hex = try @import("utils").hex.encodeBuffer(&addr_buf, &addr);

        // Save to keystore
        const json = try std.fmt.allocPrint(allocator, "{{\"address\":\"{s}\",\"version\":3}}", .{addr_hex});
        defer allocator.free(json);

        const filename = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ keystoreDirPath, addr_hex });
        defer allocator.free(filename);

        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();
        try file.writeAll(json);

        std.debug.print("  " ++ C_GRN ++ "✓" ++ RST ++ " Created account: " ++ BOLD ++ C_CYAN ++ "0x{s}" ++ RST ++ "\n", .{addr_hex});
        std.debug.print("  " ++ C_GRN ++ "✓" ++ RST ++ " Saved to: " ++ C_DIM ++ "{s}" ++ RST ++ "\n\n", .{filename});
    } else if (std.mem.eql(u8, sub, "list")) {
        std.debug.print("\n  " ++ BOLD ++ C_CYAN ++ "◆ Local Accounts" ++ RST ++ "\n  " ++ C_DIM ++ "────────────────────────────────" ++ RST ++ "\n", .{});
        var dir = try std.fs.cwd().openDir(keystoreDirPath, .{ .iterate = true });
        defer dir.close();

        var it = dir.iterate();
        var count: u32 = 0;
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".json")) {
                const full_path = try std.fs.path.join(allocator, &[_][]const u8{ keystoreDirPath, entry.name });
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

/// Initializes and starts a Zephyria blockchain node.
/// Orchestrates the setup of storage, consensus, networking (P2P), RPC, and VM components.
/// If `shouldMine` is true, begins active block production.
fn startNode(allocator: std.mem.Allocator, args: []const []const u8) !void {
    // ── Parse Arguments ──
    var p2pPort: u16 = 30303;
    var httpPort: u16 = 8545;
    var dataDir: []const u8 = "./node_data";
    var networkName: []const u8 = "devnet";
    var shouldMine: bool = false;
    var minerKeyHex: ?[]const u8 = null;
    var minerKeystorePath: ?[]const u8 = null;
    var password: []const u8 = "password";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port")) {
            if (i + 1 < args.len) {
                p2pPort = try std.fmt.parseInt(u16, args[i + 1], 10);
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--http.port")) {
            if (i + 1 < args.len) {
                httpPort = try std.fmt.parseInt(u16, args[i + 1], 10);
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--datadir")) {
            if (i + 1 < args.len) {
                dataDir = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--network")) {
            if (i + 1 < args.len) {
                networkName = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--mine")) {
            shouldMine = true;
        } else if (std.mem.eql(u8, args[i], "--miner.key")) {
            if (i + 1 < args.len) {
                minerKeyHex = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--keystore")) {
            if (i + 1 < args.len) {
                minerKeystorePath = args[i + 1];
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
    if (std.mem.eql(u8, networkName, "devnet") and !shouldMine) {
        shouldMine = true;
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
    try std.fs.cwd().makePath(dataDir);
    var db = try storage.lsm.db.DB.init(allocator, dataDir);
    defer db.deinit();
    printComponentLine("├─", "Storage       ", "ZephyrDB + LSM engine");

    var trie = try storage.verkle.trie.VerkleTrie.init(allocator, db.asAbstractDB());
    defer trie.deinit();
    printComponentLine("├─", "Verkle Trie   ", "IPA commitments");

    var worldState = core.state.State.init(allocator, trie);
    defer worldState.deinit();

    // 2. Network config + Genesis
    const network = core.genesis.getNetworkConfig(networkName);

    // Determine Miner Identity
    var minerPrivKey: [32]u8 = undefined;
    var validatorAddr: Address = undefined;

    if (minerKeyHex) |hex_str| {
        const trimmed = if (hex_str.len >= 2 and hex_str[0] == '0' and hex_str[1] == 'x')
            hex_str[2..]
        else
            hex_str;
        _ = std.fmt.hexToBytes(&minerPrivKey, trimmed) catch |err| {
            log.err("Invalid --miner.key: {}", .{err});
            return error.InvalidMinerKey;
        };
        var hashBuf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&minerPrivKey, &hashBuf, .{});
        @memcpy(&validatorAddr.bytes, hashBuf[12..]);
    } else if (minerKeystorePath) |ks_path| {
        const ks_data = try std.fs.cwd().readFileAlloc(allocator, ks_path, 4096);
        defer allocator.free(ks_data);
        const parsed = try std.json.parseFromSlice(struct { address: []const u8 }, allocator, ks_data, .{});
        defer parsed.deinit();
        // NOTE: Keystore decryption not yet implemented — generating random key
        log.warn("Keystore decryption not implemented, using random key", .{});
        std.crypto.random.bytes(&minerPrivKey);
        var hashBuf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&minerPrivKey, &hashBuf, .{});
        @memcpy(&validatorAddr.bytes, hashBuf[12..]);
    } else if (shouldMine) {
        std.crypto.random.bytes(&minerPrivKey);
        var hashBuf: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&minerPrivKey, &hashBuf, .{});
        @memcpy(&validatorAddr.bytes, hashBuf[12..]);
    } else {
        log.err("Mining requested but no key provided. Use --miner.key <hex> or --keystore <path>", .{});
        return error.MinerKeyRequired;
    }

    // 3. Blockchain
    var chain = try core.blockchain.Blockchain.init(allocator, db.asAbstractDB(), @as(u64, @intCast(network.chainId)));
    defer chain.deinit();

    var genesisHash: Hash = Hash.zero();
    if (chain.getHead()) |head| {
        genesisHash = head.hash();
        printComponentFmt("├─", "Chain         ", "Block #{d}", head.header.number);
    } else {
        const alloc = core.genesis.getDefaultAlloc();
        const sysContracts = core.genesis.getDefaultSystemContracts();
        const genesis = core.genesis.Genesis{
            .config = network,
            .alloc = &alloc,
            .systemContracts = &sysContracts,
        };
        const genesisBlock = core.genesis.applyGenesis(allocator, trie, genesis) catch {
            log.err("Failed to create genesis block", .{});
            return;
        };
        try chain.addBlock(genesisBlock);
        genesisHash = genesisBlock.hash();
        printComponentLine("├─", "Genesis       ", "New chain created");
    }

    // 4. Consensus Engine (Zelius PoS)
    const validatorInfo = consensus.types.ValidatorInfo{
        .address = validatorAddr,
        .stake = 100_000_000_000_000_000_000_000, // 100k ZEE
        .status = .Active,
        .blsPubKey = [_]u8{0} ** 48,
        .commission = 500, // 5%
        .activationBlock = 0,
        .slashCount = 0,
        .totalRewards = 0,
        .name = "validator-0",
        .website = "",
    };
    const validators = [_]consensus.types.ValidatorInfo{validatorInfo};
    const engine = try consensus.ZeliusEngine.init(allocator, &validators);
    defer engine.deinit();
    engine.setPrivKey(minerPrivKey);
    engine.setBlsPrivKey(&minerPrivKey);
    printComponentLine("├─", "Consensus     ", "Loom Genesis Adaptive PoS");

    // Initial epoch rotation to seed adaptive consensus
    {
        const initial_stakes = [_]u64{100_000_000_000};
        engine.rotateEpoch(0, genesisHash.bytes, &initial_stakes) catch |err| {
            log.err("Initial epoch rotation failed: {}", .{err});
        };
    }

    // 5. DAG Pipeline (primary execution path for 1M+ TPS)
    var dagPool = try core.dag_mempool.DAGMempool.init(allocator, &worldState, .{});
    defer dagPool.deinit();

    var dagExecutor = core.dag_executor.DAGExecutor.init(allocator, &worldState, .{
        .numThreads = 8,
        .blockGasLimit = @as(u64, @intCast(network.gasLimit)),
        .coinbase = validatorAddr,
        .baseFee = network.baseFee orelse 1_000_000_000,
        .transferFastPath = true,
    });

    // ── Performance Optimization Modules (P0-P2) ────────────────────

    // P0: Async State Root — background Verkle trie commitment
    var asyncRoot = core.async_state_root.AsyncStateRootComputer.init(
        allocator,
        &worldState,
        .{ .rootLag = 2, .maxQueueDepth = 8 },
    );
    defer asyncRoot.deinit();
    // NOTE: Do NOT start the async root background thread here.
    // The miner already calls trie.commit() + rootHash() directly in
    // its block production loop. Starting the bg thread causes a race
    // where it clears dirty_count before the miner can commit, resulting
    // in stale (unchanging) state roots. The async root computer object
    // is still registered with DAGExecutor for future use when the DAG
    // path handles its own commits independently.
    dagExecutor.setAsyncRoot(&asyncRoot);

    // P1: State Prefetcher — trie cache warming before lane execution
    var statePrefetcher = core.state_prefetcher.StatePrefetcher.init(
        allocator,
        &worldState,
        .{ .maxAddresses = 1_000_000, .prefetchCode = true },
    );
    defer statePrefetcher.deinit();
    dagExecutor.setPrefetcher(&statePrefetcher);

    // P1: Lock-Free Delta Merger — parallel merge of lane deltas
    var deltaMerger = core.delta_merge.DeltaMerger.init(allocator);
    defer deltaMerger.deinit();
    dagExecutor.setDeltaMerger(&deltaMerger);

    printComponentLine("├─", "DAG Pipeline  ", "256-shard mempool + parallel executor");
    printComponentLine("├─", "Optimizations ", "AsyncRoot + Prefetch + DeltaMerge");

    // 5b. BlockProducer — unified production interface (DAG primary)
    var producer = core.block_producer.BlockProducer.init(
        allocator,
        chain,
        &worldState,
        validatorAddr,
        @as(u64, @intCast(network.gasLimit)),
    );
    producer.setDAGPipeline(dagPool, &dagExecutor);
    producer.setAsyncRoot(&asyncRoot);
    printComponentLine("├─", "BlockProducer ", "DAG-native + async root");

    // 5c. Consensus subsystems
    var pipeline = consensus.Pipeline.init(allocator, .{
        .validatorCount = 1,
        .ourIndex = 0,
        .ourAddress = validatorAddr,
        .threadCount = engine.getThreadCount(),
        .tier = engine.getCurrentTier(),
    });
    defer pipeline.deinit();

    var staking = consensus.Staking.init(allocator, .{});
    defer staking.deinit();

    // Register initial validator in staking
    staking.registerValidator(
        validatorAddr,
        100_000_000_000_000_000_000_000, // 100k ZEE self-stake
        500, // 5% commission
        0, // registered at genesis
    ) catch {};

    // Loom Genesis Adaptive Consensus subsystems
    var threadAttestPool = consensus.ThreadAttestationPool.init(allocator);
    defer threadAttestPool.deinit();

    var snowball = consensus.Snowball.init(allocator, .{});
    defer snowball.deinit();
    printComponentLine("├─", "Adaptive      ", "ThreadPool + Snowball ready");

    // 6. VM Bridge (thread-safe, wired to both executors)
    var riscvBridge = vm_bridge.VMBridge.init(allocator, .{
        .enableJit = true,
        .optimizationLevel = .Fast,
        .traceExecution = false,
    });
    defer riscvBridge.deinit();

    // Wire execution context for contracts (block env + chain config)
    riscvBridge.setExecutionContext(.{
        .timestamp = @intCast(@max(0, std.time.timestamp())),
        .blockNumber = 0,
        .chainId = 99999,
        .coinbase = validatorAddr.bytes,
        .prevRandao = genesisHash.bytes,
    });

    // Wire VM callback to executor
    dagExecutor.setVMCallback(riscvBridge.getCallback());
    printComponentLine("├─", "VM Engine     ", "RISC-V RV64IM (thread-safe)");

    // 7. Miner (uses BlockProducer for unified DAG/legacy production)
    var nodeMiner = try node.Miner.init(
        allocator,
        chain,
        dagPool, // Using dagPool instead of legacy pool
        engine,
        &dagExecutor, // Using dagExecutor instead of legacy exec
        &worldState,
        validatorAddr,
        &running,
        &producer,
    );
    defer nodeMiner.deinit();

    nodeMiner.setPipeline(&pipeline);
    nodeMiner.setStaking(&staking);
    nodeMiner.setValidatorIndex(0);

    // 8. Epoch Integration
    const epochIntegration = try node.EpochIntegration.init(
        allocator,
        db.asAbstractDB(),
        100,
    );
    defer epochIntegration.deinit();
    nodeMiner.setEpochIntegration(epochIntegration);

    // 9. Historical State
    const historicalState = try core.historical_state.HistoricalState.init(
        allocator,
        db.asAbstractDB(),
        &worldState,
    );
    defer historicalState.deinit();
    historicalState.setHead(chain.getHeadNumber());

    // 10. P2P Server
    var p2pServer = try p2p.Server.init(allocator, chain, engine, dagPool, .{ .listenPort = p2pPort });
    defer p2pServer.deinit();
    nodeMiner.setP2p(p2pServer);
    p2pServer.setThreadAttestPool(&threadAttestPool);
    p2pServer.setSnowballEngine(&snowball);

    // P2: Shred Signature Verifier — Ed25519 + 10% sampling
    var shredVerifier = p2p.shred_verifier.ShredVerifier.init(allocator, .{
        .sampleRate = 0.10,
        .enabled = true,
    });
    defer shredVerifier.deinit();

    // Register our own validator for self-verification
    try shredVerifier.addValidator(.{
        .address = validatorAddr,
        .pubkey = [_]u8{0} ** 32, // Populated from BLS/Ed25519 key in production
        .stake = 100_000_000_000, // 100K ZEE (in gwei units)
        .active = true,
    });
    p2pServer.setShredVerifier(&shredVerifier);

    try p2pServer.start();
    printComponentFmt("├─", "P2P           ", "Port {d} + shred verification", p2pPort);

    // 11. JSON-RPC Server
    const rpcServer = try rpc.Server.init(allocator, httpPort, chain, dagPool, &dagExecutor, &worldState);
    defer rpcServer.deinit();
    rpcServer.setP2P(p2pServer);
    rpcServer.setHistoricalState(historicalState);
    rpcServer.setDAGPool(dagPool);
    try rpcServer.start();
    printComponentFmt("└─", "JSON-RPC      ", "Port {d}", httpPort);

    // ── Node Dashboard ──
    var addr_buf: [42]u8 = undefined;
    const addr_hex = try @import("utils").hex.encodeBuffer(&addr_buf, &validatorAddr.bytes);

    // Top border
    std.debug.print("\n  " ++ C_GLW ++ "╔══════════════════════════════════════════════════════════╗" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ BOLD ++ C_GRN ++ "◉ NODE ACTIVE" ++ RST ++ "                                           " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "╠══════════════════════════════════════════════════════════╣" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "                                                          " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    // Network, Chain ID, Validator — each as its own print call
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Network" ++ RST ++ "       " ++ C_WHT ++ "{s: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{networkName});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Chain ID" ++ RST ++ "      " ++ C_WHT ++ "{d: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{network.chainId});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Validator" ++ RST ++ "   " ++ C_CYAN ++ "{s: <38}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{addr_hex});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Mining" ++ RST ++ "          " ++ C_WHT ++ "{s: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{if (shouldMine) "● Active" else "○ Standby"});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Consensus" ++ RST ++ "       " ++ C_MAG ++ "{s: <38}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{@tagName(engine.getCurrentTier())});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Threads" ++ RST ++ "       " ++ C_WHT ++ "{d: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{engine.getThreadCount()});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "                                                          " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    // Endpoints section
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ BOLD ++ C_PUR ++ "ENDPOINTS" ++ RST ++ "                                               " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "P2P" ++ RST ++ "           " ++ C_BLUE ++ ":{d: <39}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{p2pPort});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "JSON-RPC" ++ RST ++ "      " ++ C_BLUE ++ "http://127.0.0.1:{d: <23}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{httpPort});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "  " ++ C_TEAL ++ "Data Dir" ++ RST ++ "      " ++ C_DIM ++ "{s: <40}" ++ RST ++ "  " ++ C_GLW ++ "║" ++ RST ++ "\n", .{dataDir});
    std.debug.print("  " ++ C_GLW ++ "║" ++ RST ++ "                                                          " ++ C_GLW ++ "║" ++ RST ++ "\n", .{});
    // Bottom border
    std.debug.print("  " ++ C_GLW ++ "╚══════════════════════════════════════════════════════════╝" ++ RST ++ "\n\n", .{});

    // ── Start Block Production ──
    if (shouldMine) {
        std.debug.print("  " ++ C_CYAN ++ "⚡" ++ RST ++ " Block production started. Press " ++ BOLD ++ "Ctrl+C" ++ RST ++ " to stop.\n\n", .{});
        try nodeMiner.start();
    } else {
        std.debug.print("  " ++ C_GRN ++ "◉" ++ RST ++ " Node ready (standby). Press " ++ BOLD ++ "Ctrl+C" ++ RST ++ " to stop.\n\n", .{});
        while (running.load(.seq_cst)) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }

    std.debug.print("\n  " ++ C_YEL ++ "●" ++ RST ++ " Node stopped.\n\n", .{});
}
