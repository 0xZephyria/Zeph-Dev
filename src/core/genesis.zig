// ============================================================================
// Zephyria — Genesis Configuration
// ============================================================================
//
// Genesis block initialization with proper format for:
//   • Initial token allocations (dev accounts, foundation, etc.)
//   • System contract deployment (staking, rewards, validator, randomness)
//   • Network parameter configuration
//
// Supports devnet, testnet, and mainnet profiles.

const std = @import("std");
const types = @import("types.zig");
const system = @import("accounts/system.zig");

// ── System Parameters ───────────────────────────────────────────────────

pub const SystemParams = struct {
    vdfIterations: u64,
    vdfInterval: u64,
    slotTime: u64,
    epochLength: u64,
    stakingAddr: types.Address,
    rewardAddr: types.Address,
    validatorAddr: types.Address,
    randomnessAddr: types.Address,
    defaultGasLimit: u64,
    defaultBaseFee: u256,
};

// ── Network Config ──────────────────────────────────────────────────────

pub const NetworkConfig = struct {
    chainId: u256,
    genesisTime: u64,
    genesisHash: types.Hash,
    gasLimit: u64,
    baseFee: ?u256,
    coinbase: types.Address,
    systemParams: SystemParams,
};

// ── Genesis Allocations ─────────────────────────────────────────────────

pub const GenesisAlloc = struct {
    addr: types.Address,
    balance: u256,
    /// Optional bytecode for system contracts
    code: ?[]const u8 = null,
    /// Optional initial storage for system contracts
    storage: ?[]const StorageEntry = null,
};

pub const StorageEntry = struct {
    slot: [32]u8,
    value: [32]u8,
};

/// System contract deployment specification
pub const SystemContract = struct {
    address: types.Address,
    name: []const u8,
    balance: u256 = 0,
    code: ?[]const u8 = null,
};

// ── Genesis ─────────────────────────────────────────────────────────────

pub const Genesis = struct {
    config: NetworkConfig,
    alloc: []const GenesisAlloc,
    systemContracts: []const SystemContract,
};

// ── Network Presets ─────────────────────────────────────────────────────

pub fn getNetworkConfig(network: []const u8) NetworkConfig {
    if (std.mem.eql(u8, network, "devnet")) {
        return NetworkConfig{
            .chainId = 91919191,
            .genesisTime = 1735689600, // 2025-01-01
            .genesisHash = types.Hash.zero(),
            .gasLimit = 60000000,
            .baseFee = 1000000000,
            .coinbase = parseAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            .systemParams = SystemParams{
                .vdfIterations = 1100000,
                .vdfInterval = 15000,
                .slotTime = 12,
                .epochLength = 32,
                .stakingAddr = system.STAKING_ADDRESS,
                .rewardAddr = system.REWARDS_ADDRESS,
                .validatorAddr = system.VALIDATOR_ADDRESS,
                .randomnessAddr = system.RANDOMNESS_ADDRESS,
                .defaultGasLimit = 60000000,
                .defaultBaseFee = 1000000000,
            },
        };
    }

    if (std.mem.eql(u8, network, "testnet")) {
        return NetworkConfig{
            .chainId = 88888,
            .genesisTime = 0,
            .genesisHash = types.Hash.zero(),
            .gasLimit = 100000000,
            .baseFee = 1000000000,
            .coinbase = types.Address.zero(),
            .systemParams = SystemParams{
                .vdfIterations = 5000000,
                .vdfInterval = 15000,
                .slotTime = 6,
                .epochLength = 64,
                .stakingAddr = system.STAKING_ADDRESS,
                .rewardAddr = system.REWARDS_ADDRESS,
                .validatorAddr = system.VALIDATOR_ADDRESS,
                .randomnessAddr = system.RANDOMNESS_ADDRESS,
                .defaultGasLimit = 100000000,
                .defaultBaseFee = 1000000000,
            },
        };
    }

    // Mainnet
    return NetworkConfig{
        .chainId = 1,
        .genesisTime = 0,
        .genesisHash = types.Hash.zero(),
        .gasLimit = 200000000,
        .baseFee = null,
        .coinbase = types.Address.zero(),
        .systemParams = SystemParams{
            .vdfIterations = 10000000,
            .vdfInterval = 15000,
            .slotTime = 4,
            .epochLength = 128,
            .stakingAddr = system.STAKING_ADDRESS,
            .rewardAddr = system.REWARDS_ADDRESS,
            .validatorAddr = system.VALIDATOR_ADDRESS,
            .randomnessAddr = system.RANDOMNESS_ADDRESS,
            .defaultGasLimit = 200000000,
            .defaultBaseFee = 1000000000,
        },
    };
}

// ── Genesis Application ─────────────────────────────────────────────────

/// Apply genesis allocations and system contracts, return the genesis block.
pub fn applyGenesis(allocator: std.mem.Allocator, trie: anytype, genesis: Genesis) !*types.Block {
    const state = @import("state.zig");

    // 1. Apply token allocations
    for (genesis.alloc) |entry| {
        const key = state.State.balanceKey(entry.addr);
        var balanceBytes = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &balanceBytes, entry.balance, .big);
        try trie.put(key, &balanceBytes);

        // Deploy code if present (system contracts)
        if (entry.code) |code| {
            const codeKeyVal = state.State.codeKey(entry.addr);
            try trie.put(codeKeyVal, code);
            var codeHash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(code, &codeHash, .{});
            try trie.put(state.State.codeHashKey(entry.addr), &codeHash);
        }

        // Set initial storage if present
        if (entry.storage) |entries| {
            for (entries) |s| {
                const sKey = state.State.storageKey(entry.addr, s.slot);
                try trie.put(sKey, &s.value);
            }
        }
    }

    // 2. Deploy system contracts
    for (genesis.systemContracts) |sys| {
        // Set balance
        const balKey = state.State.balanceKey(sys.address);
        var balBytes = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &balBytes, sys.balance, .big);
        try trie.put(balKey, &balBytes);

        // Deploy bytecode
        if (sys.code) |code| {
            const codeKeyVal = state.State.codeKey(sys.address);
            try trie.put(codeKeyVal, code);
            var codeHash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(code, &codeHash, .{});
            try trie.put(state.State.codeHashKey(sys.address), &codeHash);
        }
    }

    // 3. Commit state
    try trie.commit();
    const verkleRootArr = trie.rootHash();

    // 4. Construct genesis block
    const header = types.Header{
        .parentHash = types.Hash.zero(),
        .number = 0,
        .time = genesis.config.genesisTime,
        .verkleRoot = types.Hash{ .bytes = verkleRootArr },
        .txHash = types.Hash.zero(),
        .coinbase = genesis.config.coinbase,
        .extraData = &[_]u8{},
        .gasLimit = genesis.config.gasLimit,
        .gasUsed = 0,
        .baseFee = genesis.config.baseFee orelse 1000000000,
    };

    const block = try allocator.create(types.Block);
    block.* = types.Block{
        .header = header,
        .transactions = &[_]types.Transaction{},
    };
    return block;
}

// ── Default Allocations ─────────────────────────────────────────────────

pub fn getDefaultAlloc() [4]GenesisAlloc {
    const dev_addr = parseAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const dev_balance: u256 = 100_000 * 1_000_000_000_000_000_000;
    const sys_balance: u256 = 1_000_000_000_000_000_000;

    return [_]GenesisAlloc{
        .{ .addr = dev_addr, .balance = dev_balance },
        .{ .addr = system.STAKING_ADDRESS, .balance = sys_balance },
        .{ .addr = system.REWARDS_ADDRESS, .balance = sys_balance },
        .{ .addr = system.VALIDATOR_ADDRESS, .balance = sys_balance },
    };
}

pub fn getDefaultSystemContracts() [4]SystemContract {
    return .{
        .{ .address = system.STAKING_ADDRESS, .name = "staking", .balance = 1_000_000_000_000_000_000 },
        .{ .address = system.REWARDS_ADDRESS, .name = "rewards", .balance = 1_000_000_000_000_000_000 },
        .{ .address = system.VALIDATOR_ADDRESS, .name = "validator", .balance = 1_000_000_000_000_000_000 },
        .{ .address = system.RANDOMNESS_ADDRESS, .name = "randomness", .balance = 0 },
    };
}

// ── Helpers ─────────────────────────────────────────────────────────────

pub fn parseAddress(hex: []const u8) types.Address {
    var addr = types.Address.zero();
    if (hex.len >= 2 and hex[0] == '0' and hex[1] == 'x') {
        const hexStr = hex[2..];
        var i: usize = 0;
        while (i < @min(hexStr.len / 2, 20)) : (i += 1) {
            const hi = std.fmt.charToDigit(hexStr[i * 2], 16) catch 0;
            const lo = std.fmt.charToDigit(hexStr[i * 2 + 1], 16) catch 0;
            addr.bytes[i] = (hi << 4) | lo;
        }
    }
    return addr;
}

pub const default_dev_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
