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
const accounts_common = @import("accounts/common.zig");

// ── System Parameters ───────────────────────────────────────────────────

pub const SystemParams = struct {
    slotTime: u64,
    epochLength: u64,
    stakingAddr: types.Address,
    rewardAddr: types.Address,
    validatorAddr: types.Address,
    randomnessAddr: types.Address,
    defaultExecutionBudget: u64,
};

// ── Network Config ──────────────────────────────────────────────────────

pub const NetworkConfig = struct {
    chainId: u256,
    genesisTime: u64,
    genesisHash: types.Hash,
    executionBudget: u64,
    producer: types.Address,
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

pub fn deriveAddressFromSeedHex(seed_hex: []const u8) types.Address {
    var seed: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&seed, seed_hex) catch unreachable;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    var addr = types.Address.zero();
    std.crypto.hash.Blake3.hash(&key_pair.public_key.bytes, &addr.bytes, .{});
    return addr;
}

pub fn getNetworkConfig(network: []const u8) NetworkConfig {
    if (std.mem.eql(u8, network, "devnet")) {
        return NetworkConfig{
            .chainId = 91919191,
            .genesisTime = 1735689600, // 2025-01-01
            .genesisHash = types.Hash.zero(),
            .executionBudget = 60000000,
            .producer = deriveAddressFromSeedHex(default_dev_key),
            .systemParams = SystemParams{
                .slotTime = 12,
                .epochLength = 32,
                .stakingAddr = system.STAKING_ADDRESS,
                .rewardAddr = system.REWARDS_ADDRESS,
                .validatorAddr = system.VALIDATOR_ADDRESS,
                .randomnessAddr = system.RANDOMNESS_ADDRESS,
                .defaultExecutionBudget = 60000000,
            },
        };
    }

    if (std.mem.eql(u8, network, "testnet")) {
        return NetworkConfig{
            .chainId = 88888,
            .genesisTime = 1735689600,
            .genesisHash = types.Hash.zero(),
            .executionBudget = 100000000,
            .producer = types.Address.zero(),
            .systemParams = SystemParams{
                .slotTime = 6,
                .epochLength = 64,
                .stakingAddr = system.STAKING_ADDRESS,
                .rewardAddr = system.REWARDS_ADDRESS,
                .validatorAddr = system.VALIDATOR_ADDRESS,
                .randomnessAddr = system.RANDOMNESS_ADDRESS,
                .defaultExecutionBudget = 100000000,
            },
        };
    }

    // Mainnet
    return NetworkConfig{
        .chainId = 1,
        .genesisTime = 1735689600,
        .genesisHash = types.Hash.zero(),
        .executionBudget = 200000000,
        .producer = types.Address.zero(),
            .systemParams = SystemParams{
                .slotTime = 4,
            .epochLength = 128,
            .stakingAddr = system.STAKING_ADDRESS,
            .rewardAddr = system.REWARDS_ADDRESS,
            .validatorAddr = system.VALIDATOR_ADDRESS,
            .randomnessAddr = system.RANDOMNESS_ADDRESS,
            .defaultExecutionBudget = 200000000,
        },
    };
}

// ── Genesis Application ─────────────────────────────────────────────────

/// Apply genesis allocations and system contracts, return the genesis block.
pub fn applyGenesis(allocator: std.mem.Allocator, db: anytype, genesis: Genesis) !*types.Block {
    const state = @import("state.zig");

    // 1. Apply token allocations
    for (genesis.alloc) |entry| {
        const addr = entry.addr;
        const is_contract = entry.code != null;

        // Write type discriminator
        try accounts_common.writeAccountType(db, addr, if (is_contract) .ContractRoot else .EOA);

        // Write balance
        const key = state.State.balanceKey(addr);
        var balanceBytes = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &balanceBytes, entry.balance, .big);
        try db.write(&key, &balanceBytes);

        // Set sequence to 0 (implicitly zero, but write type to mark existence)
        if (!is_contract) {
            const skey = state.State.sequenceKey(addr);
            var sequenceBytes = [_]u8{0} ** 8;
            try db.write(&skey, &sequenceBytes);
        }

        // Deploy code if present (system contracts)
        if (entry.code) |code| {
            const codeKeyVal = state.State.codeKey(addr);
            try db.write(&codeKeyVal, code);
            var codeHash: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(code, &codeHash, .{});
            try db.write(&state.State.codeHashKey(addr), &codeHash);
        }

        // Set initial storage if present
        if (entry.storage) |entries| {
            for (entries) |s| {
                const sKey = state.State.storageKey(addr, s.slot);
                try db.write(&sKey, &s.value);
            }
        }
    }

    // 2. Deploy system contracts
    for (genesis.systemContracts) |sys| {
        const addr = sys.address;

        // Write type discriminator
        try accounts_common.writeAccountType(db, addr, .System);

        // Set balance
        const balKey = state.State.balanceKey(addr);
        var balBytes = [_]u8{0} ** 32;
        std.mem.writeInt(u256, &balBytes, sys.balance, .big);
        try db.write(&balKey, &balBytes);

        // Deploy bytecode
        if (sys.code) |code| {
            const codeKeyVal = state.State.codeKey(addr);
            try db.write(&codeKeyVal, code);
            var codeHash: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(code, &codeHash, .{});
            try db.write(&state.State.codeHashKey(addr), &codeHash);
        }
    }

    // 3. Flat KV: no state root computation
    const header = types.Header{
        .parentHash = types.Hash.zero(),
        .number = 0,
        .time = genesis.config.genesisTime,
        .stateRoot = types.Hash.zero(),
        .txHash = types.Hash.zero(),
        .producer = genesis.config.producer,
        .extraData = &[_]u8{},
        .executionBudget = genesis.config.executionBudget,
        .gasUsed = 0,
    };

    const block = try allocator.create(types.Block);
    block.* = types.Block{
        .header = header,
        .transactions = &[_]types.Transaction{},
    };
    return block;
}

// ── Dynamic Allocations ─────────────────────────────────────────────────

pub fn getGenesisAllocations(allocator: std.mem.Allocator, network: []const u8) ![]const GenesisAlloc {
    var list = std.ArrayList(GenesisAlloc).empty;
    errdefer list.deinit(allocator);

    const dev_balance: u256 = 100_000 * 1_000_000_000_000_000_000;
    const sys_balance: u256 = 1_000_000_000_000_000_000;

    if (std.mem.eql(u8, network, "devnet") or std.mem.eql(u8, network, "testnet")) {
        const anvil_dev = parseAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        try list.append(allocator, .{ .addr = anvil_dev, .balance = dev_balance });

        // Add 3 standard validators derived from standard dev keys
        const seeds = [_][]const u8{
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            "5de4111e5eb43d2c7900717e3a5559069eb2447954e0c03b4d21e35d1f2e18d8",
        };
        for (seeds) |s| {
            try list.append(allocator, .{ .addr = deriveAddressFromSeedHex(s), .balance = dev_balance });
        }
    } else {
        // Mainnet
        // Allocate to foundation / reserve
        const reserve_addr = parseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        try list.append(allocator, .{ .addr = reserve_addr, .balance = 50_000_000 * 1_000_000_000_000_000_000 });
    }

    // Allocate to system accounts
    try list.append(allocator, .{ .addr = system.STAKING_ADDRESS, .balance = sys_balance });
    try list.append(allocator, .{ .addr = system.REWARDS_ADDRESS, .balance = sys_balance });
    try list.append(allocator, .{ .addr = system.VALIDATOR_ADDRESS, .balance = sys_balance });

    return list.toOwnedSlice(allocator);
}

pub fn getGenesisSystemContracts(allocator: std.mem.Allocator, network: []const u8) ![]const SystemContract {
    _ = network;
    var list = std.ArrayList(SystemContract).empty;
    errdefer list.deinit(allocator);

    const sys_balance: u256 = 1_000_000_000_000_000_000;
    try list.append(allocator, .{ .address = system.STAKING_ADDRESS, .name = "staking", .balance = sys_balance });
    try list.append(allocator, .{ .address = system.REWARDS_ADDRESS, .name = "rewards", .balance = sys_balance });
    try list.append(allocator, .{ .address = system.VALIDATOR_ADDRESS, .name = "validator", .balance = sys_balance });
    try list.append(allocator, .{ .address = system.RANDOMNESS_ADDRESS, .name = "randomness", .balance = 0 });

    return list.toOwnedSlice(allocator);
}

// ── Helpers ─────────────────────────────────────────────────────────────

pub fn parseAddress(hex: []const u8) types.Address {
    var addr = types.Address.zero();
    if (hex.len >= 2 and hex[0] == '0' and hex[1] == 'x') {
        const hexStr = hex[2..];
        var i: usize = 0;
        while (i < @min(hexStr.len / 2, 32)) : (i += 1) {
            const hi = std.fmt.charToDigit(hexStr[i * 2], 16) catch 0;
            const lo = std.fmt.charToDigit(hexStr[i * 2 + 1], 16) catch 0;
            addr.bytes[i] = (hi << 4) | lo;
        }
    }
    return addr;
}

pub const default_dev_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
