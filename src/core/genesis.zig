// ============================================================================
// Zephyria — Genesis Configuration
// ============================================================================
//
// Genesis block initialization for Zephyria blockchain.
//
// Cryptography:
//   - Signatures:  Ed25519 (32-byte pubkey, 64-byte signature)
//   - Addresses:   Blake3(ADDR_DERIVE_TAG ‖ pubkey) → 32 bytes
//   - Hashes:      Blake3 throughout (block ids, tx ids, state root)
//
// Supports devnet, testnet, and mainnet profiles.
// All address allocations use Ed25519 key derivation — NO Ethereum-style
// 20-byte addresses are used anywhere in Zephyria.

const std = @import("std");
const types = @import("types.zig");
const system = @import("accounts/system.zig");
const accounts_common = @import("accounts/common.zig");

// ── Network / Crypto Config ─────────────────────────────────────────────

/// Describes the cryptographic and network parameters for this chain.
/// Embedded in genesis and readable by peers at handshake time.
pub const GenesisConfig = struct {
    /// Human-readable chain name (e.g. "zephyria-testnet-1")
    chainName: []const u8,
    /// Numeric chain id for replay protection
    chainId: u256,
    /// Unix timestamp of genesis block creation
    genesisTimestamp: u64,
    /// Signature scheme used for transactions and validator keys
    cryptoScheme: CryptoScheme = .ed25519_blake3,
    /// Hash function used for block ids, tx ids, addresses
    hashFunction: HashFunction = .blake3,
    /// Address length in bytes (always 32 for Zephyria)
    addressLength: u8 = 32,
    /// Signature length in bytes (Ed25519 = 64)
    signatureLength: u8 = 64,
    /// Public key length in bytes (Ed25519 = 32)
    pubkeyLength: u8 = 32,
    /// Minimum stake to register as a validator (attoZEE)
    minValidatorStake: u256 = 10_000 * 1_000_000_000_000_000_000,
    /// Maximum number of active validators
    maxValidators: u32 = 2000,
};

pub const CryptoScheme = enum(u8) {
    ed25519_blake3 = 1,
};

pub const HashFunction = enum(u8) {
    blake3 = 1,
};

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
    genesisConfig: GenesisConfig,
    genesisTime: u64,
    executionBudget: u64,
    producer: types.Address,
    systemParams: SystemParams,

    // Convenience accessors
    pub fn chainId(self: NetworkConfig) u256 {
        return self.genesisConfig.chainId;
    }
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

// ── Address Derivation ──────────────────────────────────────────────────

/// Derive a Zephyria address from a 32-byte Ed25519 private key seed.
/// Steps:
///   1. Ed25519 deterministic keygen from seed → public key (32 bytes)
///   2. address = Blake3(ADDR_DERIVE_TAG ‖ pubkey)
pub fn deriveAddressFromSeed(seed: *const [32]u8) types.Address {
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed.*) catch unreachable;
    return types.Address.fromPubKey(&key_pair.public_key.bytes);
}

/// Derive a Zephyria address from a hex-encoded 32-byte private key seed.
/// `seed_hex` must be exactly 64 hex characters (no 0x prefix).
pub fn deriveAddressFromSeedHex(seed_hex: []const u8) types.Address {
    var seed: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&seed, seed_hex) catch unreachable;
    return deriveAddressFromSeed(&seed);
}

/// Derive the Ed25519 public key bytes from a seed (for use by the consensus engine).
pub fn pubKeyFromSeed(seed: *const [32]u8) [32]u8 {
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed.*) catch unreachable;
    return key_pair.public_key.bytes;
}

// ── Network Presets ─────────────────────────────────────────────────────

/// Well-known developer seed (validator 0 / testnet index 0).
/// This is the same seed used by the testnet test script.
pub const default_dev_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Standard dev seeds for testnet validators 0-2 (matching testnet_test.py).
pub const testnet_dev_seeds = [_][]const u8{
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111e5eb43d2c7900717e3a5559069eb2447954e0c03b4d21e35d1f2e18d8",
};

pub fn getNetworkConfig(network: []const u8) NetworkConfig {
    if (std.mem.eql(u8, network, "devnet")) {
        return NetworkConfig{
            .genesisConfig = .{
                .chainName = "zephyria-devnet-1",
                .chainId = 91919191,
                .genesisTimestamp = 1735689600,
            },
            .genesisTime = 1735689600,
            .executionBudget = 60_000_000,
            .producer = deriveAddressFromSeedHex(default_dev_key),
            .systemParams = SystemParams{
                .slotTime = 12,
                .epochLength = 32,
                .stakingAddr = system.STAKING_ADDRESS,
                .rewardAddr = system.REWARDS_ADDRESS,
                .validatorAddr = system.VALIDATOR_ADDRESS,
                .randomnessAddr = system.RANDOMNESS_ADDRESS,
                .defaultExecutionBudget = 60_000_000,
            },
        };
    }

    if (std.mem.eql(u8, network, "testnet")) {
        return NetworkConfig{
            .genesisConfig = .{
                .chainName = "zephyria-testnet-1",
                .chainId = 88888,
                .genesisTimestamp = 1735689600,
            },
            .genesisTime = 1735689600,
            .executionBudget = 100_000_000,
            .producer = types.Address.zero(), // set by first block proposer
            .systemParams = SystemParams{
                .slotTime = 6,
                .epochLength = 64,
                .stakingAddr = system.STAKING_ADDRESS,
                .rewardAddr = system.REWARDS_ADDRESS,
                .validatorAddr = system.VALIDATOR_ADDRESS,
                .randomnessAddr = system.RANDOMNESS_ADDRESS,
                .defaultExecutionBudget = 100_000_000,
            },
        };
    }

    // Mainnet
    return NetworkConfig{
        .genesisConfig = .{
            .chainName = "zephyria-mainnet-1",
            .chainId = 1,
            .genesisTimestamp = 1735689600,
        },
        .genesisTime = 1735689600,
        .executionBudget = 200_000_000,
        .producer = types.Address.zero(),
        .systemParams = SystemParams{
            .slotTime = 4,
            .epochLength = 128,
            .stakingAddr = system.STAKING_ADDRESS,
            .rewardAddr = system.REWARDS_ADDRESS,
            .validatorAddr = system.VALIDATOR_ADDRESS,
            .randomnessAddr = system.RANDOMNESS_ADDRESS,
            .defaultExecutionBudget = 200_000_000,
        },
    };
}

// ── Genesis Application ─────────────────────────────────────────────────

/// Apply genesis allocations and system contracts, return the genesis block.
/// The genesis block has:
///   - parentId     = Hash.zero() (no parent)
///   - number       = 0
///   - txMerkleRoot = Hash.zero() (no transactions)
///   - stateRoot    = Hash.zero() (computed post-apply in full nodes)
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

        // Write sequence = 0 (mark account as existing)
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

    // 3. Build genesis block
    // parentId = zero, txMerkleRoot = zero (no transactions), stateRoot = zero
    const header = types.Header{
        .parentId = types.Hash.zero(),
        .number = 0,
        .time = genesis.config.genesisTime,
        .stateRoot = types.Hash.zero(),
        .txMerkleRoot = types.Hash.zero(),
        .producer = genesis.config.producer,
        .extraData = &[_]u8{},
        .executionBudget = genesis.config.executionBudget,
        .budgetUsed = 0,
    };

    const block = try allocator.create(types.Block);
    block.* = types.Block{
        .header = header,
        .transactions = &[_]types.Transaction{},
    };
    return block;
}

// ── Genesis Allocations Builder ─────────────────────────────────────────

/// Build genesis token allocations for the given network.
/// All addresses are Ed25519-derived 32-byte Blake3 addresses.
pub fn getGenesisAllocations(allocator: std.mem.Allocator, network: []const u8) ![]const GenesisAlloc {
    var list = std.ArrayList(GenesisAlloc).empty;
    errdefer list.deinit(allocator);

    const dev_balance: u256 = 100_000 * 1_000_000_000_000_000_000;

    if (std.mem.eql(u8, network, "devnet") or std.mem.eql(u8, network, "testnet")) {
        // Allocate to all standard dev validators
        for (testnet_dev_seeds) |seed_hex| {
            const addr = deriveAddressFromSeedHex(seed_hex);
            try list.append(allocator, .{ .addr = addr, .balance = dev_balance });
        }
    } else {
        // Mainnet: foundation/reserve address derived from a deterministic seed
        // In production this would be replaced with the actual foundation key.
        const reserve_addr = deriveAddressFromSeedHex(
            "70997970c51812dc3a010c7d01b50e0d17dc79c870997970c51812dc3a010c7",
        );
        try list.append(allocator, .{
            .addr = reserve_addr,
            .balance = 50_000_000 * 1_000_000_000_000_000_000,
        });
    }

    // System accounts get a small bootstrapping balance
    const sys_balance: u256 = 1_000_000_000_000_000_000;
    try list.append(allocator, .{ .addr = system.STAKING_ADDRESS,   .balance = sys_balance });
    try list.append(allocator, .{ .addr = system.REWARDS_ADDRESS,   .balance = sys_balance });
    try list.append(allocator, .{ .addr = system.VALIDATOR_ADDRESS, .balance = sys_balance });

    return list.toOwnedSlice(allocator);
}

pub fn getGenesisSystemContracts(allocator: std.mem.Allocator, network: []const u8) ![]const SystemContract {
    _ = network;
    var list = std.ArrayList(SystemContract).empty;
    errdefer list.deinit(allocator);

    const sys_balance: u256 = 1_000_000_000_000_000_000;
    try list.append(allocator, .{ .address = system.STAKING_ADDRESS,   .name = "staking",    .balance = sys_balance });
    try list.append(allocator, .{ .address = system.REWARDS_ADDRESS,   .name = "rewards",    .balance = sys_balance });
    try list.append(allocator, .{ .address = system.VALIDATOR_ADDRESS, .name = "validator",  .balance = sys_balance });
    try list.append(allocator, .{ .address = system.RANDOMNESS_ADDRESS, .name = "randomness", .balance = 0 });

    return list.toOwnedSlice(allocator);
}
