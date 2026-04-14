// ============================================================================
// Zephyria — Block Rewards Module
// ============================================================================
//
// Extensible block reward system. Currently applies a fixed base reward
// to the coinbase (block producer) address. Designed to be swapped out
// for a production-ready smart contract–based rewards system.
//
// Production roadmap:
//   1. Replace fixed reward with a call to the Validator Rewards Contract
//   2. Support dynamic reward curves (halving, inflation cap)
//   3. Integrate slashing penalties from consensus layer
//   4. Support MEV tip distribution to validators
//   5. Epoch-based reward accumulation with batch payouts
//
// The module mutates world state directly (via State.set_balance / add_balance),
// ensuring the Verkle trie state root changes every block — even empty ones.

const std = @import("std");
const types = @import("../core/types.zig");
const state_mod = @import("../core/state.zig");

/// Reward configuration — all values in wei.
pub const RewardConfig = struct {
    /// Base reward per block for the proposer (default: 2 ZEE)
    base_reward: u256 = 2_000_000_000_000_000_000,

    /// Extra reward per gas unit used in the block (default: 0, enable for EIP-1559 tips)
    per_gas_reward: u256 = 0,

    /// Extra reward per included transaction (default: 0)
    per_tx_reward: u256 = 0,

    /// Whether rewards are enabled
    enabled: bool = true,

    // ── Future: Smart Contract Rewards ────────────────────────────────
    // When implementing contract-based rewards, these fields will be used:
    //
    // reward_contract: ?types.Address = null,
    // reward_method_selector: [4]u8 = .{ 0, 0, 0, 0 }, // distributeRewards(address,uint256)
    // epoch_length: u64 = 100,
    // accumulated_rewards: u256 = 0,
};

/// Block reward context passed to applyRewards.
pub const RewardContext = struct {
    coinbase: types.Address,
    block_number: u64,
    gas_used: u64,
    tx_count: u64,
    timestamp: u64,
};

/// Apply block rewards to the world state.
/// This is called after transaction execution but before state root computation,
/// ensuring the state root changes every block.
///
/// Returns the total reward amount applied.
pub fn applyRewards(
    state: *state_mod.State,
    config: RewardConfig,
    ctx: RewardContext,
) !u256 {
    if (!config.enabled) return 0;

    // Calculate total reward
    var total: u256 = config.base_reward;

    // Gas-proportional reward (for future EIP-1559 tip integration)
    if (config.per_gas_reward > 0 and ctx.gas_used > 0) {
        total += config.per_gas_reward * @as(u256, ctx.gas_used);
    }

    // Per-transaction reward (incentivizes block fullness)
    if (config.per_tx_reward > 0 and ctx.tx_count > 0) {
        total += config.per_tx_reward * @as(u256, ctx.tx_count);
    }

    // Apply reward to coinbase
    if (total > 0) {
        const current_balance = state.get_balance(ctx.coinbase);
        try state.set_balance(ctx.coinbase, current_balance + total);

        // Also bump the coinbase nonce to make state root more distinct
        // (some chains do this; optional)
    }

    return total;
}

/// Get the current reward schedule description (for CLI display).
pub fn getRewardDescription(config: RewardConfig) []const u8 {
    if (!config.enabled) return "disabled";
    if (config.base_reward == 2_000_000_000_000_000_000) return "2 ZEE/block";
    if (config.base_reward == 0) return "contract-only";
    return "custom";
}
