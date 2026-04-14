// ============================================================================
// Zephyria — Core Module Root
// ============================================================================
//
// The core module provides the foundational blockchain logic for Zephyria.
// All external consumers (main.zig, consensus, rpc, p2p, node) access
// core functionality through these re-exports.

pub const types = @import("types.zig");
pub const accounts = @import("accounts/mod.zig");
pub const state = @import("state.zig");
pub const genesis = @import("genesis.zig");
pub const blockchain = @import("blockchain.zig");
pub const block_producer = @import("block_producer.zig");
pub const scheduler = @import("scheduler.zig");
pub const executor = @import("executor.zig");
pub const tx_pool = @import("tx_pool.zig");
pub const tx_list = @import("tx_list.zig");
pub const tx_decode = @import("tx_decode.zig");
pub const historical_state = @import("historical_state.zig");
pub const logger = @import("logger.zig");
pub const security = @import("security.zig");
pub const turbo_executor = @import("turbo_executor.zig");
pub const dag_mempool = @import("dag_mempool.zig");
pub const dag_scheduler = @import("dag_scheduler.zig");
pub const dag_executor = @import("dag_executor.zig");
pub const block_rewards = @import("block_rewards.zig");
pub const async_state_root = @import("async_state_root.zig");
pub const state_prefetcher = @import("state_prefetcher.zig");
pub const delta_merge = @import("delta_merge.zig");

// Shorthand re-exports for backward compatibility with p2p, rpc, node modules
pub const Blockchain = blockchain.Blockchain;
pub const State = state.State;
pub const Overlay = state.Overlay;
pub const HistoricalState = historical_state.HistoricalState;
pub const account = accounts.eoa;
pub const crypto = @import("crypto");
