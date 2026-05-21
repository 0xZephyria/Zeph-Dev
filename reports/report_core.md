# Module Report: Core Engine (`src/core/`)

This report provides a comprehensive architectural and performance analysis of the Zephyria Core Engine codebase, its transactions, execution pipeline, mempool, state tree, and databases, evaluated against the target of achieving 1M+ TPS through Mechanical Sympathy.

---

## 1. Directory Structure & File Index

The `src/core/` module forms the backbone of the Zephyria blockchain, defining the state transitions, scheduling parallel execution lanes, managing the mempool, and computing asynchronous Verkle tree roots.

### Root Core Directory

| File | Size (Bytes) | Role & Responsibility |
| :--- | :--- | :--- |
| [types.zig](file:///Users/karan/sol2zig/src/core/types.zig) | 16,231 | Defines basic cryptographic hashes, addresses, blocks, headers, transactions, and VM receipts. |
| [state.zig](file:///Users/karan/sol2zig/src/core/state.zig) | 22,269 | Implements the global state interface, wrapping the Verkle trie database and transaction-local cache overlays. |
| [historical_state.zig](file:///Users/karan/sol2zig/src/core/historical_state.zig) | 7,401 | Restores and queries historic world state snapshot read-only views for RPC and sync. |
| [state_prefetcher.zig](file:///Users/karan/sol2zig/src/core/state_prefetcher.zig) | 8,430 | Asynchronously fetches account and storage cell data into cache ahead of scheduling. |
| [dag_scheduler.zig](file:///Users/karan/sol2zig/src/core/dag_scheduler.zig) | 14,383 | Performs topological sort and groups transaction lanes into gas-balanced parallel execution buckets. |
| [dag_executor.zig](file:///Users/karan/sol2zig/src/core/dag_executor.zig) | 25,639 | Executes parallel lanes over thread pools, resolves sender nonce orders, and aggregates state updates. |
| [dag_mempool.zig](file:///Users/karan/sol2zig/src/core/dag_mempool.zig) | 39,064 | Implements a sharded, 256-bucket thread-safe transaction pool that extracts execution-ready lanes. |
| [delta_merge.zig](file:///Users/karan/sol2zig/src/core/delta_merge.zig) | 13,556 | Merges thread-local transaction deltas (balance/nonce/storage) using parallel additive sum and absolute last-writer-wins logic. |
| [async_state_root.zig](file:///Users/karan/sol2zig/src/core/async_state_root.zig) | 15,239 | Pipeline-safe background Verkle root computer using ring-buffer queues to shift hashing latency off block production. |
| [block_producer.zig](file:///Users/karan/sol2zig/src/core/block_producer.zig) | 6,831 | Coordinates block construction by calling DAG mempool lane extraction, scheduling, executing, and block assembly. |
| [block_rewards.zig](file:///Users/karan/sol2zig/src/core/block_rewards.zig) | 3,636 | Evaluates block rewards (proposer, base fees, gas-proportional fees) and credits the coinbase. |
| [blockchain.zig](file:///Users/karan/sol2zig/src/core/blockchain.zig) | 10,609 | Tracks current blockchain head block, manages database updates, handles fork-choice logic, and calculates EIP-1559 base fees. |
| [genesis.zig](file:///Users/karan/sol2zig/src/core/genesis.zig) | 10,023 | Defines genesis configurations, devnet/testnet/mainnet parameters, system contracts, and allocates initial state values. |
| [security.zig](file:///Users/karan/sol2zig/src/core/security.zig) | 16,508 | Houses token-bucket rate limits, deep transaction sanitization, counting bloom filters, and gas meters. |
| [tx_decode.zig](file:///Users/karan/sol2zig/src/core/tx_decode.zig) | 3,583 | RLP decodes raw transactions and recovers sender public keys and addresses via ECDSA recovery. |
| [tx_list.zig](file:///Users/karan/sol2zig/src/core/tx_list.zig) | 5,103 | Manages sender-specific transaction queues split into sequential `ready` and gapped `future` arrays. |
| [logger.zig](file:///Users/karan/sol2zig/src/core/logger.zig) | 2,141 | Provides multi-level structured logging (ERR, WRN, INF, DBG, TRC) with runtime level filtering. |
| [mod.zig](file:///Users/karan/sol2zig/src/core/mod.zig) | 1,786 | Exposes clean, aggregate API paths for external modules. |

### Accounts Subdirectory (`src/core/accounts/`)

| File | Size (Bytes) | Role & Responsibility |
| :--- | :--- | :--- |
| [mod.zig](file:///Users/karan/sol2zig/src/core/accounts/mod.zig) | 1,857 | Root re-exports for account subtypes. |
| [config.zig](file:///Users/karan/sol2zig/src/core/accounts/config.zig) | 4,413 | Manages account-level parameters and features (e.g., maximum slot depth). |
| [header.zig](file:///Users/karan/sol2zig/src/core/accounts/header.zig) | 2,195 | Defines serialization formats for global account metadata. |
| [code.zig](file:///Users/karan/sol2zig/src/core/accounts/code.zig) | 1,983 | Handles contract deployment bytecode storage. |
| [contract_root.zig](file:///Users/karan/sol2zig/src/core/accounts/contract_root.zig) | 3,651 | Configures system contract entry and dispatch parameters. |
| [derived.zig](file:///Users/karan/sol2zig/src/core/accounts/derived.zig) | 7,065 | Handles per-user derived slots to prevent multi-sender contract storage conflicts. |
| [eoa.zig](file:///Users/karan/sol2zig/src/core/accounts/eoa.zig) | 5,169 | Manages Externally Owned Accounts, including ECDSA public-key recovery. |
| [storage_cell.zig](file:///Users/karan/sol2zig/src/core/accounts/storage_cell.zig) | 3,272 | Reprsents single storage keys wrapped as discrete accounts. |
| [system.zig](file:///Users/karan/sol2zig/src/core/accounts/system.zig) | 2,799 | Declares addresses and behaviors of core system contracts (staking, validator registration). |
| [vault.zig](file:///Users/karan/sol2zig/src/core/accounts/vault.zig) | 1,966 | Dedicated token deposit and escrow balance accounts. |

### RLP Subdirectory (`src/core/rlp/`)

| File | Size (Bytes) | Role & Responsibility |
| :--- | :--- | :--- |
| [rlp.zig](file:///Users/karan/sol2zig/src/core/rlp/rlp.zig) | 11,432 | High-performance Recursive Length Prefix (RLP) serialization/deserialization. |

---

## 2. Core Architecture Analysis

### A. Isolated Slot-Based Account Model (No-Conflict Execution)
Zephyria replaces standard account-level monolithic storage trie trees with **isolated slot-based states**.
- Each storage slot is treated as a separate, leaf-level Verkle trie account (`StorageCell`).
- Accounts are partitioned into:
  1. **DerivedState**: Per-user storage keys (derived from hashing the sender address alongside the contract slot). This isolates concurrent contract calls. If Alice and Bob both write to the same contract storage, they write to separate derived keys, removing execution bottlenecks.
  2. **Global Accumulators**: Commutative variables (like balance or nonces). These updates are deferred, using deterministic delta queues merged at Phase 2 via the `DeltaMerger`, allowing execution to remain out-of-order.

### B. Sharded Mempool (`dag_mempool.zig`)
The transaction pool is sharded across **256 independent buckets** keyed by the first byte of the sender address.
- Mutex locks are local to each shard, eliminating lock contention on parallel transaction ingestion.
- **AccountLane**: Organizes transactions per sender in strict nonce order.
- **Bloom Filter**: Uses a pre-allocated counting Bloom filter to reject duplicate transactions with zero database accesses.
- **Hot Shard Economics**: If one shard gets hit with double the average load, the gas floor premium for that shard is dynamically scaled up to direct traffic away from the hotspot.

### C. Parallel DAG Execution Pipeline (`dag_scheduler.zig` & `dag_executor.zig`)
- **Topological Sorting**: Group transactions into non-conflicting parallel lanes (sender-scoped).
- **Execution**: Run execution over `numThreads` using thread-local overlays. During Phase 1, transactions read from a cached read-through buffer and write to their thread-local `Overlay` map, bypassing database write-locks.
- **Async State Root Computer (`async_state_root.zig`)**: Implements deferred execution. Writing to the state disk is shifted off the block production hot-path. Block N header uses the Verkle root computed from Block N-lag (e.g., N-2), preventing consensus from stalling on disk writes.

---

## 3. Bottlenecks & Mechanical Sympathy Critiques

To scale from tens of thousands of TPS to 1 million TPS, the following design choices present bottlenecks that must be resolved:

### A. Core Memory Allocations on Hot Path
- **Overlay Maps**: The transaction overlays use standard dynamic hash maps (`std.AutoHashMap`). In the execution loop, every single read/write dirty state modification invokes an allocator to resize maps or duplicate keys/values (`dupe`).
- **DAG Mempool extraction**: `dag_mempool.extract` dynamically allocates arrays of `LaneCandidate`, sorts them, and allocates `ExtractedLane` structures on every block cycle.
- **Mitigation**: Switch all memory management on the hot path to a pre-allocated, thread-local **FixedBufferAllocator** or arena allocator that resets its offset pointer to zero at the start of each block execution, reducing the runtime heap allocation overhead to zero.

### B. Lock Contention and Thread Sync
- **State Prefetcher Mutexes**: The `StatePrefetcher` spawns parallel worker threads that poll queues using standard OS mutexes and condition variables (`std.Thread.Mutex`, `std.Thread.Condition`). Under massive transaction pressure, the threads spin-lock or go to sleep via OS kernel interrupts.
- **Blockchain RWLock**: Reading block history or transaction locations hits a global `RwLock`. This blocks execution threads during head updates.
- **Mitigation**: Move to lock-free MPMC (Multi-Producer Multi-Consumer) queues using atomic pointer CAS operations (`std.atomic.Value`). Thread signaling should be handled via fast spin-locks or hardware thread pausing (e.g., `_mm_pause` on x86 or `isb` on ARM) before falling back to kernel syscall waits.

### C. Single-Writer Serialization in Delta Merge
- While Phase 1 executes in parallel, **Phase 2 (delta merge)** in `delta_merge.zig` aggregates the thread-local buffers sequentially on a single thread. For 1M TPS, merging millions of deltas sequentially limits scaling.
- **Mitigation**: Implement a parallel divide-and-conquer merge algorithm. In parallel, merge sub-buffers pairwise (Lane 0+1, Lane 2+3) over a fork-join worker pool until the final consolidated array is reached, keeping thread execution balanced.

### D. RLP Decoding Overhead
- RLP is a sequential, variable-length prefix encoding format. It cannot be parsed using parallel SIMD instructions or zero-copy slicing because item offsets depend on preceding item sizes.
- **Mitigation**: Transition internal peer-to-peer and execution serialization formats to a fixed-width, cache-aligned layout (like FlatBuffers, Cap'n Proto, or a custom aligned byte-struct). The node should only RLP-decode raw transaction payloads once at the gateway RPC ingress, converting them immediately to internal binary formats.

### E. Static Sector Alignment in Storage Writes
- Writing committed blocks to the disk in `blockchain.zig` uses dynamic byte array buffers returned from RLP serialization. If these buffers are not aligned to the storage media's sector boundaries (e.g., 4096 bytes), the operating system falls back to a slow Read-Modify-Write cycle.
- **Mitigation**: Pad and align all block serialization and state changes to 4KB alignment boundaries. Leverage `O_DIRECT` or direct user-space disk controllers to commit aligned state blocks directly to NVMe disks.
