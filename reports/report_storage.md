# Module Report: Storage Engine (`storage/`)

This report provides a comprehensive analysis of the Zephyria storage architecture, including ZephyrDB, the LSM Tree engine, Verkle Trie state commitments, Epoch Aggregator history pruner, Merkle Mountain Range (MMR), and contract CodeStore. It identifies key performance barriers and outlines mechanical sympathy optimizations to support 1 million transactions per second (TPS).

---

## 1. Directory Structure & File Index

The `storage/` directory forms the state and ledger layer of the blockchain. It combines an in-memory hot-state store (ZephyrDB) with disk-backed append-only logs, a state trie (Verkle), and historical prune aggregators.

### Submodules & Components

| File/Subdirectory | Role & Responsibility |
| :--- | :--- |
| [`mod.zig`](file:///Users/karan/sol2zig/src/storage/mod.zig) | Public entrypoint exposing DB traits, benchmarking utilities, and submodules. |
| [**`zephyrdb/`**](file:///Users/karan/sol2zig/src/storage/zephyrdb) | In-memory hot state DB (Arena, AccountTable, SlotStore, WAL, Checkpoints). |
| [**`lsm/`**](file:///Users/karan/sol2zig/src/storage/lsm) | Sharded Memtable, LSM SSTables, Bloom filters, and `io_uring` async I/O. |
| [**`verkle/`**](file:///Users/karan/sol2zig/src/storage/verkle) | 256-ary state commitment tree using Banderwagon group curves and IPA proofs. |
| [**`epoch/`**](file:///Users/karan/sol2zig/src/storage/epoch) | State delta tracker, RLE compression, BLS signature aggregator, and block pruner. |
| [**`mmr/`**](file:///Users/karan/sol2zig/src/storage/mmr) | Merkle Mountain Range for O(log n) verification of historical headers. |
| [**`codestore/`**](file:///Users/karan/sol2zig/src/storage/codestore) | Content-addressed contract bytecode deduplicator with LRU caching. |

---

## 2. Core Components Analysis

### A. ZephyrDB (Hot State Engine)
- **Memory Arena (`arena.zig`)**: Employs `mmap` to pre-allocate a monolithic 4GB virtual address block at startup. It utilizes thread-safe free-lists split into size-classes (64B, 256B, 1KB, 4KB, 64KB) and falls back to atomic bump pointers.
- **Account Table (`account_table.zig`)**: Implements Robin Hood hashing in an open-addressed array of 128-byte extern structs (cache-line aligned). Reads are lock-free; writes lock one of 64 mutexes in a striped array.
- **Slot Store (`slot_store.zig`)**: Incorporates 8 inline storage slots inside each account entry. Overflow slots spill to an `OverflowMap` located in the Arena.
- **WAL Ring Buffer (`wal_ring.zig`)**: Accumulates transactions in a 256MB in-memory ring using atomic head increments. Group commit collects up to 1024 entries and flushes via a single `fsync` using a background thread waking every 1ms.

### B. LSM Tree & I/O Engine
- **HighPerfDB (`highperf_db.zig`)**: Integrates a sharded memtable (16 shards) supporting lock-free reads and mutex-locked updates.
- **Async I/O (`io.zig`)**: Contains an Linux-specific `IoUringEngine` implementing async disk submissions using `io_uring` submission and completion queues, bypassing the user-kernel context-switching overhead of POSIX threads. Falls back to a POSIX thread pool on other OSes (like macOS).
- **SSTables (`sstable.zig`)**: Employs Bloom filters with double hashing (via XxHash64) and binary-searched index blocks to minimize read amplification.

### C. Verkle Trie (`verkle/`)
- **Structure**: 256-ary radix trie committing to internal nodes via Pedersen vector commitments (using Banderwagon/IPA).
- **Commitment Cache**: Maps commitment bytes to curve elements. It avoids Pedersen calculations for unchanged subtrees.
- **Parallel Subtree Commit**: Stems marked dirty in `dirty_stems` are grouped by their first prefix byte. Stems are partitioned and committed in parallel across up to 8 threads.

### D. Epoch Aggregation (`epoch/`)
- **State Deltas (`delta.zig`)**: Records state diffs per epoch using 256 RwLock-guarded shards. Merges state updates at block/epoch boundaries.
- **RLE Delta Compression**: Serializes deltas using a hand-rolled Run-Length Encoding (RLE) routine.
- **BLS Signature Aggregator (`signature_aggregator.zig`)**: Aggregates validator signatures on epoch checkpoints using the `blst` library.

### E. Merkle Mountain Range & Code Store
- **MMR (`mmr/tree.zig`)**: Retains peak roots of historical headers in memory to achieve constant-size verification.
- **CodeStore (`codestore/store.zig`)**: Content-addresses bytecode via Keccak256. Employs 256 Sharded RwLocks and an LRU cache.

---

## 3. Critical Bottlenecks & Design Critiques

To consistently sustain 1 million TPS, the storage module has several performance bottlenecks:

### A. Account Table Resize Failure
- **Issue**: The `AccountTable` throws a `TableFull` error when the load factor is exceeded. It completely lacks resizing logic.
- **Critique**: A production blockchain must grow dynamically. Standard resizing requires allocating a new table and re-inserting all items, which halts transaction processing (introducing multi-second latency spikes).
- **Mitigation**: Implement **progressive/incremental rehashing** where buckets are migrated in small batches (e.g., 64 buckets per transaction write) across multiple blocks, keeping write operations bounded to O(1) time.

### B. Dynamic Thread Spawning in Verkle Commitments
- **Issue**: `commitParallel` spawns fresh OS threads for every block commit:
  ```zig
  threads[t] = std.Thread.spawn(.{}, commitSubtreeRange, ...);
  ```
- **Critique**: Spawning and joining up to 8 OS threads per block commits introduces thousands of context switches, page table updates, and kernel scheduler traps. At 1M TPS, this will saturate the CPU with kernel overhead.
- **Mitigation**: Utilize a static, core-pinned worker thread pool using lock-free ring buffers (MPSC/MPMC queues) to submit subtree tasks.

### C. Cache-Bypassing Verkle Traversal
- **Issue**: The commitment cache lookup is evaluated bottom-up. However, the trie must still traverse the full height down to the leaf nodes during `updateCommitmentsWithCache` to check for dirty flags because ancestors are not flagged as dirty during a `put`.
- **Critique**: Traversing down a 31-level deep tree for hundreds of thousands of keys is highly cache-unfriendly, causing constant L1/L2/L3 cache misses.
- **Mitigation**: Implement **active ancestor dirty propagation** or a flat queue of dirty nodes. When a leaf is written, its parent node index is immediately added to a level-grouped execution queue, enabling true bottom-up commitment calculation without top-down trie traversal.

### D. MMR Node Growth in RAM
- **Issue**: The MMR stores *every* node in an unbounded `std.ArrayList(MMRNode)` in RAM.
- **Critique**: As the block height grows, the memory footprint increases by 44 bytes per node, reaching gigabytes of RAM. This violates the "constant-size" blockchain design.
- **Mitigation**: Persist intermediate MMR nodes to an append-only flat file using asynchronous Direct I/O (`O_DIRECT`). Only retain the sparse set of active peak hashes in RAM.

### E. O(N) Cache Eviction in CodeStore
- **Issue**: `CodeCache` tracks the LRU order via `std.ArrayList(CodeHash)` and evicts the LRU item using:
  ```zig
  const to_evict = self.access_order.orderedRemove(0);
  ```
- **Critique**: `orderedRemove(0)` shifts every single element in the array to the left, which is an O(N) operation. At high concurrency, this shifts memory repeatedly while holding the cache write lock.
- **Mitigation**: Replace the `ArrayList` with an intrusive doubly-linked list (`std.DoublyLinkedList`) or a lock-free ring buffer, turning the LRU eviction into a fast O(1) operation.

### F. Lock Contention on StateDelta and CodeStore
- **Issue**: Sharded locks (`RwLock`) are used in `StateDelta` and `CodeStore` write/read paths.
- **Critique**: Thread synchronization via RwLock incurs kernel futex/syscall traps under high transaction rates.
- **Mitigation**: Transition to lock-free design using Atomic Pointer Swapping (Epoch-based Reclamation) or Thread-per-Core architecture where each thread writes exclusively to a thread-local StateDelta/CodeStore.
