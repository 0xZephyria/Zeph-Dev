Here is the comprehensive src/core/ analysis.
src/core/ — Complete Map (32 files)
# Module Overview
core/
├── mod.zig                # Re-exports everything (shorthand + struct aliases)
├── types.zig              # Primitive types: Address, Hash, Header, Transaction, Block, AccountType, SlotClassification, CreditReceipt, AccumulatorDelta, ParallelTxResult
│
├── state.zig              # State + Overlay (arena-based dirty maps + journal + commit + conflict detection)
├── dag_executor.zig       # DAGExecutor — parallel lane execution, Phase 1/1.5/2/2.5/3 pipeline
├── blockchain.zig         # Blockchain — block storage/retrieval, fork choice, head tracking
├── block_producer.zig     # BlockProducer — orchestrates extract→schedule→execute→assemble
├── genesis.zig            # Genesis — network configs, alloc application, system contract deploy
├── dag_mempool.zig        # DAGMempool — 256-shard mempool, per-sender lanes, bloom filter, GC
├── dag_scheduler.zig      # Scheduler — schedule(), scheduleFromTxs(), assignToThreads(), validatePlan(), computeDAGRoot()
│
├── delta_merge.zig        # DeltaBuffer, DeltaMerger, ParallelDeltaMerger — lock-free merge of lane deltas
├── async_state_root.zig   # ⚠️ DEAD CODE — background root computer (unused since sync swap)
├── block_rewards.zig      # ⚠️ MOSTLY DEAD — applyRewards() duplicated in dag_executor Phase 2.5
│
├── historical_state.zig   # HistoricalState — epoch-based time-travel queries
├── logger.zig             # Compile-time level-filtered structured logging
├── security.zig           # RateLimiter, TxSanitizer, TxBloomFilter, ReentrancyGuard, GasMeter, ExecutionTimer
├── signature.zig          # Ed25519 + BLS12-381 + PoP verification + aggregate verify
├── state_prefetcher.zig   # StatePrefetcher — batch-read cache warming before Phase 1
├── tx_decode.zig          # recoverFromTx(), decodeTransaction()
├── tx_list.zig            # ⚠️ DUPLICATE of AccountLane in dag_mempool.zig — ready/future queues
│
├── state_root/
│   ├── mod.zig            # Re-exports sorted_delta + types/StateDelta/ComputerFn
│   ├── sorted_delta.zig   # compute() — precise deterministic Blake3 chain root
│   └── types.zig          # StateDelta struct + ComputerFn function pointer type
│
├── accounts/
│   ├── mod.zig            # Re-exports all account types + MetadataRegistry + DeltaQueue + ReceiptQueue
│   ├── common.zig         # accountStem() + key derivation (nonce/balance/codeHash/code/typeKey) + read/writeAccountType
│   ├── resolver.zig       # resolve(), expectType(), resolveCreateType(), Resolution, CreateContext
│   ├── header.zig         # AccountHeader struct (60 bytes base for all account types)
│   ├── eoa.zig            # EOA — wallet account (balance + nonce) with serialize/deserialize/debit/credit
│   ├── contract_root.zig  # ContractRoot — contract metadata (code_hash, storage_version)
│   ├── code.zig           # CodeAccount — immutable bytecode storage, serialize/deserialize, hashCode()
│   ├── storage_cell.zig   # StorageCellAccount — per-slot isolated storage
│   ├── vault.zig          # VaultAccount — contract balance holder ⚠️ dead code (balanceKey used directly)
│   ├── derived.zig        # DerivedStateAccount — per-user contract state + DeltaQueue + ReceiptQueue
│   ├── config.zig         # ConfigAccount + ContractMetadata + MetadataRegistry — slot classification
│   └── system.zig         # SystemAccount — protocol accounts, well-known addresses
│
└── rlp/
    └── rlp.zig            # RLP encoding/decoding (Ethereum legacy format — for backward compat)

## Import / Export Dependency Graph

### External imports (from outside core/):
  storage          → state.zig, blockchain.zig, historical_state.zig, accounts/common.zig
  encoding         → types.zig, blockchain.zig (RLP)
  utils            → types.zig, blockchain.zig (hex encoding)
  crypto           → signature.zig (blst BLS)
  accounts         → dag_executor.zig, dag_mempool.zig, dag_scheduler.zig (DeltaQueue, ReceiptQueue)

### Internal dependency chain:
  types.zig ←── state_root/types.zig ──→ state_root/sorted_delta.zig ←── state_root/mod.zig
      ↑             ↑                       ↑
      │             │                       └── async_state_root.zig
      │             │
      │    accounts/*.zig ──→ accounts/mod.zig
      │         ↑
      ├──── state.zig (State + Overlay)
      │
      ├──── blockchain.zig ←── block_producer.zig
      ├──── dag_mempool.zig ←── dag_scheduler.zig ──→ block_producer.zig
      ├──── dag_executor.zig ←──────┘                 ↑
      ├──── delta_merge.zig                           │
      ├──── state_prefetcher.zig                      │
      ├──── security.zig  ←── dag_mempool.zig         │
      ├──── signature.zig ←── security.zig            │
      ├──── tx_decode.zig  ←── blockchain.zig         │
      └──── genesis.zig

## Identified Issues

### BUGS & MEMORY ISSUES

1. dag_executor.zig:550 — Use-after-free in delta merge: DeltaQueue.deinit() at line 520 frees combined_deltas.items, but merge() at line 530 accesses those items. The code copies deltas into combined_deltas from delta_queues[i], then merges. If dq.items.items are owned by dq, the merged result may reference freed memory after delta_queues are deinitialized (defer at line 311 runs at scope exit, but combined_deltas.deinit() at line 520 runs before merge at 530... actually the flow is: push copies into combined_deltas, merge creates new allocation, then combined_deltas.deinit(). This is safe because merge() creates a new map. However push() just appends the delta struct itself (which is a value type), not references. So this is actually OK. Let me re-check...
Actually looking more carefully: combined_deltas.push(delta) at line 524 appends delta (a types.AccumulatorDelta value). Then combined_deltas.merge() creates a new DeltaMap from those values. Then combined_deltas.deinit() frees its internal ArrayList. The merged map owns its own allocations. This is safe.
2. dag_executor.zig:388-434 — Thread pool panic on empty plan: When plan.lanes.len == 0, the code calls pool.init() and then immediately pool.deinit(). Thread pool with 0 work items is fine in Zig's stdlib, but the groups allocation at line 413 does @min(num_threads, 0) = 0 groups, then line 431 iterates over 0 groups. The wg is used with 0 spawns, so wg.wait() is a no-op. This is safe but wasteful.
3. block_rewards.zig — Dead code with re-entrancy bug: The applyRewards() function writes directly to State (via state.setBalance()), NOT through an overlay. Meanwhile dag_executor.zig:593 writes through the reward overlay. If both paths execute, the state is mutated twice. But since block_rewards.zig is never imported by the executor, this is latent.
4. state_prefetcher.zig — Prefetches only trigger cache but don't track misses correctly: Lines 150-154 count cacheHits/cacheMisses based on state.db.read() result — but db.read() may return null even for existing data in certain storage backends (e.g., lazy-loaded). The stats are misleading.
5. dag_mempool.zig:670-715 — removeCommitted() deadlock risk: Holds by_hash_lock (line 677) then iterates senders and acquires shard.lock (line 699). If any other path acquires shard.lock then by_hash_lock, deadlock. The extract function acquires shard.lock then does NOT acquire by_hash_lock — but get() at line 804 does by_hash_lock then shard.lock (reverse order).
6. state_root/sorted_delta.zig:28 — Arena allocator not reset between blocks: Arena is created, used, then defer arena.deinit() frees everything. This is fine (creates fresh arena per call), but wasteful — could reuse.
DEAD CODE
1. async_state_root.zig — Entire file. 245 lines. No longer used since sync root swap. Still imported in mod.zig line 27, dag_executor.zig:37, block_producer.zig:20.
2. block_rewards.zig — 98 lines. applyRewards() bypassed by executor's overlay-based reward in Phase 2.5. No caller in the codebase.
3. state_prefetcher.zig — 221 lines. Wired in dag_executor.zig:349 but db.read() calls in a flat KV model have no trie cache to warm. The comment says "Verkle trie cache" but there's no Verkle trie. The entire prefetch is a no-op that just reads keys for no benefit.
4. tx_list.zig — 151 lines. A second implementation of per-sender TX queuing. Identical purpose to AccountLane in dag_mempool.zig. Neither module imports the other.
5. delta_merge.zig DeltaMerger — 604 lines. The DeltaMerger and ParallelDeltaMerger are completely unused. The executor's Phase 2 does its own inline merge (lines 519-557). The DeltaMerger.applyToState() is never called. The entire module is dead.
6. accounts/vault.zig — vaultKey() never used. Contract balances go through balanceKey() directly.
7. accounts/header.zig — The AccountHeader struct (60 bytes) with owner_program, balance, nonce, flags, data_hash is defined but the actual state serialization uses flat KV (individual fields), not blob-based account headers. The header type is aspirational for Phase 1 blob serialization.
ETHEREUM / SOLANA PATTERNS (NOT ZEPHYRIA-NATIVE)
 1. types.zig:74-155 — Ethereum Header struct: baseFee, gasLimit, gasUsed, coinbase are all Ethereum concepts. Zephyria-native should use Zephyria-specific reward mechanism and not EIP-1559 base fee.
 2. types.zig:165 — Transaction uses nonce: Ethereum-style sequential nonces for replay protection. Zephyria should use account sequence numbers or epoch-based nonces.
 3. types.zig:301-321 — Transaction.hash(): Uses Blake3 over entire binary format. Zephyria-native should define its own TX identity scheme.
 4. rp/ directory: RL P encoding is Ethereum's serialization format. Entirely unnecessary for a Zephyria-native chain. All encodeToRLP/decodeFromRLP methods in types.zig are dead weight.
 5. blockchain.zig:231-256 — calcBaseFee(): Exact copy of EIP-1559 formula. Zephyria should not use EIP-1559.
 6. dag_executor.zig:945-956 — computeIntrinsicGas(): Ethereum's 21,000 base gas + calldata costs. Zephyria should define its own fee model.
 7. state.zig:401-406 — JournalEntry.suicide: Ethereum SELFDESTRUCT semantics. Zephyria should have its own account lifecycle.
 8. state.zig:344 — selfDestructs: Ethereum suicide set.
 9. dag_executor.zig:797 — Block-STM conflict re-execution: This is Solana's approach (optimistic execution + rollback). Zephyria's DAG model guarantees zero conflicts — this entire Phase 1.5 should never trigger. Still 60 lines of complexity.
10. security.zig:327-353 — GasMeter with EIP-3529 refund cap: Ethereum-specific gas logic.
DUPLICATED FUNCTIONALITY
1. Three StateDelta structs: state_root/types.zig:5-17, delta_merge.zig:35-46, storage/epoch/delta.zig. All represent "set of key-value changes". Different fields, different purposes, but conceptually identical.
2. tx_list.zig ≈ dag_mempool.AccountLane: Both implement per-sender nonce-ordered TX queues with ready/future promotion and replacement.
3. dag_executor.zig Phase 2 merge vs delta_merge.zig.DeltaMerger: The executor does its own inline merge (lines 519-557). The DeltaMerger module is a parallel version — unused.
4. Key derivation functions: common.zig defines nonceKey()/balanceKey()/codeKey()/codeHashKey(). state.zig wraps them. eoa.zig wraps common.nonceKey/balanceKey. code.zig wraps common.codeKey/codeHashKey. The wrappers are trivial one-liners.
5. block_rewards.zig vs dag_executor.zig:588-596: Reward logic duplicated. Block rewards module is aspirational; executor has the real implementation.

# Summary Stats
Metric	Value

Total files	32

Total lines	~7,800

Dead code files	4 (async_state_root.zig, block_rewards.zig, state_prefetcher.zig, tx_list.zig)

Dead lines	~715

Unused modules	2 (delta_merge.zig, rlp/rlp.zig)

Duplicate structs	3 (StateDelta)

Duplicate TX queues	2 (AccountLane vs TxList)

Ethereum patterns	10+

Memory/use-after-free bugs	0 critical (reviewed carefully)

Deadlock risk	1 (dag_mempool lock ordering)


## Which file would you like to tackle first? I suggest starting with the highest-impact cleanup:
1. Remove dead code — async_state_root.zig, state_prefetcher.zig, tx_list.zig, block_rewards.zig, delta_merge.zig (~715 lines gone)

2. Remove RLP — drop rlp/ subdir, remove all encodeToRLP/decodeFromRLP from types.zig

3. Rename Ethereum concepts — coinbase → producer, nonce → sequence, gasLimit → executionBudget, baseFee → remove

4. Consolidate — unify StateDelta, remove duplicate key wrappers, collapse EIP-1559/TX gas logic