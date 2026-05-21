# Architectural Roadmap — Phase 1 Implementation Plan

> Optimize the sol2zig codebase for high throughput per the [architectural_roadmap.md](file:///Users/karan/sol2zig/reports/architectural_roadmap.md), without breaking existing functionality or deleting correct code.

## Guiding Principles

- **No deletion of correct code.** Every existing function, test, and API stays intact.
- **Additive-first.** New optimized code paths are added alongside existing ones. Existing callers opt in via config flags or new method names.
- **80–100 line edit chunks.** Each step is a single, self-contained edit of ≤100 lines.
- **Build-verify after each chunk.** We compile after every major change to catch regressions early.

---

## Overview of Changes (Ordered by Impact & Safety)

| # | Subsystem | File | Optimization | Risk |
|---|-----------|------|-------------|------|
| 1 | VM | [sandbox.zig](file:///Users/karan/sol2zig/vm/memory/sandbox.zig) | Dirty-slice write-log reset (replace 384KB memset with tracked dirty ranges) | Low |
| 2 | Consensus | [zelius.zig](file:///Users/karan/sol2zig/src/consensus/zelius.zig) | O(N²) → O(S log S) write-set independence via sorting | Low |
| 3 | Storage | [store.zig](file:///Users/karan/sol2zig/src/storage/codestore/store.zig) | O(N) `orderedRemove` → O(1) intrusive doubly-linked LRU list | Low |
| 4 | Core | [delta_merge.zig](file:///Users/karan/sol2zig/src/core/delta_merge.zig) | Fork-join parallel merge using thread pool | Medium |
| 5 | Storage | [account_table.zig](file:///Users/karan/sol2zig/src/storage/zephyrdb/account_table.zig) | Progressive rehashing (incremental resize instead of `TableFull`) | Medium |
| 6 | Consensus | [vdf.zig](file:///Users/karan/sol2zig/src/consensus/vdf.zig) | True parallel VDF checkpoint verification with threads | Low |

---

## 1. Dirty-Slice VM Reset — [sandbox.zig](file:///Users/karan/sol2zig/vm/memory/sandbox.zig)

**Current:** `reset()` calls `@memset(0)` on ~384KB (Heap+Stack+Calldata+Return+Scratch) every transaction.

**Target:** Track which memory ranges were actually written, and only zero those on reset. Typical TX touches a few KB → 100x reduction in memset.

### Chunk 1A — Add DirtyTracker struct (~80 lines)
Add a new `DirtyTracker` struct at the top of `sandbox.zig` that maintains a fixed-size array of dirty ranges (start, len). When the array is full, it falls back to a "fully dirty" flag that triggers the original full memset.

### Chunk 1B — Integrate tracker into SandboxMemory stores (~60 lines)
Modify `storeByte`, `storeWord`, `storeHalfword`, `storeDoubleword`, and `getSliceMut` to call `self.dirty_tracker.markDirty(addr, size)` after a successful write.

### Chunk 1C — Add `resetTracked()` method + update `reset()` (~50 lines)
Add `resetTracked()` that only zeros dirty ranges. Leave the original `reset()` completely unchanged for backward compatibility. Add a `use_dirty_tracking: bool` config field — when true, `reset()` delegates to `resetTracked()`.

### Chunk 1D — Tests (~60 lines)
Add tests that verify dirty tracking correctly zeros only written regions and that `resetTracked()` produces identical results to `reset()`.

---

## 2. O(S log S) Write-Set Independence — [zelius.zig](file:///Users/karan/sol2zig/src/consensus/zelius.zig)

**Current:** `validateBlockDAG()` at [L656](file:///Users/karan/sol2zig/src/consensus/zelius.zig#L656) uses nested loops → O(N²) comparisons.

**Target:** Sort the key arrays and use a single linear scan for duplicates → O(S log S).

### Chunk 2A — Replace nested loop with sort+scan (~70 lines)
Replace the nested `for` loops at lines 656–671 with:
1. Collect all nonce keys and balance keys into a single flat array of `[32]u8`.
2. Sort the array (`std.mem.sortUnstable`).
3. Linear scan for adjacent duplicates.

This preserves the same error types (`NonceKeyCollision`, `BalanceKeyCollision`) and the same function signature.

---

## 3. O(1) Intrusive LRU for CodeCache — [store.zig](file:///Users/karan/sol2zig/src/storage/codestore/store.zig)

**Current:** `CodeCache.put()` calls `self.access_order.orderedRemove(0)` → O(N) shift of the entire ArrayList.

**Target:** Replace `access_order: ArrayList` with an intrusive doubly-linked list for O(1) eviction.

### Chunk 3A — Add LRU linked list node + list struct (~90 lines)
Add `LruNode` (prev/next pointers + hash key) and `LruList` (head/tail + count) structs at the bottom of `store.zig`. Include `moveToBack`, `pushBack`, `remove`, and `popFront` methods.

### Chunk 3B — Rewire CodeCache to use LruList (~80 lines)
- Replace `access_order: std.ArrayList(CodeHash)` with `lru_list: LruList`.
- Update `CacheEntry` to include an `lru_node: *LruNode` field.
- Modify `get()` to call `lru_list.moveToBack(entry.lru_node)`.
- Modify `put()` to call `lru_list.popFront()` for eviction and `lru_list.pushBack()` for new entries.
- Update `deinit()` to free LRU nodes.

### Chunk 3C — Tests (~40 lines)
Add test for LRU eviction order verification.

---

## 4. Fork-Join Parallel Delta Merge — [delta_merge.zig](file:///Users/karan/sol2zig/src/core/delta_merge.zig)

**Current:** `mergeBuffers()` is a sequential single-threaded loop.

**Target:** Binary tree reduction — divide buffers into pairs, merge each pair in parallel, then merge results.

### Chunk 4A — Add `ParallelDeltaMerger` struct (~90 lines)
New struct wrapping `DeltaMerger` with a `mergeParallel()` method that:
1. Splits input buffers into pairs.
2. Spawns threads to merge each pair into intermediate `AutoHashMap` results.
3. Merges intermediate results in a final sequential pass.
Falls back to `mergeBuffers()` for ≤2 buffers.

### Chunk 4B — Thread worker function + merge-two helper (~70 lines)
Add `mergeTwoBuffers()` that merges exactly two `DeltaBuffer`s into a `AutoHashMap`, and a worker wrapper for `std.Thread.spawn`.

### Chunk 4C — Tests (~50 lines)
Test that `mergeParallel()` produces identical results to `mergeBuffers()` across 4 lanes.

---

## 5. Progressive Rehashing — [account_table.zig](file:///Users/karan/sol2zig/src/storage/zephyrdb/account_table.zig)

**Current:** `getOrCreate()` returns `error.TableFull` when load factor exceeds 70%.

**Target:** Instead of erroring, begin incremental migration to a new table that is 2× the size. Migrate 64 buckets per write operation until complete.

### Chunk 5A — Add resize state fields + new table pointer (~60 lines)
Add `resize_target: ?[]AccountEntry`, `resize_capacity: u32`, `resize_progress: u32`, `is_resizing: bool` fields to `AccountTable`.

### Chunk 5B — `beginResize()` + `migrateChunk()` methods (~90 lines)
- `beginResize()` allocates a new entries slice at 2× capacity from the arena.
- `migrateChunk(batch_size)` re-inserts `batch_size` entries from the old table into the new one. Called during `getOrCreate()`.

### Chunk 5C — Rewire `getOrCreate()` and `get()` for dual-table lookup (~70 lines)
- `get()` checks both old and new table during resize.
- `getOrCreate()` calls `migrateChunk(64)` on every insert if resizing, and inserts into the new table.
- When migration completes, swap the tables.

### Chunk 5D — Tests (~50 lines)
Test that progressive resize doesn't lose entries and lookups work throughout migration.

---

## 6. Parallel VDF Verification — [vdf.zig](file:///Users/karan/sol2zig/src/consensus/vdf.zig)

**Current:** `verify_parallel()` is sequential despite its name.

**Target:** Actually spawn threads to verify each checkpoint segment in parallel.

### Chunk 6A — True parallel verification (~80 lines)
Replace the sequential loop in `verify_parallel()` with thread-per-segment verification:
1. Spawn one thread per checkpoint segment (capped at 8).
2. Each thread calls `verify_step()` on its segment.
3. Collect results via a shared atomic error flag.
4. Join all threads and return combined result.

---

## Verification Plan

### Build Check
After each chunk group (1A-1D, 2A, 3A-3C, etc.), run:
```bash
cd /Users/karan/sol2zig && zig build 2>&1 | head -30
```

### Unit Tests
After completing each subsystem, run existing tests to verify no regressions:
```bash
cd /Users/karan/sol2zig && zig build test 2>&1 | tail -20
```

### Specific File Tests
For files with inline tests (sandbox.zig, vm_pool.zig, delta_merge.zig, account_table.zig), verify:
```bash
zig test vm/memory/sandbox.zig
zig test src/core/delta_merge.zig
```

> [!IMPORTANT]
> All existing tests and APIs must pass unchanged. The optimizations are strictly additive — new methods, new structs, new config options — never modifying the existing function signatures or removing working code.

## Open Questions

1. **Thread count for parallel delta merge**: Should we hardcode 4 threads (matching the roadmap's Core 2-5 allocation) or make it configurable? I'm leaning toward a configurable `merge_workers: u32 = 4` field.

2. **Dirty tracker capacity**: For the VM dirty-slice tracker, how many dirty ranges should we track before falling back to full memset? I'm proposing 256 entries (covers most realistic TX patterns). Higher values consume more memory per VM sandbox.

3. **Progressive rehash batch size**: The roadmap suggests 64 buckets per operation. Should we also support a bulk `finishResize()` for epoch boundaries where a brief pause is acceptable?
