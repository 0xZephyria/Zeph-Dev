# Zephyria — Production-Grade Robustification Plan

> **Status**: Phases 1–5 COMPLETE. Phase 3 deeper pass COMPLETE. Build passes. All tests pass.
> **TODOs**: 28 → 12 remaining (all LOW/INFO infrastructure)
> **Remaining for Gemini**: 12 infra TODOs, P2P debug print cleanup, Phases 6-7.

---

## ✅ COMPLETED — Do NOT Redo

### Phase 1: Structured Logger (DONE)
- `src/core/logger.zig` — level-gated logger (err/warn/info/debug/trace)
- Exported via `src/core/mod.zig`

### Phase 2: Core Cleanup (DONE)
- `executor.zig` 392→258 lines, removed Legacy mode
- `blockchain.zig` — 10 prints → 2 logger calls
- `miner.zig` 188→171 lines
- `state.zig`, `mod.zig` — removed debug prints

### Phase 3: TODOs (16 FIXED, 12 REMAINING)

**Fixed (16):**
- block_builder: tx_hash Keccak + calc_base_fee
- deferred_executor: blocks_pending count
- registry: Keccak hashing + RLP encode/decode + state write
- pipeline: Keccak proposal signature + finalization timing tracking
- state_bridge: VM callback for CALL + block_number field + chain_id field
- websocket: JSON-RPC serialize newHeads + logs
- turbine: XOR-based Reed-Solomon recovery + Keccak shred signatures
- gulf_stream: Keccak-based VRF proof
- grpc/server: auth documentation + method routing by handler name
- grpc/transport: HTTP/2 SETTINGS parameter parsing
- vm_bridge: documented StateBridge execution integration
- security: JWT claims validation documentation
- tx_list: 10% minimum gas price replacement policy

**Remaining (12 — all LOW/INFO infrastructure):**

| File | TODO |
|---|---|
| `src/crypto/blst/Pairing.zig:71` | Assertion for len > 0 |
| `src/core/rlp/deserialize.zig:162` | Missing: Many, C parser types |
| `src/storage/epoch/signature_aggregator.zig:149` | Optimize memory |
| `src/storage/lsm/io.zig:177` | io_uring engine |
| `src/storage/lsm/db.zig:79` | SSTable flush |
| `src/storage/zephyrdb/mod.zig:291` | Return slice from arena |
| `src/storage/verkle/lib/**` | 3 optimization notes |
| `src/p2p/grpc/tests.zig` | Update tests for Spice API |
| `src/p2p/quic/transport/stream.zig:59` | QUIC flush |

### Phase 4: Dead Code Removal (DONE)
- Removed Legacy ExecutionMode
- Compacted all ASCII banners → `log.info()`
- Added `--log-level` CLI flag

### Phase 5: Debug Print Batch Replacement (DONE)
- 8 modules: `std.debug.print` → `log.debug()`
- Storage: kept `std.debug.print` (circular dep)

---

## ⬜ REMAINING FOR GEMINI

### Remaining Debug Prints (~105)
| Module | Count | Action |
|---|---|---|
| `src/p2p/` (quic, grpc) | 63 | Replace with `log.debug()` |
| `src/main.zig` | 21 | CLI help output — **keep as-is** |
| `src/storage/` | 18 | Circular dep — keep or move logger |
| `src/sdk/` | 3 | Replace with `log.debug()` |

### Phase 6: Wire Zero-Conflict Parallel Executor
### Phase 7: Comprehensive Test Suites

---

## Verification Commands
```bash
zig build               # zero errors
zig build test-node     # all pass
grep -rn "TODO" src/ --include="*.zig" | grep -v "_test.zig" | grep -v "bench.zig" | wc -l  # → 12
```
