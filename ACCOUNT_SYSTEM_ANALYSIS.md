# Zephyria Account System — Complete Analysis

## Architecture Overview

The Zephyria account system is built around **8 account types** defined in `src/core/accounts/`:

| Type | Name | Purpose |
|------|------|---------|
| 0 | EOA | User wallet (balance + nonce) |
| 1 | ContractRoot | Contract metadata (code_hash, storage_root) |
| 2 | Code | Immutable RISC-V bytecode |
| 3 | Config | Slot classification metadata |
| 4 | StorageCell | Per-slot isolated storage |
| 5 | DerivedState | Per-user contract state (DEX parallelism) |
| 6 | Vault | Contract balance holder |
| 7 | System | Protocol-level accounts |

## Current State

### What Works
- **Flat KV storage**: All state stored as Blake3-derived 32-byte key → raw bytes
- **Per-slot isolation**: Each storage slot is a separate account — zero conflicts on different slots
- **Derived storage**: Per-user keys for DEX parallelism
- **Global accumulators**: Commutative state with delta merge
- **DAG mempool**: 256-shard mempool with per-sender lanes
- **Async state root**: Background thread for state root computation

### What Needs Work

**Account structs are documentation-only**: The account structs (EOA, ContractRoot, CodeAccount, etc.) are never serialized/deserialized. The storage layer uses raw key-value pairs. Structs serve as type-level organization but not as runtime storage schemas.

**Duplicate key derivation**: Same functions defined in 3 places:
- `accounts/eoa.zig`: `accountStem`, `nonceKey`, `balanceKey` — **dead code** (zero callers)
- `accounts/contract_root.zig`: `contractStem`, `codeHashKey`, `codeKey` — **dead code** (zero callers)
- `state.zig`: All key functions with TLS caching — **the real runtime code**

**No type enforcement at storage**: No check that an address is an EOA before setting balance. No system flag enforcement.

**DAG write-key prediction incomplete**: Currently hardcodes one slot per TX. Needs to use forge's access list declarations.

**Block rewards bypass overlay**: Direct `state.setBalance()` call isn't captured in StateDelta for root computation.

**MetadataRegistry not persisted**: Slot classification lost on restart.

## Forge Language Integration

The forge compiler at `/Users/karan/forge` has:

1. **Explicit account declarations** per action:
   ```forge
   action transfer(to is Wallet, amount is u256):
       accounts:
           mine is Data owned_by this
           vault is Vault owned_by this
   ```

2. **AccessList** type in checker — per-action read/write sets with `conflictsWith()`

3. **Authority system**: `authorities:` blocks, `only authName:` guards, `transfer_ownership`

4. **Annotations**: `#[parallel]`, `#[reads mine.X]`, `#[writes mine.X]`

5. **Account types in forge**: data, vault, asset, oracle, wallet, program, system

6. **AccessList is NOT embedded in .fozbin binary** — needs to be added

## Recommended Changes

### Phase 1 — Account Module System (IN PROGRESS)
- Make each account type a self-contained module with serialize/deserialize, key derivation, CRUD ops
- Move ALL key derivation into account modules (single source of truth)
- Refactor state.zig to delegate to account modules
- Clean up dead code

### Phase 2 — Owner-Program & Authority Enforcement
- Add owner field to account storage
- Enforce owner check on write operations
- Implement AUTHORITY_CHECK/GRANT/REVOKE syscalls at State layer
- System flag enforcement

### Phase 3 — DAG Integration
- Embed AccessList in .fozbin binary
- Parse at deploy time, use for write-key prediction
- Fix DAGVertex.computeWriteKeys

### Phase 4 — Storage & Persistence
- Persist MetadataRegistry to DB
- Include block rewards in state delta
- Rename StateDelta naming collision

## Key Decision: Flat KV vs Single Blob

**Current**: Flat KV — each field stored at separate key (balanceKey, nonceKey, codeKey, etc.)
**Proposed**: Single blob per account — one DB key per address, serialized AccountHeader + type-specific payload

**Trade-off**: Fewer DB ops, simpler atomicity, type enforcement built-in vs larger reads/writes

The user chose single-blob approach. Implementation deferred after module system refactor.
