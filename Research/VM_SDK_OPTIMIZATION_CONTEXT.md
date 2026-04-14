# Zephyria VM & SDK — Production Roadmap & Optimization Context

> **Purpose**: Comprehensive context for completing the ZephVM + SDK into a production-grade smart contract execution engine capable of any contract type, optimized for 1M TPS on consumer hardware (8 cores, 16 GB RAM, 1 Gbps NIC).

---

## 1. Current Architecture Summary

### VM (ZephVM — RISC-V RV32EM Interpreter)
| Component | File | Lines | Status |
|---|---|---|---|
| Decoder | `vm/core/decoder.zig` | ~350 | ✅ Production: 7 format variants (R/I/S/B/U/J/System) |
| Executor | `vm/core/executor.zig` | ~400 | ✅ Production: Fetch-decode-execute-gas loop, 10M step limit |
| Gas Meter | `vm/gas/meter.zig` | ~200 | ✅ Production: EIP-3529 refunds, warm/cold tracking |
| Gas Table | `vm/gas/table.zig` | ~150 | ✅ Production: 128-entry opcode lookup + EIP-2929 costs |
| Sandbox Memory | `vm/memory/sandbox.zig` | ~340 | ✅ Production: 640KB, 5 regions, permission-enforced |
| Syscall Dispatch | `vm/syscall/dispatch.zig` | ~700 | ✅ 35 syscalls implemented |
| Contract Loader | `vm/loader/contract_loader.zig` | ~300 | ✅ ELF + .zeph + raw bytecode |
| VM Pool | `vm/vm_pool.zig` | ~250 | ✅ Zero-alloc sandbox reuse |
| VM Bridge | `src/vm_bridge.zig` | ~200 | ✅ Thread-safe DAG executor → VM |

### SDK (`sdk/src/` — 19 files + openzeppelin)
| Component | File | Lines | Status |
|---|---|---|---|
| ABI Codec | `abi_codec.zig` | ~700 | ✅ Full Solidity ABI encode/decode |
| Accounts | `accounts.zig` | ~500 | ✅ Address utilities, account abstractions |
| Storage | `storage.zig` | ~350 | ✅ StorageMapping, StorageArray, StorageString, StorageSlot |
| Events | `events.zig` | ~200 | ✅ LOG0-LOG4 with indexed topics |
| Crypto | `crypto.zig` | ~300 | ✅ Keccak256, SHA256, RIPEMD160 |
| Host Calls | `host_calls.zig` | ~400 | ✅ All 35 syscalls wrapped |
| Types | `types.zig` | ~600 | ✅ u256, Address, bytes32, fixed arrays |
| Math | `math.zig` | ~200 | ✅ SafeMath for u256 |
| Modifiers | `modifiers.zig` | ~200 | ✅ onlyOwner, nonReentrant, whenNotPaused |
| Runtime | `riscv_runtime.zig` | ~150 | ✅ _start → riscvMain lifecycle |
| Context | `context.zig` | ~250 | ✅ ExecutionContext from host |
| Precompiles | `precompiles.zig` | ~250 | ✅ ECRECOVER, SHA256, RIPEMD160 |
| Testing | `testing.zig` | ~200 | ✅ Mock state for unit tests |
| Libraries | `libraries.zig` | ~200 | ⚠️ Started |
| OpenZeppelin | `openzeppelin/` | | ⚠️ Started |

---

## 2. Critical Gaps — What's Missing for Production

### P0: Ship-Blockers (Cannot Deploy Real Contracts Without These)

#### Gap 1: Pseudo-ECRECOVER — Not Cryptographically Real
```
Current:  ecrecover in dispatch.zig computes keccak256(hash || v || r || s) — deterministic but FAKE
Impact:   Cannot verify EIP-712 permits, meta-transactions, or any signature-dependent DeFi
Required: Bind real secp256k1 point recovery (libsecp256k1 or Zig's std.crypto.ecc.Secp256k1)
Effort:   2-3 days
```

**Implementation approach:**
```
1. In dispatch.zig ECRECOVER handler:
   - Parse (hash[32], v[1], r[32], s[32]) from guest memory
   - Call std.crypto.ecc.Secp256k1 point recovery with recovery_id = v - 27
   - Convert recovered pubkey → keccak256 → take last 20 bytes → write to guest a0
   
2. Gas: Keep EIP-2929 ECRECOVER cost (3000 gas)

3. Test: Deploy ERC-20 permit() contract, verify signature round-trip
```

#### Gap 2: No CREATE2 (Salt-Based Deployment)
```
Current:  Only CREATE (nonce-based address derivation)
Impact:   No factory patterns (Uniswap V3), no counterfactual wallets, no clone factories
Required: CREATE2 syscall: address = keccak256(0xFF || sender || salt || keccak256(initcode))
Effort:   1-2 days
```

**Implementation approach:**
```
1. Add syscall 0x25 CREATE2 to dispatch.zig
2. Args: a0=initcode_ptr, a1=initcode_len, a2=salt_ptr (32 bytes), a3=value
3. Derive address: keccak256(0xFF || caller || salt || keccak256(initcode))[12:]
4. Execute initcode in child VM instance (same as CREATE)
5. Store runtime bytecode at derived address
6. Return address in a0
```

#### Gap 3: No Transient Storage (EIP-1153 — TLOAD/TSTORE)
```
Current:  Not implemented
Impact:   No re-entrancy locks without 5000 gas SSTORE, no flash loan callbacks, no zero-cost routing state
Required: TLOAD (0x23) / TSTORE (0x24) syscalls backed by per-TX ephemeral HashMap
Effort:   2-3 days
```

**Implementation approach:**
```
1. Add TransientStorage HashMap(u256, u256) to StateBridge
2. TSTORE: write to transient map (100 gas, same as EIP-1153)
3. TLOAD: read from transient map (100 gas)
4. Auto-clear at TX boundary (StateBridge.reset())
5. Not persisted to state, not committed to overlay
```

---

### P1: High Priority — Needed for Advanced Smart Contracts

#### Gap 4: No BLS12-381 Precompiles (EIP-2537)
```
Current:  Not implemented
Impact:   No on-chain ZK-SNARK verification, no BLS aggregation in contracts
Required: BLS_G1_ADD, BLS_G1_MUL, BLS_G2_ADD, BLS_G2_MUL, BLS_PAIRING, BLS_MAP_G1, BLS_MAP_G2
Effort:   1-2 weeks
Approach: Bind our existing crypto/blst library to syscall handlers
```

#### Gap 5: No Bytecode Source Mapping / Debug Info
```
Current:  Panic at PC=0x1234 gives zero context. ELF symbols stripped.
Impact:   Developer experience is severely limited. Explorers can't show source traces.
Required: DWARF or custom .zeph debug section with source line ↔ PC mapping
Effort:   1-2 weeks
```

#### Gap 6: No EIP-1167 Minimal Proxy / Clone Factory
```
Current:  DELEGATECALL works but no standardized minimal proxy pattern
Impact:   Cannot cheaply deploy hundreds of identical contracts (DEX pairs)
Required: SDK-level MinimalProxy + CREATE2-based CloneFactory
Effort:   3-4 days (SDK only, no VM changes needed)
```

#### Gap 7: VM-Level Re-Entrancy Protection
```
Current:  Cross-contract calls allow unbounded re-entrancy
Impact:   Classic re-entrancy attacks possible without manual guards
Required: Call depth tracking + optional global re-entrancy mutex per-contract
Effort:   2-3 days
Approach: 
  - Track call depth in executor (max 1024, matching EVM)
  - Add optional re-entrancy flag per contract address in StateBridge
  - SDK nonReentrant modifier already exists, but VM enforcement is safer
```

---

### P2: Production Hardening

#### Gap 8: Metered Memory Growth (EIP-3860)
```
Current:  Fixed 640KB sandbox. No initcode size limit enforcement.
Impact:   Oversized initcode could waste gas. No dynamic heap growth metering.
Required: Charge 2 gas per 32-byte word of initcode (EIP-3860)
Effort:   1 day
```

#### Gap 9: Full Event Log Indexing
```
Current:  Events emitted but not indexed for eth_getLogs queries
Impact:   Block explorer cannot filter events, DApps cannot subscribe to events
Required: Bloom filter per block + topic/address index in storage
Effort:   1 week
```

#### Gap 10: Incomplete Error Propagation on Nested Reverts
```
Current:  Nested call reverts may truncate error strings
Impact:   Debugging multi-hop DeFi failures is difficult
Required: Full revert data propagation through call stack with RETURNDATACOPY
Effort:   2-3 days
```

---

## 3. Optimization Plan for 1M TPS on Consumer Hardware

### 3.1 Current Performance Baseline
```
VM Interpreter:     ~40-100M RISC-V instructions/second (single core)
Avg TX complexity:  ~200 instructions (simple transfer)
                    ~2000 instructions (DEX swap)
                    ~5000 instructions (complex DeFi)

Single-core TPS:    100M / 200 = 500K (simple), 50K (swap), 20K (DeFi)
8-core TPS:         4M (simple), 400K (swap), 160K (DeFi)

Bottleneck:         VM interpreter loop is the primary CPU bottleneck
```

### 3.2 Optimization 1: AOT/JIT Compilation (15-50x VM Speedup) — CRITICAL

**The single biggest TPS multiplier.**

#### Option A: AOT Compilation at Deploy Time (Recommended)
```
When:     At contract deployment (CREATE/CREATE2)
What:     Translate RISC-V basic blocks → native x86-64/ARM64 machine code
Cache:    Store compiled native code alongside bytecode in CodeStore
Execute:  On TX execution, jump directly to native code instead of interpret
Speedup:  15-50x (1 ns/instruction vs 15 ns/instruction)

Impact:   200 insn × 1 ns = 200 ns per simple TX → 5M TPS per core
          8 cores × 5M = 40M TPS for simple transfers
          Even DeFi: 5000 insn × 1 ns = 5 μs → 200K TPS/core → 1.6M TPS total
```

**Implementation strategy:**
```
Phase 1: Basic Block Identification
  - Walk bytecode, identify basic blocks (sequences between branches)
  - Build CFG (Control Flow Graph)
  
Phase 2: Code Generation (choose ONE backend)
  Option 1: Cranelift (Rust, battle-tested, used by Wasmer/Wasmtime)
    - Compile via C FFI to libcranelift
    - Pros: Production-grade, handles register allocation
    - Cons: External dependency, C FFI overhead
    
  Option 2: DynASM-style direct emission
    - Emit x86-64 machine code directly from Zig
    - Map RISC-V registers → x86-64 registers (RV has 16, x86 has 16 — 1:1)
    - Pros: Zero dependencies, fastest possible compilation
    - Cons: More complex, x86-64 only initially
    
  Option 3: LLVM backend
    - Generate LLVM IR → native via LLVM JIT (ORC)
    - Pros: Maximum optimization, cross-platform
    - Cons: Large dependency, compilation latency
    
RECOMMENDED: Option 2 (DynASM-style) for initial 15x gain, then Option 3 for peak perf

Phase 3: Gas Metering in Native Code
  - Insert gas checks at basic block boundaries (not per-instruction)
  - Pre-compute gas cost per basic block
  - Single branch: if (gas_remaining < block_cost) trap();
  
Phase 4: Syscall Bridge
  - ECALL instructions → call into host via function pointer table
  - Zero copying: pass guest memory pointers directly to host handlers
```

#### Option B: Tiered JIT (Interpret First, JIT Hot Paths)
```
Tier 0: Interpret all code (current behavior)
Tier 1: After 100 executions, compile with simple register allocator (5x speedup)
Tier 2: After 1000 executions, compile with full optimizations (15-50x speedup)

Best for: Long-running contracts executed millions of times (DEX routers, AMMs)
```

### 3.3 Optimization 2: VM Instance Pool Optimization (Already Done, Refine)
```
Current:  vm_pool.zig pre-allocates sandbox memory buffers
Refine:   
  - Pool compiled native code segments (avoid re-compilation)
  - Warm the JIT cache: keep top-100 hot contracts pre-compiled in memory
  - NUMA-aware allocation: pin VM instances to specific CPU cores
```

### 3.4 Optimization 3: Interpreter Fast-Path Optimizations (2-3x, No JIT Required)
```
Technique 1: Threaded Interpretation (computed goto)
  - Replace switch(opcode) dispatch with computed goto table
  - Eliminates branch prediction misses on opcode dispatch
  - Zig @call(.always_tail, ...) for tail-call dispatch
  - Speedup: 1.5-2x on modern CPUs

Technique 2: Super-instructions (pattern matching)
  - Common RISC-V patterns like LOAD+ADD+STORE → single "super-instruction"
  - Pre-scan bytecode at load time, replace common sequences
  - Speedup: 1.3-1.5x for arithmetic-heavy contracts

Technique 3: Register pinning
  - Pin RISC-V x10-x15 (syscall registers) to x86 callee-saved registers
  - Avoid memory loads for hot registers on every instruction
  - Speedup: 1.2-1.5x

Technique 4: Branch prediction hints
  - Use @branchHint(.likely) on common decode paths (R-type, I-type)
  - Reduce pipeline stalls on instruction decode
  
Combined interpreter speedup: 2-3x → ~100-300M insn/sec without JIT
```

### 3.5 Optimization 4: Parallel Gas Pre-Validation
```
Current:  Gas is checked per-instruction in the hot loop
Optimize: Pre-compute gas cost for entire basic block at load time
          Only check gas at block boundaries (every ~5-10 instructions)
          Reduces gas overhead from 15ns/insn to ~3ns/insn amortized
```

### 3.6 Optimization 5: SIMD String Operations in SDK
```
Current:  ABI encoding/decoding uses byte-by-byte operations
Optimize: Use @Vector(32, u8) for:
  - Keccak256 input padding
  - ABI calldata copies (32-byte words)
  - Memory clearing between TXs
  - StorageMapping key derivation batch hashing
Speedup:  2-4x for ABI-heavy contracts
```

### 3.7 Optimization 6: Zero-Copy Syscall Bridge
```
Current:  Syscalls copy data between guest memory and host buffers
Optimize: For SLOAD/SSTORE, pass direct pointers into sandbox backing array
          Guest memory is already in host address space (no protection ring boundary)
          Eliminates memcpy on every storage operation
Speedup:  1.2-1.5x for storage-heavy contracts
```

---

## 4. SDK Production Completeness Checklist

### Standard Contract Patterns Needed
| Pattern | SDK Support | Missing |
|---|---|---|
| ERC-20 Token | ✅ Complete | — |
| ERC-721 NFT | ✅ Complete | — |
| ERC-1155 Multi-Token | ⚠️ Partial | Batch transfer, approval for all |
| Upgradeable Proxy (EIP-1967) | ❌ Missing | Needs DELEGATECALL + storage slots |
| Minimal Proxy Clone (EIP-1167) | ❌ Missing | Needs CREATE2 |
| Access Control (Roles) | ⚠️ Started | OpenZeppelin AccessControl port |
| Timelock Controller | ❌ Missing | Needs block.timestamp + mapping |
| Governor / DAO | ❌ Missing | Needs proposal + voting + timelock |
| Flash Loans (EIP-3156) | ❌ Missing | Needs TLOAD/TSTORE for re-entrancy |
| AMM / DEX Router | ⚠️ Partial | Cross-contract calls work, needs CREATE2 for pair factory |
| Staking Vault (ERC-4626) | ❌ Missing | Needs share/asset math |
| Multisig Wallet | ⚠️ Partial | Needs real ECRECOVER |
| Permit2 (Uniswap) | ❌ Missing | Needs real ECRECOVER + EIP-712 |

### SDK Developer Experience Gaps
| Feature | Status | Required For |
|---|---|---|
| Contract testing framework | ✅ `testing.zig` | Unit testing |
| Gas estimation API | ✅ `eth_estimateGas` with VM sim | Deployment UX |
| Source-level debugging | ❌ Missing | Developer adoption |
| Contract verification | ❌ Missing | Explorer integration |
| ABI export to JSON | ⚠️ Manual | Tooling interop |
| Event subscription | ❌ Missing | DApp development |
| Hardhat/Foundry compatibility | ❌ Missing | Existing ecosystem |
| TypeScript SDK bindings | ❌ Missing | Frontend integration |

---

## 5. Priority Implementation Order

### Sprint 1 (Week 1-2): Ship-Blockers
1. **Real ECRECOVER** — secp256k1 point recovery in dispatch.zig
2. **CREATE2** — salt-based deployment syscall
3. **TLOAD/TSTORE** — transient storage for re-entrancy guards
4. **Call depth tracking** — max 1024 depth enforcement

### Sprint 2 (Week 3-4): VM Performance
5. **Threaded interpreter** — computed goto dispatch (2x)
6. **Basic block gas pre-computation** — amortized gas checks
7. **Super-instructions** — common pattern collapsing
8. **Register pinning** — hot registers in x86 callee-saved

### Sprint 3 (Week 5-8): AOT Compiler
9. **Basic block identification** + CFG construction
10. **x86-64 code emission** — DynASM-style direct emission
11. **Native gas metering** — per-block-boundary checks
12. **Compiled code cache** — per-contract address in CodeStore

### Sprint 4 (Week 9-10): SDK Completeness
13. **ERC-1155** complete implementation
14. **Upgradeable Proxy** (EIP-1967) pattern
15. **Minimal Proxy Clone** (EIP-1167) + factory
16. **Flash Loan** (EIP-3156) standard
17. **ERC-4626** vault standard

### Sprint 5 (Week 11-12): Production Hardening
18. **BLS12-381 precompiles** via BLST library
19. **Event log indexing** + bloom filters
20. **Source mapping** for debugging
21. **Full revert data propagation**

---

## 6. TPS Impact Summary

| Optimization | Speedup | TPS Impact (8 cores) | Effort |
|---|---|---|---|
| Current baseline | 1x | ~400K (simple) | — |
| Threaded interpreter | 2x | 800K | 1 week |
| Super-instructions | 1.3x | 1M | 3 days |
| Basic block gas | 1.2x | 1.2M | 2 days |
| Register pinning | 1.2x | 1.4M | 3 days |
| AOT compilation | 15x | **6M+** | 4 weeks |
| Zero-copy syscalls | 1.3x | **8M+** | 3 days |

**Conservative target with interpreter optimizations only: 1-1.5M TPS**
**With AOT compilation: 6-10M TPS for simple transfers**
