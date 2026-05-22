# RISC-V 64-bit Blockchain Execution Engine: EVM Decoupling and Architecture Redesign

This document presents a deep-dive research analysis of the current virtual machine (`vm/`) and node integration state, identifying EVM/Ethereum concepts that leak into the design, explaining why they are unsuitable for a high-performance RISC-V 64-bit execution engine, and detailing the architectural changes required to decouple them.

---

## 1. Analysis of EVM/Ethereum Leaked Concepts

An inspection of the codebase reveals several areas where Ethereum/EVM-specific structures, constants, and naming conventions have leaked into the system.

### A. Gas Metering and Refund Structure (`vm/gas/`)
* **Current State**: 
  - `vm/gas/table.zig` explicitly references EIP-2929 style warm/cold access costs and EVM Shanghai costs for storage operations.
  - `vm/gas/meter.zig` and the core `GasMeter` implement an EIP-3529 style gas refund model where refunds are accumulated (e.g., from `SSTORE` clears) and capped at $1/5$ of the total gas used (`effectiveGasUsed = used - min(refund, used / 5)`).
  - `src/core/dag_executor.zig` replicates the exact same $1/5$ gas refund logic at the transaction completion boundary.
* **Why It is Unsuitable**: 
  - EVM gas costs are calibrated for a 256-bit stack machine running on a single CPU thread. For a register-based RV64IM (64-bit) architecture, instruction cost should reflect physical CPU cycles and hardware instruction execution complexity, not Ethereum's state economics.
  - EVM-style state-clearing refunds add transaction-level state dependency, which complicates parallel out-of-order merging and makes execution profiling non-deterministic.

### B. Address Space and Contract Derivation (`src/vm/riscv/mod.zig`)
* **Current State**:
  - The node uses a 20-byte address format (`[20]u8` or `types.Address`).
  - Standard deployment (`CREATE_CONTRACT` / 0x43) derives contract addresses using `keccak256(RLP([sender, nonce]))[12..32]`.
  - Salt-based deployment (`CREATE2_CONTRACT` / 0x44) derives deterministic contract addresses using EIP-1014: `keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]`.
* **Why It is Unsuitable**:
  - Truncating 32-byte hashes to 20-byte Ethereum-aligned addresses increases the risk of hash collisions and lacks the namespace security required for modern high-throughput execution engines.
  - Derivation via RLP and Keccak256 introduces legacy cryptographic dependency, whereas modern performance-focused engines standardise on 32-byte addresses derived natively from faster hash functions (such as BLAKE3).

### C. Signature Schemes, Recovery, and Replay Protection (`src/core/`)
* **Current State**:
  - `src/core/security.zig` implements Ethereum-style signature malleability rules (constraining $s$ to the lower half of the secp256k1 order: $s \le N/2$) and EIP-155 replay protection using $v = \text{chainId} \times 2 + 35 + \text{recovery\_id}$.
  - `src/vm/riscv/mod.zig` exposes an `ecrecoverFn` provider mapping secp256k1 ECDSA signature recovery directly to retrieve the transaction sender address.
* **Why It is Unsuitable**:
  - secp256k1 signature verification is slow and lacks native batch-verification optimizations.
  - Replay protection bound to EIP-155 format assumes an Ethereum transaction envelope structure, forcing the node to carry over variable-length field decoding (like RLP) and Ethereum-specific transaction fields.

### D. Serialization / Transaction Envelopes (`src/core/rlp/`)
* **Current State**:
  - Transaction payloads are encoded and decoded using Recursive Length Prefix (RLP) serialization.
* **Why It is Unsuitable**:
  - RLP is a variable-length prefix-based format. Offsets within an RLP-serialized byte stream cannot be computed without sequentially scanning all preceding items. This introduces a major CPU bottleneck, preventing SIMD vectorization and parallel transaction decoding at ingestion.

### E. Call Stack and Depth Limits (`vm/core/executor.zig`)
* **Current State**:
  - The VM enforces an arbitrary call depth limit of 1024 (`callDepth` / `maxCallDepth`).
* **Why It is Unsuitable**:
  - The 1024 call depth limit in EVM is a workaround for EVM stack frames and gas tracking bugs. A native RISC-V 64-bit engine should limit recursive depth based on real physical stack size and gas limits, avoiding hardcoded magic numbers.

---

## 2. Redesign Proposal: A Complete Novel RISC-V 64-bit Execution Engine

To achieve the user's requirement of a completely novel, decoupled, and production-grade RV64IM execution engine, the following architectural redesign is proposed:

### 1. Unified 32-byte Address Space and BLAKE3 Derivation
* **Redesign**: Replace all 20-byte address types with a standard 32-byte address space (`[32]u8`).
* **Address Derivation**: 
  - Standard deployment: Derive contract address as `blake3(sender_address || sender_nonce)`.
  - Deterministic deployment (equivalent to CREATE2): Derive address as `blake3(0xFF || sender_address || salt || blake3(initcode))`.
* **Benefit**: Standardizes the system on BLAKE3 (which is significantly faster than Keccak256) and increases address entropy to eliminate address collisions.

### 2. Hardware-Calibrated Cycle Gas Model
* **Redesign**: Replace EIP-2929/Shanghai-based gas models with a strict CPU-cycle-based cost model:
  - Base ALU operations (ADD, SUB, AND, OR, etc.) cost 1 cycle-gas.
  - Multiplication/division operations (MUL, DIV, REM) cost cycle-gas relative to execution latency on standard RV64IM hardware implementations.
  - Storage and FFI host-access costs should scale linearly with memory/disk read/write latencies (calibrated via benchmark micro-seconds), with no concept of warm/cold storage flags in the interpreter.
  - Remove all EIP-3529 gas refunds. State reclamation should either be free or carry a flat incentive, rather than dynamic transaction-level gas refunds.

### 3. Ed25519 / BLS12-381 Native Signature Verification
* **Redesign**: Transition transaction signatures from secp256k1 to Ed25519 (for EOA transactions) and BLS12-381 (for validator-signed payloads).
* **Benefit**: Allows the node to use SIMD instruction sets to verify transaction signatures in batch at ingress, bypassing the slow, malleability-constrained ECDSA ecrecover pipeline.

### 4. Cache-Aligned Fixed-Width Binary Serialization
* **Redesign**: Deprecate RLP for transaction serialization. Instead, use a fixed-width binary layout:
  ```
  +-----------------------------------------------------------+
  | Sender (32B) | Target (32B) | Value (32B) | GasLimit (8B) |
  +-----------------------------------------------------------+
  | GasPrice (8B)| Nonce (8B)   | Signature (64B)             |
  +-----------------------------------------------------------+
  | Calldata Length (4B) | Calldata (Variable bytes...)       |
  +-----------------------------------------------------------+
  ```
* **Benefit**: Allows the network ingress poller to perform zero-copy deserialization by casting bytes directly to struct pointers, eliminating parsing overhead and supporting out-of-order signature verification.

### 5. Native Stack Frame and Memory Management
* **Redesign**: Eliminate the 1024 call depth check. The VM should instead allocate a contiguous stack memory region and track stack pointer overflows natively. If a contract exhausts its gas or registers, execution terminates.

---

## 3. Phased Decoupling Strategy

To transition our codebase while ensuring correctness and continuous operation, we will execute the decoupling in two main phases:

### Phase A: Short-Term Correctness & Routing Integration (Active Plan)
We will immediately proceed with fixing the correctness issues identified in the current integration:
1. **Fix EOA Address Hijacking**: Update the `VMCallback` signature and `executeCallback` to accept both `selfAddress` (the contract being executed) and `caller` (the msg.sender).
2. **Wire State Bridges**: Map transient storage (`TRANSIENT_LOAD` / `TRANSIENT_STORE`), derived storage (`STORAGE_LOAD_DERIVED` / `STORAGE_STORE_DERIVED`), and global storage (`STORAGE_LOAD_GLOBAL` / `STORAGE_STORE_GLOBAL`) to their respective handlers.
3. **Route Lane Queues**: Ensure that `deltaQueue` and `receiptQueue` are correctly routed through the VM callbacks to active execution lanes in the DAG executor.

### Phase B: EVM Decoupling and Redesign Execution
Following the correctness fixes, we will systematically replace EVM-specific logic:
1. **Refactor Gas**: Redesign `vm/gas/meter.zig` and `vm/gas/table.zig` to eliminate EIP-2929/EIP-3529 references, implementing a pure cycle-gas metric.
2. **Deprecate RLP**: Replace RLP decoding in `tx_decode.zig` with the fixed-width binary transaction layout.
3. **Migrate Addresses**: Transition from 20-byte addresses to 32-byte BLAKE3-derived address spaces.
4. **Transition Signatures**: Replace secp256k1 recovery with native Ed25519/BLS signature verification.
