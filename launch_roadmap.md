# Launch Roadmap: Testnet to Mainnet Transition

This document outlines the essential protocol modifications, cryptographic upgrades, security enhancements, and operational requirements needed to transition the Zephyria codebase from a high-performance simulation to a production-grade decentralized Testnet, and eventually to a secure Mainnet launch.

---

## 1. Consensus & Cryptography (Protocol Safety)

### 🔴 BLS Signature Scheme Integration [Done]
* **Current State**: The pluggable signature verification in `src/core/signature.zig` returns `error.UnsupportedScheme` for BLS12-381 signatures, treating them as stubs.
* **Mainnet Requirement**: 
  - Fully integrate the `blst` C/assembly bindings into the `verify` routing path.
  - Implement aggregate signature verification on G2 fields so that multi-threaded committee votes can be verified in a single step during Phase 1/Phase 2 consensus.
  - Ensure defense against **rogue-key attacks** by requiring Proof-of-Possession (PoP) of private keys during validator registration.

### 🟡 Verifiable Delay Function (VDF) Algebraic Upgrade [Done]
* **Current State**: The VDF in `src/consensus/vdf.zig` relies on sequential SHA-256 hashing.
* **Gaps**: sequential hashing is CPU-intensive to verify ($O(N)$ CPU operations for the verifier, even when split into segment checkpoints).
* **Mainnet Requirement**: 
  - Transition to algebraic VDFs (e.g., **Pietrzak** or **Wesolowski** over RSA groups or class groups).
  - These allow $O(1)$ constant-time verification taking microseconds, preventing denial-of-service (DoS) attacks on nodes syncing block headers.

### 🟢 Post-Quantum Cryptography Migration (ML-DSA) [Future]
* **Current State**: Signatures default to Ed25519.
* **Mainnet Requirement**: 
  - Integrate NIST round-3 post-quantum algorithms (e.g., **ML-DSA** / Dilithium) into transaction signature layouts.
  - Define custom serialization to accommodate the larger public key and signature sizes in RLP blocks without creating large memory footprints.

---

## 2. P2P Networking & Transport (Loom Gossip)

### 🔴 Encrypted Transport Layer (QUIC + Noise/TLS)
* **Current State**: The QUIC transport subdirectory was pruned, and the node runs a basic UDP socket framework.
* **Mainnet Requirement**: 
  - Re-integrate **QUIC (RFC 9000)** as the primary transport protocol.
  - Secure all peer streams using **TLS 1.3** or the **Noise Protocol Framework (IK handshake)**.
  - Implement strict mutual authentication (mTLS) where connection certificates are tied directly to the peer's network identity keys.

### 🟡 Kademlia DHT Peer Discovery (discv5)
* **Current State**: Discovery relies on hardcoded addresses and mock bootstrap peer generation.
* **Mainnet Requirement**: 
  - Implement a standard Kademlia DHT protocol (like Ethereum's **discv5**).
  - Use signed ENRs (Ethereum Node Records) containing IP addresses, TCP/UDP ports, and cryptographic capabilities.
  - Prevent **eclipse attacks** by enforcing IP subnet diversity limits on the peer routing table.

### 🟢 Turbine Shredding & FEC Robustness
* **Current State**: Shred verifiers and Turbine structures are simplified.
* **Mainnet Requirement**: 
  - Integrate Reed-Solomon Forward Error Correction (FEC) with dynamic coding ratios based on network latency.
  - Implement missing shred retransmission protocols using a stratified parent-child tree routing algorithm to ensure block availability even under 30% random packet drop conditions.

---

## 3. Storage & Crash Consistency (ZephyrDB)

### 🔴 Write-Ahead Log (WAL) Synchronous Commit [Done]
* **Current State**: `HybridDB` uses an asynchronous worker thread to write to the persistent LSM database.
* **Gaps**: A node crash will result in the loss of all uncommitted writes sitting in the in-memory `queue`.
* **Mainnet Requirement**: 
  - Block commitments (Phase 3) must write block transaction effects to a physical WAL on disk using synchronous write flags (`O_SYNC` / `fsync`) **before** marking the block as finalized.
  - On restart, the storage engine must scan the WAL to recover any state changes that did not make it into the LSM SSTables.

### 🟡 State Pruning & Snap Sync
* **Current State**: Trie nodes and historic MMR blocks are appended without pruning.
* **Mainnet Requirement**: 
  - Implement epoch-based state pruning to remove historical Verkle trie commitments that are older than $N$ epochs.
  - Develop a **Snap Sync** protocol that allows joining nodes to download leaf state commitments directly from peers and verify them against the state root, avoiding executing blocks from genesis.

---

## 4. Transaction execution & Gas Economics

### 🔴 Dynamic Fee Market (EIP-1559)
* **Current State**: Core scheduler has base fees but lacks dynamic adjustment.
* **Mainnet Requirement**: 
  - Enforce a base fee that automatically scales up or down based on block utilization (gas target vs gas limit).
  - Implement fee burning where the base fee is burned, and validator priority tips are passed to block producers.

### 🟡 VM AOT Safety & Isolation
* **Current State**: ForgeVM compiles RISC-V bytecode into native shared libraries and executes them.
* **Gaps**: Rogue smart contracts could attempt sandbox escapes or perform illegal memory access inside the compiled binary.
* **Mainnet Requirement**: 
  - Enforce strict memory-limit checks on memory stores/loads during AOT compilation by embedding hardware-enforced guard pages or compile-time range checks.
  - Perform validation on the RISC-V bytecode (e.g. check for invalid jump destinations or unsafe instructions) before passing it to the AOT compiler.

---

## 5. Validator Governance & Slashing (Economic Security)

### 🔴 Validator Rotation & Staking Limits
* **Current State**: Validator sets are static per genesis parameters.
* **Mainnet Requirement**: 
  - Implement dynamic epoch transitions that calculate staking changes, validator entries, exits, and lock-up cooldowns.
  - Define minimum staking limits and reward curssves (inflation schedule) that adjust based on the total staked supply.

### 🟡 Automated Slashing & Fraud Proofs
* **Current State**: Slashing structures are present, but automated evidence collection is missing.
* **Mainnet Requirement**: 
  - Build automated double-voting and surround-voting detectors.
  - Validators must automatically broadcast slashing messages containing signatures of the offender to collect rewards and evict bad actors immediately.

---

## 6. Launch Sequence & Upgrades

| Phase | Milestone | Focus Areas | Exit Criteria |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Internal Devnet** | Cryptographic integration (BLS, Wesolowski VDF) & Crash-consistent WAL. | 100% test coverage; 50-node stable run for 48 hours. |
| **Phase 2** | **Public Testnet** | discv5 Discovery, QUIC Transport Encryption, ForgeVM Gas Tuning. | Stable block times under simulated spam; zero network partitions. |
| **Phase 3** | **Incentivized Testnet** | Attack simulations, validator rotation, live slashing drills. | Validation of staking rewards and exit queue handling. |
| **Phase 4** | **Mainnet Genesis** | Genesis block allocation, inflation curves, token distribution. | Cryptographic key ceremonies; official genesis launch. |
