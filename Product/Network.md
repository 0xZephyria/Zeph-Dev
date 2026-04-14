# Zephyria Network Protocol — 1M+ TPS on Consumer Hardware with Linear Scaling

> **Scope**: This document is a fresh, independent architecture plan for the Zephyria network layer. It addresses the three hard constraints simultaneously: **1,000,000+ TPS**, **consumer-grade hardware** (16-core CPU, 32 GB RAM, 10 Gbps NIC, NVMe SSD), and a **large, permissionless validator set** (thousands of validators, not 20–100).

---

## 1. The Three Constraints That Fight Each Other

Most blockchain designs optimize for at most two of these three properties. Zephyria must solve all three on a single L1 without rollups or L2 delegation.

| Constraint | Why It's Hard | Current Code Gap |
|:-----------|:-------------|:-----------------|
| **1M+ TPS execution** | 1 tx/μs sustained — requires zero-conflict parallel execution + pipelined block production | DAG executor works but state root commit is synchronous; blocks the pipeline |
| **Consumer hardware** | 10 Gbps NIC = ~1.16 GB/s raw. A 1M-tx block is ~150 MB. Gossip to 1000 peers = 150 TB/s — physically impossible. | Turbine shredding exists but is not wired as primary propagation; gossip is still default |
| **Thousands of validators** | Traditional BFT has O(N²) message complexity. At N=1000, that's 1 million messages per round. | `max_validators: u32 = 100` hard-coded in `EpochConfig`. Round-robin leader schedule. No committee structure. |

**The core insight**: You cannot have 1000 validators all directly voting on every block at 1M TPS. The communication and aggregation overhead will crush throughput. The solution is **hierarchical committee consensus with BLS aggregation**, where only a small rotating committee produces and finalizes each block, while the full validator set provides economic security through staking and periodic committee rotation.

---

## 2. Validator Architecture: Committees + Subnets

### 2.1 The Ethereum Lesson

Ethereum runs ~900,000 validators by:
- Splitting validators into **committees of 128** per slot
- Using **BLS signature aggregation** to compress thousands of attestations into one 96-byte aggregate signature
- Rotating committee assignments every **epoch** (6.4 minutes)
- Using 64 **attestation subnets** for gossip partitioning

Ethereum achieves this for ~15 TPS. Zephyria must replicate this committee structure but tune it for 1M TPS block production.

### 2.2 Zephyria Committee Design

**Total Validators**: Unbounded (target: 1,000–100,000+)

**Active Committee per Slot**: 256 validators (randomly sampled, stake-weighted)

**Committee Roles**:

| Role | Count | Responsibility |
|:-----|:------|:--------------|
| **Block Producer** | 1 | Builds the block from DAG mempool, shreds it via Turbine |
| **Attestation Committee** | 255 | Receives shreds, reconstructs block, verifies execution, signs attestation |
| **Aggregators** | 16 (within the 256) | Collect attestations within their subnet, produce aggregate BLS signatures |
| **Full Validator Set** | All staked | Economically secures the chain. Rotates into committees every epoch. |

**Why 256?** At 256 committee members:
- BFT threshold = 171 signatures (2/3 + 1)
- 16 aggregation subnets × 16 validators each = 256 attestations compressed into 16 aggregate signatures → compressed into 1 final aggregate
- O(N) message complexity for committee members (each sends 1 attestation to their subnet aggregator)
- Security: Corrupting the committee requires controlling >1/3 of 256 randomly-sampled validators from a pool of thousands. With 10,000 total validators and an adversary controlling 33%, probability of corrupting a single committee ≈ 10⁻¹⁵

### 2.3 Committee Rotation

```
Epoch = 2048 blocks (~34 minutes at 1 block/s)

At each epoch boundary:
  1. Compute epoch_seed = VRF(prev_epoch_seed, epoch_number, proposer_key)
  2. Shuffle full validator list using Fisher-Yates with epoch_seed as PRNG
  3. Slice shuffled list into committees of 256
  4. Each slot within the epoch maps to one committee
  5. Within each committee, block producer = VRF(epoch_seed, slot_number)
```

**Key properties**:
- Validator assignments are unpredictable before epoch_seed is revealed (VRF output)
- Every validator participates in exactly `ceil(epoch_slots / num_committees)` committees per epoch
- Committee membership is deterministic given the seed — any node can verify independently
- No single entity can predict or bias committee selection

### 2.4 Changes Required to Current Code

| File | Change |
|:-----|:-------|
| `consensus/zelius.zig` | Remove `max_validators: u32 = 100`. Add `CommitteeConfig` with `committee_size: u32 = 256`, `aggregation_subnets: u32 = 16`. Add `selectCommittee(epoch_seed, slot) -> []ValidatorInfo` |
| `consensus/pipeline.zig` | `Proposal.vote_bitmap` must support 256-bit bitmap (currently `u256` — this already works). Add `aggregate_signatures: [16][96]u8` field for subnet aggregates |
| `consensus/staking.zig` | Remove artificial caps. Add `getFullValidatorSet() -> []Validator` sorted by stake. Add `shuffleForEpoch(seed) -> [][]Validator` returning committee assignments |
| `consensus/vrf.zig` | Already has `check_eligibility`. Add `selectProposer(committee: []ValidatorInfo, seed: [32]u8, slot: u64) -> ValidatorInfo` |

---

## 3. Consensus Protocol: Pipelined HotStuff with BLS Aggregation

### 3.1 Why Not Current Design

The current Zelius consensus is a simple propose → vote → finalize pipeline with direct vote counting. This has several problems at scale:

1. **No view synchronization** — validators can diverge on which block to vote for
2. **No signature aggregation** — each vote is processed individually
3. **No pipelining** — block N must finalize before block N+1 can be proposed
4. **Round-robin leader** — predictable, DDoS-vulnerable

### 3.2 Pipelined Two-Phase HotStuff

Adopt a pipelined variant of HotStuff-2 (two phases instead of three):

```
Slot S:
  Producer P(S) proposes Block B(S)
  Committee votes on B(S) → produces QC(S) (Quorum Certificate = aggregate BLS sig)

Slot S+1:
  Producer P(S+1) proposes Block B(S+1) referencing QC(S)
  Block B(S-1) becomes FINALIZED when QC(S) is included in B(S+1)
  (Two consecutive QCs = finality)
```

**Finality latency**: 2 slots = ~2 seconds (with 1-second slot time)

**Properties**:
- **Optimistic responsiveness**: Proceeds as fast as the network allows, not waiting for timeouts
- **Linear message complexity**: Each validator sends exactly 1 attestation per slot to their subnet aggregator
- **Pipelined**: Block N+1 is proposed while Block N is being attested. No idle time.
- **BLS aggregation**: 256 attestations → 16 subnet aggregates → 1 final QC (96 bytes)

### 3.3 Quorum Certificate (QC) Structure

```zig
pub const QuorumCertificate = struct {
    block_hash: Hash,
    block_number: u64,
    aggregate_signature: [96]u8,       // Final aggregate BLS signature
    participation_bitmap: [32]u8,       // 256-bit bitmap: which committee members signed
    committee_epoch: u64,               // Epoch that selected this committee
    proposer_vrf_proof: [48]u8,         // Proves this proposer was legitimately selected
};
```

A QC is valid if:
1. `popcount(participation_bitmap) >= 171` (2/3 + 1 of 256)
2. `aggregate_signature` verifies against the public keys indicated by the bitmap
3. `proposer_vrf_proof` proves the block producer was selected by the VRF for this slot

### 3.4 View Change (Leader Failure)

If the committee doesn't receive a valid proposal within `slot_timeout` (default 4s):

1. Each committee member broadcasts a `ViewChange(slot, highest_QC_seen)` to their subnet
2. Aggregators collect ViewChange messages. At 171+ ViewChanges → produce `ViewChangeQC`
3. Next leader in VRF sequence takes over, includes `ViewChangeQC` in their proposal
4. Exponential backoff: timeout doubles on each consecutive failure (`4s → 8s → 16s → ...`), resets on successful block

---

## 4. Block Propagation: Turbine Tree with Erasure Coding

### 4.1 The Bandwidth Problem

**Hard math**:
- 1M transactions × ~150 bytes/tx = **150 MB per block**
- Consumer NIC: 10 Gbps = **1.16 GB/s**
- If the block producer gossips to 1000 validators directly: needs 150 GB/s outbound → **impossible**

**Solution**: Turbine tree propagation with Reed-Solomon erasure coding.

### 4.2 Turbine Protocol (Production Design)

```
Block (150 MB) → Shredder → 2048 data shreds + 512 parity shreds (each ~75 KB)

Propagation Tree (fanout = 32):
  Layer 0: Producer sends 80 unique shreds to each of 32 Layer-1 nodes
  Layer 1: Each Layer-1 node forwards its shreds to 32 Layer-2 nodes
  Layer 2: 32 × 32 = 1024 nodes — covers entire committee + observers

Bandwidth per node:
  Layer 0 (producer):   80 shreds × 32 peers × 75 KB = 192 MB outbound
  Layer 1 (relayer):    80 shreds × 32 peers × 75 KB = 192 MB outbound
  Layer 2 (receiver):   80 shreds × 75 KB = 5.9 MB inbound

  All within 10 Gbps NIC budget (1.16 GB/s)
```

**Reed-Solomon recovery**: Any node that receives ≥2048 of 2560 total shreds (data + parity) can reconstruct the full block. This tolerates **20% packet loss** without retransmission.

### 4.3 Changes Required

| File | Change |
|:-----|:-------|
| `p2p/turbine.zig` | Replace XOR parity with proper Reed-Solomon (GF(2⁸) field arithmetic). Increase `data_shreds` and `parity_shreds` to scale with block size. Add `PropagationTree` struct with stake-weighted assignment. |
| `p2p/server.zig` | Make Turbine the **primary** block propagation path. Remove gossip-based block relay entirely. Attestations (96 bytes each) can still use direct QUIC messaging. |
| `p2p/gulf_stream.zig` | Increase `batch_size` from 256 to 4096. Add transaction batching with compression (snappy/lz4). Transactions are small — Gulf Stream remains efficient for TX forwarding. |

### 4.4 Linear Scaling Property

As bandwidth increases (10 Gbps → 25 Gbps → 100 Gbps), the system scales linearly:

| NIC Speed | Max Block Size | Max TPS (150 byte txs) |
|:----------|:--------------|:-----------------------|
| 1 Gbps | 15 MB | ~100K |
| 10 Gbps | 150 MB | ~1M |
| 25 Gbps | 375 MB | ~2.5M |
| 100 Gbps | 1.5 GB | ~10M |

No protocol changes needed — just increase shred count proportionally. This is the **linear scaling** guarantee.

---

## 5. Execution Pipeline: Achieving 1M TPS on 16 Cores

### 5.1 Transaction Processing Pipeline (Tile Architecture)

To sustain 1M TPS, the node must process transactions in a pipelined fashion where no single stage is the bottleneck. Each "tile" runs on its own CPU core(s):

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  QUIC    │──▶│  Verify  │──▶│  Dedup   │──▶│ Schedule │──▶│ Execute  │──▶│  Commit  │
│  Ingress │   │  Sigs    │   │  + DAG   │   │  Lanes   │   │  Parallel│   │  State   │
│  (2 core)│   │  (2 core)│   │  (1 core)│   │  (1 core)│   │  (8 core)│   │  (2 core)│
└──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
     │                                                                           │
     │              ┌──────────┐   ┌──────────┐                                  │
     │              │ Turbine  │──▶│  Attest  │                                  │
     └─────────────▶│ Broadcast│   │  + QC    │◀─────────────────────────────────┘
                    │  (1 core)│   │  (1 core)│
                    └──────────┘   └──────────┘
```

**16 cores total** — fits on consumer hardware (Ryzen 7/9, Apple M3 Pro+, Intel i7-14th gen)

### 5.2 Per-Tile Throughput Budget

| Tile | Throughput Target | Bottleneck | Solution |
|:-----|:-----------------|:-----------|:---------|
| **QUIC Ingress** | 2M pkt/s | Kernel syscall overhead | `io_uring` batch recv (Linux) or `kqueue` batch (macOS), `sendmmsg`/`recvmmsg` |
| **Signature Verify** | 500K sigs/s | Ed25519 verification | Batch verification (64 sigs at once), SIMD (AVX2/NEON), 2 cores = 1M/s |
| **Dedup + DAG Insert** | 2M tx/s | Bloom filter + hash map | 256-shard DAG mempool already handles this. Bloom filter reset every epoch. |
| **Schedule** | 1.5M tx/s | Lane assignment | Per-sender lanes + O(n log n) sort by gas. Already implemented. |
| **Execute** | 1M tx/s | VM execution | 8 cores × ~125K tx/core/s. Simple transfers: ~130ns each. Contract calls: 500ns–1μs. Average workload achieves budget. |
| **Commit** | 1M state ops/s | Verkle trie hashing | **Async pipeline**: Block N executes while Block N-1's state root is hashed in background. |
| **Turbine** | 1 block/s | Shredding + RS encoding | Single core can shred 150 MB + encode parity in ~200ms |
| **Attest** | 256 attestations/s | BLS aggregation | 16 subnet aggregations × BLS aggregate (~0.5ms each) = 8ms total |

### 5.3 Asynchronous State Root Pipeline

**The critical optimization** the current code is missing. State root computation is the #1 bottleneck.

```
Block N:   [Execute] ────▶ [Deltas to ZephyrDB] ────▶ [Done, start N+1]
                                    │
                                    ▼ (background thread)
                            [Verkle Root Hash] ────▶ [Root available]
                                                          │
Block N+2: ◀──── [Includes state_root of Block N] ────────┘
```

**Block header commits to `state_root(N-2)`** (two blocks behind). This gives the background hasher 2 full block times (~2 seconds) to compute the Verkle root without blocking the execution pipeline.

### 5.4 Changes Required

| File | Change |
|:-----|:-------|
| `core/dag_executor.zig` | Split Phase 3 (commit) into two stages: (a) fast delta flush to ZephyrDB, (b) async Verkle root computation on separate thread. Return `BlockResult` immediately after (a). |
| `core/types.zig` | Add `state_root_height: u64` to `Header` — indicates which block's state this root corresponds to. Validators verify `state_root == computed_root(state_root_height)`. |
| `core/block_producer.zig` | Pipeline: while executing Block N, use the state root from Block N-2. Builder no longer waits for state root. |
| `storage/zephyrdb/mod.zig` | Add concurrent-safe `flushDeltas(deltas: []Delta)` using striped locks (16 stripes keyed by `hash(account_key) % 16`). Eliminates lock contention during merge. |

---

## 6. Network I/O: Kernel Bypass for Consumer Hardware

### 6.1 The Syscall Problem

Standard `recvfrom()`/`sendto()` costs ~2–5μs per syscall (kernel context switch). At 1M packets/s, that's 2–5 seconds of CPU time just on syscalls — impossible.

### 6.2 Tiered I/O Strategy

Consumer hardware doesn't have SR-IOV or DPDK-capable NICs. The solution must work on standard hardware:

**Linux (primary target)**:
- **`io_uring`** for all socket I/O — batches syscalls, achieves 2–5M operations/s per core
- **`sendmmsg`/`recvmmsg`** as fallback — sends/receives up to 1024 packets per syscall
- **`SO_BUSY_POLL`** — eliminates interrupt latency for hot sockets

**macOS (development target)**:
- **`kqueue`** batch mode with `kevent64` for async I/O
- **GCD dispatch sources** for parallel packet processing

**AF_XDP (optional, Linux 5.4+)**:
- For validators with XDP-capable NICs, enables full kernel bypass
- Packets delivered directly to userspace ring buffer — zero syscall overhead
- **Not required** for 1M TPS at 10 Gbps, but enables 10M+ TPS on 100 Gbps hardware

### 6.3 Changes Required

| File | Change |
|:-----|:-------|
| `p2p/server.zig` | Replace single-threaded `recvfrom` loop with `io_uring` submission queue (Linux) or `kqueue` (macOS). Batch packet processing: dequeue up to 256 packets per iteration. |
| `storage/lsm/io.zig` | Complete the `io_uring` engine TODO at line 180. Wire into ZephyrDB WAL flush path. |
| `p2p/server.zig` | Increase thread pool from 4 to configurable (default: `num_cpus / 2` for I/O tiles). |

---

## 7. DDoS Resistance with Large Validator Set

### 7.1 The Problem is Harder with Thousands of Validators

With 100 validators, you can maintain persistent authenticated connections. With 10,000 validators, maintaining 10,000 QUIC connections is infeasible — each connection costs ~10 KB of state.

### 7.2 Layered Defense Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 0: XDP/eBPF (NIC-level, optional)                         │
│   Drop packets with unknown QUIC connection IDs in nanoseconds  │
├─────────────────────────────────────────────────────────────────┤
│ Layer 1: Connection Budget (userspace)                          │
│   Max 512 persistent QUIC connections per node                  │
│   Priority: current committee > same-subnet validators > peers  │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Stake-Weighted Rate Limiting (userspace)               │
│   Token bucket per connection, refill rate ∝ sqrt(stake)        │
│   Committee members get 10× burst allowance during their slot   │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: RPC Relay Shield (infrastructure)                      │
│   Public users → RPC nodes → batched + signed → validator       │
│   Validators never accept direct public connections             │
└─────────────────────────────────────────────────────────────────┘
```

### 7.3 Subnet-Based Gossip

Instead of all-to-all gossip, validators are organized into **subnets**:

```
Attestation Subnets: 64 persistent subnets
  - Each validator subscribes to 2 subnets (randomly assigned per epoch)
  - Attestations propagate within subnet, then aggregated cross-subnet
  - Subnet gossip: each node connects to 8 peers in each subnet

Block Propagation: Turbine tree (not gossip-based)
  - Separate from attestation subnets
  - Tree structure rotates every slot based on committee assignment

Transaction Gossip: Gulf Stream (direct to predicted leader)
  - Not gossip-based — transactions go directly to the predicted leader
  - Backup: 2 next predicted leaders also receive copies
```

**Result**: Each validator maintains ~64 persistent connections (8 peers × 2 subnets + committee connections), not 10,000.

---

## 8. Economic Security Analysis

### 8.1 Security Bound with Committee-Based Consensus

The fundamental security question: **Is a committee of 256 as secure as the full validator set?**

**Assuming adversary controls `f` fraction of total stake**:

Probability of adversary controlling >1/3 of a random 256-member committee:

| Adversary Stake (f) | P(committee corruption) | Expected time to corrupt 1 committee |
|:---------------------|:------------------------|:--------------------------------------|
| 10% | ~10⁻⁴⁰ | Longer than the universe |
| 20% | ~10⁻¹⁵ | ~30 million years |
| 25% | ~10⁻⁸ | ~3 years |
| 30% | ~10⁻⁴ | ~10 minutes |
| 33% | ~10⁻¹ | Every ~10 slots |

**Conclusion**: With committee size 256, the system is secure against adversaries controlling up to ~25% of total stake — slightly below traditional BFT's 33% threshold. To recover the full 33% threshold, we can:
1. **Increase committee size to 512** (probability drops to ~10⁻⁸ at 30% adversary) at cost of slightly more attestation bandwidth
2. **Require two consecutive honest committees for finality** (already the case with 2-phase HotStuff)
3. **Implement fraud proofs** — if a finalized block is later proven fraudulent, the entire committee is slashed

### 8.2 Slashing and Accountability

Every committee member's attestation is individually identifiable via the participation bitmap + BLS public keys:

- **Equivocation (double-signing)**: Automatic 100% stake slash + tombstone. Evidence: two conflicting signed attestations.
- **Inactivity leak**: If a validator misses >50% of their assigned committee slots in an epoch, their stake is gradually drained (1% per epoch of inactivity) until they exit or return.
- **Invalid block attestation**: If a committee finalizes an invalid block (provable via fraud proof), all attestors who signed are slashed 50%.

---

## 9. Linear Scaling Roadmap

### 9.1 Phase 1: Single-Shard 1M TPS (Current Architecture)

Everything described so far operates on a **single execution shard**. All 1M transactions are executed by every validator. This is the baseline that must ship first.

**Hardware budget**: 16-core CPU, 32 GB RAM, 10 Gbps NIC
**Target**: 1M TPS with 1000+ validators providing economic security

### 9.2 Phase 2: Execution Sharding (Linear Scaling)

Once Phase 1 is stable, introduce **execution shards** for linear scaling:

```
Shard 0: Accounts 0x0... – 0x3...
Shard 1: Accounts 0x4... – 0x7...
Shard 2: Accounts 0x8... – 0xB...
Shard 3: Accounts 0xC... – 0xF...

Each shard: independent committee, independent execution, independent state
Beacon chain: coordinates shard assignments, cross-shard receipts, finality
```

**Why this works with isolated accounts**: Zephyria's account model already isolates state by account address. Each storage cell is `hash(contract_root || slot)` — the first nibble deterministically maps to a shard. Cross-shard transactions use **receipt-based async messaging** (not synchronous calls):

1. TX on Shard 0 writes a "cross-shard receipt" to the beacon chain
2. Shard 2 picks up the receipt and processes it in the next block
3. Atomic cross-shard transactions require 2-block latency but maintain correctness

**Scaling math**:
- 4 shards × 1M TPS each = 4M TPS total
- 16 shards × 1M TPS each = 16M TPS total
- Each shard has its own committee of 256 validators
- Total validators needed: `num_shards × 256 × slots_per_epoch / total_slots_per_validator`

### 9.3 Phase 3: Data Availability Sampling (DAS)

For very large validator counts (100,000+), not every validator needs to download every shard's data. Introduce **DAS**:

- Validators randomly sample small chunks of each shard's block
- If enough random samples succeed, the block is probabilistically guaranteed to be available
- Reduces per-validator bandwidth from O(shards × block_size) to O(samples × chunk_size)
- Enables "light validators" that stake and attest without full execution — significantly lowering hardware requirements

---

## 10. Summary of Protocol Parameters

| Parameter | Value | Rationale |
|:----------|:------|:----------|
| Slot time | 1 second | Fits within 10 Gbps bandwidth for 150 MB blocks |
| Committee size | 256 | Security bound: >10⁻¹⁵ adversary success at 20% corruption |
| Aggregation subnets | 16 | 16 attestations per subnet → 16 aggregate sigs → 1 final QC |
| Finality | 2 slots (2 seconds) | Pipelined HotStuff-2: two consecutive QCs |
| Epoch length | 2048 blocks (~34 min) | Long enough for stable committees, short enough for rotation |
| Gossip subnets | 64 | Each validator subscribes to 2, connects to 8 peers per subnet |
| Max connections per node | ~512 | 64 subnet peers + committee + reserve |
| Turbine data shreds | 2048 | 150 MB / 75 KB per shred |
| Turbine parity shreds | 512 | 20% redundancy → tolerates 20% packet loss |
| Turbine fanout | 32 | 2 layers covers 1024 nodes |
| Execution cores | 8 | Sustains 1M TPS with DAG parallel lanes |
| State root lag | 2 blocks | Async Verkle hashing, non-blocking pipeline |
| VRF scheme | BLS-based (already implemented) | Unpredictable, unbiasable leader/committee selection |
| Signature scheme | BLS12-381 (already implemented) | Enables aggregation — critical for committee attestations |

---

## 11. Implementation Priority Order

| Priority | Component | Blocks What | Effort |
|:---------|:----------|:-----------|:-------|
| **P0** | Async state root pipeline | Everything — this is the #1 bottleneck | 1–2 weeks |
| **P0** | Committee selection + rotation in Zelius | Large validator support | 2–3 weeks |
| **P0** | BLS attestation aggregation (16-subnet) | Consensus at scale | 2–3 weeks |
| **P0** | Reed-Solomon erasure coding (replace XOR in Turbine) | Reliable block propagation | 1–2 weeks |
| **P1** | Pipelined HotStuff-2 consensus | Throughput + finality | 3–4 weeks |
| **P1** | `io_uring` socket I/O | Packet processing throughput | 2–3 weeks |
| **P1** | ZephyrDB striped locks / concurrent delta flush | Execution pipeline throughput | 1–2 weeks |
| **P2** | Subnet-based gossip topology | Network efficiency at 1000+ validators | 2–3 weeks |
| **P2** | Stake-weighted rate limiting + DDoS layering | Security at scale | 1–2 weeks |
| **P2** | Fraud proofs for invalid committee finalization | Economic security hardening | 3–4 weeks |
| **P3** | Execution sharding (Phase 2 linear scaling) | >1M TPS | 6–8 weeks |
| **P3** | Data availability sampling | Light validator support | 4–6 weeks |
