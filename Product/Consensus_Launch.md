# Zephyria Adaptive Consensus — From 10 Validators to 10,000 (and Beyond)

> **Design Principle**: One protocol whose internal parameters self-tune based on validator count. No hard forks, no manual reconfiguration. The same binary at epoch 1 (10 validators) and epoch 10,000 (10K validators) — with a clean upgrade path to full Loom threading at 100K.

---

## 1. Why Loom Can't Launch As-Is

The Loom design (Consensus.md) targets **100K validators** with:
- ~100 VRF-selected weavers per thread × 10 threads = 1,000 weavers/slot
- ~1,000 attestors for Snowball finality  
- Statistical security via random sampling from a massive pool

At **10–50 validators**, these numbers are physically impossible:

| Loom Role | Required | Available at 10 Validators | Available at 50 |
|:----------|:---------|:--------------------------|:----------------|
| Weavers (per thread) | ~100 | 10 total for ALL roles | 50 total |
| Attestors | ~1000 | Impossible | Impossible |
| Snowball k=20 | 20 peers/round | Can't even sample 20 | Barely possible |

**The sampling amplification that makes Loom safe at 100K simply doesn't exist at 10–50 nodes.** We need a protocol that achieves the same security guarantees through different mechanisms at small scale, then smoothly transitions to Loom mechanisms as the validator set grows.

---

## 2. The Adaptive Consensus Protocol: "Loom Genesis"

### 2.1 Core Idea: Three Tiers, One Protocol

Instead of designing a separate "starter protocol" and later migrating, Loom Genesis is **one protocol with three operating tiers** selected automatically per-epoch based on `N` (active validator count):

| Tier | Validators (N) | Consensus Mode | Threads | How Security Works |
|:-----|:--------------|:---------------|:--------|:-------------------|
| **Tier 1: Full BFT** | N ≤ 100 | All-to-all BLS voting | 1–2 | Every node verifies everything. Classical BFT safety. |
| **Tier 2: Committee Loom** | 100 < N ≤ 2,000 | Fixed committees + BLS voting | 2–5 | Committees large enough for statistical safety. VRF begins. |
| **Tier 3: Full Loom** | N > 2,000 | Full VRF sortition + Snowball | 5–100+ | Statistical sampling provides extreme security. |

**Tier transitions are automatic.** At the start of each epoch, the protocol evaluates `N` and selects the operating tier. No governance vote. No hard fork. The binary contains all three tiers.

### 2.2 Why This Works

- **Tier 1** (10–100 validators): Classical BFT has been proven secure for decades (PBFT, Tendermint, HotStuff). With ≤100 nodes, all-to-all communication is trivially cheap — even 100 × 100 = 10K messages/slot fits in microseconds on 1 Gbps.
- **Tier 2** (100–2K): Committees of 50–100 validators provide real statistical amplification. VRF sortition begins, but with larger expected committee sizes than full Loom.
- **Tier 3** (2K+): Full Loom as designed. The statistical sampling is now decisive.

The key insight: **at small N, you don't need sampling — you can afford to have every node verify everything.** The bandwidth cost of full verification is low when N × TPS × tx_size fits in 1 Gbps.

---

## 3. Tier 1: Full BFT Mode (10–100 Validators)

### 3.1 How It Works

This is the launch configuration. Every validator does everything:

```
EVERY validator, EVERY slot:
  1. Receive full block (all transactions, all threads)
  2. Verify all transactions
  3. Cast BLS vote on block hash
  4. Participate in BLS aggregate signature (QC)
```

**No VRF sortition needed** — all validators are known, and the set is small enough that concealing the proposer is less critical (DDoS is addressed by the existing P2P private overlay in `P2P_ARCHITECTURE.md`).

### 3.2 Proposer Selection: Deterministic Rotation + VRF Tiebreaker

At 10–50 validators, VRF-only selection is wasteful (high variance, frequent empty slots). Instead:

```
Epoch Schedule:
  - At epoch start, generate a deterministic rotation schedule:
    schedule[slot] = validators sorted by VRF(sk, epoch_seed ‖ slot)
  - The validator with the lowest VRF hash for each slot is the proposer
  - The SCHEDULE is computed by all validators at epoch start (deterministic)
  - But the VRF proof is only revealed when the proposer broadcasts the block
```

**Properties:**
- **Deterministic schedule** (every node computes the same ordering) — enables Gulf Stream to pre-route transactions to the right proposer
- **VRF-based** — unpredictable if you don't know all validators' secret keys (which you don't)
- **Fallback**: If the primary proposer misses their slot (timeout: 2× slot time), the second-ranked validator proposes. View change after 3 consecutive misses.

### 3.3 Block Structure: Threads Start at 1

At Tier 1, the block has **1 thread** (or 2 if N ≥ 30):

```zig
pub const AdaptiveBlockHeader = struct {
    slot: u64,
    epoch: u64,
    parent_hash: Hash,
    proposer_index: u32,
    proposer_vrf_proof: [48]u8,

    // Thread structure (adaptive)
    thread_count: u8,                      // 1 at Tier 1, scales up
    thread_roots: [MAX_THREADS]Hash,       // Merkle root per thread
    thread_tx_counts: [MAX_THREADS]u32,    // Tx count per thread
    woven_root: Hash,                      // Merkle(thread_roots[0..thread_count])

    // State (deferred execution, same as Loom)
    state_root: Hash,                      // Committed 2 slots behind
    total_tx_count: u32,
    randomness_seed: [32]u8,

    // Tier 1 specific: all validators vote, so QC is simple
    tier: ConsensuseTier,
};

pub const ConsensusTier = enum(u8) {
    FullBFT = 1,       // N ≤ 100
    CommitteeLoom = 2,  // 100 < N ≤ 2000
    FullLoom = 3,       // N > 2000
};

pub const MAX_THREADS: u8 = 128;
```

**Why still use the thread structure with 1 thread?** Because the block format is identical across all tiers. The DAG executor, deferred executor, fraud proofs, and state storage work identically whether there's 1 thread or 100. This means **zero code changes** when scaling up.

### 3.4 Voting: Direct BLS Aggregate (No Snowball)

At 10–100 validators, Snowball is overkill. Direct BLS voting is simpler and equally secure:

```
Slot Lifecycle (Tier 1, 400ms):

 0ms ────── 80ms ────── 200ms ────── 320ms ────── 400ms
  │ Propose   │ Distribute  │   Verify     │  Vote+QC   │
  │ Build     │ Turbine     │   Full       │  BLS       │
  │ block     │ (1 tree)    │   block      │  aggregate │
```

1. **Propose (0–80ms)**: Proposer builds block, assigns txs to thread(s)
2. **Distribute (80–200ms)**: Turbine propagation with 1 tree (existing `turbine.zig` — 1 tree for 1 thread is trivial)
3. **Verify (200–320ms)**: Every validator downloads and verifies the full block
4. **Vote+QC (320–400ms)**: 
   - Each validator signs `(slot, woven_root)` with BLS
   - Broadcast vote to all peers (10–100 messages — trivial)
   - Any validator reaching ≥ 67% stake forms the QC by aggregating BLS sigs

**QC = same struct as Loom:**

```zig
pub const QuorumCertificate = struct {
    slot: u64,
    woven_root: Hash,
    aggregate_signature: [96]u8,      // BLS aggregate
    voter_bitmap: [32]u8,             // Which validators signed (256-bit)
    total_attesting_stake: u64,
    randomness_seed: [32]u8,          // For next slot
    tier: ConsensusTier,              // Which tier produced this QC
};
```

### 3.5 Bandwidth at Tier 1

With 1 thread, every validator downloads the FULL block:

| Metric | 100K TPS (1 thread) | 400K TPS (2 threads) | 1M TPS (impossible at Tier 1) |
|:-------|:--------------------|:---------------------|:------------------------------|
| Block data per 400ms slot | 40K txs × 150B = **6 MB** | 80K txs × 150B = **12 MB** | 150K txs × 150B = 60 MB |
| Bandwidth per validator | **120 Mbps** | **240 Mbps** | 1.2 Gbps ❌ |
| Fits in 1 Gbps? | ✅ Easily | ✅ Yes | ❌ No |

**Tier 1 caps at ~400K–500K TPS** (2 threads, all nodes verify everything). This is still **5× Solana's throughput** and orders of magnitude beyond Ethereum.

**To reach 1M TPS, you NEED thread-based partial verification (Tier 2+), which requires more validators.** This is the honest engineering reality — you cannot have 10 validators and 1M TPS with full verification without > 1 Gbps NICs.

### 3.6 Security at Tier 1

This is **standard Byzantine Fault Tolerance**, the most battle-tested consensus model in existence:

| Property | Guarantee |
|:---------|:----------|
| Safety | ≥ 67% honest stake → no two conflicting QCs possible (identical to Tendermint/HotStuff) |
| Liveness | ≥ 67% honest stake + network synchrony → chain progresses every slot |
| Finality | **Single-slot (400ms)** — same as Loom |
| Verification | **100% of data verified by 100% of validators** — stronger than Loom's sampling |

At 10 validators (Tier 1), your security is as follows:
- **Adversary tolerance**: Can tolerate up to 3 Byzantine validators (33% of 10)
- **No sampling risk**: Every node verifies everything — no statistical arguments needed
- **View change**: If proposer is down, next in VRF schedule takes over after 800ms timeout

| Validators | Max Byzantine Tolerance | Offline Tolerance Before Stall |
|:-----------|:----------------------|:------------------------------|
| 10 | 3 validators | 3 validators (67% minimum) |
| 20 | 6 validators | 6 validators |
| 50 | 16 validators | 16 validators |
| 100 | 33 validators | 33 validators |

---

## 4. Tier 2: Committee Loom (100–2,000 Validators)

### 4.1 When and Why

At N > 100, all-to-all voting starts generating significant message overhead:
- 100 validators: 100 votes/slot → fine
- 500 validators: 500 votes/slot → manageable  
- 2000 validators: 2000 votes/slot → 2000 × ~200 bytes = 400 KB/slot → still fine bandwidth-wise, but BLS verification of 2000 sigs takes ~200ms

The real reason to switch isn't message overhead — it's **to enable more threads**. At N > 100, you have enough validators to form meaningful committees per thread, enabling partial verification and higher TPS.

### 4.2 Committee Formation

Instead of Loom's fully random VRF sortition (which needs N > 2K for statistical safety), Tier 2 uses **epoch-shuffled fixed committees**:

```
At epoch start (every 1024 slots ≈ 7 minutes):

1. Compute epoch_seed = Keccak256(prev_epoch_seed ‖ last_QC.aggregate_sig)
2. Shuffle all N validators using Fisher-Yates with epoch_seed as PRNG
3. Assign committees:

   Thread Committee Size = max(20, N / (thread_count * 2))
   
   For thread_count = 3, N = 300:
     Committee size = max(20, 300 / 6) = 50 validators per thread committee
   
   Attestor Pool = remaining validators (or overlap with thread committees)
```

**Properties:**
- Committees are **fixed for the epoch** (7 minutes) — no per-slot VRF overhead
- Committee size ≥ 20 guarantees statistical safety: P(adversary ≥ 1/3 of 20 from 300 with 33% adversary) ≈ 10⁻³
- Committees rotate every epoch — no persistent targeting
- Committee assignments are **publicly verifiable** (any node can recompute with the seed)

### 4.3 Slot Lifecycle (Tier 2)

```
 0ms ────── 60ms ────── 160ms ────── 280ms ────── 400ms
  │ Propose   │ Distribute  │  Committee    │  Attest+QC │
  │ Build     │ Turbine     │  Verify       │  BLS vote  │
  │ block     │ per-thread  │  Thread certs │  aggregate │
```

1. **Propose (0–60ms)**: VRF-selected proposer builds block with T threads
2. **Distribute (60–160ms)**: Turbine trees per thread (each thread's data goes to its committee)
3. **Committee Verify (160–280ms)**: 
   - Each thread committee downloads and verifies their thread's data
   - Committee signs thread certificate when ≥ 67% of committee stake agrees
4. **Attest+QC (280–400ms)**: 
   - All validators receive block header + T thread certificates
   - **Direct BLS vote** (not Snowball — at 100-2K nodes, BLS aggregate is still fast enough)
   - QC formed when ≥ 67% of total stake votes

### 4.4 Thread Scaling at Tier 2

| N (validators) | Threads | Committee Size | TPS/Thread | Total TPS | Security (P of committee corruption) |
|:--------------|:--------|:--------------|:-----------|:----------|:------------------------------------|
| 100 | 2 | 50 | 100K | **200K** | < 10⁻⁵ |
| 200 | 3 | 33 | 100K | **300K** | < 10⁻⁴ |
| 500 | 5 | 50 | 100K | **500K** | < 10⁻⁵ |
| 1,000 | 8 | 62 | 100K | **800K** | < 10⁻⁶ |
| 2,000 | 10 | 100 | 100K | **1M** | < 10⁻⁸ |

**At 2,000 validators, you reach full 1M TPS with 10 threads** — matching Loom's original target, but with fixed committees instead of per-slot VRF sortition.

### 4.5 Proposer Selection at Tier 2

Switch to **VRF sortition** (as in Loom):
```
PROPOSER: BLS_VRF(sk, epoch_seed ‖ slot ‖ "proposer")
  → ~3 expected candidates, lowest hash wins
```

At N > 100, VRF provides genuine unpredictability. The existing `vrf.zig` `check_eligibility()` function works exactly as-is — simply adjust the stake proportion for higher expected selection count.

### 4.6 Gulf Stream Integration at Tier 2

The existing `gulf_stream.zig` `LeaderSchedule` computes leaders `LEADER_LOOKAHEAD` slots ahead. At Tier 2:

```
For VRF-based proposer selection:
  - Gulf Stream can't predict exact proposer (VRF is private)
  - Solution: Forward transactions to top-3 most likely proposers
    (validators with highest stake have highest VRF selection probability)
  - The proposer's VRF proof reveals selection; non-proposers discard pre-routed txs
```

This is the same approach as Algorand's Gulf Stream equivalent.

---

## 5. Tier 3: Full Loom (2,000+ Validators)

At N > 2,000, the protocol transitions to full Loom as described in `Consensus.md`:

- **VRF sortition** per-slot for all roles (proposer, weavers, attestors)
- **Per-slot random weaver selection** (~100 per thread from thousands)
- **Snowball finality** instead of BLS all-to-all voting
- **DAS** for data availability

This transition is seamless because:
1. Block format is identical (same `AdaptiveBlockHeader`, just `tier = FullLoom`)
2. QC format is identical
3. Turbine propagation is identical (just more trees)
4. Execution is identical (DAG executor sees one block regardless of tier)

### 5.1 Changes from Tier 2 to Tier 3

| Component | Tier 2 | Tier 3 |
|:----------|:-------|:-------|
| Thread committees | Fixed per epoch | VRF-selected per slot |
| Finality voting | BLS all-to-all | Snowball sub-sampled |
| Data availability | Full download by committee | DAS by attestors |
| Proposer | VRF (same) | VRF (same) |

---

## 6. Adaptive Thread Count Formula

The thread count self-tunes based on validator count and network bandwidth:

```
thread_count(N) = 
  if N ≤ 30:   1
  if N ≤ 100:  2
  if N ≤ 200:  3
  if N ≤ 500:  5
  if N ≤ 1000: 8
  if N ≤ 2000: 10
  if N > 2000: min(N / 200, MAX_THREADS)   // 1 thread per 200 validators
```

**Constraint**: Each thread needs a minimum committee of 20 validators for statistical safety. Thread count is always `≤ N / 20`.

This means:
- **10 validators → 1 thread → ~100K TPS** (all nodes verify everything)
- **50 validators → 2 threads → ~200K TPS** (all nodes still verify everything, but data is split for propagation efficiency)
- **500 validators → 5 threads → ~500K TPS** (committee-based per-thread verification)
- **2000 validators → 10 threads → ~1M TPS** (full Loom target)
- **10000 validators → 50 threads → ~5M TPS** (beyond original goal)

---

## 7. Integration with Existing Codebase

### 7.1 What Changes

| Module | Current State | Change Needed |
|:-------|:-------------|:-------------|
| `zelius.zig` | Round-robin with `max_validators: u32 = 100` | Remove max_validators cap. Add tier detection at epoch boundary. Replace round-robin with VRF schedule. Wire up the correct voting path (BLS all-to-all for Tier 1–2, Snowball for Tier 3). |
| `pipeline.zig` | Sequential Propose→Vote→Finalize | Add `AdaptiveBlockHeader` with `thread_count` and `tier` fields. Slot lifecycle stays the same structure, just the verification path branches by tier. |
| `vrf.zig` | BLS VRF with eligibility check | No changes needed — `check_eligibility()` already works for proposer selection. Add domain separators for weaver/attestor roles (Tier 2+). |
| `votepool.zig` | BLS vote aggregation with quorum check | No changes needed for Tier 1–2 — direct BLS voting is exactly what it already does. Add Snowball path for Tier 3. |
| `staking.zig` | `max_validators: u32 = 100` in config, full delegation system | Remove validator cap. Add tier computation: `getTier(active_count)`. Everything else (delegation, slashing, rewards) stays identical. |

### 7.2 What Stays Identical

| Module | Why Unchanged |
|:-------|:-------------|
| `turbine.zig` | Already supports multi-tree propagation. 1 thread = 1 Turbine tree. 10 threads = 10 trees. No API change needed. |
| `gulf_stream.zig` | Already forwards txs to predicted leader. At Tier 1 (deterministic schedule), it works as-is. At Tier 2+, the leader schedule update function changes but the forwarding logic stays. |
| `server.zig` | P2P server handles packets generically. Shred messages, attestations, QC messages — all already defined in `types.zig`. |
| `dag_executor.zig` | Executes all threads' transactions in unified pass. Thread assignment is invisible to execution. |
| `deferred_executor.zig` | Still runs 2 blocks behind. Tier doesn't affect deferred execution. |
| `fraud_proof.zig` | State root challenges work identically across all tiers. |
| `compression.zig` | Zstd compression is content-agnostic. |

### 7.3 New Module: `snowball.zig` (Only Used at Tier 3)

Created but dormant until N > 2,000:

```zig
pub const Snowball = struct {
    k: u32,        // sample size per round
    alpha: u32,    // quorum threshold
    beta: u32,     // consecutive rounds to finalize
    
    pub fn init(k: u32, alpha: u32, beta: u32) Snowball { ... }
    pub fn query(self: *Snowball, peers: []PeerId, block_hash: Hash) Preference { ... }
    pub fn isFinalized(self: *const Snowball) bool { ... }
};
```

At Tier 1–2, this module is never called. At Tier 3, it replaces the BLS all-to-all voting in the finality phase.

---

## 8. Epoch-Based Tier Transition

### 8.1 Detection

```
At the start of each epoch (every 1024 slots ≈ 7 minutes):

1. Count active validators: N = len(active_validator_set)
2. Compute tier:
   tier = if (N <= 100) .FullBFT
          else if (N <= 2000) .CommitteeLoom
          else .FullLoom
3. Compute thread_count based on N (Section 6 formula)
4. If tier changed from previous epoch:
   - Log: "Consensus tier transition: {old} → {new}, threads: {old_t} → {new_t}"
   - Recompute committees (Tier 2) or sortition params (Tier 3)
5. All validators compute this independently — deterministic from on-chain state
```

### 8.2 Transition Safety

Tier transitions happen at epoch boundaries (every ~7 min). During the transition slot:
- The LAST slot of the old epoch uses old-tier rules
- The FIRST slot of the new epoch uses new-tier rules
- QCs from either tier are valid (same format, same BLS aggregate verification)
- No ambiguity because every validator computes the tier deterministically

---

## 9. Slashing and Accountability (Tier-Adapted)

| Offense | Tier 1 (10–100) | Tier 2 (100–2K) | Tier 3 (2K+) |
|:--------|:----------------|:-----------------|:-------------|
| **Double Proposal** | 100% slash, tombstone | Same | Same |
| **Double Vote** | 100% slash, tombstone | Same | Same |
| **Invalid Block** | 50% slash, jail | 50% slash, jail | 50% slash, jail |
| **Inactivity** | 1% stake/epoch leak | Same | Same |
| **Invalid Thread Root** | N/A (all verify) | 50% slash (committee member) | 50% slash (weaver) |

At Tier 1, "invalid thread root" is not applicable because every validator verifies the full block and would simply reject it. At Tier 2+, committee members/weavers who attest to invalid data are slashed.

---

## 10. Randomness Seed (Same Across All Tiers)

```
R(slot) = Keccak256(R(slot-1) ‖ QC(slot-1).aggregate_signature ‖ slot)
```

Identical to Loom. Works at any N because:
- BLS aggregate signature depends on ≥ 67% of signers — no single validator controls it
- Chain-linked — compromising one slot doesn't help with future slots

---

## 11. User Experience Timeline (Same Across All Tiers)

```
 0ms ──── 50ms ──── 100ms ──── 200ms ────── 400ms
  │        │         │          │              │
 Submit   Gulf      Proposer   Validators     QC
  tx     Stream    includes   verify          formed
         routes    in block   and vote
 
         ↓          ↓                         ↓
    "Submitted" "Confirmed"              "Finalized"
                (optimistic)             (irreversible)
```

| Level | Latency | Safety |
|:------|:--------|:-------|
| **Submitted** | ~50ms | Tx received by proposer |
| **Confirmed** (optimistic) | **~100ms** | 99.99%+ — block is propagating |
| **Finalized** | **400ms** | Cryptographically irreversible (QC signed) |

**Users see the same latency regardless of network size.** This is a hard requirement.

---

## 12. Growth Roadmap: Validators → TPS → Security

| Phase | Validators | Tier | Threads | TPS | Finality | Security Model | Time to Reach |
|:------|:----------|:-----|:--------|:----|:---------|:--------------|:-------------|
| **Genesis** | 10–20 | Full BFT | 1 | **100K** | 400ms | Classical BFT (all verify all) | Day 1 |
| **Early Growth** | 20–50 | Full BFT | 1–2 | **100–200K** | 400ms | Classical BFT | Month 1–3 |
| **Traction** | 50–100 | Full BFT | 2 | **200K** | 400ms | Classical BFT, max for Tier 1 | Month 3–6 |
| **Expansion** | 100–500 | Committee Loom | 2–5 | **200–500K** | 400ms | Committee-based per-thread | Month 6–12 |
| **Scale** | 500–2,000 | Committee Loom | 5–10 | **500K–1M** | 400ms | Large committees, strong stats | Year 1–2 |
| **Full Loom** | 2,000–10,000 | Full Loom | 10–50 | **1M–5M** | 400ms | Full Loom (VRF+Snowball+DAS) | Year 2+ |
| **Hyperscale** | 10,000–100K | Full Loom | 50–100+ | **5M–10M+** | 400ms | Maximum statistical security | Long term |

---

## 13. Security Analysis Per Phase

### 13.1 Genesis Phase (10–20 Validators)

**Model**: Classical BFT — identical to Tendermint/CometBFT security model used by Cosmos chains with $30B+ TVL.

| Property | Value |
|:---------|:------|
| Byzantine tolerance | 33% of stake (3 of 10, 6 of 20) |
| Verification coverage | **100%** — every node checks every transaction |
| P(invalid block finalized) | **0** — impossible without ≥ 67% Byzantine |
| Data availability | **100%** — every node has full data |
| Attack cost (33% stake) | Cost to acquire 33% of total staked ZEE |
| Offline tolerance | Up to 33% of validators |

**Why this is secure enough for launch:**
- Every major Cosmos chain launched with 50–150 validators using this exact model
- Ethereum Beacon Chain launched its deposit contract with far fewer initial validators
- The security depends on the **economic cost of acquiring 33% stake**, not on validator count
- With proper token distribution (team + early backers), adversary can't easily buy 33% at launch

### 13.2 At 50 Validators

Still Full BFT. Security identical to genesis but with wider stake distribution:

| Property | Value |
|:---------|:------|
| Byzantine tolerance | 16 validators |
| Offline tolerance | 16 validators |
| Verification | 100% coverage |
| Statistical amplification needed | **None** — full verification |

### 13.3 At 500 Validators (Committee Loom)

Committees provide real sampling security:

| Property | Value |
|:---------|:------|
| Threads | 5 |
| Committee size | 50 per thread |
| P(committee ≥ 1/3 Byzantine) | < 10⁻⁵ |
| P(ALL 5 committees corrupt) | < 10⁻²⁵ (impossible) |
| Plus: every validator receives block header + QC | Full chain verification |

### 13.4 At 2,000+ Validators (Full Loom)

Full Loom security as described in Consensus.md Section 14.

---

## 14. Comparison: Loom Genesis vs. Other Launch Strategies

| | Ethereum 2.0 Launch | Cosmos Launch | Solana Launch | **Zephyria Loom Genesis** |
|:--|:-------------------|:-------------|:-------------|:------------------------|
| Initial validators | ~500 (beacon only) | 100–150 | ~200 | **10–50** |
| Initial TPS | ~30 | ~70 | ~1K | **100–200K** |
| Finality | 12.8 min | ~7s | ~0.4s | **400ms** |
| Consensus at launch | Casper FFG (fixed) | Tendermint (fixed) | Tower BFT (fixed) | **Adaptive (self-tuning)** |
| Scales to 1M TPS | Via L2s only | No | No | **Yes, at 2,000 validators** |
| Protocol change needed to scale | Hard fork (sharding) | No (can't scale) | No (can't scale) | **None (automatic tier transition)** |
| Hardware required | Consumer | Consumer | Datacenter | **Mid-tier consumer** |

---

## 15. Summary — What Makes Loom Genesis Novel

1. **One Binary, Three Tiers**: The protocol self-adapts based on validator count. No hard forks, no manual reconfiguration. The same node binary serves 10 validators at genesis and 10,000 validators two years later.

2. **Full BFT at Small Scale**: At 10–100 validators, every node verifies everything — the strongest possible security model. No sampling risk, no committee corruption risk.

3. **Smooth Scaling**: As validators join, the protocol automatically adds threads and shifts verification from all-to-all to committee-based to VRF-sampled. TPS grows linearly with validator count.

4. **Consistent User Experience**: 400ms finality and ~100ms optimistic confirmation regardless of network size or operating tier.

5. **Existing Infrastructure Compatibility**: The existing P2P layer (Turbine, Gulf Stream), execution engine (DAG executor, deferred executor), and state storage (ZephyrDB) work unchanged across all tiers.

6. **Honest Engineering**: We don't claim 1M TPS with 10 validators. 10 validators gives you ~100K TPS (which is still 2× Solana). 1M TPS requires 2,000+ validators. This is the physics of bandwidth.

**Block Time: 400ms. Finality: 400ms. TPS: 100K (10 validators) → 1M (2K validators) → 5M+ (10K validators). Hardware: Mid-tier consumer. Hard forks to scale: Zero.**
