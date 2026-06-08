Consensus Deep Analysis — Complete
Import/Export Graph
mod.zig (entry point)
  ├── types.zig           ─── shared types (CoreTier, Header, QC, etc.)
  ├── vdf.zig             ─── SHA-256 sequential VDF
  ├── vrf.zig             ─── BLS-based VRF sortition
  ├── zelius.zig          ─── main engine (887 lines)
  │   ├── types/vdf/vrf/adaptive/staking
  ├── votepool.zig        ─── vote aggregation + lock-free queue
  │   ├── types/zelius
  ├── staking.zig         ─── staking protocol (777 lines)
  │   ├── core.types/core.State/storage.DB
  ├── pipeline.zig        ─── 3-stage Propose→Vote→Finalize
  ├── adaptive.zig        ─── tier detection + QC formation
  │   ├── types/vrf/committees
  ├── committees.zig      ─── epoch-shuffled committee formation
  ├── snowball.zig        ─── probabilistic finality (Tier 3)
  └── thread_pool.zig     ─── thread attestation collection
Issues Fixed (5)
File	Issue	Fix
adaptive.zig:421,427	consecutive_misses → struct field consecutiveMisses	Renamed to match struct
adaptive.zig:462,464	header.thread_roots / header.thread_tx_counts → threadRoots / threadTxCounts	Fixed field names
votepool.zig:219-268	total_stake: u128 truncated from u256 val.stake	Changed to u256
zelius.zig:706-709	coinbase_hex Ethereum naming	Renamed to producer_hex
6 consensus files	FORGEYRIA_* DST strings	Changed to ZEPHYRIA_*
Remaining Issues — Refactor Plan
Phase A — Naming consistency:
- votepool.zig: add_vote→addVote, check_quorum→checkQuorum, check_quorum_adaptive→checkQuorumAdaptive
- zelius.zig: verify_vote_signature→verifyVoteSignature, create_vote→createVote, create_adaptive_vote→createAdaptiveVote
- snowball.zig: selectPeers→selectPeers (already camelCase), pruneOlderThan→pruneOlderThan (ok)
Phase B — Performance:
- zelius.zig:662-667: Replace O(n) linear validator scan with HashMap(Address, usize) in engine
- zelius.zig:543-627: Simplify seal() — eliminate double allocation (remove final_payload, just use preserved_data directly)
- snowball.zig:257-289: selectPeers can return duplicates; add duplicate rejection
Phase C — Correctness:
- committees.zig:126-127: Replace catch continue with proper error propagation
- zelius.zig:831-849: computeHeaderHash stack buffer [256]u8 could overflow with large extraData; use dynamic allocation
- votepool.zig:211: check_quorum uses all-validator stake but should use totalVotingStake from adaptive
Phase D — Design (deferred):
- vdf.zig: SHA-256 VDF is not delay-hard; replace with Wesolowski VDF (groups of unknown order) for production



// New Idea

Here's my analysis of what fits Zephyria's architecture cleanly:
Current Architecture (untouched)
block.header.extraData = [VDF_checkpoints | VRF_proof(48) | BLS_sig(96)]
seal():  compute_checkpoints(T, interval) → verify_parallel(segments)
The checkpoint + parallel verification framework is generic — it doesn't depend on SHA-256. The inner operation is pluggable.
The Leanest Swap: Repeated Squaring in ℤ_N^* (Group of Unknown Order)
Replace the inner SHA256(buf) with buf = buf² mod N where N is a 2048-bit RSA modulus. The existing checkpoint architecture stays identical:
Layer	Current (SHA-256)	New (RSA squaring)
compute_checkpoints()	SHA256(buf) × T	buf² mod N × T
verify_parallel()	verify N segments	same code, unchanged
Checkpoint size	32 bytes each	256 bytes each
Sequential guarantee	❌ None (ASIC-speedup)	✅ Provable (unknown order)
Why this fits perfectly:
- Pure Zig via std.math.big.int.Managed — no C FFI, no new dependencies
- Checkpoint + parallel verify framework stays completely unchanged
- Genesis config (SystemParams) gets one new field: vdfModulus: [256]u8
- The 2048-bit modulus is generated once at chain genesis, factors discarded — no trusted runtime ceremony
- Parameters vdfIterations and vdfCheckpointInterval keep their exact same role
Why it stands out: Ethereum uses VDF only for RANDAO randomness. Solana doesn't use one at all. Chia uses SHA-256 (not delay-hard). No L1 uses per-block class-group or RSA VDF for time-delay proving — Zephyria would be the first.
What Changes
New field in genesis config:
pub const SystemParams = struct {
    vdfModulus: [256]u8,    // ← new: 2048-bit RSA modulus N
    vdfIterations: u64,      // unchanged
    vdfInterval: u64,        // unchanged
    ...
};
Inner loop in vdf.zig changes from:
std.crypto.hash.sha2.Sha256.hash(&buf, &next_buf, .{});
to:
var x = Managed.init(allocator);
defer x.deinit();
x.setBytes(buf[0..32]) catch ...;
x.sqr() catch ...;
x.mod(&modulus) catch ...;
x.toBytes(buf[0..32]) catch ...;
Allocations change from 32-byte checkpoint slices to 256-byte slices.
Performance Estimate (pure Zig)
Parameter	Dev	Mainnet
Iterations (T)	1,000	50,000
Checkpoint interval	100	5,000
Checkpoints	10	10
Time per squaring	~2μs	~2-5μs
Total compute time	~2ms	~100-250ms
Verification (8 threads)	~0.5ms	~25ms
Fits within the 400ms slot budget.
Want me to implement this? The changes are:
1. vdf.zig — replace SHA-256 inner loop with big.int modular squaring
2. genesis.zig — add vdfModulus to SystemParams
3. zelius.zig — update seal() and verify() for 256-byte checkpoint size
4. main.zig — pass modulus from genesis to engine
~100 lines total change, zero new dependencies.