Zephyria P2P Layer — Architecture Refactoring Plan

### Phase 1: Gulf Stream Leader Prediction Alignment
Problem

gulf_stream.zig:LeaderSchedule.update() hashes Blake3(epoch‖slot) % N independently, while adaptive.zig:deterministicProposer uses Blake3(epochSeed‖slot) % N. Different inputs → different leaders → TXs forwarded to wrong node.

Changes

1a. Remove LeaderSchedule.update() in gulf_stream.zig (lines 58-96):
- Delete the ValidatorInfo import/usage in Gulf Stream
- Remove LeaderSlot.epoch field (not needed if using consensus)
- GulfStream no longer needs its own LeaderSchedule — delegates to consensus

1b. Replace with consensus call in GulfStream.advanceSlot() (line 234):
- Instead of self.schedule.update(slot, epoch, validators), store a reference to the ZeliusEngine or AdaptiveConsensus
- getForwardTargets() calls self.engine.getExpectedProposer(slot + i) for i = 0..LEADER_LOOKAHEAD
- currentLeader() calls self.engine.getExpectedProposer(self.current_slot)

1c. Update server.zig initialization (around line 738):
- Pass engine: *ZeliusEngine to GulfStream.init() instead of building a separate ValidatorInfo array
- Remove the gs_validators allocation loop
- advanceSlot(slot) no longer needs the validator list — engine already has it
Files touched
- src/p2p/gulf_stream.zig — delete LeaderSchedule, LeaderSlot, ValidatorInfo, inject engine ref
- src/p2p/server.zig — simplify the two advanceSlot call sites

### Phase 2: Turbine Propagation Tree Stake Weighting

Problem

PropagationTree.build() assigns tree positions by flat validatorIndex order (from sorted address list). A low-stake validator is equally likely to be a bottleneck as a high-stake one.

Changes

2a. Add stake parameter to build() (turbine.zig:623):
pub fn build(self: *Self, peers: []const struct { addr: Address, stake: u256 }, total_shreds: u32) !void

2b. Sort by stake descending within build():
- Sort the peers by stake, highest first
- Root (index 0) is always the producer (highest stake)
- Higher-stake nodes get higher fanout: stake_ratio * TURBINE_FANOUT children instead of uniform fanout
- Lower-stake nodes are leaf-only (zero children)

2c. Update handleShred in server.zig (around line 930-990):
- Replace address-only sort with stake-weighted sort
- Gather stakes from self.engine.activeValidators[i].stake
- Pass []struct { Address, u256 } to build()

2d. Update broadcastBlockViaTurbine (server.zig:410-470):
- Same change — pass stakes to build()

Files touched
- src/p2p/turbine.zig — rewrite PropagationTree.build(), add getChildren()/getParentIndex() stake-awareness
- src/p2p/server.zig — two call sites for buildPropTree

### Phase 3: Replace Ed25519 Shred Signatures with BLS

Problem

Two crypto systems. Validators need Ed25519 keys JUST for shreds, adding complexity, key management surface, and 10% sampling security hole.

Design Decision

Remove per-shred signatures entirely. The block is already BLS-signed by the producer. A shred is a fragment of a block. If a receiver collects enough shreds to reconstruct the block, the block-level BLS signature authenticates all shreds. Per-shred signatures add 64 bytes * ~54K shreds = ~3.4MB overhead per block with zero marginal security benefit after block-level verification.
Changes

3a. Change Shred.producerSignature from [64]u8 → [96]u8 (turbine.zig:369)
- Store the block-level BLS sig in every shred of the block (redundant but enables destination checks)

3b. Change ShredMsg.producerSignature from [64]u8 → [96]u8 (types.zig:239)

3c. Remove ShredVerifier entirely (shred_verifier.zig — delete file)
- No per-shred signature verification needed
- Block-level BLS verification in zelius.zig:verify() handles authentication
- Eliminates the 10% sampling vulnerability

3d. Simplify handleShred (server.zig:877-994):
- Remove all shredVerifier.verifyShred() calls
- Remove ShredVerifier field from Server struct
- Remove setShredVerifier()

3e. Remove ShredVerifyConfig and ValidatorEntry from p2p/mod.zig exports

Files touched
- src/p2p/types.zig — ShredMsg.producerSignature width
- src/p2p/turbine.zig — Shred.producerSignature width
- src/p2p/shred_verifier.zig — DELETE (296 lines removed)
- src/p2p/server.zig — remove all shred verifier references
- src/p2p/mod.zig — remove re-export of shred_verifier
- src/p2p/tests.zig — remove shred verifier tests, update Shred struct construction

### Phase 4: Attestation Subnets → Thread Topology

Problem

64 gossip subnets, 2 per validator (exact Ethereum 2.0 copy). Zephyria's consensus uses thread-based attestation with MAX_THREADS (currently 16). Subnets should map to threads.

Changes

4a. Change constants in types.zig:
- GOSSIP_SUBNETS = 16 (or MAX_THREADS, import from consensus)
- SUBNETS_PER_VALIDATOR = 1 (each validator subscribes to its thread's subnet)
- Remove AGGREGATION_SUBNETS (Eth2 aggregator role not needed)

4b. Subnet assignment uses thread ID instead of Blake3(validatorAddr) % GOSSIP_SUBNETS:
- In registerPeerSubnets() (server.zig), subscribe peer to the subnet matching their committeeAssignment.threadId
- Remove the Ethereum-style "random 2 subnets" assignment

4c. Update ThreadAttestationMsg and ThreadCertificateMsg propagation:
- These already exist in types.zig — ensure they're gossiped within the thread subnet, not globally
- Add handlerThreadAttestation in handleShred path or a dedicated handler

Files touched
- src/p2p/types.zig — rewrite subnet constants
- src/p2p/server.zig — registerPeerSubnets, handleSubnetSubscribe, gossipToSubnet
- src/p2p/peer.zig — subnet bitmap size may change

### Phase 5: DAG Mempool + Gulf Stream Integration

Problem

Transactions flow through two independent channels: DAG Mempool (local block building) and Gulf Stream (speculative forwarding). No coordination → TXs may be forwarded multiple times or dropped.
Changes

5a. Gulf Stream reads from the DAG Mempool, not from a separate handleTxBatch path:
- Remove GulfStream.pendingBatch and GulfStream.queue (the internal FIFO)
- GulfStream.drainBatch() calls dagPool.extractPending(MAX_BATCH_SIZE) instead
- No duplicate TX tracking between mempool and Gulf Stream

5b. handleTxBatch feeds directly into DAG Mempool (server.zig:810):
- Incoming TXs go to dagPool.add(heapTx) only
- Gulf Stream is the sender side: it reads from the mempool and forwards to the predicted leader
- On the receiving end, the leader receives TXs into their mempool (not into Gulf Stream's separate queue)

5c. Remove duplicate TX tracking from Gulf Stream:
- LeaderSchedule is already removed (Phase 1)
- ForwardBatch.txHashes / ForwardBatch.txData replaced by mempool's TX pool
- queueTransaction(), flushPendingBatch(), expireOldBatches() all removed

5d. Simplify GulfStream struct:
- Only fields: allocator, mutex, dagPool, engine, slotBytesForwarded, throttleSlot, stats
- Methods: init, deinit, advanceSlot, drainBatch, getStats

Files touched
- src/p2p/gulf_stream.zig — rewrite (remove queue, batch, schedule logic)
- src/p2p/server.zig — handleTxBatch simplified, forwardGulfStream calls dagPool not gulfStream.queueTransaction
- src/p2p/types.zig — TxBatchMsg may simplify

### Phase 6: Security Gaps

6a. Rate-limit MsgShredRepairRequest (handleShredRepairRequest in server.zig):
- Add repairBudget: usize to ServerConfig (default 100/peer/minute)
- Track per-peer repair request count in a sliding window
- Reject excess with peer.updateScore(-5)

6b. Remove per-shred sampling (already handled by Phase 3 — ShredVerifier deleted)

6c. Unify secureZero into a shared utility:
- Move secureZero to src/utils/mod.zig (already has allocators)
- Import in server.zig, discovery.zig — remove local copies

6d. Add inbound rate limiter for the main packet loop:
- Per-IP: max 1000 packets/second (configurable)
- Use a simple token bucket per IP in handlePacket

### Phase 7: Flow Coherence — Connect the Islands

┌─────────────────────────────────────────────────────────────────────┐
│                      PROPOSED ARCHITECTURE                          │
│                                                                     │
│  TX arrives  ──►  DAG Mempool  ──►  Gulf Stream (reads from        │
│                     (local)            mempool, forwards to         │
│                                        predicted leader via         │
│                                        CONCENSUS's VRF-based slot)  │
│                                              │                      │
│  Block Producer  ──►  Turbine  ──►  Propagation Tree                │
│  (BLS signs block)     (shreds)        (stake-weighted)             │
│                              │                                      │
│  Receiver ──►  Reconstruct block  ──►  ZeliusEngine.verify()        │
│  (no per-shred sig)              │      └─ block-level BLS sig      │
│                                  │      └─ QC validation            │
│                                  │      └─ VRF proposer check       │
│                                  │                                  │
│                                  └─►  Vote + QC propagation         │
│                                        via stake-weighted tree      │
│                                                                     │
│  Thread Attestations  ──►  thread-specific subnets                  │
│  (per thread)                  (not 64 Eth2 subnets)                │
│                                    │                                │
│  ThreadCertificates  ──►  WovenQC  ──►  propagated via Turbine     │
│  (per thread)                      tree (stake-weighted)            │
└─────────────────────────────────────────────────────────────────────┘

7a. New block flow (unified):
1. Block producer BLS-signs block header (already done in seal())
2. broadcastBlockViaTurbine() shreds block with block-level BLS sig in every shred
3. Propagation tree (stake-weighted) distributes shreds
4. Receiver rebuilds block from shreds (no per-shred verification)
5. Calls ZeliusEngine.verify() — checks block-level BLS, VRF proposer, QC
6. If valid, casts BLS vote → broadcast to committee → QC formed → propagated via tree

7b. Thread certificates flow (new):
1. Thread attestations gossiped within thread subnet (Phase 4)
2. Aggregator produces ThreadCertificate → forwarded via stake-weighted tree
3. All ThreadCertificates combined into WovenQuorumCertificate
4. WovenQC propagated alongside the QC in the same tree

Implementation Order

Phase	Effort	Risk	Impact	Do First?

3 (BLS shreds)	Medium	Medium	Eliminates Ed25519 entirely, removes 296-line verifier	✅ Yes — biggest security gain, deletes code

1 (Gulf Stream leader)	Small	Low	Fixes wrong TX forwarding	✅ Yes — simple, blocks other phases

6c (secureZero)	Trivial	None	Cleanup	Do inline with other changes

4 (Subnets→Threads)	Medium	Low	Removes Ethereum copy	After 1, 3

2 (Stake-weighted tree)	Medium	Low	Better propagation	After 4 (needs stakes aligned)

5 (Mempool integration)	Large	Medium	Simplifies TX flow	After 1 (needs correct leader)
6a,6d (Rate limits)	Small	Low	Security hardening	Any time

7 (Flow coherence)	Large	High	Rearchitects propagation	Last — depends on all above

Files to Delete
- src/p2p/shred_verifier.zig (296 lines — replaced by block-level BLS)

Files to Significantly Rewrite

- src/p2p/gulf_stream.zig (440 lines → ~100 lines, remove internal queue/schedule)
- src/p2p/turbine.zig (PropagationTree.build rewrite for stake-weighting)

Files to Modify

- src/p2p/types.zig — shred sig width, subnet constants
- src/p2p/server.zig — shredverifier removal, subnets, rate limits, secureZero
- src/p2p/tests.zig — remove shredverifier tests, update turbine tests
- src/p2p/mod.zig — exports
- src/utils/mod.zig — add shared secureZero


sWant me to start executing Phase 3 (BLS shreds) now? It's the highest-impact change: eliminates an entire crypto system, removes the 10% sampling vulnerability, and deletes 296 lines of code.