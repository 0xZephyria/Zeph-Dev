# Implementation Plan — Codebase Cleanup and Alignment

This plan identifies and removes unrequired research-phase files and duplicate implementations across the Zephyria node and ForgeVM. Cleaning these files ensures that future optimizations (e.g. progressive rehashing, intrusive LRU caching) target the correct active production candidates.

## User Review Required

We have conducted a recursive dependency analysis of all subsystems to map out what is active and what is dead code. Overwriting the existing plan with this clean-up strategy is necessary before executing any code changes.

> [!WARNING]
> This plan involves deleting multiple unused subdirectories (`src/storage/verkle`, `src/storage/lsm`, `src/storage/flatkv`, `src/storage/mmr`, `src/storage/codestore`, `src/p2p/grpc`, `src/rpc/grpc.zig`, `src/rpc/websocket.zig`, and several unused files under `src/consensus/`). 
> 
> All core production functionalities (DAG mempool, parallel executor, ZephyrDB, Loom adaptive PoS consensus, HTTP JSON-RPC, UDP P2P) will remain untouched and verified.

---

## 1. Graph of Used vs. Unused Components

Below is the recursive dependency graph showing what is active in the production node (`src/main.zig`) and what is dead code leftover from research/experimentation.

```mermaid
graph TD
    %% Active Components
    subgraph Active Production Pipeline
        Main[src/main.zig] --> VMBridge[src/vm_bridge.zig]
        Main --> Core[src/core/mod.zig]
        Main --> Consensus[src/consensus/mod.zig]
        Main --> P2P[src/p2p/mod.zig]
        Main --> RPC[src/rpc/mod.zig]
        Main --> Node[src/node/mod.zig]

        %% VM dependencies
        VMBridge --> RISC_V_Bridge[src/vm/riscv/mod.zig]
        RISC_V_Bridge --> ForgeVM_API[vm/vm.zig]
        ForgeVM_API --> ThreadedExecutor[vm/core/threaded_executor.zig]
        ForgeVM_API --> SwitchExecutor[vm/core/executor.zig]
        ForgeVM_API --> SandboxMemory[vm/memory/sandbox.zig]
        ForgeVM_API --> ContractLoader[vm/loader/contract_loader.zig]

        %% Core dependencies
        Core --> DAGExecutor[src/core/dag_executor.zig]
        Core --> DAGMempool[src/core/dag_mempool.zig]
        Core --> DAGScheduler[src/core/dag_scheduler.zig]
        Core --> State[src/core/state.zig]
        Core --> AsyncRoot[src/core/async_state_root.zig]
        Core --> DeltaMerge[src/core/delta_merge.zig]

        %% Consensus dependencies
        Consensus --> Zelius[src/consensus/zelius.zig]
        Consensus --> Adaptive[src/consensus/adaptive.zig]
        Consensus --> Committees[src/consensus/committees.zig]
        Consensus --> Snowball[src/consensus/snowball.zig]
        Consensus --> VotePool[src/consensus/votepool.zig]

        %% P2P dependencies
        P2P --> UDPServer[src/p2p/server.zig]
        P2P --> Peer[src/p2p/peer.zig]
        P2P --> Turbine[src/p2p/turbine.zig]
        P2P --> GulfStream[src/p2p/gulf_stream.zig]
        P2P --> ShredVerifier[src/p2p/shred_verifier.zig]
        P2P --> QUICPacket[src/p2p/quic/transport/packet.zig]

        %% RPC dependencies
        RPC --> HTTPServer[src/rpc/http_server.zig]
        RPC --> Methods[src/rpc/methods.zig]

        %% Storage dependencies
        Node --> EpochIntegration[src/node/epoch_integration.zig]
        EpochIntegration --> ZephyrDB[src/storage/zephyrdb/mod.zig]
        EpochIntegration --> EpochStorage[src/storage/epoch/mod.zig]
        State --> ZephyrDB
        State --> EpochStorage
    end

    %% Dead Components
    subgraph Unused / Research Remnants (To Be Deleted)
        DeadStorage[Unused Storage]
        DeadStorage --> LSM[src/storage/lsm/*]
        DeadStorage --> Verkle[src/storage/verkle/*]
        DeadStorage --> FlatKV[src/storage/flatkv/*]
        DeadStorage --> MMR[src/storage/mmr/*]
        DeadStorage --> CodeStore[src/storage/codestore/*]

        DeadConsensus[Unused Consensus]
        DeadConsensus --> Deferred[src/consensus/deferred_executor.zig]
        DeadConsensus --> Fraud[src/consensus/fraud_proof.zig]
        DeadConsensus --> Registry[src/consensus/registry.zig]

        DeadP2P[Unused P2P Protocols]
        DeadP2P --> P2P_gRPC[src/p2p/grpc/*]
        DeadP2P --> QUIC_Full[src/p2p/quic/transport/congestion.zig, recovery.zig, stream.zig, socket.zig, migration.zig, http3.zig, lib.zig, quic.zig]

        DeadRPC[Unused RPC Server Types]
        DeadRPC --> RPC_gRPC[src/rpc/grpc.zig]
        DeadRPC --> RPC_WS[src/rpc/websocket.zig]

        DeadTests[Dead Tests]
        DeadTests --> VerkleIsolate[tests/verkle_isolate.zig]
    end

    classDef active fill:#28a745,stroke:#333,stroke-width:2px,color:#fff;
    classDef dead fill:#dc3545,stroke:#333,stroke-width:2px,color:#fff;
    class Main,VMBridge,Core,Consensus,P2P,RPC,Node,RISC_V_Bridge,ForgeVM_API,ThreadedExecutor,SwitchExecutor,SandboxMemory,ContractLoader,DAGExecutor,DAGMempool,DAGScheduler,State,AsyncRoot,DeltaMerge,Zelius,Adaptive,Committees,Snowball,VotePool,UDPServer,Peer,Turbine,GulfStream,ShredVerifier,QUICPacket,HTTPServer,Methods,EpochIntegration,ZephyrDB,EpochStorage active;
    class DeadStorage,LSM,Verkle,FlatKV,MMR,CodeStore,DeadConsensus,Deferred,Fraud,Registry,DeadP2P,P2P_gRPC,QUIC_Full,DeadRPC,RPC_gRPC,RPC_WS,VerkleIsolate dead;
```

---

## 2. Comparative Analysis: Active vs. Dead Candidates

### A. Storage Engines: ZephyrDB vs. LSM vs. FlatKV vs. Verkle
* **Active (ZephyrDB + Epoch Storage)**: ZephyrDB implements a TigerBeetle-inspired, arena-backed in-memory state engine designed for 1M+ TPS with lock-free/low-contention indexing. Epoch Storage provides state delta tracking, transaction indexing, and background pruning.
* **Dead (LSM, FlatKV, Verkle)**: 
  * **LSM**: Hand-rolled LSM tree. Slower than ZephyrDB's sharded flat-table setup due to compaction spikes and write amplification. Unused in production.
  * **FlatKV**: Sharded HashMap in RAM with optional WAL. Superceded by ZephyrDB which provides higher robustness, a ring-buffer WAL, and custom memory management.
  * **Verkle**: An experimental Verkle Trie with IPA commitments. Completely disabled in the node (`computeRoot = false` always). The cryptographic overhead of IPA commitments on every block execution is a massive bottleneck.
  * **MMR**: Merkle Mountain Range. Unused by ledger or consensus validation.
  * **CodeStore**: A simple LRU bytecode caching struct. Standalone/unused because the VM bridge implements its own caching via `vm_pool.VMPool` and `contractLoader`.
* **Verdict**: **ZephyrDB + Epoch Storage** are the correct, robust, and highly performant choices. The other engines are research remnants and must be pruned to avoid wrong optimization focus.

### B. Consensus: Zelius/Loom vs. Deferred vs. Fraud Proofs vs. Registry
* **Active (Zelius Adaptive consensus)**: The Loom PoS engine is a direct implementation of Loom consensus, running pipeline verification, VRF/VDF, committees, snowball query, and attestation certificates.
* **Dead (Deferred, Fraud Proofs, Registry)**:
  * **DeferredExecutor**: Monad-inspired execution lagging 2 blocks behind consensus. Replaced by the native block producer and parallel DAG execution which executes transactions inline with negligible overhead.
  * **FraudProofManager**: Optimistic rollups style fraud proof validator. Unused in Loom Adaptive PoS.
  * **ValidatorRegistry**: A state-based validator database wrapper. Unused because the validator set is managed in-memory via `consensus.Staking`.
* **Verdict**: Keep **Zelius/Loom** consensus files. Remove the three unused helpers.

### C. P2P Transport: UDP Server vs. gRPC P2P vs. Full QUIC
* **Active (UDP Server + Turbine + Gulf Stream)**: The production network layer uses UDP socket batching (`socket_utils.sendBatch`), Turbine block shredding, and Gulf Stream transaction forwarding. Packets are simple UDP payloads wrapped in a minimal header.
* **Dead (gRPC P2P, Full QUIC)**:
  * **gRPC P2P**: A research gRPC wrapper over HTTP/2. Unused.
  * **Full QUIC**: High-overhead congestion control, stream buffers, connection state, migration, recovery, and HTTP/3. Unused for networking; only the mock packet encoder/decoder (`src/p2p/quic/transport/packet.zig`) is used as a packet structure.
* **Verdict**: Retain UDP Server and Turbine/Gulf Stream. Delete `src/p2p/grpc` and keep only `src/p2p/quic/transport/packet.zig` (deleting all other files in `src/p2p/quic/`).

### D. RPC Server: HTTP JSON-RPC vs. gRPC RPC vs. WebSocket RPC
* **Active (HTTP Server)**: Standard JSON-RPC server over HTTP (`src/rpc/http_server.zig`).
* **Dead (gRPC RPC, WebSocket RPC)**:
  * **gRPC RPC**: Standalone gRPC listener. Unused.
  * **WebSocket RPC**: Unreferenced WebSocket dispatcher. Unused.
* **Verdict**: Retain HTTP JSON-RPC. Delete `grpc.zig` and `websocket.zig` in `src/rpc/`.

---

## 3. Proposed Changes

We will systematically delete dead files and update module roots to remove exports of deleted files.

### [Component: Storage]

#### [DELETE] [lsm](file:///Users/karan/sol2zig/src/storage/lsm)
#### [DELETE] [verkle](file:///Users/karan/sol2zig/src/storage/verkle)
#### [DELETE] [flatkv](file:///Users/karan/sol2zig/src/storage/flatkv)
#### [DELETE] [mmr](file:///Users/karan/sol2zig/src/storage/mmr)
#### [DELETE] [codestore](file:///Users/karan/sol2zig/src/storage/codestore)
#### [DELETE] [verkle_isolate.zig](file:///Users/karan/sol2zig/tests/verkle_isolate.zig)

#### [MODIFY] [mod.zig](file:///Users/karan/sol2zig/src/storage/mod.zig)
Remove imports/re-exports of `lsm`, `verkle`, `flatkv`, `mmr`, and `codestore`. Remove obsolete `test` blocks referring to them.

---

### [Component: Consensus]

#### [DELETE] [deferred_executor.zig](file:///Users/karan/sol2zig/src/consensus/deferred_executor.zig)
#### [DELETE] [fraud_proof.zig](file:///Users/karan/sol2zig/src/consensus/fraud_proof.zig)
#### [DELETE] [registry.zig](file:///Users/karan/sol2zig/src/consensus/registry.zig)

#### [MODIFY] [mod.zig](file:///Users/karan/sol2zig/src/consensus/mod.zig)
Remove imports and re-exports of `DeferredExecutor`, `FraudProofManager`, and `ValidatorRegistry`.

---

### [Component: P2P]

#### [DELETE] [grpc](file:///Users/karan/sol2zig/src/p2p/grpc)
#### [DELETE] [congestion.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/congestion.zig)
#### [DELETE] [connection.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/connection.zig)
#### [DELETE] [migration.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/migration.zig)
#### [DELETE] [recovery.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/recovery.zig)
#### [DELETE] [socket.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/socket.zig)
#### [DELETE] [stream.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/stream.zig)
#### [DELETE] [crypto](file:///Users/karan/sol2zig/src/p2p/quic/crypto)
#### [DELETE] [utils](file:///Users/karan/sol2zig/src/p2p/quic/utils)
#### [DELETE] [http3.zig](file:///Users/karan/sol2zig/src/p2p/quic/http3.zig)
#### [DELETE] [lib.zig](file:///Users/karan/sol2zig/src/p2p/quic/lib.zig)
#### [DELETE] [quic.zig](file:///Users/karan/sol2zig/src/p2p/quic/quic.zig)

#### [MODIFY] [peer.zig](file:///Users/karan/sol2zig/src/p2p/peer.zig)
Update the `Peer` struct to remove the mock `quicConn` and `quicStream` fields. Update `send` and `sendRaw` to directly enqueue UDP packets onto the server's UDP socket via `server.enqueueSend` instead of writing to a mock in-memory stream buffer. (This corrects the simulated transmit behavior and fixes a memory buildup issue!)

#### [MODIFY] [server.zig](file:///Users/karan/sol2zig/src/p2p/server.zig)
Update `handlePacket` to decode incoming packets using `zquic.transport.packet.Packet.decode` but attach raw UDP properties to the `Peer` without creating mock `Connection` and stream objects. Remove unused fields.

#### [MODIFY] [root.zig](file:///Users/karan/sol2zig/src/p2p/quic/root.zig)
Only re-export `transport.packet` (delete re-exports of `congestion`, `connection`, `stream`, `quic`, `http3`).

#### [MODIFY] [mod.zig](file:///Users/karan/sol2zig/src/p2p/mod.zig)
Remove gRPC re-export.

---

### [Component: RPC]

#### [DELETE] [grpc.zig](file:///Users/karan/sol2zig/src/rpc/grpc.zig)
#### [DELETE] [websocket.zig](file:///Users/karan/sol2zig/src/rpc/websocket.zig)
#### [DELETE] [proto](file:///Users/karan/sol2zig/src/rpc/proto)

#### [MODIFY] [mod.zig](file:///Users/karan/sol2zig/src/rpc/mod.zig)
Remove `GrpcServer` imports and re-exports.

---

## 4. Verification Plan

### Automated Verification
Run compile check:
```bash
zig build
```

Run test suite:
```bash
zig build test
```

### Manual Verification
Ensure that the node starts correctly in mining mode:
```bash
./zig-out/bin/zephyria start --network devnet --mine
```
Check that the simulated blockchain workflow benchmark executes correctly:
```bash
./zig-out/bin/blockchain_benchmark
```
