# Zephyria: P2P Network Architecture for 1M+ TPS

This document defines the production-grade Peer-to-Peer (P2P) network architecture required for Zephyria to sustain 1,000,000+ Transactions Per Second (TPS) while completely mitigating Distributed Denial of Service (DDoS) attacks against known block leaders (the Gulf Stream problem).

To achieve linear scaling, the network must abandon traditional gossip protocols and adopt a structured, hardware-accelerated, and stake-weighted routing topology.

---

## 1. The Core Problem: The Gulf Stream Paradox
Zephyria uses **Gulf Stream** to forward transactions directly to the upcoming block leader, eliminating mempool gossip bandwidth overhead. However, this reveals the leader's IP address ahead of time.

*   **The Threat**: An attacker can rent a botnet to flood the upcoming leader (e.g., 100 Gbps of UDP garbage). The leader's NIC (Network Interface Card) saturates, dropping legitimate consensus votes and transactions. The leader misses their slot, degrading network throughput.
*   **The Goal**: The leader must be able to receive 1M TPS of valid transactions while flawlessly ignoring 100 Gbps of invalid DDoS traffic, with zero CPU impact.

---

## 2. The DDoS Defense Architecture (Stake-Weighted QoS)

To survive DDoS attacks when the leader is known, Zephyria implements **Stake-Weighted Quality of Service (QoS)** combined with hardware-level packet filtering.

### 2.1 Private Validator overlay (The "Inner Ring")
Validators **never** expose their consensus ports to the public internet.
*   **Validator-to-Validator (V2V) Connection**: Validators establish persistent, mutually authenticated QUIC tunnels (using TLS 1.3 with their registered BLS public keys) only with other staked validators.
*   **IP Masking**: The public IP of a validator is hidden behind a fleet of RPC/Proxy nodes.

### 2.2 Stake-Weighted Packet Prioritization
When the leader's NIC receives packets, it must instantly know which packets to process and which to drop.
1.  **QUIC Connection IDs**: The leader assigns specific QUIC Connection IDs to peers based on their staked weight.
2.  **eBPF / XDP Hardware Filtering**: Zephyria deploys an eXpress Data Path (XDP) layer directly on the Linux kernel (running on the NIC before packets reach the Zig application). 
    *   The XDP program inspects the QUIC packet header.
    *   If the Connection ID maps to a top-staked validator, it passes instantly.
    *   If the Connection ID belongs to an unstaked IP spamming traffic, the NIC drops the packet in nanoseconds (handling 100s of Gbps of DDoS with near-zero CPU usage).

### 2.3 The RPC "Meat Shield" (Gulf Stream Relays)
How do normal users send their 1M TPS to the leader?
*   Users send TXs to public RPC nodes (e.g., Infura/Alchemy equivalents for Zephyria).
*   RPC nodes have staked ZEE (or pay validators for peering agreements).
*   RPC nodes batch user TXs, sign the batch, and forward it to the leader via their high-priority QUIC tunnel. 
*   **Result**: The leader only talks to 100 authenticated RPC/Validator peers, never to 1,000,000 individual user IPs.

---

## 3. Achieving 1M TPS with Linear Scaling (Turbine & QUIC)

Traditional blockchains gossip blocks: Node A sends the 150MB block to 10 peers, who send it to 10 peers. This creates an exponential bandwidth explosion (150MB * 10 = 1.5GB outbound per node per second).

To linearly scale to 1M TPS, Zephyria implements:

### 3.1 UDP Erasure Coding (Turbine Protocol)
*   **Shredding**: A 150MB block is chopped into 1,000 UDP packets (shreds). 
*   **Reed-Solomon Recovery**: Parity shreds are generated (e.g., 1,000 data + 200 parity). If the network drops 15% of the packets, the receiving node mathematically reconstructs the missing data without ever asking for a retransmission. This eliminates TCP ACKs and latency jitter.

### 3.2 Deterministic Tree Propagation
Instead of random gossip, the network forms a mathematically perfect tree for every block based on the stake weights of validators.
*   **Layer 0 (Leader)**: Sends Shreds 1-10 to Node B, Shreds 11-20 to Node C. (Leader only uses 150MB bandwidth total).
*   **Layer 1 (Nodes B & C)**: Exchange their shreds with each other and push them down to Layer 2.
*   **Linear Scaling**: Bandwidth usage per node is strictly constrained to `Block_Size * Fanout_Ratio_Log`, completely eliminating network saturation. As hardware bandwidth increases (e.g., 1Gbps -> 10Gbps -> 100Gbps), TPS scales linearly.

### 3.3 Zero-Copy Socket I/O (`io_uring`)
*   The `src/p2p/server.zig` event loop must bypass the standard POSIX `recvfrom`/`sendto` syscalls.
*   By utilizing Linux `io_uring` and `sendmmsg` (send multiple messages), Zephyria batches kernel interactions, allowing single consumer CPUs to push millions of UDP packets per second directly from user-space memory to the NIC hardware ring buffer.

---

## 4. Summary of Zephyria Network Feature Set

To hit the 1M TPS target alongside the existing zero-conflict DAG executor, the P2P layer must implement these exact physical specifications:

1.  **Transport**: 100% QUIC (UDP) for consensus and data plane. Zero TCP.
2.  **Topology**: Deterministic Stake-Weighted Tree (Turbine) for blocks. Gulf Stream for transactions.
3.  **DDoS Mitigation**: Local XDP/eBPF kernel-bypass packet filtering based on authenticated QUIC Connection IDs.
4.  **Error Correction**: Configurable Reed-Solomon erasure coding (FEC) for all shredded block propagation.
5.  **Peering**: Private V2V overlay. Staked Proxy/RPC nodes handle all public ingress.
6.  **I/O Operations**: `io_uring` exclusively for all socket networking to prevent CPU syscall saturation.

When these network features are coupled with Zephyria's zero-conflict `dag_executor` and TigerBeetle-style `ZephyrDB`, the system mathematically guarantees the ability to saturate standard 10Gbps consumer hardware, pushing past 1M TPS seamlessly.
