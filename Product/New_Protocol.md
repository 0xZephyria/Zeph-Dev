# Zephyria: Z-HTTP & Sphynx Mixnet (Anonymous Protocol)

This document defines the architectural blueprint for Zephyria's custom, fully anonymous HTTP-like protocol where nodes are completely untraceable and IP addresses are never revealed. We achieve this by building an **Overlay Network** running on top of the standard internet, utilizing a **Mixnet** combined with **Onion Routing**.

## 1. Identity over Location (Cryptographic Addressing)
Instead of binding to an IPv4/IPv6 address, a node creates a permanent Ed25519 or secp256k1 keypair. 
* **The Address:** A node's address is strictly the hash of its public key (e.g., `znp://[PubKeyHash]`). 
* **The Concept:** You never ask "What is the IP of Node A?" Instead, you ask the network, "Can you route this encrypted packet to `PubKeyHash`?"

## 2. The Sphynx Packet Format (Zero Metadata)
To prevent ISPs and global passive adversaries from performing traffic analysis (e.g., looking at packet sizes and timing to guess who is talking to whom), we use the **Sphinx Packet Format** (used natively by Nym and the Lightning Network).
* **Indistinguishability:** Every single packet in the protocol is padded to the exact same size (e.g., 1KB). 
* **Cover Traffic:** Nodes constantly send dummy "noise" packets to random nodes even when they have no real data to send. This means an ISP just sees a constant, flat stream of encrypted noise going in and out of your router. They cannot tell when a real transaction is happening.

## 3. Onion-Routed Mixnets (The Core Transport)
When Node A wants to send a custom HTTP-like request to Node B, it **never** connects directly.
1. Node A selects a random 3-hop circuit from the network: `Guard -> Mix 1 -> Exit/Destination`.
2. Node A encrypts the payload 3 times (like layers of an onion). 
3. **The Guard Node** only knows Node A's IP address and Mix 1's IP. It peels the first layer of encryption.
4. **Mix 1** only knows the Guard and the Exit. It peels the second layer. It also briefly buffers and shuffles packets (Mixing) to destroy timing correlations.
5. **The Destination (Node B)** only knows it received a packet from Mix 1. **Node B never learns Node A's IP address, and Node A never learns Node B's IP address.**

## 4. Distributed Hash Table (DHT) for Rendezvous
If there are no IPs, how does Node A find Node B to establish the circuit?
* We use a **Kademlia DHT** (like BitTorrent or IPFS).
* When Node B boots up, it picks a few random "Introduction Nodes" and sets up an onion circuit to them.
* Node B then publishes a signed record to the DHT: *"If you want to reach [PubKeyHash], send your onion packets to Introduction Node X."*
* When Node A wants to connect to Node B, it queries the DHT for Node B's Intro Nodes, and then builds an onion circuit to that Intro Node. **Both nodes remain perfectly hidden.**

## 5. Z-HTTP: The Custom Anonymous Application Layer
Standard HTTP is terrible for anonymity because it leaks User-Agents, accepted languages, operating systems, and timezones in plaintext headers. We will build a custom binary protocol over our Onion transport.

* **Streams over Datagrams:** The Mixnet operates using noisy UDP datagrams (perfect for your existing `io_uring` and QUIC setup). We multiplex streams over these datagrams.
* **Binary RPC Formulation:** Instead of string-based headers (`GET /path HTTP/1.1`), we use a tightly packed binary format (like Cap'n Proto or FlatBuffers).
* **Format Structure:**
  ```zig
  const ZHttpRequest = struct {
      stream_id: u32,             // Ephemeral ID to link request/response
      method: u8,                 // 0 = GET, 1 = POST, 2 = RPC_CALL
      resource_hash: [32]u8,      // Blake3 hash of the endpoint (e.g., hash("/submit_tx"))
      payload_len: u16,
      payload: []const u8,        // The encrypted application data
  };
  ```

## 6. Real-World Node Operation Lifecycle
1. **Bootup:** The node starts. It loads its `secret_key`. It checks its local DHT cache.
2. **Obfuscation (Pluggable Transports):** It wraps all its outbound UDP traffic in something that looks exactly like standard WebRTC video call traffic. Firewalls and ISPs let it through, thinking the user is just on a Zoom call.
3. **Integration:** The node starts pulling blocks and mempool data through its onion circuits. Because it uses Erasure Coding (Turbine) over the Mixnet, dropped packets are automatically mathematically recovered without needing retransmissions.
4. **Result:** The node is running a full copy of the chain, submitting 1M TPS, and validating blocks, but to the outside world, the physical server is completely invisible. It has no open ports, and its IP cannot be found or DDoS'd.

## Next Steps for Implementation
To build this in `sol2zig/src/p2p/`, the following core modules must be developed:
1. `src/p2p/sphinx.zig`: The cryptographic packet wrapper ensuring all packets look identical.
2. `src/p2p/mixnet.zig`: The circuit builder and packet shuffler/buffer.
3. `src/p2p/zhttp.zig`: The binary, metadata-stripped HTTP alternative that runs inside the mixnet.
