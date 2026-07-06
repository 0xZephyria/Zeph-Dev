# QUIC Transport Implementation — Zephyria Blockchain

## Background

The Zephyria P2P stack currently uses raw UDP sockets with a custom packet framing protocol. The `src/p2p/quic/` directory is a stub containing only a toy packet encode/decode struct — no real QUIC state machine, no TLS, no connection management.

Per the Mainnet Readiness Analysis, the network's P2P transport must move to QUIC to achieve:
- **Encrypted transport** (no MITM/eclipse attacks)
- **Multiplexed streams** (gossip, block, tx, votes on independent QUIC streams)
- **Stake-weighted rate limiting** at the QUIC connection level (Solana Gulf Stream model)
- **0-RTT reconnection** for known validators (sub-millisecond reconnect)

## Strategy: Pure-Zig, Firedancer-Inspired `fd_quic` Port

### Why NOT use a C binding to Firedancer's fd_quic directly

| Concern | Firedancer C binding | Our approach |
|---------|---------------------|--------------|
| Build complexity | fd_quic requires the entire Firedancer build system (bazel + fd_* runtime). Cannot be stripped without significant effort. | Pure Zig — zero C dependencies beyond libc |
| Memory model | fd_quic uses fd_wksp custom workspace arenas — incompatible with Zig's allocator interface | Zig allocator-compatible from day 1 |
| macOS / ARM64 support | Firedancer is Linux-only (uses io_uring, AF_XDP) | Cross-platform via posix sockets |
| Security audit surface | Importing entire C TLS/QUIC stack adds ~15k LoC of C to audit | Our Zig implementation is fully auditable |

### Design: Firedancer-Inspired Architecture in Zig

We implement the **same algorithmic core** as fd_quic but natively in Zig:

```
┌──────────────────────────────────────────────────────────┐
│                    P2P Server (server.zig)                │
│  UDP recv loop → QuicEndpoint.feedDatagram()             │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│              QuicEndpoint  (quic/endpoint.zig)            │
│  • Connection table (conn_id → QuicConn)                  │
│  • Stateless Reset Token generation                       │
│  • Initial packet dispatch → TLS handshake                │
│  • 1-RTT packet dispatch → stream multiplexer             │
└────────────────────┬─────────────────────────────────────┘
                     │
      ┌──────────────┴──────────────┐
      │                             │
┌─────▼──────────┐         ┌────────▼───────────────────────┐
│ TlsHandshake   │         │  QuicConn  (quic/conn.zig)     │
│ (quic/tls.zig) │         │  • Packet number space mgmt    │
│ • HKDF-SHA256  │         │  • ACK tracking (recv ranges)  │
│ • AES-128-GCM  │         │  • Stream map (id → QuicStream)│
│ • CHACHA20-Poly│         │  • Congestion control (CUBIC)  │
│ • Ed25519 cert │         └────────────┬───────────────────┘
└────────────────┘                      │
                               ┌────────▼───────────┐
                               │  QuicStream        │
                               │  (quic/stream.zig) │
                               │  • STREAM frames   │
                               │  • Flow control    │
                               │  • Ordered recv buf│
                               └────────────────────┘
```

## Proposed Changes

---

### Layer 1 — Cryptographic Primitives (QUIC Initial Key Derivation)

QUIC Initial packets are protected with keys derived from the QUIC version salt + connection ID using **HKDF-SHA256** and encrypted with **AES-128-GCM**. Zig's std.crypto has all needed primitives.

#### [MODIFY] [build.zig](file:///Users/karan/sol2zig/build.zig)
- Add `quic_mod` as a named module under `src/p2p/quic/`
- Wire `quic_mod` into `p2p_mod`
- No new C library dependencies (uses Zig `std.crypto` only)

---

### Layer 2 — QUIC Packet Codec

#### [MODIFY] [transport/packet.zig](file:///Users/karan/sol2zig/src/p2p/quic/transport/packet.zig)
- Full RFC 9000 long-header decode (Initial, Handshake, Retry, 0-RTT)
- Full RFC 9000 short-header decode (1-RTT with connection ID)
- Variable-length integer (QUIC VarInt) encode/decode
- Packet number encode/decode (header protection removal via AES-ECB mask)

#### [NEW] `src/p2p/quic/frames.zig`
- Frame type enum (PADDING, PING, ACK, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, BLOCKED, STREAM_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE)
- Frame serialize/deserialize

---

### Layer 3 — TLS 1.3 / QUIC Crypto Layer

#### [NEW] `src/p2p/quic/tls.zig`
Full TLS 1.3 QUIC integration (RFC 9001):

```zig
// Initial secret derivation
const QUIC_V1_SALT = [20]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                              0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

pub fn deriveInitialSecrets(conn_id: []const u8) InitialSecrets;
pub fn deriveHandshakeSecrets(transcript: *TranscriptHash) HandshakeSecrets;
pub fn derive1RttSecrets(transcript: *TranscriptHash) AppSecrets;
```

- HKDF-SHA256 key derivation (QUIC-specific label scheme per RFC 9001 §5)
- AES-128-GCM packet protection (Initial/Handshake)
- ChaCha20-Poly1305 support (optional, per peer negotiation)
- Header protection (AES-ECB mask generation per RFC 9001 §5.4)
- Ed25519 identity certificate (validator key reused as TLS certificate)
- Client Hello / Server Hello / Certificate / Finished message construction

---

### Layer 4 — Connection State Machine

#### [NEW] `src/p2p/quic/conn.zig`

State machine with 7 states (fd_quic-aligned):
```
IDLE → INITIAL → HANDSHAKE → ESTABLISHED → DRAINING → CLOSED
                                        ↘ PEER_CLOSE
```

Key fields:
- `src_conn_id: [20]u8` — our connection ID (random)
- `dst_conn_id: [20]u8` — peer's connection ID
- `crypto_state: TlsState` — in-progress TLS context
- `pn_space: [3]PacketNumberSpace` — Initial / Handshake / 1-RTT
- `streams: AutoHashMap(u64, *QuicStream)` — active streams
- `send_buf: CircularBuffer` — retransmit queue
- `recv_buf: AckRange` — ranges we've seen (for ACK frames)
- `max_data_local / remote: u64` — flow control
- `stake_weight: u64` — for server-side rate limiting

ACK management: sliding window bitmap (32 packets) + range list for sparse ACK frames.

---

### Layer 5 — Stream Multiplexer

#### [NEW] `src/p2p/quic/stream.zig`

```zig
pub const StreamId = u64;
pub const StreamDir = enum { client_bidi, server_bidi, client_uni, server_uni };

pub const QuicStream = struct {
    id: StreamId,
    send_offset: u64,
    recv_offset: u64,
    recv_buf: std.ArrayList(u8),  // ordered reassembly
    max_stream_data: u64,
    fin_received: bool,
    // ...
};
```

Reserved stream IDs for Zephyria protocol:
- Stream 0: **Handshake / Auth** (MsgCommitteeHandshake)
- Stream 4: **Gossip** (MsgStatus, MsgPeers, MsgPing/Pong)
- Stream 8: **Block propagation** (MsgNewBlock, MsgShred, MsgVote)
- Stream 12: **Transaction forwarding** (MsgTxBatch — Gulf Stream)

---

### Layer 6 — QUIC Endpoint (Connection Manager)

#### [NEW] `src/p2p/quic/endpoint.zig`

The `QuicEndpoint` replaces the raw `posix.socket_t` receive path in `server.zig`:

```zig
pub const QuicEndpoint = struct {
    allocator: std.mem.Allocator,
    sock: posix.socket_t,
    conns: AutoHashMap([20]u8, *QuicConn),   // dst_conn_id → conn
    token_map: AutoHashMap([16]u8, [32]u8),  // Stateless Reset tokens
    callbacks: EndpointCallbacks,
    tls_config: TlsConfig,                   // validator's Ed25519 key

    // fd_quic-style tile: process up to 64 datagrams per call
    pub fn serviceDatagram(self: *Self, buf: []const u8, from: std.net.Address) !void;
    pub fn sendPending(self: *Self) !void;    // flush outbound queue
    pub fn acceptStream(conn: *QuicConn, stream_id: u64) void;
    pub fn onStreamData(conn: *QuicConn, stream_id: u64, data: []const u8) void;
};
```

Stake-weighted rate limiting: `QuicConn.stake_weight` is set from `discovery.localNode.stakeAmount` on connection establishment. High-stake peers get higher burst allowance.

---

### Layer 7 — Integration: Replace UDP Raw Socket in Server

#### [MODIFY] [server.zig](file:///Users/karan/sol2zig/src/p2p/server.zig)

The `serverLoop` currently calls `posix.recvfrom()` directly. We will:

1. Add `quicEndpoint: ?*quic.QuicEndpoint` field to `Server`
2. In `start()`, initialize `QuicEndpoint` with the server's `sock` and validator Ed25519 identity key
3. In `serverLoop`, route received UDP datagrams through `quicEndpoint.serviceDatagram()` instead of directly to `handlePacket()`
4. Stream demux: stream-0 callbacks route to existing `handlePacket()` logic
5. Gulf Stream sends over stream-12 (unidirectional, low-latency)

The existing `Packet` framing is preserved within QUIC STREAM frames — no protocol change needed for upper layers.

#### [MODIFY] [gulf_stream.zig](file:///Users/karan/sol2zig/src/p2p/gulf_stream.zig)
- `drainBatch()` result is now sent over QUIC stream-12 instead of raw UDP
- Add `sendViaQuic(conn: *QuicConn, data: []const u8)` helper

#### [MODIFY] [mod.zig](file:///Users/karan/sol2zig/src/p2p/mod.zig)
- Export `QuicEndpoint`, `QuicConn`, `QuicStream`

#### [MODIFY] [quic/root.zig](file:///Users/karan/sol2zig/src/p2p/quic/root.zig)
- Export all submodules: `endpoint`, `conn`, `stream`, `tls`, `frames`, `transport`

---

### Layer 8 — Tests

#### [MODIFY] [src/p2p/tests.zig](file:///Users/karan/sol2zig/src/p2p/tests.zig)
Add QUIC-specific unit tests:
- `test "QUIC VarInt round-trip"` — variable-length integer codec
- `test "QUIC Initial key derivation"` — test vectors from RFC 9001 Appendix A
- `test "QUIC packet encode/decode Initial"` — end-to-end packet round-trip
- `test "QUIC TLS handshake simulation"` — client/server Initial exchange
- `test "QUIC stream reassembly"` — out-of-order STREAM frame reassembly
- `test "QUIC ACK range encoding"` — sparse ACK frame construction

#### [NEW] `src/p2p/quic/quic_test.zig`
Standalone QUIC tests using RFC 9001 Appendix A test vectors (hardcoded keys for deterministic verification).

---

## Open Questions

> [!IMPORTANT]
> **Q1: Firedancer C bindings vs Pure Zig?**
> The plan above implements a pure-Zig QUIC stack. Attempting to bind fd_quic from Firedancer requires compiling the entire Firedancer workspace (bazel-based, Linux-only), which is not feasible on macOS for our dev environment. The pure-Zig approach is recommended. Confirm if you want to pursue C bindings instead (would require Docker/Linux CI).

> [!IMPORTANT]
> **Q2: TLS Certificate Identity**
> For mutual TLS authentication, we need a certificate. Solana uses its **validator identity Ed25519 keypair** directly as the certificate (no CA chain). We'll do the same — the `identityKey` in `ServerConfig` becomes the QUIC TLS cert. **Confirm this approach.**

> [!NOTE]
> **Q3: Congestion Control Scope**
> Full CUBIC or BBR congestion control is ~800 LoC. For the first implementation, we'll use a simple pacer (token bucket at ~10 Gbps max rate per connection). Full congestion control can be added in a follow-up PR. Confirm if acceptable.

> [!NOTE]
> **Q4: 0-RTT Support**
> QUIC 0-RTT (early data) requires session tickets. This is an advanced feature. Phase 1 will be 1-RTT only (full TLS handshake every connection). 0-RTT can be added after the base stack is stable.

---

## File Summary

| File | Status | Purpose |
|------|--------|---------|
| `src/p2p/quic/transport/packet.zig` | MODIFY | Full RFC 9000 packet codec |
| `src/p2p/quic/frames.zig` | NEW | QUIC frame types & codec |
| `src/p2p/quic/tls.zig` | NEW | TLS 1.3 / QUIC crypto (RFC 9001) |
| `src/p2p/quic/conn.zig` | NEW | Connection state machine |
| `src/p2p/quic/stream.zig` | NEW | Stream multiplexer |
| `src/p2p/quic/endpoint.zig` | NEW | Connection manager / UDP tile |
| `src/p2p/quic/quic_test.zig` | NEW | RFC 9001 test vectors |
| `src/p2p/quic/root.zig` | MODIFY | Re-export all submodules |
| `src/p2p/server.zig` | MODIFY | Wire QUIC endpoint into receive loop |
| `src/p2p/gulf_stream.zig` | MODIFY | Send TXs over QUIC stream-12 |
| `src/p2p/mod.zig` | MODIFY | Export new QUIC types |
| `build.zig` | MODIFY | Add quic_test artifact |

**New LoC estimate**: ~3,000–3,500 lines of well-documented Zig  
**New C dependencies**: None  
**New system library deps**: None (uses `std.crypto` AES-GCM/ChaCha20/SHA256/HKDF)

---

## Verification Plan

### Automated Tests
```bash
# QUIC unit tests (RFC 9001 test vectors)
zig build test-p2p

# Standalone QUIC test suite  
zig test src/p2p/quic/quic_test.zig

# Full build
zig build
```

### Manual Verification
1. Start two Zephyria nodes and verify QUIC handshake completes (log: "QUIC: 1-RTT established with peer X")
2. Wireshark/tcpdump capture shows UDP traffic (not plaintext Zephyria framing)
3. Benchmark: `zig build bench-blockchain` should show same or better throughput after QUIC switch
