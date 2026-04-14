# Zephyria Block Explorer — Full Context for AI Code Generation

> **Purpose**: This document provides everything needed to build a complete, production-quality block explorer for the **Zephyria blockchain**. It covers the RPC API, data structures, chain configuration, and exact JSON response formats. Use this to build a Next.js or Vite web application that connects to a running Zephyria node.

---

## 1. Chain Overview

| Property | Value |
|---|---|
| **Chain Name** | Zephyria |
| **Chain ID** | `99999` (devnet), `91919191` (testnet) |
| **Consensus** | Loom Genesis Adaptive PoS (BLS12-381 signatures) |
| **Block Time** | 400ms |
| **Finality** | Single-slot (instant, 1-block) |
| **VM** | RISC-V RV32EM (not EVM — but RPC is Ethereum-compatible) |
| **State** | Verkle Trie (IPA commitments) |
| **Storage** | ZephyrDB (custom LSM-tree) |
| **Execution** | DAG-based parallel execution (zero-conflict isolated accounts) |
| **Target TPS** | 1,000,000+ |
| **Native Token** | ZEE |
| **Denomination** | Wei (1 ZEE = 10^18 wei) |
| **Client Version** | `Zephyria/v0.1.0/zig-edition` |
| **Default RPC Port** | `8545` (HTTP JSON-RPC) |
| **Default P2P Port** | `30303` (UDP) |

---

## 2. JSON-RPC Connection

The node exposes a **standard Ethereum-compatible JSON-RPC 2.0** API over HTTP.

### Connection Details
```
URL:     http://localhost:8545
Method:  POST
Headers: Content-Type: application/json
CORS:    Enabled (Access-Control-Allow-Origin: *)
```

### Request Format
```json
{
  "jsonrpc": "2.0",
  "method": "eth_blockNumber",
  "params": [],
  "id": 1
}
```

### Response Format
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0xa"
}
```

### Batch Requests Supported
Send an array of JSON-RPC objects and receive an array of responses.

### Rate Limiting
- 100 requests per burst capacity
- 40 requests/second refill rate
- 1000 max requests per TCP connection (keep-alive)

---

## 3. Complete RPC API Reference

### 3.1 Chain / Network Info

| Method | Params | Returns | Description |
|---|---|---|---|
| `eth_chainId` | `[]` | `"0x1869f"` (99999) | Chain ID in hex |
| `net_version` | `[]` | `"99999"` | Network ID as decimal string |
| `web3_clientVersion` | `[]` | `"Zephyria/v0.1.0/zig-edition"` | Client version string |
| `eth_protocolVersion` | `[]` | `"0x44"` (68) | Protocol version |
| `net_listening` | `[]` | `true` | Always true when running |
| `net_peerCount` | `[]` | `"0x0"` | Connected peer count (hex) |
| `eth_syncing` | `[]` | `false` | Block-aware sync state (returns object if syncing) |
| `eth_mining` | `[]` | `false` | PoS — no mining |
| `eth_hashrate` | `[]` | `"0x0"` | Always 0 (PoS) |

### 3.2 Block Queries

| Method | Params | Returns | Description |
|---|---|---|---|
| `eth_blockNumber` | `[]` | `"0xa"` | Latest block number (hex) |
| `eth_getBlockByNumber` | `[blockTag, fullTx]` | Block object or `null` | Get block by number |
| `eth_getBlockByHash` | `[hash, fullTx]` | Block object or `null` | Get block by hash |
| `eth_getBlockTransactionCountByNumber` | `[blockTag]` | `"0x5"` or `null` | TX count in block |
| `eth_getBlockTransactionCountByHash` | `[hash]` | `"0x5"` or `null` | TX count in block |
| `eth_getUncleCountByBlockNumber` | `[blockTag]` | `"0x0"` | Always 0 (PoS) |
| `eth_getUncleCountByBlockHash` | `[hash]` | `"0x0"` | Always 0 (PoS) |

**Block tags**: `"latest"`, `"earliest"`, or hex block number like `"0xa"`.

#### Block Object Response Format
```json
{
  "number": "0xa",
  "hash": "0xabc...",
  "parentHash": "0xdef...",
  "stateRoot": "0x123...",
  "transactionsRoot": "0x456...",
  "receiptsRoot": "0x000...",
  "miner": "0xcoinbase_address...",
  "timestamp": "0x65f1a2b0",
  "gasLimit": "0x1c9c380",
  "gasUsed": "0x5208",
  "baseFeePerGas": "0x430e23400",
  "difficulty": "0x0",
  "totalDifficulty": "0x0",
  "size": "0x200",
  "extraData": "0x...",
  "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
  "mixHash": "0x000...000",
  "nonce": "0x0000000000000000",
  "logsBloom": "0x00000...00000",
  "uncles": [],
  "withdrawals": [],
  "withdrawalsRoot": "0x000...000",
  "transactions": [
    "0xtx_hash_1...",
    "0xtx_hash_2..."
  ]
}
```

When `fullTx = true`, `transactions` contains full transaction objects instead of hashes:
```json
{
  "hash": "0x...",
  "nonce": "0x0",
  "blockHash": "0x...",
  "blockNumber": "0xa",
  "transactionIndex": "0x0",
  "from": "0xsender...",
  "to": "0xreceiver...",
  "value": "0xde0b6b3a7640000",
  "gas": "0x5208",
  "gasPrice": "0x4a817c800",
  "input": "0x",
  "type": "0x2",
  "chainId": "0x1869f",
  "v": "0x1",
  "r": "0x...",
  "s": "0x..."
}
```

### 3.3 Transaction Queries

| Method | Params | Returns | Description |
|---|---|---|---|
| `eth_getTransactionByHash` | `[txHash]` | TX object or `null` | Look up TX by hash |
| `eth_getTransactionByBlockNumberAndIndex` | `[blockTag, index]` | TX object or `null` | TX at index in block by number |
| `eth_getTransactionByBlockHashAndIndex` | `[blockHash, index]` | TX object or `null` | TX at index in block by hash |
| `eth_getTransactionReceipt` | `[txHash]` | Receipt object or `null` | Get TX receipt |
| `eth_getTransactionCount` | `[address, blockTag]` | `"0x5"` | Account nonce |

#### Transaction Receipt Response Format
```json
{
  "transactionHash": "0x...",
  "transactionIndex": "0x0",
  "blockHash": "0x...",
  "blockNumber": "0xa",
  "from": "0xsender...",
  "to": "0xreceiver...",
  "contractAddress": null,
  "cumulativeGasUsed": "0x5208",
  "gasUsed": "0x5208",
  "effectiveGasPrice": "0x4a817c800",
  "status": "0x1",
  "type": "0x2",
  "root": "0x",
  "logs": [],
  "logsBloom": "0x00000...00000"
}
```
- When `to` is `null` (contract creation), `contractAddress` contains the deployed contract address.
- `status`: `"0x1"` = success (currently always success).

### 3.4 Account / State Queries

| Method | Params | Returns | Description |
|---|---|---|---|
| `eth_getBalance` | `[address, blockTag]` | `"0xde0b6b3a7640000"` | Account balance in wei (hex) |
| `eth_getCode` | `[address, blockTag]` | `"0x6080..."` or `"0x"` | Contract bytecode |
| `eth_getStorageAt` | `[address, slot, blockTag]` | `"0x..."` | Storage value at slot |
| `eth_accounts` | `[]` | `[]` | Always empty (no managed accounts) |

**IMPORTANT**: `eth_getBalance` supports historical queries via block tag. The node has `HistoricalState` for time-travel queries to past blocks.

### 3.5 Transaction Submission

| Method | Params | Returns | Description |
|---|---|---|---|
| `eth_sendRawTransaction` | `[signedTxHex]` | `"0xtx_hash..."` | Submit signed TX |
| `eth_sendTransaction` | `[txObject]` | `"0xtx_hash..."` | Sign + submit (devnet only) |
| `eth_estimateGas` | `[callObject]` | `"0x5208"` | Estimate gas (with VM simulation) |
| `eth_gasPrice` | `[]` | `"0x4a817c800"` | Computed from latest block base_fee + 2 Gwei priority fee |
| `eth_maxPriorityFeePerGas` | `[]` | `"0x77359400"` | 2 Gwei |
| `eth_feeHistory` | `[blockCount, newestBlock, percentiles]` | Fee history object | Historical fee data |
| `eth_call` | `[callObject, blockTag]` | `"0xresult..."` | Simulate contract call (read-only) |

### 3.6 Log and Filter Methods

| Method | Params | Returns | Description |
|---|---|---|---|
| `eth_getLogs` | `[filterObject]` | `[logObjects]` | Scan blocks for logs matching address/topic filter (capped at 10K block range) |
| `eth_newFilter` | `[filterObject]` | `"0xfilter_id"` | Create a log filter |
| `eth_newBlockFilter` | `[]` | `"0xfilter_id"` | Create a block filter to track new blocks |
| `eth_getFilterChanges` | `[filterId]` | `[hashes]` or `[logs]` | Poll filter for new events since last poll |
| `eth_getFilterLogs` | `[filterId]` | `[logObjects]` | Get all logs matching a filter |
| `eth_uninstallFilter` | `[filterId]` | `true`/`false` | Remove a filter |

#### Filter Object
```json
{
  "fromBlock": "0x1",
  "toBlock": "latest",
  "address": "0xcontract_address...",
  "topics": ["0xevent_signature..."]
}
```

### 3.7 Utility Methods

| Method | Params | Returns | Description |
|---|---|---|---|
| `web3_sha3` | `["0xdata..."]` | `"0xhash..."` | Keccak256 hash of input data |

### 3.8 Zephyria-Specific RPC Methods (Custom Namespace)

These are **unique to Zephyria** and should be featured in the explorer:

#### `zeph_getDAGMetrics`
Returns **live** DAG parallel execution pipeline metrics from the actual mempool.
```json
{
  "pipeline": "dag_first",
  "executionModel": "parallel_isolated_accounts",
  "conflictResolution": "credit_receipts",
  "accountTypes": 8,
  "storageIsolation": "one_slot_one_account",
  "targetTPS": 1000000,
  "maxExecutionLanes": 64,
  "live": {
    "totalVertices": 142,
    "activeLanes": 38,
    "totalAdded": 50420,
    "totalRejected": 12,
    "totalEvicted": 5,
    "gcEvicted": 2,
    "duplicateRejected": 8,
    "rateLimited": 0,
    "nonceRejected": 3,
    "gasPriceRejected": 1,
    "replacementCount": 7,
    "bloomCount": 50432,
    "maxShardLoad": 12,
    "hotShardPremiumApplied": 0
  }
}
```

#### `zeph_getThreadInfo`
Returns consensus thread/tier information **with runtime data**.
```json
{
  "consensusProtocol": "loom_genesis",
  "signatureScheme": "BLS12-381",
  "finality": "single_slot",
  "slotsPerEpoch": 1024,
  "uptimeSeconds": 3600,
  "currentBlock": 1200,
  "connectedPeers": 12,
  "avgBlockTimeMs": 400,
  "tiers": [
    { "name": "FullBFT", "validatorRange": "1-100" },
    { "name": "CommitteeLoom", "validatorRange": "101-2000" },
    { "name": "FullLoom", "validatorRange": "2001+" }
  ]
}
```

#### `zeph_getAccountTypes`
Returns the isolated account type taxonomy.
```json
{
  "model": "isolated_accounts",
  "parallelism": "zero_conflict_by_construction",
  "types": [
    { "id": 0, "name": "EOA", "description": "Externally Owned Account", "keyDerivation": "keccak256(address)" },
    { "id": 1, "name": "ContractRoot", "description": "Contract metadata and nonce", "keyDerivation": "keccak256(address || 0x01)" },
    { "id": 2, "name": "Code", "description": "Contract bytecode (immutable)", "keyDerivation": "keccak256(address || 0x02)" },
    { "id": 3, "name": "Config", "description": "Contract configuration", "keyDerivation": "keccak256(address || 0x03)" },
    { "id": 4, "name": "StorageCell", "description": "Per-slot isolated storage", "keyDerivation": "keccak256(address || slot)" },
    { "id": 5, "name": "DerivedState", "description": "Per-user derived storage", "keyDerivation": "keccak256(user || contract || slot)" },
    { "id": 6, "name": "Vault", "description": "Contract balance holder", "keyDerivation": "keccak256(vault || address)" },
    { "id": 7, "name": "System", "description": "Protocol-level system account", "keyDerivation": "fixed prefix" }
  ],
  "sdkBindings": "DerivedStorage, VaultAccess, GlobalAccumulator, StorageCellRef, AccountScheme"
}
```

#### `zeph_getNodeInfo`
Comprehensive node identity and architecture info.
```json
{
  "client": "Zephyria/v0.1.0/zig-edition",
  "chainId": "0x1869f",
  "networkId": "99999",
  "genesisHash": "0xabc...",
  "headBlock": "0x4b0",
  "headHash": "0xdef...",
  "headTimestamp": "0x65f1a2b0",
  "uptimeSeconds": 3600,
  "protocols": ["eth/68", "zeph/1"],
  "peerCount": 12,
  "execution": "RISC-V VM (Zephyr)",
  "stateDB": "Verkle Trie",
  "consensus": "Loom",
  "mempool": "DAG-Based Sharded"
}
```

#### `zeph_getMempoolStats`
Combined DAG + legacy mempool statistics.
```json
{
  "dag": {
    "pending": 142,
    "activeSenders": 38,
    "totalAdmitted": 50420,
    "totalRejected": 12,
    "totalEvicted": 5,
    "gcEvicted": 2,
    "duplicates": 8,
    "rateLimited": 0,
    "replacements": 7,
    "bloomFilterEntries": 50432,
    "maxShardLoad": 12,
    "shardCount": 256
  },
  "legacy": {
    "pending": 5,
    "rejected": 0,
    "evicted": 0,
    "bloomEntries": 5
  },
  "totalPending": 147,
  "primaryPool": "dag"
}
```

#### `zeph_getMempoolContent`
Pending transactions grouped by sender (like `txpool_content`).
```json
{
  "pending": {
    "0xsender1...": [
      { "nonce": "0x0", "gasPrice": "0x4a817c800", "gasLimit": "0x5208", "value": "0xde0b6b3a7640000", "to": "0x...", "dataSize": 0 }
    ]
  },
  "txCount": 5
}
```

#### `zeph_getBlockProducerInfo`
Block producer configuration and gas info.
```json
{
  "blockGasLimit": "0x1c9c380",
  "minGasPrice": "0x3b9aca00",
  "baseFeeEnabled": true,
  "latestBaseFee": "0x430e23400",
  "latestGasUsed": "0x5208",
  "latestGasLimit": "0x1c9c380",
  "coinbase": "0xcoinbase...",
  "executionEngine": "parallel_wave_executor",
  "vmTarget": "RISC-V RV32IM",
  "maxContractSize": 49152
}
```

#### `zeph_getPeers`
Connected P2P peers.
```json
{
  "peers": [
    { "id": "abc123", "connected": true }
  ],
  "count": 12,
  "maxPeers": 50
}
```

#### `zeph_getVMStats`
VM architecture and optimization details.
```json
{
  "vmArchitecture": "RISC-V RV32IM",
  "executorType": "threaded_interpreter",
  "features": "pre-decoded insn cache, per-block gas, basic block analysis, zero-copy SLOAD/SSTORE",
  "callDepthLimit": 1024,
  "maxInitcodeSize": 49152,
  "codeCache": { "type": "LRU", "maxEntries": 100, "keyType": "code_hash", "valueType": "DecodedInsn[]" },
  "optimizations": {
    "threadedDispatch": true,
    "basicBlockGas": true,
    "superInstructions": true,
    "zeroCopySyscalls": true,
    "reentryGuards": true,
    "eip3860Metering": true
  }
}
```

#### `zeph_getShardDistribution`
Per-shard breakdown of DAG mempool load.
```json
{
  "shards": [
    { "id": 42, "vertices": 15, "gas": 315000 },
    { "id": 170, "vertices": 8, "gas": 168000 }
  ],
  "totalShards": 256,
  "activeShards": 38,
  "totalVertices": 142,
  "maxShardLoad": 15,
  "avgShardLoad": 3
}
```

#### `zeph_getConfig`
Node runtime configuration.
```json
{
  "chain": { "chainId": 99999, "blockGasLimit": 30000000 },
  "txPool": { "maxPoolSize": 10000, "minGasPrice": "0x3b9aca00", "replacementBumpPct": 10 },
  "dagMempool": { "maxTxsPerLane": 256, "maxTotalVertices": 500000, "shardCount": 256, "minGasPrice": "0x3b9aca00" },
  "vm": { "maxCallDepth": 1024, "maxInitcodeSize": 49152, "codeCacheSize": 100 }
}
```

#### `zeph_getExecutorStats`
Parallel executor performance.
```json
{
  "type": "parallel_wave_executor",
  "vmEnabled": true,
  "latestBlock": {
    "blockNumber": 1200,
    "txCount": 42,
    "gasUsed": "0x1e8480",
    "gasLimit": "0x1c9c380",
    "gasUtilizationPct": 6
  },
  "config": { "blockGasLimit": 60000000, "maxThreads": 16 }
}
```

#### `zeph_getStateMetrics`
Verkle trie storage metrics.
```json
{
  "type": "verkle_trie",
  "stateRoot": "0x...",
  "totalNodes": 15420,
  "internalNodes": 3100,
  "leafNodes": 12320,
  "totalValues": 8500,
  "treeDepth": 12,
  "backend": "RocksDB-compatible",
  "proofType": "Verkle (IPA commitment)"
}
```

#### `zeph_getChainMetrics`
Chain-level performance from recent blocks.
```json
{
  "headBlock": 1200,
  "chainId": 99999,
  "sampleBlocks": 10,
  "totalTransactions": 420,
  "totalGasUsed": "0x12345",
  "blockTimes": [1, 1, 1, 1, 1, 1, 1, 1, 1],
  "avgTPS": 42,
  "avgGasPerBlock": 1234,
  "avgTxPerBlock": 42,
  "currentBaseFee": "0x430e23400"
}
```

#### `zeph_pendingTransactions`
All pending transactions with full details (like `txpool_inspect`).
```json
[
  {
    "hash": "0x...",
    "from": "0xsender...",
    "to": "0xreceiver...",
    "nonce": "0x0",
    "value": "0xde0b6b3a7640000",
    "gasPrice": "0x4a817c800",
    "gas": "0x5208",
    "input": "0x"
  }
]
```

#### `zeph_compileEOF`
Compiles FORGE source code via forgec and returns bytecode.
```json
// Request params: ["pragma solidity ^0.8.0; contract Hello { ... }"]
// Response:
{
  "success": true,
  "contracts": [
    { "name": "/tmp/zephyria_compile.sol:Hello", "bytecode": "6080..." }
  ]
}
```

---

## 4. Core Data Structures

### Address
20 bytes, hex-encoded with `0x` prefix: `"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"`

### Hash
32 bytes, hex-encoded with `0x` prefix: `"0xabc123..."`

### Block Header Fields
| Field | Type | Description |
|---|---|---|
| `parent_hash` | Hash | Previous block hash |
| `number` | u64 | Block height |
| `time` | u64 | Unix timestamp |
| `verkle_root` | Hash | State root (Verkle trie commitment) |
| `tx_hash` | Hash | Transactions root |
| `coinbase` | Address | Block producer address |
| `extra_data` | bytes | Arbitrary data (typically empty) |
| `gas_limit` | u64 | Block gas limit (default: 30,000,000) |
| `gas_used` | u64 | Total gas consumed |
| `base_fee` | u256 | EIP-1559 base fee per gas |

### Transaction Fields
| Field | Type | Description |
|---|---|---|
| `nonce` | u64 | Sender's transaction count |
| `gas_price` | u256 | Gas price in wei |
| `gas_limit` | u64 | Max gas for this TX |
| `from` | Address | Sender address |
| `to` | ?Address | Receiver (null for contract creation) |
| `value` | u256 | Wei transferred |
| `data` | bytes | Calldata / initcode |
| `v`, `r`, `s` | u256 | ECDSA signature components |

---

## 5. Genesis Accounts (Devnet)

The devnet pre-funds these accounts for testing:

| Address | Balance | Purpose |
|---|---|---|
| `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` derived | 100,000 ZEE | Default devnet validator |
| (auto-generated) | 100,000 ZEE | Auto-generated on `zephyria start --mine` |

The explorer should query `eth_getBalance` for any address to check balances.

---

## 6. Block Explorer Feature Requirements

### 6.1 Dashboard / Home Page
- **Latest block number** (poll `eth_blockNumber` every 400ms or 1s)
- **Chain ID** and **network name** (from `eth_chainId`)
- **Client version** (from `web3_clientVersion`)
- **Peer count** (from `net_peerCount`)
- **Latest blocks feed** (stream of last ~20 blocks with number, hash, tx count, gas used, timestamp)
- **Latest transactions feed** (stream of recent TXs with hash, from, to, value, status)
- **DAG metrics panel** (from `zeph_getDAGMetrics`) — show TPS target, execution lanes, account model
- **Consensus info panel** (from `zeph_getThreadInfo`) — show consensus tier, finality type, BLS scheme

### 6.2 Block Detail Page (`/block/:number` or `/block/:hash`)
- Fetch via `eth_getBlockByNumber` with `fullTx=true`
- Display all header fields: number, hash, parent hash, state root, miner, timestamp, gas limit/used, base fee
- **Transaction list table**: hash, from, to, value, gas, status
- Time since previous block (computed from timestamps)
- Block size
- Navigation: previous/next block links

### 6.3 Transaction Detail Page (`/tx/:hash`)
- Fetch via `eth_getTransactionByHash` + `eth_getTransactionReceipt`
- Display: hash, status (success/fail), block number, from, to, value, gas price, gas used, effective gas price, nonce, input data
- For contract creation: show deployed contract address from receipt
- Signature fields: v, r, s

### 6.4 Address Detail Page (`/address/:address`)
- **Balance**: `eth_getBalance(address, "latest")` — display in ZEE (value / 10^18) and wei
- **Nonce / TX count**: `eth_getTransactionCount(address, "latest")`
- **Contract code**: `eth_getCode(address, "latest")` — if non-empty, mark as "Contract"
- **Account type indicator**: EOA vs. Contract
- **Transaction history**: Iterate recent blocks and filter TXs by from/to matching the address (or build a local index)

### 6.5 Search
- Search by: block number, block hash, TX hash, address
- Auto-detect input type (20 bytes = address, 32 bytes = hash, number = block)

### 6.6 Zephyria-Specific Pages

#### Network / Architecture Page
- Display `zeph_getNodeInfo` — client version, chain ID, genesis hash, uptime, protocols, architecture stack
- Display `zeph_getThreadInfo` — consensus protocol, finality, connected peers, block production rate
- Display `zeph_getAccountTypes` — account model diagram with 8 account types and key derivation schemes
- Display `zeph_getVMStats` — VM architecture, optimization flags, code cache stats

#### Mempool Page
- **Live mempool stats** from `zeph_getMempoolStats` — DAG vs legacy pool comparison
- **Pending transactions table** from `zeph_pendingTransactions` — hash, from, to, value, gas
- **Mempool content grouped by sender** from `zeph_getMempoolContent`
- **Shard distribution heatmap** from `zeph_getShardDistribution` — 256-shard load visualization

#### Node Dashboard Page
- **Node info card** from `zeph_getNodeInfo` — uptime, peer count, architecture
- **Block producer info** from `zeph_getBlockProducerInfo` — coinbase, gas config, execution engine
- **Executor stats** from `zeph_getExecutorStats` — gas utilization %, thread config
- **State metrics** from `zeph_getStateMetrics` — Verkle trie stats (nodes, values, depth)
- **Chain metrics** from `zeph_getChainMetrics` — TPS, block times, gas per block
- **Node config** from `zeph_getConfig` — runtime configuration for all subsystems

#### P2P Network Page
- **Connected peers** from `zeph_getPeers` — peer list with IDs and connection status
- **Peer count** and max peers

### 6.7 Real-Time Updates
- Poll `eth_blockNumber` every 1 second
- When new block detected, fetch block + transactions
- Use `eth_newBlockFilter` + `eth_getFilterChanges` as alternative to polling
- Update dashboard counters in real-time
- Show block production rate (blocks/second)
- Poll `zeph_getChainMetrics` for live TPS display
- Poll `zeph_getMempoolStats` for live mempool depth

---

## 7. Polling Strategy for Real-Time Data

```javascript
// Recommended polling approach
const RPC_URL = "http://localhost:8545";

async function rpcCall(method, params = []) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: Date.now() })
  });
  const json = await res.json();
  return json.result;
}

// Dashboard polling loop
let lastBlock = 0;
setInterval(async () => {
  const blockHex = await rpcCall("eth_blockNumber");
  const currentBlock = parseInt(blockHex, 16);
  
  if (currentBlock > lastBlock) {
    // New block(s) detected — fetch details
    for (let i = lastBlock + 1; i <= currentBlock; i++) {
      const block = await rpcCall("eth_getBlockByNumber", ["0x" + i.toString(16), true]);
      // Update UI with new block + transactions
    }
    lastBlock = currentBlock;
  }
}, 1000);

// Check any address balance
async function getBalance(address) {
  const weiHex = await rpcCall("eth_getBalance", [address, "latest"]);
  const wei = BigInt(weiHex);
  const zee = Number(wei) / 1e18;
  return { wei, zee };
}
```

---

## 8. Batch RPC Example (Efficient Multi-Query)

```javascript
// Fetch multiple pieces of data in one HTTP request
const batchRequest = [
  { jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 },
  { jsonrpc: "2.0", method: "eth_chainId", params: [], id: 2 },
  { jsonrpc: "2.0", method: "net_peerCount", params: [], id: 3 },
  { jsonrpc: "2.0", method: "zeph_getDAGMetrics", params: [], id: 4 },
  { jsonrpc: "2.0", method: "zeph_getThreadInfo", params: [], id: 5 },
  { jsonrpc: "2.0", method: "zeph_getNodeInfo", params: [], id: 6 },
  { jsonrpc: "2.0", method: "zeph_getMempoolStats", params: [], id: 7 },
  { jsonrpc: "2.0", method: "zeph_getChainMetrics", params: [], id: 8 },
];

const response = await fetch(RPC_URL, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(batchRequest)
});
const results = await response.json();
// results is an array of {jsonrpc, id, result} objects
```

---

## 9. Value Formatting

All numeric values in RPC responses are **hex-encoded strings** with `0x` prefix.

```javascript
// Conversion helpers
function hexToNumber(hex) {
  return parseInt(hex, 16);
}

function hexToBigInt(hex) {
  return BigInt(hex);
}

function weiToZee(weiHex) {
  const wei = BigInt(weiHex);
  // For display: divide by 10^18
  const whole = wei / BigInt(1e18);
  const frac = wei % BigInt(1e18);
  return `${whole}.${frac.toString().padStart(18, '0').slice(0, 6)}`;
}

function formatGasPrice(gasPriceHex) {
  const gwei = Number(BigInt(gasPriceHex)) / 1e9;
  return `${gwei.toFixed(2)} Gwei`;
}

function formatTimestamp(timestampHex) {
  return new Date(parseInt(timestampHex, 16) * 1000).toLocaleString();
}

function shortenHash(hash) {
  return hash.slice(0, 10) + "..." + hash.slice(-8);
}

function shortenAddress(addr) {
  return addr.slice(0, 8) + "..." + addr.slice(-6);
}
```

---

## 10. Design Guidelines

### Color Palette (Zephyria Brand)
| Name | Hex | Usage |
|---|---|---|
| Void Black | `#0a0a0f` | Primary background |
| Deep Navy | `#0d1117` | Card backgrounds |
| Cyber Cyan | `#00f0ff` | Primary accent, links |
| Neon Magenta | `#ff2d78` | Secondary accent, alerts |
| Electric Purple | `#a855f7` | Tertiary accent |
| Teal Green | `#2dd4bf` | Success states |
| Ember Orange | `#f97316` | Warning states |
| Soft White | `#e2e8f0` | Body text |
| Dim Gray | `#64748b` | Secondary text |

### Typography
- **Headings**: `Inter` or `Outfit` (Google Fonts)
- **Monospace**: `JetBrains Mono` or `Fira Code` (for hashes, addresses, code)

### UI Style
- Dark mode by default (cyberpunk/blockchain aesthetic)
- Glassmorphism panels with subtle glow borders
- Smooth micro-animations on data updates
- Responsive: works on mobile and desktop
- Real-time data pulse indicators (glowing dots for live blocks)

---

## 11. Error Handling

### RPC Errors
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32601,
    "message": "Method not found"
  }
}
```

| Code | Meaning |
|---|---|
| `-32700` | Parse error (invalid JSON) |
| `-32600` | Invalid Request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |

### Handling Missing Data
- `eth_getBlockByNumber` returns `null` for non-existent blocks
- `eth_getTransactionByHash` returns `null` if TX not found
- `eth_getTransactionReceipt` returns `null` for pending or unknown TXs
- `eth_getBalance` returns `"0x0"` for non-existent accounts
- `eth_getCode` returns `"0x"` for EOAs (no code)

---

## 12. Technology Recommendations

Build as a **Vite + React** (or Next.js) application:
- Use `ethers.js` v6 or vanilla `fetch` for RPC calls
- The node is **fully Ethereum-compatible** so ethers.js `JsonRpcProvider` works:
  ```javascript
  import { ethers } from "ethers";
  const provider = new ethers.JsonRpcProvider("http://localhost:8545");
  const blockNumber = await provider.getBlockNumber();
  const balance = await provider.getBalance("0x...");
  ```
- For Zephyria-specific methods (`zeph_*`), use raw `fetch` or `provider.send()`:
  ```javascript
  const dagMetrics = await provider.send("zeph_getDAGMetrics", []);
  ```

---

## 13. Summary of All 54 Available RPC Methods

### Standard Ethereum RPC (38 methods)
```
eth_chainId                            eth_blockNumber
eth_getBlockByNumber                   eth_getBlockByHash
eth_getBlockTransactionCountByNumber   eth_getBlockTransactionCountByHash
eth_getUncleCountByBlockNumber         eth_getUncleCountByBlockHash
eth_getTransactionByHash               eth_getTransactionReceipt
eth_getTransactionByBlockNumberAndIndex eth_getTransactionByBlockHashAndIndex
eth_getTransactionCount                eth_getBalance
eth_getCode                            eth_getStorageAt
eth_call                               eth_estimateGas
eth_sendRawTransaction                 eth_sendTransaction
eth_gasPrice                           eth_maxPriorityFeePerGas
eth_feeHistory                         eth_getLogs
eth_newFilter                          eth_newBlockFilter
eth_getFilterChanges                   eth_getFilterLogs
eth_uninstallFilter                    eth_accounts
eth_syncing                            eth_mining
eth_hashrate                           eth_protocolVersion
net_version                            net_listening
net_peerCount                          web3_clientVersion
web3_sha3
```

### Zephyria-Specific RPC (16 methods)
```
zeph_getDAGMetrics                     zeph_getThreadInfo
zeph_getAccountTypes                   zeph_getNodeInfo
zeph_getMempoolStats                   zeph_getMempoolContent
zeph_getBlockProducerInfo              zeph_getPeers
zeph_getVMStats                        zeph_getShardDistribution
zeph_getConfig                         zeph_getExecutorStats
zeph_getStateMetrics                   zeph_getChainMetrics
zeph_pendingTransactions               zeph_compileEOF
```
