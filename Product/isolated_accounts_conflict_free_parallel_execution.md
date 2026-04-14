# Research: Isolated Accounts System for Conflict-Free Parallel Execution (ZIG RISC-V VM)

## 1. Executive Summary
The core challenge of scaling an Ethereum-compatible blockchain is the inherently sequential nature of transaction execution. When multiple transactions attempt to interact with the same smart contract state or user account simultaneously, conflicts arise. 

This research document outlines the creation of an **Isolated Accounts System** that achieves **100% conflict-free parallel execution** for a custom **ZIG-based RISC-V Virtual Machine (VM)**. The system is designed to maintain 100% RPC and tooling compatibility with standard Ethereum tools (e.g., MetaMask), meaning users sign standard EVM-like transactions, but the underlying execution engine leverages highly performant, natively compiled RISC-V code.

Furthermore, following the Solana modular architecture, we introduce **System Contracts** to handle common primitives (like Token creation), drastically reducing gas costs and state bloat.

## 2. Problem Definition and Constraints
### The Bottleneck
The standard EVM processes transactions one after another. If we simply execute everything concurrently, we run into race conditions and state corruption whenever two transactions touch the same storage slot or balance.

### Constraints Imposed by the Goal
1. **100% Conflict-Free:** We cannot rely heavily on Optimistic Concurrency Control (OCC) like Block-STM, where transactions are executed blindly and then rolled back and re-executed sequentially upon conflict. Re-execution wastes compute cycles.
2. **Standard ETH Tools Compatibility:** The user shouldn't have to construct complex read/write sets. Transactions should look like standard JSON-RPC `eth_sendRawTransaction` payloads.
3. **No Solana-style Declarations:** Developers and users shouldn't have to define up front exactly which accounts will be touched.
4. **ZIG RISC-V Engine:** The execution layer is fundamentally a custom RISC-V VM written in Zig, which offers extreme performance, fine-grained memory control, and safety, but requires a bridge to interpret standard Ethereum RPC formats.

## 3. Explored Architectures & Solutions

### 3.1. DAG-Based Mempool (Narwhal/Tusk, Bullshark style)
A Directed Acyclic Graph (DAG) mempool separates transaction dissemination from transaction ordering. 
- **Mechanism:** Instead of nodes sharing a single mempool pool, they continually batch transactions into "vertices" and broadcast them. These vertices reference past vertices, forming a DAG.
- **Why it fits:** The DAG inherently provides a partial, deterministic ordering before execution. If we map transactions into the DAG based on their state dependencies, the graph topology guarantees non-conflicting groupings. Independent branches of the DAG can be executed completely in parallel by different Zig threads.

### 3.2. Pre-Execution "Pre-flight" for Implicit Access Lists
Since users aren't providing access lists via MetaMask, the network must generate them dynamically to ensure isolated execution.
- **Mechanism:** When a transaction enters the mempool or the validator node, a lightweight "pre-flight" simulation is run against the current state using the fast Zig RISC-V VM. This traces every memory load/store that corresponds to an account or storage slot, automatically generating an internal "access list".
- **Benefit:** Standard wallets work flawlessly. The node does the heavy lifting of figuring out the isolation boundaries.
- **Caveat:** A pre-flight check might generate a read/write set that becomes invalid if a prior transaction changes the control flow. However, combined with strict ordering (like a DAG), we can lock the necessary state.

### 3.3. Shared-Nothing Architecture (State Sharding / PREDA)
An alternative to managing conflicts is eliminating the shared state entirely.
- **Mechanism:** State is fragmented into "isolated accounts" or discrete objects. Smart contracts are redesigned conceptually at the node level so that state variables belong to specific object contexts rather than a gigantic monolithic Merkle Patricia Trie.
- **Benefit:** True isolation. Transactions that operate on Object A have zero possibility of conflicting with Object B. Zig threads can be mapped 1:1 with specific state shards, executing any transaction routed to that shard immediately without mutex locks.

## 4. Native System Contracts: The Solana Advantage

One of the largest inefficiencies of the EVM is that every time a user wants to launch a token (ERC20), they must deploy duplicate bytecode to the network, resulting in state bloat and high deployment gas fees. Solana solves this via its core "Token Program."

### 4.1. The Architecture of System Contracts
In our Zig RISC-V VM, we will implement **System Contracts** (or Pre-compiles on steroids). These are highly optimized, native Zig modules that run at the node level, rather than being interpreted as smart contract bytecode.

- **Native Token System Contract:** A single, global protocol-level contract responsible for all fungible tokens.
- **Native NFT System Contract:** A single protocol-level contract for Non-Fungible Tokens.

### 4.2. How it Works for the User
Instead of a developer compiling and deploying an ERC20 bytecode, they send a standard transaction (via MetaMask) to the address of the **System Token Contract** with a specific payload (e.g., `InitializeToken(name, symbol, supply)`).

1. The System Contract creates a new "Mint Account" (an isolated data structure) representing the new token.
2. Creating a token costs fraction of a cent because no arbitrary bytecode is stored—only a tiny state struct containing the token metadata and supply.
3. When users transfer this token, they interact with the *System Contract*, which simply updates the balances in the isolated state accounts. 

### 4.3. Advantages for Parallel Execution
System Contracts are incredibly synergistic with **Isolated Accounts**. Because the logic is deterministic and universally defined natively in Zig, the VM natively understands exactly which state accounts a transfer touches without needing to simulate complex arbitrary bytecode. The Zig engine can effortlessly shard balances of the System Token Contract and process millions of transfers in parallel.

## 5. Recommended Design: "Deterministically Isolated Pre-Flight DAG with Native Primitives"

To achieve the "100% purely conflict-free and parallel executable" mandate while leveraging the power of Zig and RISC-V, the architecture will look as follows:

1. **Submission (Standard ETH Payload via MetaMask):**
   A user submits a transaction via MetaMask. This can be a standard transfer, a call to a custom RISC-V compiled smart contract, or a call to a Native System Contract.

2. **Pre-flight Tracing Engine (Zig RISC-V):**
   As soon as a validator node receives the transaction, the Zig VM performs an ultra-fast simulation. It traces exact memory bounds and storage slots, generating a strict **Read/Write Set**. 
   - *Optimization:* For calls to Native System Contracts (like Token Transfers), the VM doesn't even need to simulate; the state access patterns are statically known by the Zig native code.

3. **DAG Mempool Integration (Conflict Resolution *Before* Execution):**
   The transaction and its Read/Write set are packaged into a DAG vertex. 
   - The mempool algorithm partitions the transaction graph into **Disjoint Subgraphs**. If Tx A and Tx B touch the same account, they are connected by an edge. If Tx C touches a completely different account, it is disconnected.

4. **100% Conflict-Free Parallel Execution (Zig Threading):**
   Because all dependencies were proven and isolated in Step 3, the actual Execution phase requires **zero locks, zero conflict detection, and zero rollbacks.**
   - Zig Worker Thread 1 receives Subgraph 1.
   - Zig Worker Thread 2 receives Subgraph 2.
   - Using Zig's fearless concurrency and memory safety, they execute RISC-V instructions 100% in parallel. No sequential fallback is ever needed.

## 6. Proof of History (PoH) vs. DAG-Based Mempool

When designing a high-throughput, parallelized network, both Solana's Proof of History (PoH) and DAG-based mempools (like Narwhal/Bullshark) offer distinct approaches to the "ordering" problem.

### 6.1. Proof of History (Solana Model)
- **Mechanism:** PoH is a continuous cryptographic clock (using a VDF - Verifiable Delay Function). It establishes a definitive, verifiable sequence of events (transactions) *before* consensus is reached.
- **Pros:** 
  - Extremely low latency (block times of ~400ms).
  - Eliminates the need for validators to communicate extensively to agree on time.
  - Feeds transactions into a highly deterministic pipeline.
- **Cons:** 
  - High hardware requirements to compute the VDF continuously.
  - Transactions are strictly linearly ordered. The parallelism happens downstream *because* accounts are explicitly declared, not because the ledger itself resolves branch dependencies.

### 6.2. DAG-Based Mempool (Narwhal/Sui/Aptos Model)
- **Mechanism:** Separates transaction dissemination from consensus. Transactions are batched into "vertices" that reference previous vertices, forming a Directed Acyclic Graph.
- **Pros:**
  - Naturally captures causal dependencies. If two transactions are on disjoint paths of the DAG, they are mathematically proven to be independent.
  - Highly resilient in asynchronous network conditions (maintains high throughput even when latency spikes).
  - Perfect for **Implicit Isolation**: By mapping our Zig VM's pre-flight read/write sets onto the DAG, the graph inherently partitions itself into conflict-free buckets.
- **Cons:**
  - Slightly higher time-to-finality (latency) compared to PoH's aggressive streaming, as rounds must be structured and propagated.

### 6.3. Conclusion for our Architecture
For our goal of retaining standard ETH tooling without forcing explicit account declarations, a **DAG-based Mempool** is superior to PoH. 
PoH forces a linear sequence, requiring the VM to rely heavily on Optimistic Concurrency Control (OCC) or explicit access lists to find parallel lanes. A DAG, combined with our Zig pre-flight engine, natively groups transactions into disjoint, parallelizable clusters *before* execution.

---

## 7. Detailed Schema of Isolated Accounts

To achieve conflict-free execution, the monolithic EVM state tree is fractured into granular, isolated **Accounts** (conceptually similar to the Sui Object Model or Solana Account Model, but mapped to EVM compatibility). In our Zig RISC-V implementation, everything is an Account.

Every Account shares a standard header:
```zig
struct AccountHeader {
    owner_address: [20]u8,   // The logic/program that controls this account
    nonce: u64,              // Transaction count / mutation count
    balance: u256,           // Native gas token balance
    is_executable: bool,     // True if this is a deployed contract
    state_root: [32]u8,      // Hash of the account's internal state
}
```

Below are the specialized Account types and their roles within the ecosystem:

### 7.1. User Account (EOA - Externally Owned Account)
- **Role:** Represents a standard user wallet (e.g., managed by MetaMask).
- **Control:** Owned by the System, controlled by a user's ECDSA private key.
- **State Data:** Minimal. Only contains the standard `AccountHeader` attributes (`balance`, `nonce`).
- **Parallelism Impact:** Transferring native tokens involves locking only the sender's EOA and the receiver's EOA.

### 7.2. Smart Contract Account (EVM/WASM/RISC-V Bytecode)
- **Role:** Holds the executable logic of deployed dApps. 
- **Control:** The protocol itself executes the bytecode.
- **State Data:** Contains the compiled program bytecode. 
- **Parallelism Impact:** For parallel execution, the Smart Contract Account itself is **Read-Only** during transaction execution. Multiple threads can read the bytecode simultaneously without conflicts. Its internal storage is broken out into separate "Storage Slot Accounts" (see 7.3).

### 7.3. Contract Storage Slot Account (Fragmented State)
- **Role:** Instead of a single massive state trie, a contract's storage is fragmented. Each `SSTORE` operation in standard EVM points to a dynamic location. We model chunks of these slots as independent data objects.
- **Control:** Owned by the specific Smart Contract Account that created it.
- **State Data:** Key-Value pairs specific to that contract's execution.
- **Parallelism Impact:** This is the crux of conflict-free parallel EVM. If Tx A modifies `Contract1.Slot[0]` and Tx B modifies `Contract1.Slot[99]`, our pre-flight engine treats these as separate Account locks, allowing both to execute in parallel against the exact same smart contract.

### 7.4. Native System Token: Mint Account
- **Role:** Defines a fungible token deployed via the Native System Contract (avoids EVM bloat).
- **Control:** Owned by the `System_Token_Program`.
- **State Data:** `total_supply`, `decimals`, `mint_authority`, `freeze_authority`.
- **Parallelism Impact:** Read-only for standard transfers. Only locked when new tokens are actively being minted or burned.

### 7.5. Native System Token: Balance Account (ATA)
- **Role:** Holds the balance of a specific Native Token for a specific user. Similar to Solana's Associated Token Account (ATA).
- **Control:** Owned by the `System_Token_Program`, but delegated transfer authority to the user's EOA.
- **State Data:** `token_mint_address`, `balance`, `delegated_allowance`.
- **Parallelism Impact:** When Bob sends USDC to Alice, the VM does not lock a massive ERC20 contract. It only locks `Bob_USDC_Balance_Account` and `Alice_USDC_Balance_Account`. Thousands of USDC transactions occur simultaneously with zero bottlenecks.

## 8. Conclusion
Achieving 100% conflict-free parallelism without Solana's explicit accounts requires moving the conflict-resolution phase from **Execution** to **Ordering/Mempool**. By utilizing a DAG-based mempool enriched with automatically derived state dependencies via an ultra-fast Zig RISC-V pre-flight engine, the execution engine receives perfectly isolated batches. 

Furthermore, introducing **Native System Contracts** for primitives like Tokens, combined with a highly fragmented **Isolated Account Schema**, completely bypasses EVM bytecode bloat and state bottlenecks. This allows developers to mint and users to trade tokens natively at near-zero execution cost, rivaling Solana's user experience while keeping MetaMask compatibility intact.
