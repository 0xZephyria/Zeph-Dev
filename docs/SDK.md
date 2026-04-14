# Zephyria Contract SDK — Developer Guide

> Write smart contracts in **Zig** for the Zephyria blockchain.
> Familiar Solidity patterns, compiled to RISC-V, executed in parallel.

---

## Installation

### Option 1: `zeph init` (Recommended)

```bash
# Create a new contract project with everything pre-configured
zeph init my-token
cd my-token

# Write your contract in src/main.zig, then compile
zig build contract
```

### Option 2: Add to Existing Project

Add the SDK to your `build.zig.zon`:

```zig
.dependencies = .{
    .@"zephyria-sdk" = .{
        .url = "https://github.com/0xZephyria/zephyria-sdk/archive/refs/heads/main.tar.gz",
        .hash = "...",  // zig build will print the correct hash
    },
},
```

In your `build.zig`, link it:

```zig
const sdk_dep = b.dependency("zephyria-sdk", .{});
exe.root_module.addImport("zephyria-sdk", sdk_dep.module("zephyria-sdk"));
exe.setLinkerScript(sdk_dep.path("linker.ld"));
```

### Option 3: Local Path (Development)

```zig
.dependencies = .{
    .@"zephyria-sdk" = .{ .path = "../sdk" },
},
```

---

## Quick Start

```zig
const sdk = @import("zephyria-sdk");
const Uint256 = sdk.Uint256;
const Address = sdk.Address;

// Storage layout (slot 0 = totalSupply, slot 1 = balances mapping)
const total_supply = sdk.StorageSlot(Uint256).init(Uint256.ZERO);
const balances = sdk.StorageMapping(Address, Uint256).init(Uint256.ONE);

// Entry point — called by the VM for every transaction
export fn main() void {
    var ctx = sdk.ExecutionContext.fromHost(undefined);
    const calldata = ctx.msg_data;
    const selector = calldata[0..4].*;

    if (std.mem.eql(u8, &selector, &sdk.computeSelector("balanceOf(address)"))) {
        // ... handle balanceOf
    }
}
```

---

## Table of Contents

1. [Types](#types)
2. [Storage](#storage)
3. [Execution Context](#execution-context)
4. [Events](#events)
5. [Errors & Require](#errors--require)
6. [Access Control & Modifiers](#access-control--modifiers)
7. [Cross-Contract Calls](#cross-contract-calls)
8. [Math Utilities](#math-utilities)
9. [ABI Encoding/Decoding](#abi-encodingdecoding)
10. [Cryptography](#cryptography)
11. [Contract Dispatch Pattern](#contract-dispatch-pattern)
12. [Full Contract Examples](#full-contract-examples)

---

## Types

### Uint256

256-bit unsigned integer — equivalent to Solidity's `uint256`.

```zig
const Uint256 = sdk.Uint256;

// Creation
const zero  = Uint256.ZERO;
const one   = Uint256.ONE;
const max   = Uint256.MAX;
const val   = Uint256.fromU64(1000);
const big   = Uint256.fromU128(1_000_000_000_000_000_000);
const hex   = Uint256.fromHex("0xDE0B6B3A7640000");  // 1 ether in wei
const bytes = Uint256.fromBytes(raw_32_bytes);

// Checked arithmetic (reverts on overflow, like Solidity >=0.8)
const sum     = a.checkedAdd(b);    // a + b
const diff    = a.checkedSub(b);    // a - b  (reverts if b > a)
const product = a.checkedMul(b);    // a * b
const quotient = a.checkedDiv(b);   // a / b  (reverts if b == 0)

// Unchecked arithmetic (wrapping, like Solidity unchecked{})
const sum2 = a.add(b);
const diff2 = a.sub(b);

// Comparison
if (a.gt(b))  { }  // a > b
if (a.lt(b))  { }  // a < b
if (a.eql(b)) { }  // a == b
if (a.gte(b)) { }  // a >= b

// Bitwise
const and_result = a.bitwiseAnd(b);
const shifted    = a.shl(Uint256.fromU64(8));  // a << 8

// Conversion
const as_u64: ?u64   = val.toU64();       // null if > u64 max
const as_bytes: [32]u8 = val.toBytes();   // big-endian
```

### Int256

256-bit signed integer — equivalent to Solidity's `int256`.

```zig
const Int256 = sdk.Int256;

const neg = Int256.fromI64(-42);
const pos = Int256.fromI64(100);

const sum = pos.checkedAdd(neg);     // 58
const is_neg = neg.isNegative();     // true
const abs_val = neg.abs();           // Uint256(42)
const negated = pos.negate();        // Int256(-100)

if (neg.lt(pos)) { }  // true
```

### Address

20-byte Ethereum-compatible address.

```zig
const Address = sdk.Address;

const zero_addr = Address.ZERO;
const addr = Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
const from_uint = Address.fromUint(some_uint256);

if (addr.eql(other_addr)) { }

// Convert to/from Uint256 for storage
const as_uint = addr.toUint();
```

### Other Types

| Zig SDK Type | Solidity Equivalent | Description |
|-------------|-------------------|-------------|
| `Uint256` | `uint256` | 256-bit unsigned |
| `Int256` | `int256` | 256-bit signed |
| `Address` | `address` | 20-byte address |
| `Bytes32` | `bytes32` | Fixed 32-byte array |
| `Bytes4` | `bytes4` | Fixed 4-byte array (selectors) |
| `UintN(128)` | `uint128` | Parameterized width |
| `IntN(64)` | `int64` | Parameterized signed |
| `BytesN(20)` | `bytes20` | Parameterized bytes |

---

## Storage

Storage works exactly like Solidity — data persists on-chain across calls.

### StorageSlot — Single Values

```zig
// Equivalent to: uint256 public totalSupply;  (at slot 0)
const total_supply = sdk.StorageSlot(Uint256).init(Uint256.fromU64(0));

// Equivalent to: address public owner;  (at slot 1)
const owner = sdk.StorageSlot(Address).init(Uint256.fromU64(1));

// Equivalent to: bool public paused;  (at slot 2)
const paused = sdk.StorageSlot(bool).init(Uint256.fromU64(2));

// Read & write
fn getSupply(storage: sdk.StorageBackend) Uint256 {
    return total_supply.load(storage);
}

fn setSupply(storage: sdk.StorageBackend, value: Uint256) void {
    total_supply.store(storage, value);
}
```

### StorageMapping — Key-Value Maps

```zig
// Equivalent to: mapping(address => uint256) balances;  (slot 3)
const balances = sdk.StorageMapping(Address, Uint256).init(Uint256.fromU64(3));

// Read
const bal = balances.get(storage, user_address);

// Write
balances.set(storage, user_address, new_balance);
```

**Nested mappings** (like `mapping(address => mapping(address => uint256))`):

```zig
// Equivalent to: mapping(address => mapping(address => uint256)) allowances;
const allowances = sdk.StorageMapping(Address, sdk.StorageMapping(Address, Uint256))
    .init(Uint256.fromU64(4));

// Read allowance[owner][spender]
const inner = allowances.getMapping(owner_addr);
const allowance = inner.get(storage, spender_addr);
```

### StorageArray — Dynamic Arrays

```zig
// Equivalent to: address[] public holders;  (slot 5)
const holders = sdk.StorageArray(Address).init(Uint256.fromU64(5));

const len = holders.length(storage);          // holders.length
const addr = holders.get(storage, index);      // holders[index]
holders.push(storage, new_addr);               // holders.push(addr)
const last = holders.pop(storage);             // holders.pop()
holders.set(storage, index, updated_addr);     // holders[index] = addr
```

### StorageString — Dynamic Strings

```zig
// Equivalent to: string public name;  (slot 6)
const name = sdk.StorageString.init(Uint256.fromU64(6));

// Write
name.store(storage, "Zephyria Token");

// Read (requires allocator for long strings)
const value = try name.load(storage, allocator);
```

> **Slot assignment**: Assign sequential slots (0, 1, 2, ...) exactly like Solidity's automatic layout. Mappings/arrays use `keccak256` derivation internally — you only specify the base slot.

---

## Execution Context

Access `msg.*`, `block.*`, and `tx.*` globals — same as Solidity.

```zig
// Create context at the start of execution
var ctx = sdk.ExecutionContext.fromHost(storage_backend);

// msg.* globals
ctx.msg_sender       // Address — who called this contract
ctx.msg_value        // Uint256 — ETH sent with the call (in wei)
ctx.msg_data         // []const u8 — raw calldata

// block.* globals
ctx.block_number     // Uint256
ctx.block_timestamp  // Uint256
ctx.block_coinbase   // Address — miner/validator address
ctx.block_gaslimit   // Uint256
ctx.block_basefee    // Uint256 (EIP-1559)
ctx.block_chainid    // Uint256
ctx.block_prevrandao // Uint256 (EIP-4399)

// tx.* globals
ctx.tx_origin        // Address — original transaction sender
ctx.tx_gasprice      // Uint256

// Contract address
ctx.self_address     // Address — this contract's address

// Gas
ctx.gasLeft()        // Uint256 — remaining gas
```

---

## Events

Events are emitted exactly like Solidity `emit` statements.

```zig
// Define the event (comptime)
const Transfer = sdk.Event("Transfer", .{
    .{ .name = "from",  .type_name = "address", .indexed = true },
    .{ .name = "to",    .type_name = "address", .indexed = true },
    .{ .name = "value", .type_name = "uint256", .indexed = false },
});

const Approval = sdk.Event("Approval", .{
    .{ .name = "owner",   .type_name = "address", .indexed = true },
    .{ .name = "spender", .type_name = "address", .indexed = true },
    .{ .name = "value",   .type_name = "uint256", .indexed = false },
});

// Emit the event
Transfer.emit(&ctx, .{
    .from  = sender,
    .to    = recipient,
    .value = amount,
});
```

> **How it works**: `indexed` fields become log topics (searchable). Non-indexed fields are ABI-encoded into the log data section. `topic[0]` is always `keccak256("Transfer(address,address,uint256)")` — computed at compile time.

---

## Errors & Require

### require — Conditional Revert

```zig
// Equivalent to: require(balance >= amount, "Insufficient balance");
sdk.require(balance.gte(amount), "Insufficient balance");

// Without message
sdk.requireBool(success);
```

### revert — Unconditional Revert

```zig
// Equivalent to: revert("Not authorized");
sdk.revert("Not authorized");
```

### assert — Internal Invariant

```zig
// Equivalent to: assert(totalSupply == 0);
sdk.assert_(total.eql(Uint256.ZERO));
```

### Custom Errors (Gas-Efficient)

```zig
// Define custom error (like Solidity custom errors)
const InsufficientBalance = sdk.CustomError("InsufficientBalance", struct {
    available: Uint256,
    required: Uint256,
});

// Raise it
InsufficientBalance.raise(.{
    .available = balance,
    .required = amount,
});
```

---

## Access Control & Modifiers

### Ownable

```zig
const ownable = sdk.OwnableGuard.init(Uint256.fromU64(100)); // slot 100

// Check ownership (reverts if not owner)
ownable.checkOwner(storage, ctx.msg_sender);

// Read owner
const current_owner = ownable.owner(storage);

// Transfer ownership
ownable.transferOwnership(storage, ctx.msg_sender, new_owner);

// Renounce ownership
ownable.renounceOwnership(storage, ctx.msg_sender);
```

### Pausable

```zig
const pausable = sdk.PausableGuard.init(Uint256.fromU64(101));

pausable.requireNotPaused(storage);  // modifier: whenNotPaused
pausable.requirePaused(storage);     // modifier: whenPaused
pausable.pause(storage);             // pause()
pausable.unpause(storage);           // unpause()
```

### Role-Based Access Control

```zig
const access = sdk.AccessControl.init(Uint256.fromU64(200));

const MINTER_ROLE = sdk.keccak256("MINTER_ROLE");
const PAUSER_ROLE = sdk.keccak256("PAUSER_ROLE");

// Check role (reverts if missing)
access.checkRole(storage, MINTER_ROLE, ctx.msg_sender);

// Grant/revoke
access.grantRole(storage, MINTER_ROLE, minter_address);
access.revokeRole(storage, MINTER_ROLE, old_minter);

// Query
const has_role = access.hasRole(storage, MINTER_ROLE, some_address);
```

### Reentrancy Guard

```zig
const guard = sdk.ReentrancyGuard.init(Uint256.fromU64(102));

fn withdraw(ctx: *sdk.ExecutionContext, amount: Uint256) void {
    guard.enter(ctx.storage_backend);        // modifier pre-check
    defer guard.exit(ctx.storage_backend);   // modifier post-check

    // ... your logic here (safe from reentrancy)
}
```

---

## Cross-Contract Calls

### CALL — Standard Contract Call

```zig
const result = ctx.call(.{
    .to = target_contract,
    .value = Uint256.fromU64(1_000_000_000_000_000_000), // 1 ETH
    .data = encoded_calldata,
});

if (result.success) {
    // Call succeeded
} else {
    sdk.revert("External call failed");
}
```

### DELEGATECALL — Execute in Caller's Context

```zig
const result = ctx.delegatecall(.{
    .to = implementation_contract,
    .data = encoded_calldata,
});
```

### STATICCALL — Read-Only Call

```zig
const result = ctx.staticcall(.{
    .to = oracle_contract,
    .data = encoded_calldata,
});
```

### Transfer ETH

```zig
// transfer — reverts on failure
sdk.transfer(&ctx, recipient, amount);

// send — returns bool
const success = sdk.send(&ctx, recipient, amount);
```

---

## Math Utilities

### SafeMath (try-style that returns success)

```zig
const result = sdk.SafeMath.tryAdd(a, b);
if (result.success) {
    const sum = result.value;
}
```

### Utility Functions

```zig
const bigger    = sdk.mathMax(a, b);         // max(a, b)
const smaller   = sdk.mathMin(a, b);         // min(a, b)
const avg       = sdk.mathAverage(a, b);     // overflow-safe average
const ceil      = sdk.mathCeilDiv(a, b);     // ceil(a / b)
const root      = sdk.mathSqrt(value);       // integer sqrt
```

---

## ABI Encoding/Decoding

```zig
// Encode
const encoded = sdk.abi_encode(.{ address, amount });
const packed  = sdk.abi_encodePacked(.{ address, amount });
const with_sel = sdk.abi_encodeWithSelector(selector, .{ address, amount });
const with_sig = sdk.abi_encodeWithSignature("transfer(address,uint256)", .{ addr, amt });

// Decode
const decoded = sdk.abi_decode(SomeStruct, data);

// Compute function selector
const sel = sdk.computeSelector("transfer(address,uint256)");
// sel == bytes4(keccak256("transfer(address,uint256)"))
```

---

## Cryptography

```zig
// keccak256
const hash = sdk.keccak256("hello");   // [32]u8

// ecrecover
const signer = sdk.ecrecover(hash, v, r, s);  // Address

// addmod / mulmod
const result = sdk.addmod(a, b, modulus);  // (a + b) % modulus
```

---

## Contract Dispatch Pattern

The standard pattern for handling function calls via selectors:

```zig
const sdk = @import("zephyria-sdk");
const Contract = sdk.Contract;
const computeSelector = sdk.computeSelector;

const MyToken = struct {
    // Mix in the Contract dispatch logic
    usingnamespace Contract(MyToken);

    // Selector table (computed at comptime)
    pub const __selectors = .{
        .{ .selector = computeSelector("totalSupply()"),
           .name = "totalSupply",
           .handler = totalSupplyHandler },
        .{ .selector = computeSelector("balanceOf(address)"),
           .name = "balanceOf",
           .handler = balanceOfHandler },
        .{ .selector = computeSelector("transfer(address,uint256)"),
           .name = "transfer",
           .handler = transferHandler },
    };

    // Optional: receive() for plain ETH transfers
    pub fn receive(self: *MyToken, ctx: *sdk.ExecutionContext) ![]const u8 {
        _ = self; _ = ctx;
        return &[_]u8{};
    }

    // Optional: fallback() for unknown selectors
    pub fn fallback(self: *MyToken, ctx: *sdk.ExecutionContext, data: []const u8) ![]const u8 {
        _ = self; _ = ctx; _ = data;
        return error.UnknownSelector;
    }
};
```

---

## Full Contract Examples

### ERC-20 Token

```zig
const sdk = @import("zephyria-sdk");
const Uint256 = sdk.Uint256;
const Address = sdk.Address;

// ========== Storage Layout ==========
const SLOT_TOTAL_SUPPLY = Uint256.fromU64(0);
const SLOT_BALANCES     = Uint256.fromU64(1);
const SLOT_ALLOWANCES   = Uint256.fromU64(2);
const SLOT_NAME         = Uint256.fromU64(3);
const SLOT_SYMBOL       = Uint256.fromU64(4);
const SLOT_DECIMALS     = Uint256.fromU64(5);

const total_supply = sdk.StorageSlot(Uint256).init(SLOT_TOTAL_SUPPLY);
const balances     = sdk.StorageMapping(Address, Uint256).init(SLOT_BALANCES);
const allowances   = sdk.StorageMapping(Address,
    sdk.StorageMapping(Address, Uint256)).init(SLOT_ALLOWANCES);

// ========== Events ==========
const Transfer = sdk.Event("Transfer", .{
    .{ .name = "from",  .type_name = "address", .indexed = true },
    .{ .name = "to",    .type_name = "address", .indexed = true },
    .{ .name = "value", .type_name = "uint256", .indexed = false },
});

const Approval = sdk.Event("Approval", .{
    .{ .name = "owner",   .type_name = "address", .indexed = true },
    .{ .name = "spender", .type_name = "address", .indexed = true },
    .{ .name = "value",   .type_name = "uint256", .indexed = false },
});

// ========== Functions ==========

fn transfer(ctx: *sdk.ExecutionContext, to: Address, amount: Uint256) void {
    const storage = ctx.storage_backend;
    const sender = ctx.msg_sender;

    const sender_bal = balances.get(storage, sender);
    sdk.require(sender_bal.gte(amount), "ERC20: insufficient balance");

    balances.set(storage, sender, sender_bal.checkedSub(amount));
    const to_bal = balances.get(storage, to);
    balances.set(storage, to, to_bal.checkedAdd(amount));

    Transfer.emit(ctx, .{ .from = sender, .to = to, .value = amount });
}

fn approve(ctx: *sdk.ExecutionContext, spender: Address, amount: Uint256) void {
    const storage = ctx.storage_backend;
    const owner = ctx.msg_sender;

    const inner = allowances.getMapping(owner);
    inner.set(storage, spender, amount);

    Approval.emit(ctx, .{ .owner = owner, .spender = spender, .value = amount });
}

fn transferFrom(ctx: *sdk.ExecutionContext, from: Address, to: Address, amount: Uint256) void {
    const storage = ctx.storage_backend;
    const spender = ctx.msg_sender;

    // Check allowance
    const inner = allowances.getMapping(from);
    const current_allowance = inner.get(storage, spender);
    sdk.require(current_allowance.gte(amount), "ERC20: insufficient allowance");
    inner.set(storage, spender, current_allowance.checkedSub(amount));

    // Transfer
    const from_bal = balances.get(storage, from);
    sdk.require(from_bal.gte(amount), "ERC20: insufficient balance");
    balances.set(storage, from, from_bal.checkedSub(amount));

    const to_bal = balances.get(storage, to);
    balances.set(storage, to, to_bal.checkedAdd(amount));

    Transfer.emit(ctx, .{ .from = from, .to = to, .value = amount });
}

fn balanceOf(storage: sdk.StorageBackend, account: Address) Uint256 {
    return balances.get(storage, account);
}

fn mint(ctx: *sdk.ExecutionContext, to: Address, amount: Uint256) void {
    const storage = ctx.storage_backend;

    const supply = total_supply.load(storage);
    total_supply.store(storage, supply.checkedAdd(amount));

    const bal = balances.get(storage, to);
    balances.set(storage, to, bal.checkedAdd(amount));

    Transfer.emit(ctx, .{ .from = Address.ZERO, .to = to, .value = amount });
}
```

### Simple Vault (with Reentrancy Guard)

```zig
const sdk = @import("zephyria-sdk");
const Uint256 = sdk.Uint256;
const Address = sdk.Address;

const deposits = sdk.StorageMapping(Address, Uint256).init(Uint256.fromU64(0));
const guard = sdk.ReentrancyGuard.init(Uint256.fromU64(99));

fn deposit(ctx: *sdk.ExecutionContext) void {
    const storage = ctx.storage_backend;
    sdk.require(ctx.msg_value.gt(Uint256.ZERO), "Must deposit > 0");

    const current = deposits.get(storage, ctx.msg_sender);
    deposits.set(storage, ctx.msg_sender, current.checkedAdd(ctx.msg_value));
}

fn withdraw(ctx: *sdk.ExecutionContext, amount: Uint256) void {
    const storage = ctx.storage_backend;

    // Reentrancy protection
    guard.enter(storage);
    defer guard.exit(storage);

    const balance = deposits.get(storage, ctx.msg_sender);
    sdk.require(balance.gte(amount), "Insufficient balance");

    // Effects before interactions (Checks-Effects-Interactions)
    deposits.set(storage, ctx.msg_sender, balance.checkedSub(amount));

    // Interaction
    sdk.transfer(ctx, ctx.msg_sender, amount);
}
```

### Multi-Sig Wallet

```zig
const sdk = @import("zephyria-sdk");
const Uint256 = sdk.Uint256;
const Address = sdk.Address;

const owners      = sdk.StorageMapping(Address, bool).init(Uint256.fromU64(0));
const threshold   = sdk.StorageSlot(Uint256).init(Uint256.fromU64(1));
const tx_count    = sdk.StorageSlot(Uint256).init(Uint256.fromU64(2));
const approvals   = sdk.StorageMapping(Uint256,
    sdk.StorageMapping(Address, bool)).init(Uint256.fromU64(3));
const approval_counts = sdk.StorageMapping(Uint256, Uint256).init(Uint256.fromU64(4));

const guard = sdk.ReentrancyGuard.init(Uint256.fromU64(99));

fn submitTransaction(ctx: *sdk.ExecutionContext, to: Address, value: Uint256) Uint256 {
    const storage = ctx.storage_backend;
    sdk.require(owners.get(storage, ctx.msg_sender), "Not an owner");

    const tx_id = tx_count.load(storage);
    tx_count.store(storage, tx_id.checkedAdd(Uint256.ONE));

    // Auto-approve by submitter
    const inner = approvals.getMapping(tx_id);
    inner.set(storage, ctx.msg_sender, true);
    approval_counts.set(storage, tx_id, Uint256.ONE);

    return tx_id;
}

fn approveTransaction(ctx: *sdk.ExecutionContext, tx_id: Uint256) void {
    const storage = ctx.storage_backend;
    sdk.require(owners.get(storage, ctx.msg_sender), "Not an owner");

    const inner = approvals.getMapping(tx_id);
    sdk.require(!inner.get(storage, ctx.msg_sender), "Already approved");

    inner.set(storage, ctx.msg_sender, true);
    const count = approval_counts.get(storage, tx_id);
    approval_counts.set(storage, tx_id, count.checkedAdd(Uint256.ONE));
}

fn executeTransaction(ctx: *sdk.ExecutionContext, tx_id: Uint256, to: Address, value: Uint256) void {
    const storage = ctx.storage_backend;
    guard.enter(storage);
    defer guard.exit(storage);

    const count = approval_counts.get(storage, tx_id);
    const thresh = threshold.load(storage);
    sdk.require(count.gte(thresh), "Not enough approvals");

    sdk.transfer(ctx, to, value);
}
```

---

## Solidity → Zig Cheat Sheet

| Solidity | Zig SDK |
|----------|---------|
| `uint256` | `sdk.Uint256` |
| `int256` | `sdk.Int256` |
| `address` | `sdk.Address` |
| `bytes32` | `sdk.Bytes32` (`[32]u8`) |
| `msg.sender` | `ctx.msg_sender` |
| `msg.value` | `ctx.msg_value` |
| `block.number` | `ctx.block_number` |
| `block.timestamp` | `ctx.block_timestamp` |
| `tx.origin` | `ctx.tx_origin` |
| `mapping(K => V)` | `sdk.StorageMapping(K, V)` |
| `T[]` | `sdk.StorageArray(T)` |
| `string` | `sdk.StorageString` |
| `require(cond, msg)` | `sdk.require(cond, msg)` |
| `revert("msg")` | `sdk.revert("msg")` |
| `assert(cond)` | `sdk.assert_(cond)` |
| `emit Transfer(...)` | `Transfer.emit(&ctx, .{...})` |
| `modifier onlyOwner` | `ownable.checkOwner(storage, ctx.msg_sender)` |
| `payable` | Check `ctx.msg_value.gt(Uint256.ZERO)` |
| `address(this)` | `ctx.self_address` |
| `gasleft()` | `ctx.gasLeft()` |
| `selfdestruct(addr)` | `ctx.selfDestruct(addr)` |
| `keccak256(data)` | `sdk.keccak256(data)` |
| `abi.encode(...)` | `sdk.abi_encode(.{...})` |
| `address.call{value: v}(data)` | `ctx.call(.{ .to = addr, .value = v, .data = data })` |
