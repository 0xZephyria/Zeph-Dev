# Zephyria SDK

Write smart contracts in **Zig** for the Zephyria blockchain.

## Installation

### Option 1: `zeph init` (Recommended)

```bash
# Install the CLI tool
curl -fsSL https://install.zephyria.io | sh

# Create a new contract project
zeph init my-token
cd my-token
zig build contract
```

### Option 2: Manual Setup

Add the SDK to your `build.zig.zon`:

```zig
.dependencies = .{
    .@"zephyria-sdk" = .{
        .url = "https://github.com/0xZephyria/zephyria-sdk/archive/refs/heads/main.tar.gz",
        .hash = "...",  // zig build will tell you the correct hash
    },
},
```

In your `build.zig`, import and link the SDK:

```zig
const sdk_dep = b.dependency("zephyria-sdk", .{});
exe.root_module.addImport("zephyria-sdk", sdk_dep.module("zephyria-sdk"));
exe.setLinkerScript(sdk_dep.path("linker.ld"));
```

Then in your contract:

```zig
const sdk = @import("zephyria-sdk");
```

### Option 3: Local Path (Development)

```zig
.dependencies = .{
    .@"zephyria-sdk" = .{
        .path = "../sdk",
    },
},
```

## Quick Example

```zig
const sdk = @import("zephyria-sdk");
const Uint256 = sdk.Uint256;
const Address = sdk.Address;

const balances = sdk.StorageMapping(Address, Uint256).init(Uint256.fromU64(0));

fn transfer(ctx: *sdk.ExecutionContext, to: Address, amount: Uint256) void {
    const storage = ctx.storage_backend;
    const sender = ctx.msg_sender;

    const bal = balances.get(storage, sender);
    sdk.require(bal.gte(amount), "insufficient balance");

    balances.set(storage, sender, bal.checkedSub(amount));
    balances.set(storage, to, balances.get(storage, to).checkedAdd(amount));
}
```

## Documentation

See [docs/SDK.md](../docs/SDK.md) for the full developer guide.
