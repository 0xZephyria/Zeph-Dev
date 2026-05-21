# Module Report: Virtual Machine (`vm/`)

This report provides a detailed analysis of the ForgeVM virtual machine codebase, its execution models, performance bottlenecks, and design patterns, evaluated against the goal of achieving high throughput (up to 1M TPS).

---

## 1. Directory Structure & File Index

The `vm/` module implements a custom 64-bit RISC-V interpreter (RV64IM with custom ZEPH extensions) running inside a sandboxed memory space.

| File | Size (Bytes) | Role & Responsibility |
| :--- | :--- | :--- |
| [vm.zig](file:///Users/karan/sol2zig/vm/vm.zig) | 7,522 | Public entrypoint/wrapper interface for embedding in the blockchain node. |
| [vm_pool.zig](file:///Users/karan/sol2zig/vm/vm_pool.zig) | 13,574 | Thread-sharded, lock-free VM instance cache and LRU pre-decoded instruction cache. |
| [core/decoder.zig](file:///Users/karan/sol2zig/vm/core/decoder.zig) | 17,358 | RV64IM + custom ZEPH opcode decoder. |
| [core/basic_block.zig](file:///Users/karan/sol2zig/vm/core/basic_block.zig) | 17,942 | Program flow analyzer that splits code into basic blocks and pre-calculates branch targets. |
| [core/executor.zig](file:///Users/karan/sol2zig/vm/core/executor.zig) | 45,649 | Standard switch-based fetch-decode-execute interpreter. |
| [core/threaded_executor.zig](file:///Users/karan/sol2zig/vm/core/threaded_executor.zig) | 28,113 | High-performance interpreter using pre-decoded instructions and basic block gas pre-charging. |
| [gas/meter.zig](file:///Users/karan/sol2zig/vm/gas/meter.zig) | 3,682 | EIP-2929 style gas tracking logic. |
| [gas/table.zig](file:///Users/karan/sol2zig/vm/gas/table.zig) | 6,784 | Fixed-size cost tables for instructions. |
| [memory/sandbox.zig](file:///Users/karan/sol2zig/vm/memory/sandbox.zig) | 16,075 | 512 KB region-partitioned bounds-checked linear memory. |
| [loader/contract_loader.zig](file:///Users/karan/sol2zig/vm/loader/contract_loader.zig) | 15,504 | Orchestrates binary type checking and loads binaries into sandboxed environments. |
| [loader/forge_format.zig](file:///Users/karan/sol2zig/vm/loader/forge_format.zig) | 8,732 | Parser/builder for compiler package metadata (`.forge`). |
| [loader/forge_loader.zig](file:///Users/karan/sol2zig/vm/loader/forge_loader.zig) | 16,991 | ELF parser (supporting ELF32 and ELF64) targeting ForgeVM linker script vaddrs. |
| [loader/zephbin_loader.zig](file:///Users/karan/sol2zig/vm/loader/zephbin_loader.zig) | 8,630 | Parser/loader for the compiler's proprietary `.fozbin` (ZephBin) binary format. |
| [syscall/dispatch.zig](file:///Users/karan/sol2zig/vm/syscall/dispatch.zig) | 70,418 | Syscall router that maps ECALLs/ZEPH opcodes to state changes and host environments. |

---

## 2. Core Execution Engine Analysis

The VM features two distinct execution models:

1. **Standard Interpreter (`executor.zig`)**
   - Implements a classic `while (status == .running) { step(); }` loop.
   - For every instruction, it:
     1. Fetches a 32-bit word from sandboxed memory.
     2. Pre-charges basic gas via an opcode mapping.
     3. Decodes the instruction into an `Instruction` union.
     4. Dispatches the instruction in a large `switch` statement.
     5. Validates registers and advances the program counter.
   - **Performance Rating**: Low. Each step incurs branch prediction misses on the central switch, memory fetches, and runtime decoding overhead.

2. **Threaded Interpreter (`threaded_executor.zig`)**
   - First parses instructions into a flat array of `DecodedInsn` structs.
   - Leverages `basic_block.zig` analysis to partition the program. Gas for an entire basic block is pre-charged upfront, avoiding incremental gas checks inside the block.
   - **Direct Threading / Flat Loop**: Skips instruction fetching and decoding in the hot loop.
   - **Performance Rating**: 2-3x speedup compared to the standard executor.

---

## 3. Storage and Memory Sandboxing

- The **`SandboxMemory`** allocates a fixed 640 KB buffer containing:
  - Code region (256 KB)
  - Memory/Stack region (256 KB)
  - Calldata region (64 KB)
  - Return data region (64 KB)
- Sandboxing is enforced through explicit manual checks (`addr >= sandbox.memStart and addr + size <= sandbox.memEnd`).
- Alignment operations utilize aligned pointers (`alignCast`, `@alignCast`) to provide zero-copy memory views (`getAligned32`) directly to host environments for SLOAD/SSTORE.

---

## 4. Bottlenecks & Mechanical Sympathy Critiques

To achieve 1 million TPS, the current VM architecture has several design limitations:

### A. Dynamic Allocations in the Execution Path
- **Pre-Decoding Overhead**: Running `runThreaded` triggers `threaded_executor.preDecodeProgram` and `basicBlock.analyze`, both of which call `allocator.alloc`. Even if freed immediately, heap allocations on the transaction hot path are a massive bottleneck.
- **Mitigation**: Pre-decoded instructions and basic-block analysis must be cached persistently in the P2P / consensus pipeline once a contract is loaded or compiled, so execution is 100% allocation-free.

### B. VM Instance Pooling Contention
- The `VMPool` distributes buffers across 128 shards using a hash of the thread ID. While this reduces mutex lock contention, work stealing and overflow allocations still block on mutexes.
- **Mitigation**: Implement a completely lock-free, single-writer thread-local cache where each execution thread owns its dedicated VM sandbox and instruction cache.

### C. Host-to-VM Bridge Call Overhead
- Custom ZEPH opcodes (`execCustom`) translate into host syscalls by shifting registers (`a0`-`a5`) and running a function pointer dispatch table (`SyscallFn`).
- Indirect function calls through pointers disrupt CPU branch-target buffers (BTBs) and speculative execution.
- **Mitigation**: Use comptime-generated inline syscall handlers or a monolithic branch switch that compiler optimizations can inline, bypassing the indirect `SyscallFn` pointer.

### D. Memory Reset Cost
- When a VM is released back to the pool, it runs `mem.reset()`. Resetting 512 KB of RAM via `memset` / `zero` for every transaction introduces massive memory bandwidth overhead.
- **Mitigation**: Implement a write-log tracker inside the sandbox that records modified memory offsets. On reset, only revert the dirty memory ranges, reducing the reset footprint to a few bytes.
