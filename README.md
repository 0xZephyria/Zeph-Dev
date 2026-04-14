# Zephyria Node

This repository contains the core component of the Zephyria ecosystem:
1. **Zephyria Blockchain Node:** Next-generation L1 blockchain engineered with a RISC-V VM and native ZephyrDB storage.

## Project Structure

- `src/`: The Zephyria blockchain node source code.
- `vm/`: The standalone RISC-V RV32EM virtual machine engine.
- `tests/`: Integration tests, smart contracts tests, and e2e scripts.
- `docs/`: Technical research references.

## Building and Running

You need Zig installed.

```bash
# Build everything
zig build

# Run unit tests
zig build test

# Run VM and Node tests
zig build test-vm
zig build test-node
```
