# Zephyria Node & Sol2Zig Transpiler

This repository contains two core components of the Zephyria ecosystem:
1. **Sol2Zig Transpiler:** A robust tool designed to transpile Solidiy smart contracts into Zig.
2. **Zephyria Blockchain Node:** Next-generation L1 blockchain engineered with a RISC-V VM and native ZephyrDB storage.

## Project Structure

- `tools/transpiler/`: The Sol2Zig transpiler source code.
- `src/`: The Zephyria blockchain node source code.
- `vm/`: The standalone RISC-V RV32EM virtual machine engine.
- `tests/`: Integration tests, smart contracts tests, and e2e scripts.
- `examples/`: Sample transpiled contracts and demos.
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
