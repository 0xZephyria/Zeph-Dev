# FORGE VM — Production Readiness Change Specification
# Zephyria Blockchain · Target: 1,000,000 TPS on Consumer Hardware
#
# This document is the authoritative engineering brief for every change
# required to evolve the existing ZephVM (RISC-V RV32EM) into the
# production FORGE VM (RISC-V RV64IM). Each section names the exact
# source file, lists every struct field / function signature that must
# change, explains WHY the change is required, and gives HOW to implement
# it precisely enough for a language model to produce correct Zig 0.14+
# code on the first attempt.
#
# Gemini Anti-Hallucination Rules (embed verbatim in every prompt):
#   1. No stubs, no TODOs, no placeholder comments — every function body
#      must be complete and compilable.
#   2. Never invent Zig stdlib functions. Only use symbols that exist in
#      Zig 0.15 std (e.g. std.mem.readInt, std.Thread.spawn, NOT
#      std.os.thread or std.Thread.Pool.init with invented signatures).
#   3. All error returns must use error unions. No panic, no unreachable
#      in production paths.
#   4. All memory passed across function boundaries must carry an explicit
#      std.mem.Allocator parameter — no hidden allocations.
#   5. u64 arithmetic for ALL register and address values — never u32
#      after the RV64 upgrade.
#   6. comptime constants (MEMORY_SIZE, POOL_SIZE, etc.) must be
#      computed from named primitives, never hardcoded magic numbers.
#   7. Thread-safety annotation: mark every function that touches shared
#      state with // THREAD-UNSAFE or // THREAD-SAFE (atomic) so future
#      reviewers understand the contract.
#   8. Every public function must have at least one test block immediately
#      below it in the same file.
#   9. Import paths must match the actual file layout in this repo —
#      never guess at @import paths.
#  10. Do not emit any code that calls OS-level functions (fork, mmap,
#      pthread) directly — use Zig's std.Thread and std.heap abstractions.

================================================================================
SECTION 0 — GLOBAL RENAME & TERMINOLOGY
================================================================================

SCOPE  : Every file in vm/ and src/vm/
ACTION : Search-and-replace the following tokens before making any other change.
         This must be the first diff so that later changes compile against the
         new names.

  Old token                New token
  ─────────────────────── ────────────────────────────
  "ZEPH"                  "FORGE"
  "zeph"                  "forge"
  "ZephVM"                "ForgeVM"
  "ZephHeader"            "ForgeHeader"
  "ZephPackage"           "ForgePackage"
  "zeph_format"           "forge_format"
  "ZEPH_MAGIC"            "FORGE_MAGIC"
  "ZEPH_VERSION"          "FORGE_VERSION"
  ".zeph"                 ".forge"
  "SyscallId.ROLE_CHECK"  "SyscallId.AUTHORITY_CHECK"    (see Section 5)
  "sol2zig"               "forgec"                        (compiler name)

File renames:
  vm/loader/zeph_format.zig   → vm/loader/forge_format.zig
  vm/loader/elf_parser.zig    → vm/loader/forge_loader.zig   (extended, see §7)

WHY: FORGE is the new language replacing ZEPH. Consistent naming prevents
     Gemini from mixing old/new APIs across files.

================================================================================
SECTION 1 — ARCHITECTURE UPGRADE: RV32EM → RV64IM
================================================================================

WHY THIS IS THE MOST CRITICAL CHANGE
--------------------------------------
The current VM executes RV32EM: 32-bit words, 16 registers (E-extension).
FORGE requires RV64IM: 64-bit words, 32 registers (full I base + M extension).

Reasons:
  a) FORGE's u256 type is implemented as four u64 limbs in registers.
     With only 16 x 32-bit registers, multi-limb arithmetic spills to memory
     constantly, destroying throughput. With 32 x 64-bit registers there is
     enough register space to keep two full u256 values in-flight.
  b) FORGE addresses are 32 bytes (256-bit hashes). Pointer arithmetic on
     these values requires 64-bit intermediates. Truncating to u32 corrupts
     the high bits.
  c) RV64 native MUL produces a 128-bit result in two registers (MULH+MUL),
     which the FORGE compiler uses for checked overflow in financial ops.
  d) RV64 gives access to 8-byte atomic LD/SD instructions needed for
     lock-free inter-thread communication in the parallel scheduler.

--------------------------------------------------------------------------------
FILE: vm/core/decoder.zig  — FULL REWRITE REQUIRED
--------------------------------------------------------------------------------

CHANGE 1.1 — Register index type: u4 → u5
  ALL struct fields:
    RType.rd, RType.rs1, RType.rs2 : u4  →  u5
    IType.rd, IType.rs1            : u4  →  u5
    SType.rs1, SType.rs2           : u4  →  u5
    BType.rs1, BType.rs2           : u4  →  u5
    UType.rd                       : u4  →  u5
    JType.rd                       : u4  →  u5

  WHY: RV64I uses 32 registers (x0–x31). u4 can only address 16.
       Gemini WILL forget this — the test suite catches it because any
       instruction encoding rs1=16..31 will silently truncate.

  HOW: In decode(), the rs1/rs2/rd extraction masks change:
    Old: rd  = @truncate((word >> 7)  & 0x1F)   → yields u4 (top bit lost)
    New: rd  = @truncate((word >> 7)  & 0x1F)   → yields u5 (no change needed
         but the FIELD TYPE must be u5 to hold the value without truncation)

  Concrete: change every `rd: u4` to `rd: u5` in the struct definitions.

CHANGE 1.2 — Immediate fields: i32 → i64
  ALL immediate fields in IType, SType, BType, UType, JType:
    imm: i32  →  i64

  WHY: RV64I sign-extends 12-bit and 20-bit immediates into 64-bit values.
       Keeping i32 means AUIPC with a high-address PC will overflow.

CHANGE 1.3 — New RV64I opcodes (add to Opcode struct)
  pub const OP_32: u7     = 0b0111011;   // RV64 word ops: ADDW, SUBW, etc.
  pub const OP_IMM_32: u7 = 0b0011011;   // RV64 word imm ops: ADDIW, etc.
  pub const LOAD_FP: u7   = 0b0000111;   // Reserved — emit fault
  pub const STORE_FP: u7  = 0b0100111;   // Reserved — emit fault

  Also update the LOAD opcode handler to decode LWU (funct3=0b110) and
  LD (funct3=0b011), and the STORE opcode to decode SD (funct3=0b011).

CHANGE 1.4 — New funct3 values for RV64 loads/stores (add to Funct3 struct)
  pub const LWU: u3 = 0b110;   // Load word unsigned (zero-extend to 64)
  pub const LD:  u3 = 0b011;   // Load doubleword
  pub const SD:  u3 = 0b011;   // Store doubleword (same value, different opcode)

CHANGE 1.5 — New Instruction variants (add to Instruction union and Tag enum)
  The RV64 word-sized operations (ADDW, SUBW, SLLW, SRLW, SRAW, MULW,
  DIVW, DIVUW, REMW, REMUW) share the R-type encoding but use opcode
  OP_32. Similarly, ADDIW / SLLIW / SRLIW / SRAIW share I-type encoding
  with opcode OP_IMM_32.

  APPROACH: Do NOT add new Instruction variants. Instead, decode OP_32
  and OP_IMM_32 into the EXISTING r_type / i_type variants but set a new
  flag field `word_op: bool` on RType and IType:

    pub const RType = struct {
        rd: u5, rs1: u5, rs2: u5,
        funct3: u3, funct7: u7,
        word_op: bool,   // true = RV64W variant (ADDW not ADD)
    };
    pub const IType = struct {
        rd: u5, rs1: u5,
        funct3: u3,
        imm: i64,
        word_op: bool,   // true = ADDIW, SLLIW, etc.
    };

  HOW to set: in decode(), after extracting the opcode:
    const word_op = (opcode == Opcode.OP_32 or opcode == Opcode.OP_IMM_32);

CHANGE 1.6 — decode() function: update ALL field assignments to use u5/i64
  Every `@truncate(... & 0x1F)` that assigns to an rd/rs field must yield u5.
  Zig's @truncate keeps low bits, so the value is correct — only the type
  declaration in the struct needs widening.
  The sign-extension for immediates must produce i64:
    Old: const imm: i32 = @as(i32, @bitCast(raw_imm << 20)) >> 20;
    New: const imm: i64 = @as(i64, @bitCast(@as(u64, raw_imm) << 52)) >> 52;
  Apply the same pattern for S, B, U, J immediate extraction.

--------------------------------------------------------------------------------
FILE: vm/core/executor.zig  — MAJOR CHANGES
--------------------------------------------------------------------------------

CHANGE 1.7 — Register file: [16]u32 → [32]u64
  pub const ZephVM = struct {
    Old: regs: [16]u32,
    New: regs: [32]u64,

  WHY: 32 registers, 64-bit each. Every register read/write in execR,
       execI, execS, execB must use u64 arithmetic.

CHANGE 1.8 — PC type remains u32
  Keep `pc: u32` — the code address space is still bounded to 64 KB
  (CODE_SIZE = 0x10000) so u32 is sufficient. Do NOT change this to u64
  unless code_len itself exceeds 4 GB.

CHANGE 1.9 — All arithmetic results: u32 → u64
  In execR() and execI():
    const result: u32 = ...   →   const result: u64 = ...

  For "word" operations (when r.word_op == true), the result must be
  sign-extended from 32 bits to 64 bits:
    fn signExtend32(val: u64) u64 {
        // Treat lower 32 bits as i32, sign-extend to i64, reinterpret as u64
        return @bitCast(@as(i64, @as(i32, @truncate(val))));
    }
  Apply signExtend32() to the result of ADDW, SUBW, SLLW, SRLW, SRAW,
  MULW, DIVW, DIVUW, REMW, REMUW before writing to rd.

CHANGE 1.10 — execMulDiv: promote operands to u64/i64
  Old: const s1: i32 = @bitCast(rs1);  const s2: i32 = @bitCast(rs2);
  New: const s1: i64 = @bitCast(rs1);  const s2: i64 = @bitCast(rs2);

  MULH result: upper 64 bits of signed × signed (i128 intermediate):
    const product: i128 = @as(i128, s1) * @as(i128, s2);
    @truncate(@as(u128, @bitCast(product)) >> 64)

  MULHU: upper 64 bits of u64 × u64:
    const product: u128 = @as(u128, rs1) * @as(u128, rs2);
    @truncate(product >> 64)

  MULHSU: upper 64 bits of signed × unsigned:
    const product: i128 = @as(i128, s1) * @as(i128, @intCast(rs2));
    @truncate(@as(u128, @bitCast(product)) >> 64)

  For DIVW / REMW (word-op): operate on lower 32 bits as i32,
  then sign-extend result to u64.

CHANGE 1.11 — execI LOAD: add LWU and LD cases
  decoder.Funct3.LWU => {
      // Load 4 bytes, zero-extend to 64
      const w = vm.memory.loadWord(addr) catch { ... };
      break :blk @as(u64, w);
  },
  decoder.Funct3.LD => {
      const dw = vm.memory.loadDoubleword(addr) catch { ... };
      break :blk dw;
  },

  decoder.Funct3.SD in execS:
      vm.memory.storeDoubleword(addr, rs2) catch { ... };

CHANGE 1.12 — x0 enforcement: set regs[0] = 0 as u64 (no change needed beyond type)

CHANGE 1.13 — Stack pointer initialization: STACK_TOP as u64
  vm.regs[2] = @as(u64, sandbox.STACK_TOP);

CHANGE 1.14 — getReg / setReg: return/accept u64
  pub fn getReg(self: *const ForgeVM, reg: u5) u64 { ... }
  pub fn setReg(self: *ForgeVM, reg: u5, val: u64) void { ... }

--------------------------------------------------------------------------------
FILE: vm/core/threaded_executor.zig  — UPDATE TYPES THROUGHOUT
--------------------------------------------------------------------------------

CHANGE 1.15 — DecodedInsn: no structural change, but gas_cost stays u64 (fine)

CHANGE 1.16 — All local variables that hold register values: u32 → u64
  Search for patterns like:
    const rs1 = vm.regs[r.rs1];   // was u32, now u64 automatically
  No manual change needed IF the register file type is already changed.
  But VERIFY that no intermediate cast to u32 exists (Gemini may introduce one).

CHANGE 1.17 — dispatchDecoded: pass word_op flag through correctly
  The DecodedInsn.insn union already embeds word_op in the RType/IType struct
  (from Change 1.5). No additional fields needed in DecodedInsn.

================================================================================
SECTION 2 — MEMORY MODEL EXPANSION
================================================================================

WHY: The FORGE language operates on larger data structures than ZEPH:
  - u256 values (32 bytes each) are first-class — DeFi arithmetic
  - Asset structs with metadata can be 256–512 bytes
  - FORGE contracts are larger (up to 128 KB) due to richer type system
  - 1M TPS means each VM instance must be cache-resident (≤L2, ~256 KB)

--------------------------------------------------------------------------------
FILE: vm/memory/sandbox.zig  — REGION LAYOUT CHANGE
--------------------------------------------------------------------------------

CHANGE 2.1 — New memory region layout

  Old total: 640 KB (CODE 64KB + HEAP 256KB + STACK 64KB + CALLDATA 16KB + RETURN 16KB)
  New total: 512 KB  — SMALLER, not larger.

  WHY smaller? At 1M TPS / 8 cores = 125K TX/s/core. Each core may have
  ~4 VMs in-flight simultaneously (pipeline depth). 4 × 512KB = 2MB per core,
  which fits in L3 but not L2. Reducing to 512KB allows 2 VMs per core to fit
  in a 1MB L2 (common on modern AMD/Intel cores), doubling cache hit rate.

  New layout:
    Region       Start        End          Size    Permission
    ─────────── ──────────── ──────────── ─────── ────────────────
    Code        0x0000_0000  0x0001_FFFF   128 KB  read_execute
    Heap        0x0002_0000  0x0005_FFFF   256 KB  read_write
    Stack       0x0006_0000  0x0006_FFFF    64 KB  read_write
    Calldata    0x0007_0000  0x0007_3FFF    16 KB  read_only
    Return      0x0007_4000  0x0007_7FFF    16 KB  read_write
    Scratch     0x0007_8000  0x0007_FFFF    32 KB  read_write
    ─────────── ──────────── ──────────── ─────── ────────────────
    Total:                                512 KB

  Code region doubles (128 KB) because FORGE contracts are larger.
  Scratch region (NEW) is used for u256 intermediate computation buffers
  so the compiler can spill to a dedicated area without polluting heap.

  Update ALL constants:
    CODE_SIZE: u32   = 0x0002_0000;   // 128 KB
    HEAP_START: u32  = 0x0002_0000;
    HEAP_END: u32    = 0x0005_FFFF;
    STACK_START: u32 = 0x0006_0000;
    STACK_END: u32   = 0x0006_FFFF;
    STACK_TOP: u32   = 0x0006_FFFC;
    CALLDATA_START: u32 = 0x0007_0000;
    CALLDATA_END: u32   = 0x0007_3FFF;
    RETURN_START: u32   = 0x0007_4000;
    RETURN_END: u32     = 0x0007_7FFF;
    SCRATCH_START: u32  = 0x0007_8000;  // NEW
    SCRATCH_END: u32    = 0x0007_FFFF;  // NEW
    MEMORY_SIZE: u32    = 0x0008_0000;  // 512 KB total

CHANGE 2.2 — Add loadDoubleword / storeDoubleword methods
  These are required by the RV64 LD/SD instructions (Change 1.11).

  pub fn loadDoubleword(self: *SandboxMemory, addr: u32) MemoryError!u64 {
      // Alignment check: must be 8-byte aligned
      if (addr & 7 != 0) return MemoryError.MisalignedAccess;
      // Bounds check: addr through addr+7 must be in a readable region
      try self.checkAccess(addr, 8, .read);
      // Little-endian load of 8 bytes
      return std.mem.readInt(u64, self.backing[addr..][0..8], .little);
  }

  pub fn storeDoubleword(self: *SandboxMemory, addr: u32, val: u64) MemoryError!void {
      if (addr & 7 != 0) return MemoryError.MisalignedAccess;
      try self.checkAccess(addr, 8, .write);
      std.mem.writeInt(u64, self.backing[addr..][0..8], val, .little);
  }

  HOW to implement checkAccess (helper replacing the region-by-region lookup):
    fn checkAccess(self: *const SandboxMemory, addr: u32, size: u32, perm: AccessKind) MemoryError!void {
        const end = addr +% (size - 1);
        if (end < addr) return MemoryError.SegFault; // wrap-around
        if (end >= MEMORY_SIZE) return MemoryError.SegFault;
        // Region lookup via comptime table — O(1), no loop
        const region = regionForAddr(addr) orelse return MemoryError.SegFault;
        if (end > region.end) return MemoryError.SegFault;
        switch (perm) {
            .read  => {},  // all regions are readable
            .write => if (region.perm == .read_execute or region.perm == .read_only)
                          return MemoryError.PermissionDenied,
            .exec  => if (region.perm != .read_execute)
                          return MemoryError.PermissionDenied,
        }
    }

CHANGE 2.3 — reset() must zero the Scratch region
  Add to the existing reset() body:
    @memset(self.backing[SCRATCH_START..SCRATCH_END + 1], 0);

================================================================================
SECTION 3 — GAS MODEL RECALIBRATION FOR FORGE
================================================================================

WHY: The existing gas costs in gas/table.zig are cloned from EIP-2929 (Ethereum).
     FORGE has a different economic model:
       - No "cold storage" penalty — FORGE uses Merkle proofs batched per block
         so all storage within a TX is effectively "warm"
       - FORGE introduces ASSET opcodes with their own costs
       - RV64 multiply is cheaper on modern silicon than the existing MUL=2 cost
       - Syscall costs must reflect Zephyria's consensus model, not Ethereum's

--------------------------------------------------------------------------------
FILE: vm/gas/table.zig  — SIGNIFICANT CHANGES
--------------------------------------------------------------------------------

CHANGE 3.1 — Recalibrated InstructionGas constants
  Replace the existing struct body with:

    pub const ALU:       u64 = 1;    // unchanged
    pub const ALU_IMM:   u64 = 1;    // unchanged
    pub const MUL:       u64 = 2;    // unchanged (RV64 MULH still multi-cycle)
    pub const MULW:      u64 = 2;    // new: 32-bit word multiply
    pub const DIV:       u64 = 5;    // increased: 64-bit division is slower
    pub const DIVW:      u64 = 3;    // new: 32-bit word division
    pub const LOAD_WORD: u64 = 2;    // reduced from 3: LW/LD in hot cache
    pub const LOAD_BYTE: u64 = 3;    // LB/LH (byte lane split costs more)
    pub const STORE:     u64 = 2;    // reduced from 3
    pub const BRANCH:    u64 = 1;    // reduced: branch predictor hits >90%
    pub const JAL:       u64 = 2;    // unchanged
    pub const JALR:      u64 = 2;    // unchanged
    pub const LUI:       u64 = 1;    // unchanged
    pub const AUIPC:     u64 = 1;    // unchanged
    pub const ECALL_BASE: u64 = 3;   // reduced from 5
    pub const EBREAK:    u64 = 1;    // unchanged

CHANGE 3.2 — New opcode→cost table entries for OP_32 and OP_IMM_32
  The OPCODE_GAS_TABLE array is indexed by opcode (u7 = 0–127).
  Add entries for the new opcodes:
    OPCODE_GAS_TABLE[Opcode.OP_32]     = InstructionGas.ALU;   // base cost, executor adds extra for MUL/DIV variants
    OPCODE_GAS_TABLE[Opcode.OP_IMM_32] = InstructionGas.ALU_IMM;

CHANGE 3.3 — Replace SyscallGas with FORGE-specific costs
  Remove ALL EVM-specific comments ("EIP-2929", "EIP-3529", "Shanghai").
  Replace the struct with:

    pub const SyscallGas = struct {
        // ── Storage (FORGE flat model, no warm/cold distinction) ──
        pub const STORAGE_LOAD:         u64 = 200;
        pub const STORAGE_STORE:        u64 = 500;
        pub const STORAGE_STORE_SET:    u64 = 5_000;   // 0 → non-zero
        pub const STORAGE_CLEAR_REFUND: u64 = 2_000;   // non-zero → 0

        // ── Asset operations (FORGE-native, no EVM equivalent) ──
        pub const ASSET_TRANSFER:       u64 = 300;
        pub const ASSET_CREATE:         u64 = 20_000;
        pub const ASSET_BURN:           u64 = 500;
        pub const ASSET_QUERY_BALANCE:  u64 = 100;
        pub const ASSET_QUERY_METADATA: u64 = 150;

        // ── Authority / Role system ──
        pub const AUTHORITY_CHECK:      u64 = 50;
        pub const AUTHORITY_GRANT:      u64 = 1_000;
        pub const AUTHORITY_REVOKE:     u64 = 1_000;

        // ── Cross-contract calls ──
        pub const CALL_CONTRACT:        u64 = 200;
        pub const DELEGATECALL:         u64 = 200;
        pub const STATICCALL:           u64 = 200;

        // ── Events ──
        pub const EMIT_EVENT_BASE:      u64 = 100;
        pub const EMIT_EVENT_PER_TOPIC: u64 = 50;
        pub const EMIT_EVENT_PER_BYTE:  u64 = 4;

        // ── Environment queries ──
        pub const GET_CALLER:           u64 = 2;
        pub const GET_CALLVALUE:        u64 = 2;
        pub const GET_CALLDATA:         u64 = 2;
        pub const RETURN_DATA:          u64 = 0;
        pub const REVERT:               u64 = 0;

        // ── Cryptography ──
        pub const HASH_BLAKE3_BASE:     u64 = 20;      // replaces KECCAK256
        pub const HASH_BLAKE3_PER_WORD: u64 = 4;
        pub const HASH_SHA256_BASE:     u64 = 30;
        pub const HASH_SHA256_PER_WORD: u64 = 6;
        pub const ECRECOVER:            u64 = 3_000;
        pub const BLS_VERIFY:           u64 = 45_000;  // BLS12-381 pairing

        // ── Parallel execution hints (gas rebate for conflict-free ops) ──
        pub const PARALLEL_HINT:        u64 = 0;       // free — just metadata
        pub const RESOURCE_LOCK:        u64 = 100;
        pub const RESOURCE_UNLOCK:      u64 = 50;

        // ── Debug (stripped in production build) ──
        pub const DEBUG_LOG:            u64 = 0;
    };

================================================================================
SECTION 4 — VM POOL: LOCK-FREE PER-THREAD POOLS FOR 1M TPS
================================================================================

WHY: The existing VMPool uses a single std.ArrayList free_list with no
     synchronization. At 1M TPS / 8 cores this creates a hot mutex contention
     point that destroys throughput. The fix is per-thread pools that never
     need locking in the fast path.

--------------------------------------------------------------------------------
FILE: vm/vm_pool.zig  — MAJOR REDESIGN
--------------------------------------------------------------------------------

CHANGE 4.1 — Replace single pool with thread-local shard array

  The new design uses a statically-sized array of pool shards, one per
  hardware thread (up to MAX_SHARDS = 128). Each thread accesses only its
  own shard using a thread-local index, eliminating ALL mutex contention
  on the acquire/release hot path.

  New top-level constants:
    const MAX_SHARDS: u32    = 128;   // max hardware threads supported
    const SHARD_POOL_SIZE: u32 = 16;  // buffers per shard
    const OVERFLOW_LIMIT: u32  = 8;   // per-shard overflow allowance

  New PoolShard struct (replaces VMPool):
    pub const PoolShard = struct {
        // Fixed-size ring buffer — no dynamic allocation at runtime
        slots: [SHARD_POOL_SIZE]*SandboxMemory,
        head: u32,   // next slot to acquire from
        tail: u32,   // next slot to release to
        count: u32,  // current number of available buffers
        overflow: u32, // buffers allocated beyond the shard (to be freed on release)
    };

  New top-level ForgeVMPool:
    pub const ForgeVMPool = struct {
        shards: [MAX_SHARDS]PoolShard,
        shard_allocator: std.mem.Allocator,
        shard_count: u32,   // actual number of active shards
        code_cache: CodeCache,  // separate struct, see Change 4.3
    };

CHANGE 4.2 — acquire() and release(): shard-local, no lock

  pub fn acquire(self: *ForgeVMPool, shard_idx: u32) *SandboxMemory {
      // THREAD-UNSAFE: caller guarantees shard_idx is private to this thread
      const shard = &self.shards[shard_idx];
      if (shard.count > 0) {
          const mem = shard.slots[shard.head % SHARD_POOL_SIZE];
          shard.head += 1;
          shard.count -= 1;
          mem.reset();
          return mem;
      }
      // Overflow: allocate fresh, mark as overflow
      shard.overflow += 1;
      const fresh = self.shard_allocator.create(SandboxMemory) catch @panic("OOM in VMPool");
      fresh.* = SandboxMemory.init(self.shard_allocator) catch @panic("OOM in sandbox init");
      return fresh;
  }

  pub fn release(self: *ForgeVMPool, shard_idx: u32, mem: *SandboxMemory) void {
      // THREAD-UNSAFE
      const shard = &self.shards[shard_idx];
      if (shard.overflow > 0) {
          // This was an overflow allocation — free it rather than pool it
          mem.deinit();
          self.shard_allocator.destroy(mem);
          shard.overflow -= 1;
          return;
      }
      if (shard.count < SHARD_POOL_SIZE) {
          shard.slots[shard.tail % SHARD_POOL_SIZE] = mem;
          shard.tail += 1;
          shard.count += 1;
          return;
      }
      // Shard is full (shouldn't happen in steady state) — free it
      mem.deinit();
      self.shard_allocator.destroy(mem);
  }

CHANGE 4.3 — CodeCache: thread-safe LRU with read-write lock

  The pre-decoded instruction cache IS shared across threads (a contract
  deployed once should benefit all cores). Use a std.RwLock:

    pub const CodeCache = struct {
        entries: std.AutoHashMap([32]u8, CachedProgram),
        lock: std.Thread.RwLock,
        max_entries: u32,
        allocator: std.mem.Allocator,
        access_counter: std.atomic.Value(u64),

        pub fn get(self: *CodeCache, code_hash: [32]u8) ?[]const DecodedInsn {
            // THREAD-SAFE: acquires read lock
            self.lock.lockShared();
            defer self.lock.unlockShared();
            const entry = self.entries.get(code_hash) orelse return null;
            _ = self.access_counter.fetchAdd(1, .monotonic);
            return entry.decoded_insns;
        }

        pub fn put(self: *CodeCache, code_hash: [32]u8, insns: []const DecodedInsn, allocator: std.mem.Allocator) !void {
            // THREAD-SAFE: acquires write lock
            self.lock.lock();
            defer self.lock.unlock();
            if (self.entries.count() >= self.max_entries) {
                self.evictOldest();   // LRU eviction
            }
            const owned = try allocator.dupe(DecodedInsn, insns);
            try self.entries.put(code_hash, .{
                .decoded_insns = owned,
                .last_access = self.access_counter.load(.monotonic),
            });
        }
    };

    pub const CachedProgram = struct {
        decoded_insns: []const DecodedInsn,
        last_access: u64,
    };

CHANGE 4.4 — Remove CachedCode.decoded_insns: []const u8 (opaque bytes)
  Replace with typed:  decoded_insns: []const DecodedInsn
  WHY: The old design cast []u8 to []DecodedInsn which is undefined behavior
       if alignment differs. Use the typed slice directly.

================================================================================
SECTION 5 — SYSCALL DISPATCH: FORGE-NATIVE ABI
================================================================================

WHY: The existing dispatch.zig implements a quasi-EVM ABI with 44 syscall IDs
     (SELFDESTRUCT, RETURNDATACOPY, EXTCODESIZE, etc.) that have no meaning
     in FORGE's isolated account model. These must be replaced with FORGE's
     native operations: Assets, Authority, parallel hints, and BLAKE3 hashing.

--------------------------------------------------------------------------------
FILE: vm/syscall/dispatch.zig  — FULL SYSCALL TABLE REPLACEMENT
--------------------------------------------------------------------------------

CHANGE 5.1 — New SyscallId table (replace old struct body entirely)

  pub const SyscallId = struct {
      // ── Storage ──────────────────────────────────────────────────
      pub const STORAGE_LOAD:          u32 = 0x01;
      pub const STORAGE_STORE:         u32 = 0x02;
      pub const STORAGE_LOAD_DERIVED:  u32 = 0x03;   // per-user slot (DerivedKey)
      pub const STORAGE_STORE_DERIVED: u32 = 0x04;
      pub const STORAGE_LOAD_GLOBAL:   u32 = 0x05;   // commutative accumulator
      pub const STORAGE_STORE_GLOBAL:  u32 = 0x06;

      // ── Assets (FORGE-native, no EVM equivalent) ──────────────────
      pub const ASSET_TRANSFER:        u32 = 0x10;
      pub const ASSET_BALANCE:         u32 = 0x11;
      pub const ASSET_CREATE:          u32 = 0x12;
      pub const ASSET_BURN:            u32 = 0x13;
      pub const ASSET_METADATA:        u32 = 0x14;
      pub const ASSET_APPROVE:         u32 = 0x15;
      pub const ASSET_ALLOWANCE:       u32 = 0x16;

      // ── Authority (FORGE role system) ────────────────────────────
      pub const AUTHORITY_CHECK:       u32 = 0x20;
      pub const AUTHORITY_GRANT:       u32 = 0x21;
      pub const AUTHORITY_REVOKE:      u32 = 0x22;
      pub const AUTHORITY_LIST:        u32 = 0x23;

      // ── Events ───────────────────────────────────────────────────
      pub const EMIT_EVENT:            u32 = 0x30;
      pub const EMIT_INDEXED_EVENT:    u32 = 0x31;

      // ── Cross-contract calls ──────────────────────────────────────
      pub const CALL_CONTRACT:         u32 = 0x40;
      pub const DELEGATECALL:          u32 = 0x41;
      pub const STATICCALL:            u32 = 0x42;
      pub const CREATE_CONTRACT:       u32 = 0x43;

      // ── Execution control ────────────────────────────────────────
      pub const RETURN_DATA:           u32 = 0x50;
      pub const REVERT:                u32 = 0x51;

      // ── Environment ──────────────────────────────────────────────
      pub const GET_CALLER:            u32 = 0x60;
      pub const GET_CALLVALUE:         u32 = 0x61;
      pub const GET_CALLDATA:          u32 = 0x62;
      pub const GET_CALLDATA_SIZE:     u32 = 0x63;
      pub const GET_SELF_ADDRESS:      u32 = 0x64;
      pub const GET_BLOCK_NUMBER:      u32 = 0x65;
      pub const GET_TIMESTAMP:         u32 = 0x66;
      pub const GET_CHAIN_ID:          u32 = 0x67;
      pub const GET_GAS_REMAINING:     u32 = 0x68;
      pub const GET_TX_ORIGIN:         u32 = 0x69;
      pub const GET_GAS_PRICE:         u32 = 0x6A;
      pub const GET_COINBASE:          u32 = 0x6B;
      pub const GET_BLOCK_HASH:        u32 = 0x6C;   // VRF randomness

      // ── Cryptography ─────────────────────────────────────────────
      pub const HASH_BLAKE3:           u32 = 0x70;   // replaces KECCAK256
      pub const HASH_SHA256:           u32 = 0x71;
      pub const ECRECOVER:             u32 = 0x72;
      pub const BLS_VERIFY:            u32 = 0x73;

      // ── Parallel execution hints ──────────────────────────────────
      pub const RESOURCE_LOCK:         u32 = 0x80;   // declare write intent
      pub const RESOURCE_UNLOCK:       u32 = 0x81;
      pub const PARALLEL_HINT:         u32 = 0x82;   // mark region conflict-free

      // ── Debug (only active in debug build) ───────────────────────
      pub const DEBUG_LOG:             u32 = 0xFF;
  };

CHANGE 5.2 — Syscall ABI register conventions (update all handler code)

  FORGE syscall ABI (RV64IM calling convention):
    x10 (a0) = syscall ID
    x11 (a1) = argument 1
    x12 (a2) = argument 2
    x13 (a3) = argument 3
    x14 (a4) = argument 4
    x15 (a5) = argument 5
    Return:
    x10 (a0) = return value low 64 bits
    x11 (a1) = return value high 64 bits (for 128-bit returns like u256 low half)

  Old code read from vm.regs[10..14] as u32. Change to read as u64:
    const syscall_id: u32 = @truncate(vm.regs[10]);
    const arg1: u64 = vm.regs[11];
    const arg2: u64 = vm.regs[12];
    const arg3: u64 = vm.regs[13];
    const arg4: u64 = vm.regs[14];
    const arg5: u64 = vm.regs[15];

CHANGE 5.3 — Remove all EVM-specific syscall handlers
  Delete handler functions for:
    SELFDESTRUCT, RETURNDATASIZE, RETURNDATACOPY, EXTCODESIZE, CODECOPY,
    EXTCODEHASH (GET_CODE_HASH), TLOAD, TSTORE, CREATE2, GET_BASEFEE,
    GET_PREVRANDAO, GET_GASPRICE (rename to GET_GAS_PRICE at new ID)
  These have no equivalent in FORGE's execution model.

CHANGE 5.4 — Add BLAKE3 hash handler (replaces KECCAK256)
  WHY: BLAKE3 is ~3× faster than Keccak256 on modern CPUs without hardware
       acceleration. FORGE uses BLAKE3 as its native hash function.
       The Zig std.crypto.hash.Blake3 implementation is production-ready.

  fn handleBlake3(vm: *ForgeVM, host: *HostEnv) SyscallError!void {
      const data_ptr: u32 = @truncate(vm.regs[11]);   // pointer into sandbox
      const data_len: u32 = @truncate(vm.regs[12]);
      const out_ptr: u32  = @truncate(vm.regs[13]);   // output: 32 bytes in scratch/heap

      // Charge gas
      const word_count = (data_len + 7) / 8;  // 8-byte words for RV64
      const gas_cost = SyscallGas.HASH_BLAKE3_BASE + word_count * SyscallGas.HASH_BLAKE3_PER_WORD;
      vm.gas.consume(gas_cost) catch return SyscallError.OutOfGas;

      // Read input from sandbox memory
      const data = vm.memory.backing[data_ptr..data_ptr + data_len];

      // Compute hash
      var out: [32]u8 = undefined;
      std.crypto.hash.Blake3.hash(data, &out, .{});

      // Write result to sandbox memory
      vm.memory.backing[out_ptr..out_ptr + 32][0..32].* = out;

      // Return: a0 = 0 (success)
      vm.regs[10] = 0;
  }

CHANGE 5.5 — Add ASSET_TRANSFER handler
  Asset transfers are the most common FORGE operation. The handler must:
  1. Read asset_id (32 bytes from scratch), from_addr (20 bytes), to_addr (20 bytes), amount (u64)
  2. Call host.asset_transfer_fn with these parameters
  3. The host function validates authority and updates balances in the Overlay

  Register convention for ASSET_TRANSFER (0x10):
    x11 = pointer to 32-byte asset_id in sandbox
    x12 = pointer to 20-byte from_addr in sandbox
    x13 = pointer to 20-byte to_addr in sandbox
    x14 = amount (u64, low bits)
    x15 = amount_high (u64, for assets with >64-bit supply — set to 0 for most)

  Add to HostEnv struct:
    asset_transfer_fn: ?*const fn(host: *HostEnv, asset_id: [32]u8, from: [20]u8, to: [20]u8, amount: u128) AssetError!void = null,

CHANGE 5.6 — Add AUTHORITY_CHECK handler
  The FORGE authority system replaces ERC-721 ownership and ERC-1155 roles
  with a native capability model. Contracts declare required capabilities
  at the bytecode level; the VM checks them via this syscall.

  Register convention for AUTHORITY_CHECK (0x20):
    x11 = pointer to 32-byte role_id in sandbox
    x12 = pointer to 20-byte subject_addr in sandbox
    x10 (return) = 1 if authorized, 0 if not

CHANGE 5.7 — PARALLEL_HINT handler (new, no equivalent in old code)
  This syscall is a VM hint — it does not modify state. It informs the
  parallel scheduler that the subsequent storage accesses in this TX will
  not conflict with any other TX's declared access set.

  fn handleParallelHint(vm: *ForgeVM, host: *HostEnv) SyscallError!void {
      // x11 = pointer to ConflictDescriptor in sandbox memory
      // x12 = length of ConflictDescriptor in bytes
      // The VM simply marks this execution as parallel-safe in the host context.
      // No gas charged (PARALLEL_HINT cost = 0).
      const desc_ptr: u32 = @truncate(vm.regs[11]);
      const desc_len: u32 = @truncate(vm.regs[12]);
      _ = desc_ptr; _ = desc_len;  // Scheduler reads these asynchronously
      host.parallel_safe = true;
      vm.regs[10] = 0;
  }

  Add to HostEnv struct:
    parallel_safe: bool = false,

================================================================================
SECTION 6 — CONTRACT FORMAT: .zeph → .forge
================================================================================

--------------------------------------------------------------------------------
FILE: vm/loader/forge_format.zig  (renamed from zeph_format.zig)
--------------------------------------------------------------------------------

CHANGE 6.1 — New magic bytes and version
  pub const FORGE_MAGIC = [4]u8{ 'F', 'R', 'G', 'E' };
  pub const FORGE_VERSION: u16 = 1;

CHANGE 6.2 — Extended ForgeHeader (replace ZephHeader entirely)
  The FORGE format adds three new sections: type_table, source_map_hash,
  and parallel_descriptor. The header grows from 64 bytes to 96 bytes.

  pub const ForgeHeader = extern struct {
      magic:    [4]u8  = FORGE_MAGIC,
      version:  u16    = FORGE_VERSION,
      flags:    u16    = 0,
      arch:     u8     = 64,   // NEW: 32 or 64 (RISC-V word size)
      _pad:     [3]u8  = .{0, 0, 0},

      // Bytecode section (compiled RISC-V RV64IM)
      bytecode_offset: u32 = 0,
      bytecode_size:   u32 = 0,

      // ABI section (FORGE ABI JSON)
      abi_offset: u32 = 0,
      abi_size:   u32 = 0,

      // Metadata section
      metadata_offset: u32 = 0,
      metadata_size:   u32 = 0,

      // NEW: Type table (FORGE static type info for runtime reflection)
      type_table_offset: u32 = 0,
      type_table_size:   u32 = 0,

      // NEW: Parallel descriptor (conflict-free access set declarations)
      parallel_desc_offset: u32 = 0,
      parallel_desc_size:   u32 = 0,

      // Code hash (BLAKE3 of bytecode, not Keccak256)
      code_hash: [32]u8 = [_]u8{0} ** 32,
  };

  comptime {
      // Ensure the struct is exactly 96 bytes so the on-disk format is stable
      std.debug.assert(@sizeOf(ForgeHeader) == 96);
  }

CHANGE 6.3 — Update Flags constants
  pub const Flags = struct {
      pub const HAS_ABI:          u16 = 0x0001;
      pub const HAS_METADATA:     u16 = 0x0002;
      pub const HAS_CONSTRUCTOR:  u16 = 0x0004;
      pub const HAS_SOURCE_MAP:   u16 = 0x0008;
      pub const HAS_TYPE_TABLE:   u16 = 0x0010;   // NEW
      pub const HAS_PARALLEL_DESC: u16 = 0x0020;  // NEW
      pub const IS_RV64:          u16 = 0x0040;   // NEW: always set for FORGE
  };

CHANGE 6.4 — ForgePackage: add new optional slices
  pub const ForgePackage = struct {
      header:           ForgeHeader,
      bytecode:         []const u8,
      abi:              ?[]const u8,
      metadata:         ?[]const u8,
      type_table:       ?[]const u8,   // NEW
      parallel_desc:    ?[]const u8,   // NEW
  };

CHANGE 6.5 — code hash: Keccak256 → BLAKE3
  In the build() function, replace:
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
  With:
    std.crypto.hash.Blake3.hash(bytecode, &code_hash, .{});

================================================================================
SECTION 7 — LOADER: forge_loader.zig (replaces elf_parser.zig + contract_loader.zig)
================================================================================

WHY: The existing split between elf_parser.zig and contract_loader.zig creates
     redundant passes over the binary. Merge them into a single forge_loader.zig
     that parses .forge packages, validates, and loads in one pass.

--------------------------------------------------------------------------------
FILE: vm/loader/forge_loader.zig  — NEW FILE
--------------------------------------------------------------------------------

CHANGE 7.1 — Add ELF class validation: must be ELF64 (ELFCLASS64 = 2)
  The old elf_parser only handled ELF32. FORGE emits ELF64 for RV64.
  Check byte [4] of the ELF header:
    if (elf_data[4] != 2) return LoadError.WrongElfClass;  // must be ELFCLASS64

CHANGE 7.2 — Program header parsing: use 64-bit fields
  ELF64 program headers have different offsets and field sizes than ELF32.
  The Phdr struct for ELF64:
    p_type:   u32  at offset 0
    p_flags:  u32  at offset 4
    p_offset: u64  at offset 8
    p_vaddr:  u64  at offset 16
    p_paddr:  u64  at offset 24
    p_filesz: u64  at offset 32
    p_memsz:  u64  at offset 40
    p_align:  u64  at offset 48
  Total: 56 bytes per Phdr.

  When loading code segments, cast p_vaddr and p_filesz to u32 ONLY after
  validating they fit within the sandbox memory bounds.

CHANGE 7.3 — Entry point: read from e_entry field (u64 for ELF64)
  The ELF64 header e_entry is at offset 24 and is u64.
  After extracting: validate entry_point < CODE_END, then cast to u32.

CHANGE 7.4 — Single-pass load: parse ForgePackage → validate → load → execute
  pub fn loadAndExecute(
      allocator: std.mem.Allocator,
      forge_pkg: []const u8,   // raw .forge file bytes
      calldata: []const u8,
      gas_limit: u64,
      pool: *ForgeVMPool,
      shard_idx: u32,
      host: *HostEnv,
  ) !ContractResult {
      // Step 1: parse .forge package header
      const pkg = try forge_format.parse(forge_pkg);

      // Step 2: validate arch flag
      if (pkg.header.flags & forge_format.Flags.IS_RV64 == 0)
          return LoadError.WrongArch;

      // Step 3: acquire sandbox from pool
      const memory = pool.acquire(shard_idx);
      defer pool.release(shard_idx, memory);

      // Step 4: parse ELF64 and load segments into sandbox
      const entry_pc = try loadElf64(memory, pkg.bytecode);

      // Step 5: load calldata
      if (calldata.len > 0) try memory.loadCalldata(calldata);

      // Step 6: check code cache for pre-decoded insns
      const code_hash = pkg.header.code_hash;
      const decoded = blk: {
          if (pool.code_cache.get(code_hash)) |cached| {
              break :blk cached;
          }
          const code = memory.backing[0..sandbox.CODE_SIZE];
          const fresh = try threaded_executor.preDecodeProgram(allocator, code, sandbox.CODE_SIZE);
          try pool.code_cache.put(code_hash, fresh, allocator);
          break :blk pool.code_cache.get(code_hash).?;
      };

      // Step 7: wire up host and create ForgeVM
      const syscall_handler = syscall_dispatch.createHandler(host);
      var core_vm = ForgeVM.init(memory, sandbox.CODE_SIZE, gas_limit, syscall_handler);
      core_vm.pc = entry_pc;  // non-zero entry point from ELF

      // Step 8: analyze basic blocks (cached in practice — see Change 7.5)
      var analysis = try basic_block.analyze(allocator, memory.backing[0..sandbox.CODE_SIZE], sandbox.CODE_SIZE);
      defer analysis.deinit();

      // Step 9: execute threaded
      const result = threaded_executor.executeThreaded(&core_vm, decoded, &analysis);
      return contractResultFrom(result, &core_vm, host);
  }

CHANGE 7.5 — BasicBlock analysis caching (add to CodeCache)
  BasicBlock analysis is O(n) over code bytes but produces ~2KB of data
  (block array + pc_to_block map). Cache it alongside the decoded insns:

  In CachedProgram (vm_pool.zig):
    pub const CachedProgram = struct {
        decoded_insns: []const DecodedInsn,
        block_analysis: basic_block.ProgramAnalysis,
        last_access: u64,
    };

  In CodeCache.get(): return both decoded and analysis.
  In CodeCache.put(): store both. The ProgramAnalysis.deinit() must be
  called on eviction — add an evict callback to the LRU logic.

================================================================================
SECTION 8 — PARALLEL EXECUTION SCHEDULER
================================================================================

WHY: 1M TPS on consumer hardware is only achievable through parallel TX
     execution across all CPU cores. The existing codebase has no scheduler
     at all. The VM pool is the foundation; the scheduler sits above it.

--------------------------------------------------------------------------------
FILE: vm/parallel_scheduler.zig  — NEW FILE
--------------------------------------------------------------------------------

CHANGE 8.1 — ConflictDescriptor: declares a TX's access set upfront
  pub const ConflictDescriptor = struct {
      // Storage slots this TX will READ (up to 64 slots)
      read_slots:  [64][32]u8,
      read_count:  u8,
      // Storage slots this TX will WRITE
      write_slots: [32][32]u8,
      write_count: u8,
      // Asset IDs this TX will READ (balance checks)
      read_assets:  [16][32]u8,
      read_asset_count: u8,
      // Asset IDs this TX will WRITE (transfers)
      write_assets: [8][32]u8,
      write_asset_count: u8,
  };

CHANGE 8.2 — TxBatch: a set of non-conflicting TXs to execute in parallel
  pub const TxBatch = struct {
      txs: []const TxContext,
      thread_count: u32,
  };

  pub const TxContext = struct {
      bytecode:    []const u8,
      calldata:    []const u8,
      gas_limit:   u64,
      conflict:    ConflictDescriptor,
      host:        *HostEnv,
      result:      ExecutionResult,   // written by worker thread
  };

CHANGE 8.3 — scheduleAndExecute: O(n²) conflict check then parallel dispatch
  pub fn scheduleAndExecute(
      allocator: std.mem.Allocator,
      pool: *ForgeVMPool,
      txs: []TxContext,
  ) !void {
      // Phase 1: partition txs into non-conflicting groups (waves)
      // Each wave can execute fully in parallel.
      // O(n²) conflict check — acceptable for block sizes of ~2000 TXs.
      var waves = try buildWaves(allocator, txs);
      defer waves.deinit();

      // Phase 2: execute each wave using std.Thread.Pool
      var thread_pool: std.Thread.Pool = undefined;
      try thread_pool.init(.{ .allocator = allocator, .n_jobs = pool.shard_count });
      defer thread_pool.deinit();

      for (waves.items) |wave| {
          var wg: std.Thread.WaitGroup = .{};
          for (wave) |tx_idx| {
              wg.start();
              try thread_pool.spawn(executeTxWorker, .{ &txs[tx_idx], pool, tx_idx % pool.shard_count, &wg });
          }
          thread_pool.waitAndWork(&wg);
      }
  }

  fn conflictsWith(a: *const TxContext, b: *const TxContext) bool {
      // A conflicts with B if A writes a slot that B reads or writes,
      // or B writes a slot that A reads.
      for (a.conflict.write_slots[0..a.conflict.write_count]) |ws| {
          for (b.conflict.read_slots[0..b.conflict.read_count]) |rs| {
              if (std.mem.eql(u8, &ws, &rs)) return true;
          }
          for (b.conflict.write_slots[0..b.conflict.write_count]) |bws| {
              if (std.mem.eql(u8, &ws, &bws)) return true;
          }
      }
      return false;
  }

================================================================================
SECTION 9 — STATE BRIDGE: FORGE-NATIVE STORAGE KEY DERIVATION
================================================================================

--------------------------------------------------------------------------------
FILE: src/vm/riscv/state_bridge.zig  — TARGETED CHANGES
--------------------------------------------------------------------------------

CHANGE 9.1 — Replace all Keccak256 calls with BLAKE3

  The state bridge currently uses std.crypto.hash.sha3.Keccak256 for
  StorageKey derivation. Replace EVERY occurrence with:

    // Old:
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(data);
    hasher.final(&key);

    // New:
    std.crypto.hash.Blake3.hash(data, &key, .{});

  Affected functions:
    - deriveStorageKey()
    - deriveDerivedKey()
    - deriveGlobalKey()
    - createStorageBackend() (code hash computation)

  WHY: BLAKE3 is FORGE's canonical hash function. Using two different hash
       functions in the VM layer creates key collisions if the contract code
       assumes FORGE_HASH(x) == BLAKE3(x).

CHANGE 9.2 — Update createStorageBackend() for FORGE storage model
  The old storage backend uses EVM-style SLOAD/SSTORE with warm/cold gas.
  The new backend must support three storage tiers (flat, derived, global)
  matching the new SyscallId table.

  Add two new function pointers to StorageBackend:
    loadDerivedFn:  *const fn(ctx: *anyopaque, key: [32]u8) [32]u8,
    storeDerivedFn: *const fn(ctx: *anyopaque, key: [32]u8, val: [32]u8) void,
    loadGlobalFn:   *const fn(ctx: *anyopaque, key: [32]u8) [32]u8,
    storeGlobalFn:  *const fn(ctx: *anyopaque, key: [32]u8, val: [32]u8, delta: i64) void,
                    // storeGlobal takes a delta for commutative merge

CHANGE 9.3 — Add asset_transfer_fn and authority_check_fn to StateBridge
  These are called by the new syscall handlers (Section 5):

    pub fn assetTransfer(
        self: *StateBridge,
        asset_id: [32]u8,
        from: [20]u8,
        to: [20]u8,
        amount: u128,
    ) AssetError!void { ... }

    pub fn authorityCheck(
        self: *StateBridge,
        role_id: [32]u8,
        subject: [20]u8,
    ) bool { ... }

CHANGE 9.4 — Remove EVM-specific fields from StateBridge
  Delete:
    base_fee: u64,
    prevrandao: [32]u8,  // replace with vrf_output: [32]u8 (FORGE uses VRF)

  Add:
    vrf_output: [32]u8,  // per-block VRF randomness from consensus layer

================================================================================
SECTION 10 — INTEGRATION MODULE: src/vm/riscv/mod.zig
================================================================================

--------------------------------------------------------------------------------
FILE: src/vm/riscv/mod.zig  — UPDATE TO USE FORGE TYPES
--------------------------------------------------------------------------------

CHANGE 10.1 — Replace all ZephVM references with ForgeVM
  All pub const aliases at the top of the file:
    pub const vm_core = vm.executor;    → ForgeVM is now executor.ForgeVM
    pub const vm_syscall = vm.syscall_dispatch;
    pub const vm_gas = vm.gas_meter;
    pub const vm_memory = vm.sandbox;

CHANGE 10.2 — executeContract() and deployContract(): use loadAndExecute()
  Both functions should now delegate to forge_loader.loadAndExecute()
  instead of manually constructing a ZephVM.
  The ForgeVMPool must be passed in from the node's runtime context:

    pub fn executeContract(
        allocator: std.mem.Allocator,
        forge_pkg: []const u8,        // .forge format (was raw bytecode)
        calldata:  []const u8,
        gas_limit: u64,
        pool:      *ForgeVMPool,      // NEW parameter
        shard_idx: u32,               // NEW: which pool shard to use
        state_bridge: *anyopaque,
    ) !ExecutionResult { ... }

CHANGE 10.3 — Remove BalanceProvider and CallProvider static var pattern
  The old code uses module-level static vars for BalanceProvider.bridge,
  CallProvider.bridge — this is not thread-safe. Replace with a proper
  closure-capturing struct per call frame:

    const CallProviderCtx = struct {
        bridge: *StateBridge,
        alloc: std.mem.Allocator,
        fn callContract(self: *CallProviderCtx, ...) CallProviderResult { ... }
    };
    var call_ctx = CallProviderCtx{ .bridge = sb, .alloc = allocator };
    host.call_fn = CallProviderCtx.callContract;
    // Pass &call_ctx as the opaque context

================================================================================
SECTION 11 — GAS METER: MINOR UPDATES
================================================================================

--------------------------------------------------------------------------------
FILE: vm/gas/meter.zig
--------------------------------------------------------------------------------

CHANGE 11.1 — effectiveGasUsed(): update refund cap to FORGE's 1/4 rule
  FORGE caps refunds at 1/4 of gas used (vs Ethereum EIP-3529's 1/5).

  Old: const max_refund = self.used / 5;
  New: const max_refund = self.used / 4;

CHANGE 11.2 — Add consumeBulk() for basic-block pre-charging
  Already correct conceptually, but rename for clarity and add overflow check:

    pub fn consumeBulk(self: *GasMeter, amount: u64) error{OutOfGas}!void {
        // Same as consume() — alias for readability at block boundaries
        return self.consume(amount);
    }

================================================================================
SECTION 12 — BUILD SYSTEM
================================================================================

FILE: build.zig (create if not present, update if present)

CHANGE 12.1 — Module exports
  The build.zig must export the following modules so the node can import them:
    const forge_vm_mod = b.addModule("forge_vm", .{
        .root_source_file = b.path("vm/vm.zig"),
    });
    const forge_loader_mod = b.addModule("forge_loader", .{
        .root_source_file = b.path("vm/loader/forge_loader.zig"),
        .imports = &.{ .{ .name = "forge_vm", .module = forge_vm_mod } },
    });
    const forge_scheduler_mod = b.addModule("forge_scheduler", .{
        .root_source_file = b.path("vm/parallel_scheduler.zig"),
        .imports = &.{
            .{ .name = "forge_vm", .module = forge_vm_mod },
            .{ .name = "forge_loader", .module = forge_loader_mod },
        },
    });

CHANGE 12.2 — Release optimization flags
  The executable step must use .ReleaseFast for production builds:
    const exe = b.addExecutable(.{
        .name = "forge_vm",
        .root_source_file = b.path("vm/vm.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
  Add CPU feature flags for RISC-V host:
    target.cpu_features_add.addFeature(@intFromEnum(std.Target.riscv.Feature.m));
    target.cpu_features_add.addFeature(@intFromEnum(std.Target.riscv.Feature.a));

CHANGE 12.3 — Test step: run all per-file tests
  b.addTest with every file listed explicitly — do NOT use a wildcard glob
  because Gemini may invent a glob API that does not exist in Zig 0.14.

================================================================================
SECTION 13 — TESTING REQUIREMENTS PER FILE
================================================================================

Every file must include the following test cases at minimum.
Tests must be in the same file (not a separate test file) to match
the existing codebase pattern.

decoder.zig:
  - Decode ADDW (OP_32, funct3=0, funct7=0) → r_type with word_op=true
  - Decode ADDIW (OP_IMM_32, funct3=0) → i_type with word_op=true
  - Decode LD (LOAD opcode, funct3=3) → i_type
  - Decode SD (STORE opcode, funct3=3) → s_type
  - All 32 register indices decode correctly (rs1=31 does not truncate)

executor.zig:
  - ADDW: lower 32 bits of result sign-extended; 0xFFFF_FFFF becomes -1 in u64
  - LD/SD round-trip in heap region
  - 64-bit MUL: 0xFFFF_FFFF_FFFF_FFFF × 2 = 0xFFFF_FFFF_FFFF_FFFE
  - MULH: signed overflow case (MIN_INT × -1 = MIN_INT, upper bits = 0)
  - Register x31 can hold a value (was impossible with u4 index)
  - x0 remains zero after any write attempt targeting x0

sandbox.zig:
  - loadDoubleword: misaligned address (addr & 7 != 0) returns MisalignedAccess
  - loadDoubleword: reads correct little-endian u64
  - storeDoubleword round-trip
  - SCRATCH region is readable and writable
  - CODE region (expanded to 128KB) accepts data up to byte 0x1_FFFF

forge_format.zig:
  - build() and parse() round-trip with all sections populated
  - BLAKE3 code_hash is correct
  - ForgeHeader @sizeOf == 96
  - parse() rejects ZEPH magic bytes
  - IS_RV64 flag is set by build()

vm_pool.zig:
  - acquire() from empty shard returns fresh allocation
  - release() after acquire returns buffer to shard
  - overflow allocation: shard full → fresh alloc → release → freed (not pooled)
  - CodeCache.get() returns null for unknown hash
  - CodeCache.put() followed by get() returns same decoded content

gas/table.zig:
  - OPCODE_GAS_TABLE[OP_32] == InstructionGas.ALU
  - SyscallGas.STORAGE_LOAD == 200 (not the old 2100)
  - SyscallGas.HASH_BLAKE3_BASE < SyscallGas.HASH_SHA256_BASE (BLAKE3 is cheaper)

================================================================================
SECTION 14 — WHAT NOT TO CHANGE (Gemini must leave these alone)
================================================================================

These parts of the codebase are CORRECT as-is and must NOT be modified:

  vm/core/basic_block.zig:
    The analysis algorithm is architecture-independent. The only change
    needed is updating field types if decoder.zig struct fields change
    (start_pc, end_pc remain u32; insn_count, total_gas unchanged).

  vm/gas/meter.zig:
    Structure is correct. Only effectiveGasUsed() needs the 1/5 → 1/4
    change (Section 11). Do not touch GasMeter.init, consume, remaining.

  vm/memory/sandbox.zig (bounds-checking logic):
    The permission enforcement and bounds-checking patterns (checkAccess)
    are correct. Only the region constants and the new loadDoubleword/
    storeDoubleword methods need adding.

  vm/loader/elf_parser.zig (delete this file):
    Do not try to update it. It handles ELF32 only. The new forge_loader.zig
    replaces it entirely for ELF64.

================================================================================
SECTION 15 — ORDERING OF IMPLEMENTATION (for Gemini prompting sequence)
================================================================================

Implement files in this exact dependency order. Each file's prompt must
attach the completed version of all files it depends on.

  Step 1:  vm/gas/table.zig           (no deps — define constants first)
  Step 2:  vm/gas/meter.zig           (depends on table.zig)
  Step 3:  vm/core/decoder.zig        (depends on nothing)
  Step 4:  vm/memory/sandbox.zig      (depends on nothing)
  Step 5:  vm/core/executor.zig       (depends on decoder, sandbox, gas)
  Step 6:  vm/core/basic_block.zig    (depends on decoder, gas/table)
  Step 7:  vm/core/threaded_executor.zig (depends on executor, basic_block)
  Step 8:  vm/loader/forge_format.zig (depends on nothing)
  Step 9:  vm/syscall/dispatch.zig    (depends on executor, sandbox, gas/table)
  Step 10: vm/vm_pool.zig             (depends on sandbox, threaded_executor)
  Step 11: vm/loader/forge_loader.zig (depends on all above)
  Step 12: vm/parallel_scheduler.zig  (depends on forge_loader, vm_pool)
  Step 13: vm/vm.zig                  (top-level re-export, depends on all)
  Step 14: src/vm/riscv/state_bridge.zig (depends on vm.zig)
  Step 15: src/vm/riscv/mod.zig       (depends on state_bridge, forge_loader)
  Step 16: build.zig                  (depends on all)

================================================================================
SECTION 16 — QUICK REFERENCE: KEY NUMBER CHANGES
================================================================================

Quantity               Old Value        New Value       File
──────────────────── ──────────────── ──────────────── ──────────────────────
Register count         16 (RV32E)       32 (RV64I)      decoder.zig, executor.zig
Register width         u32              u64             executor.zig
Register index type    u4               u5              decoder.zig
Immediate width        i32              i64             decoder.zig
Code region size       64 KB            128 KB          sandbox.zig
Total sandbox size     640 KB           512 KB          sandbox.zig
Pool size (per shard)  32 (global)      16 (per shard)  vm_pool.zig
Max shards             1                128             vm_pool.zig
Gas: STORAGE_LOAD      2,100 (cold)     200 (flat)      gas/table.zig
Gas: STORAGE_STORE     5,000            500             gas/table.zig
Gas: DIV               3                5               gas/table.zig
Gas: LOAD              3                2               gas/table.zig
Gas: BRANCH            2                1               gas/table.zig
Gas refund cap         1/5              1/4             gas/meter.zig
Hash function          Keccak256        BLAKE3          forge_format, state_bridge
Contract format magic  ZEPH             FRGE            forge_format.zig
Header size            64 bytes         96 bytes        forge_format.zig
Syscall ID table       44 EVM syscalls  40 FORGE native dispatch.zig

================================================================================
END OF DOCUMENT
================================================================================
