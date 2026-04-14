const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================================================================
    // Zephyria Blockchain Node
    // =========================================================================

    // ---- Module definitions ----
    // Crypto module (BLS signatures via blst C library)
    const crypto_mod = b.addModule("crypto", .{
        .root_source_file = b.path("src/crypto/mod.zig"),
    });
    crypto_mod.addIncludePath(b.path("src/crypto/blst/blst/bindings"));
    crypto_mod.addIncludePath(b.path("src/crypto/blst/blst/src"));
    crypto_mod.addCSourceFile(.{ .file = b.path("src/crypto/blst/blst/src/server.c"), .flags = &.{"-D__BLST_PORTABLE__"} });
    crypto_mod.addCSourceFile(.{ .file = b.path("src/crypto/blst/blst/build/assembly.S"), .flags = &.{"-D__BLST_PORTABLE__"} });

    // Storage module (Verkle trie, LSM, epoch, code store)
    const storage_mod = b.addModule("storage", .{
        .root_source_file = b.path("src/storage/mod.zig"),
    });
    storage_mod.addImport("crypto", crypto_mod);

    // RLP encoding
    const rlp_mod = b.addModule("rlp", .{
        .root_source_file = b.path("src/core/rlp/rlp.zig"),
    });

    // Encoding module
    const encoding_mod = b.addModule("encoding", .{
        .root_source_file = b.path("src/encoding/mod.zig"),
    });

    // Utils module
    const utils_mod = b.addModule("utils", .{
        .root_source_file = b.path("src/utils/mod.zig"),
    });

    // Core module (blockchain, executor, scheduler, state, tx pool)
    const core_mod = b.addModule("core", .{
        .root_source_file = b.path("src/core/mod.zig"),
    });
    core_mod.addImport("crypto", crypto_mod);
    core_mod.addImport("storage", storage_mod);
    core_mod.addImport("encoding", encoding_mod);
    core_mod.addImport("utils", utils_mod);
    core_mod.addImport("rlp", rlp_mod);

    encoding_mod.addImport("core", core_mod);
    encoding_mod.addImport("rlp", rlp_mod);

    // Consensus module (Zelius PoS with BLS/VDF/VRF)
    const consensus_mod = b.addModule("consensus", .{
        .root_source_file = b.path("src/consensus/mod.zig"),
    });
    consensus_mod.addImport("core", core_mod);
    consensus_mod.addImport("rlp", rlp_mod);

    // Net utilities
    const net_utils_mod = b.addModule("net_utils", .{
        .root_source_file = b.path("src/net/mod.zig"),
    });

    // P2P module (QUIC + gRPC)
    const p2p_mod = b.addModule("p2p", .{
        .root_source_file = b.path("src/p2p/mod.zig"),
    });
    p2p_mod.addImport("core", core_mod);
    p2p_mod.addImport("consensus", consensus_mod);
    p2p_mod.addImport("encoding", encoding_mod);
    p2p_mod.addImport("utils", utils_mod);
    p2p_mod.addImport("net_utils", net_utils_mod);
    p2p_mod.addImport("rlp", rlp_mod);

    // RPC module (JSON-RPC API)
    const rpc_mod = b.addModule("rpc", .{
        .root_source_file = b.path("src/rpc/mod.zig"),
    });
    rpc_mod.addImport("core", core_mod);
    rpc_mod.addImport("p2p", p2p_mod);
    rpc_mod.addImport("encoding", encoding_mod);
    rpc_mod.addImport("utils", utils_mod);
    rpc_mod.addImport("rlp", rlp_mod);

    // Node module (miner, epoch integration)
    const node_mod = b.addModule("node", .{
        .root_source_file = b.path("src/node/mod.zig"),
    });
    node_mod.addImport("core", core_mod);
    node_mod.addImport("storage", storage_mod);
    node_mod.addImport("consensus", consensus_mod);
    node_mod.addImport("p2p", p2p_mod);
    node_mod.addImport("rlp", rlp_mod);

    // RISC-V VM module
    const vm_mod = b.addModule("vm", .{ .root_source_file = b.path("vm/vm.zig") });

    // VM Bridge module (connects RISC-V VM to executor)
    const vm_bridge_mod = b.addModule("vm_bridge", .{
        .root_source_file = b.path("src/vm_bridge.zig"),
    });
    vm_bridge_mod.addImport("core", core_mod);
    vm_bridge_mod.addImport("vm", vm_mod);

    // State Bridge (connects VM syscalls to State overlay)
    const state_bridge_mod = b.addModule("state_bridge", .{
        .root_source_file = b.path("src/vm/riscv/state_bridge.zig"),
    });
    state_bridge_mod.addImport("core", core_mod);
    state_bridge_mod.addImport("vm", vm_mod);
    vm_bridge_mod.addImport("state_bridge", state_bridge_mod);

    // ---- Zephyria blockchain node executable ----
    const node_exe = b.addExecutable(.{
        .name = "zephyria",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    node_exe.root_module.addImport("storage", storage_mod);
    node_exe.root_module.addImport("consensus", consensus_mod);
    node_exe.root_module.addImport("p2p", p2p_mod);
    node_exe.root_module.addImport("rpc", rpc_mod);
    node_exe.root_module.addImport("core", core_mod);
    node_exe.root_module.addImport("node", node_mod);
    node_exe.root_module.addImport("utils", utils_mod);
    node_exe.root_module.addImport("vm_bridge", vm_bridge_mod);
    node_exe.linkLibC();
    node_exe.linkSystemLibrary("z");
    b.installArtifact(node_exe);

    const run_node_cmd = b.addRunArtifact(node_exe);
    run_node_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_node_cmd.addArgs(args);
    }
    const run_node_step = b.step("run", "Run the Zephyria blockchain node");
    run_node_step.dependOn(&run_node_cmd.step);

    // ---- Blockchain node tests ----
    const node_test_step = b.step("test", "Run all tests");

    // Storage tests
    const storage_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/storage/mod.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    node_test_step.dependOn(&b.addRunArtifact(storage_test).step);

    // Core tests
    const core_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/tx_pool_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    core_test.root_module.addImport("utils", utils_mod);
    core_test.root_module.addImport("encoding", encoding_mod);
    core_test.root_module.addImport("rlp", rlp_mod);
    core_test.root_module.addImport("crypto", crypto_mod);
    core_test.root_module.addImport("storage", storage_mod);
    node_test_step.dependOn(&b.addRunArtifact(core_test).step);

    // State tests
    const state_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/state_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    state_test.root_module.addImport("storage", storage_mod);
    state_test.root_module.addImport("utils", utils_mod);
    state_test.root_module.addImport("crypto", crypto_mod);
    node_test_step.dependOn(&b.addRunArtifact(state_test).step);

    // Scheduler tests
    const scheduler_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/scheduler_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    scheduler_test.root_module.addImport("storage", storage_mod);
    scheduler_test.root_module.addImport("utils", utils_mod);
    scheduler_test.root_module.addImport("crypto", crypto_mod);
    node_test_step.dependOn(&b.addRunArtifact(scheduler_test).step);

    // Blockchain tests
    const blockchain_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/blockchain_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    blockchain_test.root_module.addImport("storage", storage_mod);
    blockchain_test.root_module.addImport("utils", utils_mod);
    blockchain_test.root_module.addImport("crypto", crypto_mod);
    blockchain_test.root_module.addImport("rlp", rlp_mod);
    blockchain_test.root_module.addImport("encoding", encoding_mod);
    node_test_step.dependOn(&b.addRunArtifact(blockchain_test).step);

    // Executor tests
    const executor_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/executor_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    executor_test.root_module.addImport("storage", storage_mod);
    executor_test.root_module.addImport("utils", utils_mod);
    executor_test.root_module.addImport("crypto", crypto_mod);
    executor_test.root_module.addImport("rlp", rlp_mod);
    executor_test.root_module.addImport("encoding", encoding_mod);
    node_test_step.dependOn(&b.addRunArtifact(executor_test).step);

    // P2P tests
    const p2p_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/p2p/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    p2p_test.root_module.addImport("core", core_mod);
    p2p_test.root_module.addImport("consensus", consensus_mod);
    p2p_test.root_module.addImport("utils", utils_mod);
    p2p_test.root_module.addImport("net_utils", net_utils_mod);
    p2p_test.root_module.addImport("rlp", rlp_mod);
    p2p_test.root_module.addImport("encoding", encoding_mod);
    node_test_step.dependOn(&b.addRunArtifact(p2p_test).step);

    // DAG Mempool tests
    const dag_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/dag_mempool_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    dag_test.root_module.addImport("core", core_mod);
    dag_test.root_module.addImport("storage", storage_mod);
    dag_test.root_module.addImport("utils", utils_mod);
    dag_test.root_module.addImport("crypto", crypto_mod);
    dag_test.root_module.addImport("rlp", rlp_mod);
    dag_test.root_module.addImport("encoding", encoding_mod);
    node_test_step.dependOn(&b.addRunArtifact(dag_test).step);

    // VM tests
    const vm_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("vm/vm.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    node_test_step.dependOn(&b.addRunArtifact(vm_test).step);

    // ---- Forge VM Test Suite ----
    const forge_test_suite = b.addExecutable(.{
        .name = "forge_test_suite",
        .root_module = b.createModule(.{
            .root_source_file = b.path("forge_test_suite2.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    forge_test_suite.root_module.addImport("vm", vm_mod);
    b.installArtifact(forge_test_suite);

    const run_forge_test_suite_cmd = b.addRunArtifact(forge_test_suite);
    run_forge_test_suite_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_forge_test_suite_cmd.addArgs(args);
    }
    const run_forge_test_suite_step = b.step("forge-test", "Run the ForgeVM Test Suite");
    run_forge_test_suite_step.dependOn(&run_forge_test_suite_cmd.step);
}
