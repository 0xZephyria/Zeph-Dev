const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Expose the SDK as a module that dependents can @import("zephyria-sdk")
    _ = b.addModule("zephyria-sdk", .{
        .root_source_file = b.path("src/sdk.zig"),
        .target = target,
        .optimize = optimize,
    });
}

/// Called by consumer build.zig to get the RISC-V target for contract compilation.
/// This ensures all contracts use the exact same target triple: riscv32-freestanding-none +E +M -C
pub fn riscvTarget(b: *std.Build) std.Build.ResolvedTarget {
    var rv32_query = std.Target.Query{
        .cpu_arch = .riscv32,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.generic_rv32 },
        .os_tag = .freestanding,
        .abi = .none,
    };
    rv32_query.cpu_features_add.addFeature(@intFromEnum(std.Target.riscv.Feature.e));
    rv32_query.cpu_features_add.addFeature(@intFromEnum(std.Target.riscv.Feature.m));
    rv32_query.cpu_features_sub.addFeature(@intFromEnum(std.Target.riscv.Feature.c));
    return b.resolveTargetQuery(rv32_query);
}

/// Helper: add a contract to the build graph. Returns the compile step.
/// Usage in consumer build.zig:
///   const sdk_dep = b.dependency("zephyria-sdk", .{});
///   const sdk = @import("zephyria-sdk");
///   const contract_exe = sdk.addContract(b, sdk_dep, "my_token", b.path("src/main.zig"));
pub fn addContract(
    b: *std.Build,
    sdk_dep: *std.Build.Dependency,
    name: []const u8,
    root_source_file: std.Build.LazyPath,
) *std.Build.Step.Compile {
    const riscv = riscvTarget(b);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = root_source_file,
            .target = riscv,
            .optimize = .ReleaseSmall,
        }),
    });

    // Make the SDK available as @import("zephyria-sdk")
    exe.root_module.addImport("zephyria-sdk", sdk_dep.module("zephyria-sdk"));

    // Use the Zephyria linker script (maps code to 0x0, data to 0x10000)
    exe.setLinkerScript(sdk_dep.path("linker.ld"));

    return exe;
}
