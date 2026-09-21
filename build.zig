const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("http_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit = b.addTest(.{
        .root_module = mod,
    });
    const run_unit = b.addRunArtifact(unit);
    b.step("test", "Run unit tests").dependOn(&run_unit.step);
}
