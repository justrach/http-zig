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

    const exe = b.addExecutable(.{
        .name = "http-zig-get",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/get.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "http_zig", .module = mod }},
        }),
    });
    b.installArtifact(exe);
    const run = b.addRunArtifact(exe);
    b.step("run", "GET https://nghttp2.org/ over HTTP/2").dependOn(&run.step);
}
