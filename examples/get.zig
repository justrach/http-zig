//! GET an HTTPS URL over HTTP/2. Default: https://nghttp2.org/
const std = @import("std");
const http_zig = @import("http_zig");

pub fn main() !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug.deinit();
    const gpa = debug.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const url = "https://nghttp2.org/";

    std.debug.print("GET {s} (HTTP/2)\n", .{url});
    var res = http_zig.https.get(gpa, io, url) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        return err;
    };
    defer res.deinit();
    std.debug.print("status {d}  body {d} bytes\n", .{ res.status, res.body.len });
    const n = @min(res.body.len, 240);
    std.debug.print("{s}\n", .{res.body[0..n]});
}
