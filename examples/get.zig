//! Two GETs on one HTTP/2 session. Default origin: https://nghttp2.org/
const std = @import("std");
const http_zig = @import("http_zig");

pub fn main() !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug.deinit();
    const gpa = debug.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const s = try http_zig.Session.open(gpa, io, "nghttp2.org", 443);
    defer s.close();

    var i: u8 = 0;
    while (i < 2) : (i += 1) {
        var res = try s.request(.{
            .method = "GET",
            .scheme = "https",
            .authority = "nghttp2.org",
            .path = "/",
        });
        defer res.deinit();
        std.debug.print("GET #{d} stream~{d} status {d} body {d} h1_only={}\n", .{
            i + 1,
            s.last_stream,
            res.status,
            res.body.len,
            s.h1_only,
        });
    }
}
