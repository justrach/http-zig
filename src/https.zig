//! HTTPS helpers over a reusable Session.

const std = @import("std");
const Io = std.Io;
const session_mod = @import("session.zig");

pub const Session = session_mod.Session;
pub const Request = session_mod.Request;
pub const Response = session_mod.Response;
pub const handshakeFallback = session_mod.handshakeFallback;
pub const transportFallback = session_mod.transportFallback;

pub const Url = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

pub fn parseHttpsUrl(url: []const u8) !Url {
    const rest = if (std.mem.startsWith(u8, url, "https://"))
        url["https://".len..]
    else
        return error.NeedHttps;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const hostport = rest[0..slash];
    const path = if (slash == rest.len) "/" else rest[slash..];
    if (std.mem.indexOfScalar(u8, hostport, ':')) |c| {
        const port = std.fmt.parseInt(u16, hostport[c + 1 ..], 10) catch return error.BadPort;
        return .{ .host = hostport[0..c], .port = port, .path = path };
    }
    return .{ .host = hostport, .port = 443, .path = path };
}

pub fn get(gpa: std.mem.Allocator, io: Io, url: []const u8) !Response {
    const u = try parseHttpsUrl(url);
    const s = try Session.open(gpa, io, u.host, u.port);
    defer s.close();
    return s.request(.{
        .method = "GET",
        .scheme = "https",
        .authority = u.host,
        .path = u.path,
    });
}

test "parseHttpsUrl" {
    const u = try parseHttpsUrl("https://nghttp2.org/");
    try std.testing.expectEqualStrings("nghttp2.org", u.host);
    try std.testing.expectEqual(@as(u16, 443), u.port);
    try std.testing.expectEqualStrings("/", u.path);
    const parsed = try parseHttpsUrl("https://example.com:8443/foo");
    try std.testing.expectEqual(@as(u16, 8443), parsed.port);
    try std.testing.expectEqualStrings("/foo", parsed.path);
}
