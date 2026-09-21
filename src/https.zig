//! HTTPS HTTP/2: TCP + std TLS with ALPN spliced into ClientHello.

const std = @import("std");
const Io = std.Io;
const conn_mod = @import("conn.zig");
const tls_client = @import("tls_client.zig");

pub const Response = conn_mod.Response;
pub const Request = conn_mod.Request;

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
    return request(gpa, io, .{
        .method = "GET",
        .scheme = "https",
        .authority = u.host,
        .path = u.path,
    }, u.host, u.port);
}

pub fn request(gpa: std.mem.Allocator, io: Io, req: Request, host: []const u8, port: u16) !Response {
    const host_name = try Io.net.HostName.init(host);
    const stream = try host_name.connect(io, port, .{ .mode = .stream });
    errdefer stream.close(io);

    const tls_buf_len = tls_client.min_buffer_len;
    const sock_read = try gpa.alloc(u8, tls_buf_len);
    defer gpa.free(sock_read);
    const sock_write = try gpa.alloc(u8, tls_buf_len);
    defer gpa.free(sock_write);
    const tls_read = try gpa.alloc(u8, tls_buf_len);
    defer gpa.free(tls_read);
    const tls_write = try gpa.alloc(u8, tls_buf_len);
    defer gpa.free(tls_write);
    var stream_reader = stream.reader(io, sock_read);
    var stream_writer = stream.writer(io, sock_write);

    var ca: std.crypto.Certificate.Bundle = .empty;
    var ca_lock: Io.RwLock = .init;
    const now = Io.Clock.real.now(io);
    try ca.rescan(gpa, io, now);
    defer ca.deinit(gpa);

    var entropy: [tls_client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    var tls = tls_client.init(
        &stream_reader.interface,
        &stream_writer.interface,
        .{
            .host = .{ .explicit = host },
            .ca = .{ .bundle = .{
                .gpa = gpa,
                .io = io,
                .lock = &ca_lock,
                .bundle = &ca,
            } },
            .read_buffer = tls_read,
            .write_buffer = tls_write,
            .entropy = &entropy,
            .realtime_now = now,
            .allow_truncation_attacks = true,
        },
    ) catch |err| switch (err) {
        error.WriteFailed => return stream_writer.err orelse error.WriteFailed,
        error.ReadFailed => return stream_reader.err orelse error.ReadFailed,
        else => |e| return e,
    };

    var c = conn_mod.Conn.init(gpa, &tls.reader, &tls.writer);
    defer c.deinit();
    const res = try c.request(req);
    stream.close(io);
    return res;
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
