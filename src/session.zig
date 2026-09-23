//! One HTTPS origin: HTTP/2 connection reuse (odd stream ids) with a
//! handshake fallback onto `std.http.Client` (HTTP/1.1). Ambiguous request
//! failures return to the caller rather than silently replaying a body.

const std = @import("std");
const Io = std.Io;
const conn_mod = @import("conn.zig");
const tls_client = @import("tls_client.zig");
const hpack = @import("hpack.zig");

pub const Request = conn_mod.Request;
pub const Response = conn_mod.Response;
pub const LineStream = conn_mod.LineStream;

pub const Session = struct {
    gpa: std.mem.Allocator,
    io: Io,
    host: []u8,
    port: u16,
    h1_only: bool = false,
    h2_live: bool = false,
    stream: Io.net.Stream = undefined,
    sock_read: []u8 = &.{},
    sock_write: []u8 = &.{},
    tls_read: []u8 = &.{},
    tls_write: []u8 = &.{},
    stream_reader: Io.net.Stream.Reader = undefined,
    stream_writer: Io.net.Stream.Writer = undefined,
    tls: tls_client = undefined,
    conn: conn_mod.Conn = undefined,
    ca: std.crypto.Certificate.Bundle = .empty,
    ca_lock: Io.RwLock = .init,
    last_stream: u31 = 0,

    pub fn open(gpa: std.mem.Allocator, io: Io, host: []const u8, port: u16) !*Session {
        const self = try gpa.create(Session);
        errdefer gpa.destroy(self);
        const host_copy = try gpa.dupe(u8, host);
        errdefer gpa.free(host_copy);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .host = host_copy,
            .port = port,
        };
        self.dialH2() catch |err| {
            self.teardownH2();
            if (!handshakeFallback(err)) return err;
            self.h1_only = true;
            return self;
        };
        return self;
    }

    pub fn close(self: *Session) void {
        self.teardownH2();
        self.gpa.free(self.host);
        self.gpa.destroy(self);
    }

    /// True when the next stream can go out on the live h2 connection.
    pub fn reusable(self: *const Session) bool {
        return !self.h1_only and self.h2_live and self.conn.acceptsStreams();
    }

    pub fn request(self: *Session, req: Request) !Response {
        if (self.h1_only) return requestH1(self.gpa, self.io, req, self.host, self.port);
        // A previous failed request tears down the connection. Redial before
        // touching Conn again, including when a caller reuses this Session.
        if (!self.h2_live or !self.conn.acceptsStreams()) {
            self.teardownH2();
            self.dialH2() catch |err| {
                self.teardownH2();
                if (!handshakeFallback(err)) return err;
                self.h1_only = true;
                return requestH1(self.gpa, self.io, req, self.host, self.port);
            };
        }
        return self.requestH2(req) catch |err| {
            self.teardownH2();
            // Only these responses prove the peer did not process this stream.
            // EOF, RST_STREAM and framing/TLS failures can follow a complete
            // request, so never replay them inside the transport.
            if (!safeReplay(err)) return err;
            self.dialH2() catch |dial_err| {
                self.teardownH2();
                return dial_err;
            };
            return self.requestH2(req) catch |second| {
                self.teardownH2();
                return second;
            };
        };
    }

    /// Streaming DATA as lines (SSE). The caller decides how to recover from
    /// a failed request; this transport never silently replays a sent body.
    pub fn startLines(self: *Session, req: Request) !LineStream {
        if (self.h1_only) return error.H1NoStream;
        // A connection the peer is draining (GOAWAY seen on an earlier stream)
        // takes no new streams: dial a fresh one instead of letting the next
        // request fail on it.
        if (!self.h2_live or !self.conn.acceptsStreams()) {
            self.teardownH2();
            self.dialH2() catch |err| {
                self.teardownH2();
                if (!handshakeFallback(err)) return err;
                self.h1_only = true;
                return error.H1NoStream;
            };
        }
        return self.conn.startLines(req) catch |err| {
            self.teardownH2();
            return err;
        };
    }

    fn dialH2(self: *Session) !void {
        const host_name = try Io.net.HostName.init(self.host);
        const stream = try host_name.connect(self.io, self.port, .{ .mode = .stream });
        // Once these fields are assigned, open()'s teardownH2 owns the socket
        // and the buffers. The errdefers must not also close/free them: a
        // failed handshake was closing the fd twice, and debug zig treats
        // that BADF as unreachable, which aborts the process and crashes the
        // zig 0.17 test runner (codegraff pre-push reach/tests).
        var owned = false;
        errdefer if (!owned) stream.close(self.io);
        const n = tls_client.min_buffer_len;
        const sock_read = try self.gpa.alloc(u8, n);
        errdefer if (!owned) self.gpa.free(sock_read);
        const sock_write = try self.gpa.alloc(u8, n);
        errdefer if (!owned) self.gpa.free(sock_write);
        const tls_read = try self.gpa.alloc(u8, n);
        errdefer if (!owned) self.gpa.free(tls_read);
        const tls_write = try self.gpa.alloc(u8, n);
        errdefer if (!owned) self.gpa.free(tls_write);

        self.stream = stream;
        self.sock_read = sock_read;
        self.sock_write = sock_write;
        self.tls_read = tls_read;
        self.tls_write = tls_write;
        owned = true;
        self.stream_reader = stream.reader(self.io, sock_read);
        self.stream_writer = stream.writer(self.io, sock_write);

        const now = Io.Clock.real.now(self.io);
        try self.ca.rescan(self.gpa, self.io, now);
        var entropy: [tls_client.Options.entropy_len]u8 = undefined;
        self.io.random(&entropy);
        self.tls = tls_client.init(
            &self.stream_reader.interface,
            &self.stream_writer.interface,
            .{
                .host = .{ .explicit = self.host },
                .ca = .{ .bundle = .{
                    .gpa = self.gpa,
                    .io = self.io,
                    .lock = &self.ca_lock,
                    .bundle = &self.ca,
                } },
                .read_buffer = self.tls_read,
                .write_buffer = self.tls_write,
                .entropy = &entropy,
                .realtime_now = now,
                .allow_truncation_attacks = true,
            },
        ) catch |err| switch (err) {
            error.WriteFailed => return self.stream_writer.err orelse error.WriteFailed,
            error.ReadFailed => return self.stream_reader.err orelse error.ReadFailed,
            else => |e| return e,
        };
        // RFC 9113 §3.2: speak HTTP/2 only when the server chose h2 via ALPN.
        // A server that picked http/1.1 or ignored ALPN would otherwise get the
        // preface and a request body it cannot parse.
        if (!self.tls.alpn_h2) return error.AlpnNotH2;
        self.conn = conn_mod.Conn.init(self.gpa, &self.tls.reader, &self.tls.writer);
        // Own the Conn before preface(): it holds an HPACK decoder allocation,
        // so marking it live first makes teardownH2 free it when preface()
        // fails. Marking it after leaked that allocation on every failed dial.
        self.h2_live = true;
        try self.conn.preface();
    }

    fn requestH2(self: *Session, req: Request) !Response {
        const res = try self.conn.request(req);
        self.last_stream = self.conn.next_stream - 2;
        return res;
    }

    fn teardownH2(self: *Session) void {
        if (self.h2_live) {
            self.conn.deinit();
            self.h2_live = false;
        }
        if (self.sock_read.len != 0) {
            self.stream.close(self.io);
            self.gpa.free(self.sock_read);
            self.gpa.free(self.sock_write);
            self.gpa.free(self.tls_read);
            self.gpa.free(self.tls_write);
            self.sock_read = &.{};
        }
        self.ca.deinit(self.gpa);
        self.ca = .empty;
    }
};

pub fn handshakeFallback(err: anyerror) bool {
    return switch (err) {
        error.TlsAlert,
        error.TlsUnexpectedMessage,
        error.TlsIllegalParameter,
        error.TlsConnectionTruncated,
        error.TlsBadRecordMac,
        error.TlsRecordOverflow,
        error.TlsInitializationFailed,
        error.AlpnNotH2,
        => true,
        else => false,
    };
}

pub fn safeReplay(err: anyerror) bool {
    return err == error.GoAway or err == error.StreamRefused;
}

/// Legacy transport-error classifier. It is not a replay authorization:
/// several of these errors can occur after the peer received a full request.
pub fn transportFallback(err: anyerror) bool {
    return handshakeFallback(err) or switch (err) {
        error.GoAway, error.StreamRefused, error.RstStream, error.FrameTooLarge, error.HpackIndex, error.HpackTruncated, error.EndOfStream => true,
        else => false,
    };
}

pub fn requestH1(gpa: std.mem.Allocator, io: Io, req: Request, host: []const u8, port: u16) !Response {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const url = try std.fmt.allocPrint(gpa, "https://{s}:{d}{s}", .{ host, port, req.path });
    defer gpa.free(url);
    var aw: Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const method: std.http.Method = if (std.mem.eql(u8, req.method, "POST")) .POST else .GET;
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = if (req.body.len == 0) null else req.body,
        .response_writer = &aw.writer,
    });
    const headers = try gpa.alloc(hpack.Header, 0);
    return .{
        .status = @intFromEnum(result.status),
        .headers = headers,
        .body = try aw.toOwnedSlice(),
        .allocator = gpa,
    };
}

test "handshakeFallback is TlsAlert not OOM" {
    try std.testing.expect(handshakeFallback(error.TlsAlert));
    try std.testing.expect(!handshakeFallback(error.OutOfMemory));
    try std.testing.expect(safeReplay(error.GoAway));
    try std.testing.expect(safeReplay(error.StreamRefused));
    try std.testing.expect(!safeReplay(error.EndOfStream));
    try std.testing.expect(!safeReplay(error.RstStream));
    try std.testing.expect(!safeReplay(error.OutOfMemory));
}
