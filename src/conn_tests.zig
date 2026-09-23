//! Mock-peer tests for Conn. Split out of conn.zig, which was over its line
//! budget; every peer here is a scripted byte stream over a fixed Reader and an
//! Allocating Writer, so no test opens a socket or touches the network.
const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

fn serverSettingsAckHeadersData() []const u8 {
    return &dummy;
}

const dummy = blk: {
    break :blk [_]u8{};
};

test "conn GET returns 200 ok" {
    const gpa = std.testing.allocator;

    // Server: SETTINGS, SETTINGS ACK, HEADERS :status 200 END_HEADERS, DATA "ok" END_STREAM
    var srv_aw: std.Io.Writer.Allocating = .init(gpa);
    defer srv_aw.deinit();
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
    const status_hpack = [_]u8{0x88}; // indexed :status 200
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &status_hpack });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "ok" });
    const server_bytes = try gpa.dupe(u8, srv_aw.written());
    defer gpa.free(server_bytes);

    var reader: std.Io.Reader = .fixed(server_bytes);
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();

    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();
    var res = try c.request(.{
        .method = "GET",
        .scheme = "http",
        .authority = "localhost",
        .path = "/",
    });
    defer res.deinit();
    try std.testing.expectEqual(@as(u16, 200), res.status);
    try std.testing.expectEqualStrings("ok", res.body);
    try std.testing.expect(std.mem.eql(u8, client_aw.written()[0..frame.preface.len], frame.preface));
}

test "raw chunks preserve newline-free DATA across frames and END_STREAM" {
    const gpa = std.testing.allocator;
    var srv: std.Io.Writer.Allocating = .init(gpa);
    defer srv.deinit();
    try frame.write(&srv.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    const status_hpack = [_]u8{0x88};
    try frame.write(&srv.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &status_hpack });
    try frame.write(&srv.writer, .{ .typ = .data, .flags = 0, .stream_id = 1, .payload = "ab" });
    try frame.write(&srv.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "cdef" });
    var reader: std.Io.Reader = .fixed(srv.written());
    var client: std.Io.Writer.Allocating = .init(gpa);
    defer client.deinit();
    var conn = Conn.init(gpa, &reader, &client.writer);
    defer conn.deinit();
    var stream = try conn.startLines(.{ .method = "GET", .scheme = "https", .authority = "localhost", .path = "/" });
    defer stream.deinit();
    try std.testing.expectEqual(@as(u16, 200), try stream.waitStatus());
    var buf: [3]u8 = undefined;
    try std.testing.expectError(error.EmptyBuffer, stream.readChunk(&.{}));
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    while (true) {
        const n = try stream.readChunk(&buf);
        if (n == 0) break;
        try body.appendSlice(gpa, buf[0..n]);
    }
    try std.testing.expectEqualStrings("abcdef", body.items);
    try std.testing.expect(stream.ended);
    try std.testing.expectEqual(@as(usize, 4), countFrames(client.written(), .window_update));
}

test "raw chunk stream rejects DATA before response headers" {
    const gpa = std.testing.allocator;
    var srv: std.Io.Writer.Allocating = .init(gpa);
    defer srv.deinit();
    try frame.write(&srv.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    try frame.write(&srv.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "unexpected" });
    var reader: std.Io.Reader = .fixed(srv.written());
    var client: std.Io.Writer.Allocating = .init(gpa);
    defer client.deinit();
    var conn = Conn.init(gpa, &reader, &client.writer);
    defer conn.deinit();
    var stream = try conn.startLines(.{ .method = "GET", .scheme = "https", .authority = "localhost", .path = "/" });
    defer stream.deinit();
    try std.testing.expectError(error.DataBeforeHeaders, stream.waitStatus());
}

test "conn two sequential streams" {
    const gpa = std.testing.allocator;
    var srv_aw: std.Io.Writer.Allocating = .init(gpa);
    defer srv_aw.deinit();
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
    const status_hpack = [_]u8{0x88};
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &status_hpack });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "one" });
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 3, .payload = &status_hpack });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 3, .payload = "two" });
    const server_bytes = try gpa.dupe(u8, srv_aw.written());
    defer gpa.free(server_bytes);
    var reader: std.Io.Reader = .fixed(server_bytes);
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();
    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();
    var a = try c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer a.deinit();
    var b = try c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer b.deinit();
    try std.testing.expectEqualStrings("one", a.body);
    try std.testing.expectEqualStrings("two", b.body);
    try std.testing.expectEqual(@as(u31, 5), c.next_stream);
    // Each DATA frame is credited on the connection and the stream, or the
    // peer stops after the initial 65535-byte window.
    try std.testing.expectEqual(@as(usize, 4), countFrames(client_aw.written(), .window_update));
}

fn countFrames(bytes: []const u8, typ: frame.Type) usize {
    var i: usize = 0;
    if (std.mem.startsWith(u8, bytes, frame.preface)) i = frame.preface.len;
    var n: usize = 0;
    while (i + 9 <= bytes.len) {
        const len = (@as(usize, bytes[i]) << 16) | (@as(usize, bytes[i + 1]) << 8) | bytes[i + 2];
        if (i + 9 + len > bytes.len) break;
        if (@as(frame.Type, @enumFromInt(bytes[i + 3])) == typ) n += 1;
        i += 9 + len;
    }
    return n;
}

test "conn fragmented headers reassemble before HPACK decode" {
    const gpa = std.testing.allocator;
    // Header block with incremental indexing: :status 200 + x-test: hello.
    // Split across HEADERS (no END_HEADERS) + CONTINUATION so a naive
    // per-fragment decode desyncs the dynamic table (HpackIndex on reuse).
    const block = [_]u8{
        0x88, // :status 200
        0x40, 0x06, 'x', '-', 't', 'e', 's', 't', // new name, incremental
        0x05, 'h',  'e', 'l', 'l', 'o',
    };
    const split = 5;
    var srv_aw: std.Io.Writer.Allocating = .init(gpa);
    defer srv_aw.deinit();
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = 0, .stream_id = 1, .payload = block[0..split] });
    try frame.write(&srv_aw.writer, .{ .typ = .continuation, .flags = frame.flags.end_headers, .stream_id = 1, .payload = block[split..] });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "ok" });
    // Second response references the dynamic entry (index 62) added above.
    const ref = [_]u8{ 0x88, 0xbe };
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 3, .payload = &ref });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 3, .payload = "two" });
    const server_bytes = try gpa.dupe(u8, srv_aw.written());
    defer gpa.free(server_bytes);
    var reader: std.Io.Reader = .fixed(server_bytes);
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();
    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();
    var a = try c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer a.deinit();
    try std.testing.expectEqual(@as(u16, 200), a.status);
    try std.testing.expectEqualStrings("ok", a.body);
    var b = try c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer b.deinit();
    try std.testing.expectEqualStrings("two", b.body);
    var found = false;
    for (b.headers) |h| {
        if (std.mem.eql(u8, h.name, "x-test") and std.mem.eql(u8, h.value, "hello")) found = true;
    }
    try std.testing.expect(found);
}

test "conn server push keeps HPACK in sync" {
    const gpa = std.testing.allocator;
    // nghttp2.org pushes style.css: PUSH_PROMISE + pushed HEADERS both carry
    // incremental entries. Skipping their decode desyncs the dynamic table
    // and the next response fails with HpackIndex.
    var srv_aw: std.Io.Writer.Allocating = .init(gpa);
    defer srv_aw.deinit();
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    // PUSH_PROMISE sid=1, promised 2: incremental x-req: r (adds index 62).
    const promise = [_]u8{ 0, 0, 0, 2, 0x40, 0x05, 'x', '-', 'r', 'e', 'q', 0x01, 'r' };
    try frame.write(&srv_aw.writer, .{ .typ = .push_promise, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &promise });
    // Main response headers sid=1: :status 200.
    const status_hpack = [_]u8{0x88};
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &status_hpack });
    // Pushed response HEADERS sid=2: :status 200 + incremental x-pushed: yes (adds 63).
    const pushed = [_]u8{ 0x88, 0x40, 0x08, 'x', '-', 'p', 'u', 's', 'h', 'e', 'd', 0x03, 'y', 'e', 's' };
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 2, .payload = &pushed });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 2, .payload = "css" });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "ok" });
    // Second response references the pushed entry (newest => index 62).
    const ref = [_]u8{ 0x88, 0xbe };
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 3, .payload = &ref });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 3, .payload = "two" });
    const server_bytes = try gpa.dupe(u8, srv_aw.written());
    defer gpa.free(server_bytes);
    var reader: std.Io.Reader = .fixed(server_bytes);
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();
    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();
    var a = try c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer a.deinit();
    try std.testing.expectEqualStrings("ok", a.body);
    var b = try c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer b.deinit();
    try std.testing.expectEqualStrings("two", b.body);
    var found = false;
    for (b.headers) |h| {
        if (std.mem.eql(u8, h.name, "x-pushed") and std.mem.eql(u8, h.value, "yes")) found = true;
    }
    try std.testing.expect(found);
}

/// Walk the frames this client emitted and, for DATA, how they were split.
fn scanData(gpa: std.mem.Allocator, written: []const u8, out: *std.ArrayList(u8)) !struct { frames: usize, biggest: usize, end_stream_frame: usize } {
    out.clearRetainingCapacity();
    var i: usize = 0;
    if (std.mem.startsWith(u8, written, frame.preface)) i = frame.preface.len;
    var frames: usize = 0;
    var biggest: usize = 0;
    var end_stream_frame: usize = 0;
    while (i + 9 <= written.len) {
        const len = (@as(usize, written[i]) << 16) | (@as(usize, written[i + 1]) << 8) | written[i + 2];
        if (i + 9 + len > written.len) break;
        if (@as(frame.Type, @enumFromInt(written[i + 3])) == .data) {
            frames += 1;
            if (len > biggest) biggest = len;
            if (written[i + 4] & frame.flags.end_stream != 0) end_stream_frame = frames;
            try out.appendSlice(gpa, written[i + 9 ..][0..len]);
        }
        i += 9 + len;
    }
    return .{ .frames = frames, .biggest = biggest, .end_stream_frame = end_stream_frame };
}

test "a body past MAX_FRAME_SIZE is chunked, END_STREAM only on the last frame" {
    const gpa = std.testing.allocator;
    // 40000 bytes = three frames at the 16384 initial cap. One DATA frame that
    // big is a FRAME_SIZE_ERROR connection error (RFC 9113 4.2) and the peer
    // drops the connection.
    const body = try gpa.alloc(u8, 40000);
    defer gpa.free(body);
    for (body, 0..) |*b, i| b.* = @intCast('a' + (i % 26));

    var srv_aw: std.Io.Writer.Allocating = .init(gpa);
    defer srv_aw.deinit();
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
    const status_hpack = [_]u8{0x88};
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &status_hpack });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "ok" });
    const server_bytes = try gpa.dupe(u8, srv_aw.written());
    defer gpa.free(server_bytes);

    var reader: std.Io.Reader = .fixed(server_bytes);
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();
    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();
    var res = try c.request(.{ .method = "POST", .scheme = "https", .authority = "api.x.ai", .path = "/v1/test", .body = body });
    defer res.deinit();
    try std.testing.expectEqualStrings("ok", res.body);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const scan = try scanData(gpa, client_aw.written(), &out);
    try std.testing.expectEqual(@as(usize, 3), scan.frames); // ceil(40000 / 16384)
    try std.testing.expect(scan.biggest <= 16384);
    try std.testing.expectEqual(@as(usize, 3), scan.end_stream_frame);
    try std.testing.expectEqualStrings(body, out.items);
}

test "a body past both windows waits for WINDOW_UPDATE and still reads the response" {
    const gpa = std.testing.allocator;
    // 70000 exceeds the 65535 initial connection and stream windows, so the
    // tail may not go out until the peer credits (RFC 9113 6.9) -- sending it
    // anyway is FLOW_CONTROL_ERROR. The response HEADERS and DATA arrive BEFORE
    // that credit, so a sender that reads while draining has to replay them.
    const body = try gpa.alloc(u8, 70000);
    defer gpa.free(body);
    @memset(body, 'z');

    var srv_aw: std.Io.Writer.Allocating = .init(gpa);
    defer srv_aw.deinit();
    try frame.write(&srv_aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    const status_hpack = [_]u8{0x88};
    try frame.write(&srv_aw.writer, .{ .typ = .headers, .flags = frame.flags.end_headers, .stream_id = 1, .payload = &status_hpack });
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 100_000, .big);
    try frame.write(&srv_aw.writer, .{ .typ = .window_update, .flags = 0, .stream_id = 0, .payload = &wu });
    try frame.write(&srv_aw.writer, .{ .typ = .window_update, .flags = 0, .stream_id = 1, .payload = &wu });
    try frame.write(&srv_aw.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = 1, .payload = "ok" });
    const server_bytes = try gpa.dupe(u8, srv_aw.written());
    defer gpa.free(server_bytes);

    var reader: std.Io.Reader = .fixed(server_bytes);
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();
    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();
    var res = try c.request(.{ .method = "POST", .scheme = "https", .authority = "api.x.ai", .path = "/v1/test", .body = body });
    defer res.deinit();
    // Replayed, not swallowed: status and body come back intact.
    try std.testing.expectEqual(@as(u16, 200), res.status);
    try std.testing.expectEqualStrings("ok", res.body);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const scan = try scanData(gpa, client_aw.written(), &out);
    // 65535 go out under the initial window, then 4465 after the credit.
    try std.testing.expectEqual(@as(usize, 5), scan.frames);
    try std.testing.expect(scan.biggest <= 16384);
    try std.testing.expectEqual(@as(usize, 5), scan.end_stream_frame);
    try std.testing.expectEqual(@as(usize, 70000), out.items.len);
    try std.testing.expectEqualStrings(body, out.items);
}

test "stream id exhaustion is an error, not a wrapped u31" {
    const gpa = std.testing.allocator;
    var reader: std.Io.Reader = .fixed(&.{});
    var client_aw: std.Io.Writer.Allocating = .init(gpa);
    defer client_aw.deinit();
    var c = Conn.init(gpa, &reader, &client_aw.writer);
    defer c.deinit();

    // The last usable odd id is still handed out...
    c.next_stream = std.math.maxInt(u31) - 2;
    var ls = try c.startLines(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" });
    defer ls.deinit();
    try std.testing.expectEqual(@as(u31, std.math.maxInt(u31) - 2), ls.sid);

    // ...and the next one fails cleanly so the caller can dial a new
    // connection. `next_stream += 2` past here is a u31 overflow panic.
    try std.testing.expectError(error.StreamIdsExhausted, c.startLines(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" }));
    try std.testing.expectError(error.StreamIdsExhausted, c.request(.{ .method = "GET", .scheme = "http", .authority = "localhost", .path = "/" }));
}
