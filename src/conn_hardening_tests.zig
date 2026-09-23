//! Mock-peer tests for GOAWAY draining, interim responses, RST_STREAM codes and
//! decoder bounds. Same scripted-byte-stream shape as conn_tests.zig.
const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const huffman = @import("huffman.zig");
const flow = @import("flow.zig");
const Conn = @import("conn.zig").Conn;

const status_200 = [_]u8{0x88}; // indexed :status 200
const status_103 = [_]u8{ 0x08, 0x03, '1', '0', '3' }; // literal :status 103

const Peer = struct {
    aw: std.Io.Writer.Allocating,

    fn init() Peer {
        var p: Peer = .{ .aw = .init(std.testing.allocator) };
        frame.write(&p.aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} }) catch unreachable;
        return p;
    }

    fn add(p: *Peer, typ: frame.Type, flags: u8, sid: u31, payload: []const u8) void {
        frame.write(&p.aw.writer, .{ .typ = typ, .flags = flags, .stream_id = sid, .payload = payload }) catch unreachable;
    }

    fn goaway(p: *Peer, last: u32, code: u32) void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], last, .big);
        std.mem.writeInt(u32, b[4..8], code, .big);
        p.add(.goaway, 0, 0, &b);
    }

    fn rst(p: *Peer, sid: u31, code: u32) void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, code, .big);
        p.add(.rst_stream, 0, sid, &b);
    }
};

const get: @import("conn.zig").Request = .{ .method = "POST", .scheme = "https", .authority = "x", .path = "/" };

fn expectLines(c: *Conn, want: []const []const u8) !void {
    var ls = try c.startLines(get);
    defer ls.deinit();
    try std.testing.expectEqual(@as(u16, 200), try ls.waitStatus());
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(std.testing.allocator);
    for (want) |w| {
        try std.testing.expect(try ls.readLine(&line));
        try std.testing.expectEqualStrings(w, line.items);
    }
    try std.testing.expect(!try ls.readLine(&line));
}

test "graceful GOAWAY covering the stream lets it finish and stops reuse" {
    var p = Peer.init();
    defer p.aw.deinit();
    p.add(.headers, frame.flags.end_headers, 1, &status_200);
    p.add(.data, 0, 1, "data: a\n");
    p.goaway(1, 0);
    p.add(.data, frame.flags.end_stream, 1, "data: b\n");
    var r: std.Io.Reader = .fixed(p.aw.written());
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var c = Conn.init(std.testing.allocator, &r, &out.writer);
    defer c.deinit();
    try expectLines(&c, &.{ "data: a", "data: b" });
    try std.testing.expect(!c.acceptsStreams());
}

test "GOAWAY below our stream id is error.GoAway (unprocessed)" {
    var p = Peer.init();
    defer p.aw.deinit();
    p.goaway(0, 0);
    var r: std.Io.Reader = .fixed(p.aw.written());
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var c = Conn.init(std.testing.allocator, &r, &out.writer);
    defer c.deinit();
    var ls = try c.startLines(get);
    defer ls.deinit();
    try std.testing.expectError(error.GoAway, ls.waitStatus());
}

test "103 Early Hints is skipped; the final status is returned" {
    var p = Peer.init();
    defer p.aw.deinit();
    p.add(.headers, frame.flags.end_headers, 1, &status_103);
    p.add(.headers, frame.flags.end_headers, 1, &status_200);
    p.add(.data, frame.flags.end_stream, 1, "ok\n");
    var r: std.Io.Reader = .fixed(p.aw.written());
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var c = Conn.init(std.testing.allocator, &r, &out.writer);
    defer c.deinit();
    try expectLines(&c, &.{"ok"});
}

test "RST_STREAM(NO_ERROR) after the response ends the stream cleanly" {
    var p = Peer.init();
    defer p.aw.deinit();
    p.add(.headers, frame.flags.end_headers, 1, &status_200);
    p.add(.data, 0, 1, "done\n");
    p.rst(1, 0);
    var r: std.Io.Reader = .fixed(p.aw.written());
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var c = Conn.init(std.testing.allocator, &r, &out.writer);
    defer c.deinit();
    try expectLines(&c, &.{"done"});
}

test "RST_STREAM(REFUSED_STREAM) is error.StreamRefused" {
    var p = Peer.init();
    defer p.aw.deinit();
    p.rst(1, 7);
    var r: std.Io.Reader = .fixed(p.aw.written());
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var c = Conn.init(std.testing.allocator, &r, &out.writer);
    defer c.deinit();
    var ls = try c.startLines(get);
    defer ls.deinit();
    try std.testing.expectError(error.StreamRefused, ls.waitStatus());
}

test "early response + RST_STREAM(NO_ERROR) mid-upload stops the upload and keeps the response" {
    var p = Peer.init();
    defer p.aw.deinit();
    p.add(.headers, frame.flags.end_headers, 1, &status_200);
    p.add(.data, frame.flags.end_stream, 1, "early\n");
    p.rst(1, 0);
    var r: std.Io.Reader = .fixed(p.aw.written());
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var c = Conn.init(std.testing.allocator, &r, &out.writer);
    defer c.deinit();
    // Larger than the 65535-byte initial window: the client must wait for
    // credit, sees the RST instead, and stops sending.
    const body = try std.testing.allocator.alloc(u8, 100_000);
    defer std.testing.allocator.free(body);
    @memset(body, 'x');
    var req = get;
    req.body = body;
    var ls = try c.startLines(req);
    defer ls.deinit();
    try std.testing.expectEqual(@as(u16, 200), try ls.waitStatus());
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(std.testing.allocator);
    try std.testing.expect(try ls.readLine(&line));
    try std.testing.expectEqualStrings("early", line.items);
}

test "huffman: a long run of all-ones is an error, not an integer overflow" {
    const ones: [8]u8 = @splat(0xff);
    try std.testing.expectError(error.HuffmanOverflow, huffman.decode(std.testing.allocator, &ones));
    const more: [64]u8 = @splat(0xff);
    try std.testing.expectError(error.HuffmanOverflow, huffman.decode(std.testing.allocator, &more));
}

test "hpack: table size update above the advertised maximum is rejected" {
    var d = hpack.Decoder.init(std.testing.allocator);
    defer d.deinit();
    // 001xxxxx, 5-bit prefix: 31 + 0x62 + (0x1f << 7) = 4097, one above 4096.
    const big = [_]u8{ 0x3f, 0xe2, 0x1f };
    try std.testing.expectError(error.HpackTableSize, d.decode(&big));
    // After a header field it is out of place even when small.
    const late = [_]u8{ 0x88, 0x20 };
    try std.testing.expectError(error.HpackTableSize, d.decode(&late));
}

test "flow: WINDOW_UPDATE past 2^31-1 is a flow-control error" {
    var f: flow.Flow = .{};
    f.beginStream(1);
    try std.testing.expectError(error.FlowControlOverflow, f.onWindowUpdate(0, 0x7fff_ffff));
    try std.testing.expectError(error.FlowControlOverflow, f.onWindowUpdate(1, 0x7fff_ffff));
}
