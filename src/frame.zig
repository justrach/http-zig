//! HTTP/2 frames (RFC 7540 §4, §6).
const std = @import("std");

pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const Type = enum(u8) {
    data = 0,
    headers = 1,
    priority = 2,
    rst_stream = 3,
    settings = 4,
    push_promise = 5,
    ping = 6,
    goaway = 7,
    window_update = 8,
    continuation = 9,
    _,
};

pub const flags = struct {
    pub const end_stream: u8 = 0x1;
    pub const end_headers: u8 = 0x4;
    pub const padded: u8 = 0x8;
    pub const priority: u8 = 0x20;
    pub const ack: u8 = 0x1;
};

pub const Frame = struct {
    typ: Type,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
};

pub fn write(w: *std.Io.Writer, f: Frame) !void {
    if (f.payload.len > 0xffffff) return error.FrameTooLarge;
    var hdr: [9]u8 = undefined;
    hdr[0] = @intCast((f.payload.len >> 16) & 0xff);
    hdr[1] = @intCast((f.payload.len >> 8) & 0xff);
    hdr[2] = @intCast(f.payload.len & 0xff);
    hdr[3] = @intFromEnum(f.typ);
    hdr[4] = f.flags;
    const sid: u32 = f.stream_id;
    hdr[5] = @intCast((sid >> 24) & 0x7f);
    hdr[6] = @intCast((sid >> 16) & 0xff);
    hdr[7] = @intCast((sid >> 8) & 0xff);
    hdr[8] = @intCast(sid & 0xff);
    try w.writeAll(&hdr);
    try w.writeAll(f.payload);
}

pub fn read(r: *std.Io.Reader, buf: []u8) !Frame {
    // A payload read may rebase the reader, invalidating a borrowed header.
    var hdr: [9]u8 = undefined;
    try r.readSliceAll(&hdr);
    const len: usize = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | hdr[2];
    const stream_id: u31 = @truncate(((@as(u32, hdr[5]) << 24) | (@as(u32, hdr[6]) << 16) | (@as(u32, hdr[7]) << 8) | hdr[8]) & 0x7fff_ffff);
    if (len > buf.len) return error.FrameTooLarge;
    // TLS readers buffer a record, not an entire HTTP/2 frame. Drain partial
    // records into the caller's storage before asking TLS to decode another.
    try r.readSliceAll(buf[0..len]);
    return .{
        .typ = @enumFromInt(hdr[3]),
        .flags = hdr[4],
        .stream_id = stream_id,
        .payload = buf[0..len],
    };
}

test "frame SETTINGS empty roundtrip" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try write(&aw.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
    const bytes = aw.written();
    try std.testing.expectEqual(@as(usize, 9), bytes.len);
    var r: std.Io.Reader = .fixed(bytes);
    var buf: [16]u8 = undefined;
    const f = try read(&r, &buf);
    try std.testing.expectEqual(Type.settings, f.typ);
    try std.testing.expectEqual(@as(u31, 0), f.stream_id);
    try std.testing.expectEqual(@as(usize, 0), f.payload.len);
}

test "preface is 24 bytes" {
    try std.testing.expectEqual(@as(usize, 24), preface.len);
}

const RecordReader = struct {
    interface: std.Io.Reader = undefined,
    bytes: []const u8,
    buffer: [32]u8 = undefined,

    fn init(self: *@This(), bytes: []const u8) void {
        self.bytes = bytes;
        self.interface = .{ .vtable = &.{ .stream = stream }, .buffer = &self.buffer, .seek = 0, .end = 0 };
    }

    fn stream(r: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *@This() = @fieldParentPtr("interface", r);
        if (self.bytes.len == 0) return error.EndOfStream;
        const n = @min(self.buffer.len, self.bytes.len);
        const pending = r.buffered();
        // A record decoder cannot emit half of the next record. Return a
        // test error where the TLS implementation asserts on insufficient room.
        if (pending.len + n > r.buffer.len) return error.ReadFailed;
        @memmove(r.buffer[0..pending.len], pending);
        @memcpy(r.buffer[pending.len..][0..n], self.bytes[0..n]);
        r.seek = 0;
        r.end = pending.len + n;
        self.bytes = self.bytes[n..];
        return 0;
    }
};

test "frames cross record boundaries without retaining TLS plaintext" {
    var wire: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer wire.deinit();
    const payload = "abcdefghijklmnopqrstuvwxyz012345";
    for (0..2) |_| try write(&wire.writer, .{ .typ = .data, .flags = flags.end_stream, .stream_id = 3, .payload = payload });
    var records: RecordReader = undefined;
    records.init(wire.written());
    var output: [32]u8 = undefined;
    for (0..2) |_| {
        const f = try read(&records.interface, &output);
        try std.testing.expectEqual(Type.data, f.typ);
        try std.testing.expectEqual(flags.end_stream, f.flags);
        try std.testing.expectEqual(@as(u31, 3), f.stream_id);
        try std.testing.expectEqualStrings(payload, f.payload);
    }
}

test "frame payload can exceed the reader buffer and preserves the header" {
    var wire: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer wire.deinit();
    const payload: [96]u8 = @splat('z');
    try write(&wire.writer, .{ .typ = .headers, .flags = flags.end_headers, .stream_id = 7, .payload = &payload });
    var records: RecordReader = undefined;
    records.init(wire.written());
    var output: [96]u8 = undefined;
    const f = try read(&records.interface, &output);
    try std.testing.expectEqual(Type.headers, f.typ);
    try std.testing.expectEqual(flags.end_headers, f.flags);
    try std.testing.expectEqual(@as(u31, 7), f.stream_id);
    try std.testing.expectEqualStrings(&payload, f.payload);
}

test "truncated frame payload still returns EndOfStream" {
    var wire: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer wire.deinit();
    try write(&wire.writer, .{ .typ = .data, .flags = 0, .stream_id = 1, .payload = "incomplete" });
    var records: RecordReader = undefined;
    records.init(wire.written()[0 .. wire.written().len - 1]);
    var output: [32]u8 = undefined;
    try std.testing.expectError(error.EndOfStream, read(&records.interface, &output));
}
