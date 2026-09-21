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
    const hdr = try r.takeArray(9);
    const len: usize = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | hdr[2];
    const stream_id: u31 = @truncate(((@as(u32, hdr[5]) << 24) | (@as(u32, hdr[6]) << 16) | (@as(u32, hdr[7]) << 8) | hdr[8]) & 0x7fff_ffff);
    if (len > buf.len) return error.FrameTooLarge;
    if (len > 0) {
        const got = try r.take(len);
        @memcpy(buf[0..len], got);
    }
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
