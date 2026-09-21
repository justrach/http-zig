//! Splice ALPN (`h2`, `http/1.1`) into the first TLS ClientHello.
//! Zig's `std.crypto.tls.Client` has no ALPN option; HTTPS HTTP/2 needs it.

const std = @import("std");

pub const alpn_extension = [_]u8{
    0x00, 0x10, // application_layer_protocol_negotiation
    0x00, 0x0e, // extension data length
    0x00, 0x0c, // protocol name list length
    0x02, 'h',
    '2',  0x08,
    'h',  't',
    't',  'p',
    '/',  '1',
    '.',  '1',
};

/// If `record` is a complete handshake ClientHello, return a newly allocated
/// record with ALPN appended. Otherwise return null (caller keeps the original).
pub fn patchClientHello(gpa: std.mem.Allocator, record: []const u8) !?[]u8 {
    if (record.len < 9) return null;
    if (record[0] != 0x16) return null; // not handshake
    const rec_len: usize = (@as(usize, record[3]) << 8) | record[4];
    if (record.len < 5 + rec_len) return null; // incomplete
    if (record[5] != 0x01) return null; // not client_hello
    if (hasAlpn(record[0 .. 5 + rec_len])) return null;

    var i: usize = 9; // skip TLS record (5) + handshake header (4)
    if (i + 2 + 32 >= record.len) return error.ShortClientHello;
    i += 2 + 32; // version + random
    const sid_len = record[i];
    i += 1 + sid_len;
    if (i + 2 > record.len) return error.ShortClientHello;
    const cs_len: usize = (@as(usize, record[i]) << 8) | record[i + 1];
    i += 2 + cs_len;
    if (i >= record.len) return error.ShortClientHello;
    const comp_len = record[i];
    i += 1 + comp_len;
    if (i + 2 > 5 + rec_len) return error.ShortClientHello;
    const ext_len_at = i;
    const ext_len: usize = (@as(usize, record[i]) << 8) | record[i + 1];
    i += 2;
    if (i + ext_len > 5 + rec_len) return error.ShortClientHello;

    const add = alpn_extension.len;
    const out = try gpa.alloc(u8, record.len + add);
    @memcpy(out[0..ext_len_at], record[0..ext_len_at]);
    const new_ext: u16 = @intCast(ext_len + add);
    out[ext_len_at] = @intCast(new_ext >> 8);
    out[ext_len_at + 1] = @intCast(new_ext & 0xff);
    @memcpy(out[ext_len_at + 2 .. ext_len_at + 2 + ext_len], record[ext_len_at + 2 .. ext_len_at + 2 + ext_len]);
    @memcpy(out[ext_len_at + 2 + ext_len .. ext_len_at + 2 + ext_len + add], &alpn_extension);
    const tail_from = 5 + rec_len;
    if (record.len > tail_from) {
        @memcpy(out[tail_from + add ..], record[tail_from..]);
    }

    const new_rec: u16 = @intCast(rec_len + add);
    out[3] = @intCast(new_rec >> 8);
    out[4] = @intCast(new_rec & 0xff);
    const hs_len = (@as(u32, record[6]) << 16) | (@as(u32, record[7]) << 8) | record[8];
    const new_hs = hs_len + add;
    out[6] = @intCast((new_hs >> 16) & 0xff);
    out[7] = @intCast((new_hs >> 8) & 0xff);
    out[8] = @intCast(new_hs & 0xff);
    return out;
}

fn hasAlpn(rec: []const u8) bool {
    return extensionStart(rec, 0x0010) != null;
}

fn extensionStart(rec: []const u8, want: u16) ?usize {
    const rec_len: usize = (@as(usize, rec[3]) << 8) | rec[4];
    if (rec.len < 5 + rec_len) return null;
    var i: usize = 9;
    if (i + 34 >= rec.len) return null;
    i += 34;
    if (i >= rec.len) return null;
    const sid_len = rec[i];
    i += 1 + sid_len;
    if (i + 2 > rec.len) return null;
    const cs_len: usize = (@as(usize, rec[i]) << 8) | rec[i + 1];
    i += 2 + cs_len;
    if (i >= rec.len) return null;
    const comp_len = rec[i];
    i += 1 + comp_len;
    if (i + 2 > rec.len) return null;
    const ext_len: usize = (@as(usize, rec[i]) << 8) | rec[i + 1];
    i += 2;
    const end = i + ext_len;
    if (end > rec.len) return null;
    while (i + 4 <= end) {
        const typ: u16 = (@as(u16, rec[i]) << 8) | rec[i + 1];
        const elen: usize = (@as(usize, rec[i + 2]) << 8) | rec[i + 3];
        if (typ == want) return i;
        i += 4 + elen;
    }
    return null;
}

pub const Injector = struct {
    gpa: std.mem.Allocator,
    inner: *std.Io.Writer,
    writer: std.Io.Writer,
    pending: std.ArrayList(u8) = .empty,
    done: bool = false,

    pub fn init(self: *Injector, gpa: std.mem.Allocator, inner: *std.Io.Writer, buf: []u8) void {
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .writer = .{
                .vtable = &.{ .drain = drain },
                .buffer = buf,
            },
        };
    }

    pub fn deinit(self: *Injector) void {
        self.pending.deinit(self.gpa);
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Injector = @alignCast(@fieldParentPtr("writer", w));
        const buffered = w.buffered();
        self.pending.appendSlice(self.gpa, buffered) catch return error.WriteFailed;
        w.end = 0;

        var from_data: usize = 0;
        for (data, 0..) |d, idx| {
            const times: usize = if (idx + 1 == data.len) splat else 1;
            var t: usize = 0;
            while (t < times) : (t += 1) {
                self.pending.appendSlice(self.gpa, d) catch return error.WriteFailed;
            }
            from_data += d.len * times;
        }

        if (self.done) {
            self.inner.writeAll(self.pending.items) catch return error.WriteFailed;
            self.inner.flush() catch return error.WriteFailed;
            self.pending.clearRetainingCapacity();
            return from_data;
        }

        const maybe = patchClientHello(self.gpa, self.pending.items) catch return error.WriteFailed;
        if (maybe) |patched| {
            defer self.gpa.free(patched);
            self.inner.writeAll(patched) catch return error.WriteFailed;
            self.inner.flush() catch return error.WriteFailed;
            self.pending.clearRetainingCapacity();
            self.done = true;
            return from_data;
        }
        if (self.pending.items.len >= 5) {
            const rec_len: usize = (@as(usize, self.pending.items[3]) << 8) | self.pending.items[4];
            if (self.pending.items.len >= 5 + rec_len) {
                // Complete record that we chose not to patch.
                self.inner.writeAll(self.pending.items) catch return error.WriteFailed;
                self.inner.flush() catch return error.WriteFailed;
                self.pending.clearRetainingCapacity();
                self.done = true;
            }
        }
        return from_data;
    }
};

test "patchClientHello inserts ALPN and fixes lengths" {
    const gpa = std.testing.allocator;
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(gpa);
    try hello.appendSlice(gpa, &.{ 0x16, 0x03, 0x03, 0, 0 });
    try hello.append(gpa, 0x01);
    try hello.appendSlice(gpa, &.{ 0, 0, 0 });
    try hello.appendSlice(gpa, &.{ 0x03, 0x03 });
    var z: usize = 0;
    while (z < 32) : (z += 1) try hello.append(gpa, 0);
    try hello.append(gpa, 0); // session id
    try hello.appendSlice(gpa, &.{ 0, 2, 0x00, 0x2f }); // ciphers
    try hello.appendSlice(gpa, &.{ 1, 0 }); // compression
    try hello.appendSlice(gpa, &.{ 0, 4, 0x00, 0x00, 0x00, 0x00 }); // dummy ext
    const rec_len: u16 = @intCast(hello.items.len - 5);
    hello.items[3] = @intCast(rec_len >> 8);
    hello.items[4] = @intCast(rec_len & 0xff);
    const hs: u32 = @intCast(hello.items.len - 9);
    hello.items[6] = @intCast((hs >> 16) & 0xff);
    hello.items[7] = @intCast((hs >> 8) & 0xff);
    hello.items[8] = @intCast(hs & 0xff);

    const patched = (try patchClientHello(gpa, hello.items)).?;
    defer gpa.free(patched);
    try std.testing.expect(std.mem.indexOf(u8, patched, "h2") != null);
    try std.testing.expectEqual(@as(usize, hello.items.len + alpn_extension.len), patched.len);
    const new_rec: usize = (@as(usize, patched[3]) << 8) | patched[4];
    try std.testing.expectEqual(patched.len - 5, new_rec);
}
