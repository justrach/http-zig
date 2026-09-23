const std = @import("std");
const tls = std.crypto.tls;
const Writer = std.Io.Writer;
const AEAD = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Capture = struct {
    writer: Writer,
    bytes: std.ArrayList(u8) = .empty,
    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *Capture = @alignCast(@fieldParentPtr("writer", w));
        self.bytes.appendSlice(std.testing.allocator, w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |part| {
            self.bytes.appendSlice(std.testing.allocator, part) catch return error.WriteFailed;
            n += part.len;
        }
        for (0..splat) |_| {
            const part = data[data.len - 1];
            self.bytes.appendSlice(std.testing.allocator, part) catch return error.WriteFailed;
            n += part.len;
        }
        return n;
    }
};

pub fn check(comptime Client: type, drain: anytype, flush: anytype) !void {
    const key: [AEAD.key_length]u8 = @splat(0);
    const iv: [AEAD.nonce_length]u8 = @splat(0);
    var socket_buf: [Client.min_buffer_len]u8 = undefined;
    var capture: Capture = .{ .writer = .{ .buffer = &socket_buf, .vtable = &.{ .drain = Capture.drain } } };
    defer capture.bytes.deinit(std.testing.allocator);
    var plaintext_buf: [Client.min_buffer_len]u8 = undefined;
    var client: Client = .{
        .input = undefined,
        .reader = undefined,
        .output = &capture.writer,
        .writer = .{ .buffer = &plaintext_buf, .vtable = &.{ .drain = drain, .flush = flush } },
        .tls_version = .tls_1_3,
        .read_seq = 0,
        .write_seq = 0,
        .received_close_notify = false,
        .allow_truncation_attacks = false,
        .ssl_key_log = null,
        .application_cipher = .{ .CHACHA20_POLY1305_SHA256 = .{ .tls_1_3 = .{
            .server_key = key,
            .server_iv = iv,
            .client_key = key,
            .client_iv = iv,
            .client_secret = undefined,
            .server_secret = undefined,
        } } },
    };
    // Fill the whole plaintext buffer. Its capacity includes ciphertext
    // overhead, so one ciphertext output buffer cannot hold all these bytes.
    var expected: [Client.min_buffer_len]u8 = undefined;
    for (&expected, 0..) |*b, i| b.* = @truncate(i);
    try client.writer.writeAll(&expected);
    try client.writer.flush();
    try std.testing.expectEqual(@as(usize, 0), client.writer.end);
    const emitted = capture.bytes.items.len;
    try client.writer.flush();
    try std.testing.expectEqual(emitted, capture.bytes.items.len);
    var clear: std.ArrayList(u8) = .empty;
    defer clear.deinit(std.testing.allocator);
    var offset: usize = 0;
    var seq: u64 = 0;
    while (offset < capture.bytes.items.len) {
        const bytes = capture.bytes.items[offset..];
        try std.testing.expect(bytes.len >= 5);
        const len = std.mem.readInt(u16, bytes[3..5], .big);
        try std.testing.expect(bytes.len >= 5 + len);
        const encrypted = bytes[5..][0 .. len - AEAD.tag_length];
        const tag = bytes[5 + encrypted.len ..][0..AEAD.tag_length].*;
        var nonce = iv;
        std.mem.writeInt(u64, nonce[4..12], seq, .big);
        const decoded = try std.testing.allocator.alloc(u8, encrypted.len);
        defer std.testing.allocator.free(decoded);
        try AEAD.decrypt(decoded, encrypted, tag, bytes[0..5], nonce, key);
        try std.testing.expectEqual(@as(u8, 23), decoded[decoded.len - 1]);
        try clear.appendSlice(std.testing.allocator, decoded[0 .. decoded.len - 1]);
        offset += 5 + len;
        seq += 1;
    }
    try std.testing.expectEqualSlices(u8, &expected, clear.items);
    try std.testing.expect(seq >= 2);
}
