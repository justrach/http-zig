//! HPACK (RFC 7541): static table, dynamic table, integer/literal coding.
const std = @import("std");
const huffman = @import("huffman.zig");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

const static_table = [_]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub const Encoder = struct {
    pub fn init() Encoder {
        return .{};
    }

    /// Indexed static entries when both name and value match; otherwise
    /// literal without indexing (never grows a table). No Huffman.
    pub fn encode(self: *Encoder, allocator: std.mem.Allocator, headers: []const Header) ![]u8 {
        _ = self;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (headers) |h| {
            if (staticIndex(h.name, h.value)) |idx| {
                try writeInteger(&out, allocator, idx, 7, 0x80);
                continue;
            }
            if (staticNameIndex(h.name)) |idx| {
                try writeInteger(&out, allocator, idx, 4, 0x00);
                try writeString(&out, allocator, h.value);
                continue;
            }
            try out.append(allocator, 0x00);
            try writeString(&out, allocator, h.name);
            try writeString(&out, allocator, h.value);
        }
        return out.toOwnedSlice(allocator);
    }
};

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    dynamic: std.ArrayList(Header),
    table_size: usize = 4096,
    used: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Decoder {
        return .{ .allocator = allocator, .dynamic = .empty };
    }

    pub fn deinit(self: *Decoder) void {
        for (self.dynamic.items) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.dynamic.deinit(self.allocator);
    }

    pub fn decode(self: *Decoder, src: []const u8) ![]Header {
        var out: std.ArrayList(Header) = .empty;
        errdefer {
            for (out.items) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            out.deinit(self.allocator);
        }
        var i: usize = 0;
        while (i < src.len) {
            const b = src[i];
            if (b & 0x80 != 0) {
                const idx, const n = try readInteger(src, i, 7);
                i = n;
                const h = try self.lookup(idx);
                try out.append(self.allocator, try self.dup(h));
            } else if (b & 0xc0 == 0x40) {
                const idx, const n = try readInteger(src, i, 6);
                i = n;
                const name, const val, const n2 = try self.readNameValue(src, i, idx);
                i = n2;
                try self.addDynamic(name, val);
                try out.append(self.allocator, try self.dup(.{ .name = name, .value = val }));
                self.allocator.free(name);
                self.allocator.free(val);
            } else if (b & 0xe0 == 0x20) {
                const size, const n = try readInteger(src, i, 5);
                i = n;
                self.table_size = size;
                self.evict();
            } else {
                // 0000 / 0001 — literal without indexing / never indexed
                const idx, const n = try readInteger(src, i, 4);
                i = n;
                const name, const val, const n2 = try self.readNameValue(src, i, idx);
                i = n2;
                try out.append(self.allocator, .{ .name = name, .value = val });
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn readNameValue(self: *Decoder, src: []const u8, start: usize, name_idx: usize) !struct { []u8, []u8, usize } {
        var i = start;
        const name: []u8 = if (name_idx == 0) blk: {
            const s, const n = try readString(self.allocator, src, i);
            i = n;
            break :blk s;
        } else blk: {
            const h = try self.lookup(name_idx);
            break :blk try self.allocator.dupe(u8, h.name);
        };
        errdefer self.allocator.free(name);
        const value, const n = try readString(self.allocator, src, i);
        return .{ name, value, n };
    }

    fn lookup(self: *Decoder, idx: usize) !Header {
        if (idx == 0) return error.HpackIndex;
        if (idx <= static_table.len) return static_table[idx - 1];
        const d = idx - static_table.len - 1;
        if (d >= self.dynamic.items.len) return error.HpackIndex;
        return self.dynamic.items[d];
    }

    fn addDynamic(self: *Decoder, name: []const u8, value: []const u8) !void {
        const n = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(n);
        const v = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(v);
        try self.dynamic.insert(self.allocator, 0, .{ .name = n, .value = v });
        self.used += n.len + v.len + 32;
        self.evict();
    }

    fn evict(self: *Decoder) void {
        while (self.used > self.table_size and self.dynamic.items.len > 0) {
            const last = self.dynamic.items[self.dynamic.items.len - 1];
            self.used -= last.name.len + last.value.len + 32;
            self.allocator.free(last.name);
            self.allocator.free(last.value);
            _ = self.dynamic.pop();
        }
    }

    fn dup(self: *Decoder, h: Header) !Header {
        return .{
            .name = try self.allocator.dupe(u8, h.name),
            .value = try self.allocator.dupe(u8, h.value),
        };
    }
};

fn staticIndex(name: []const u8, value: []const u8) ?usize {
    for (static_table, 1..) |h, i| {
        if (std.mem.eql(u8, h.name, name) and std.mem.eql(u8, h.value, value) and h.value.len != 0)
            return i;
    }
    return null;
}

fn staticNameIndex(name: []const u8) ?usize {
    for (static_table, 1..) |h, i| {
        if (std.mem.eql(u8, h.name, name)) return i;
    }
    return null;
}

fn writeInteger(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: usize, prefix_bits: u3, mask: u8) !void {
    const max = (@as(usize, 1) << prefix_bits) - 1;
    if (value < max) {
        try out.append(allocator, mask | @as(u8, @intCast(value)));
        return;
    }
    try out.append(allocator, mask | @as(u8, @intCast(max)));
    var v = value - max;
    while (v >= 128) {
        try out.append(allocator, @as(u8, @intCast((v % 128) + 128)));
        v /= 128;
    }
    try out.append(allocator, @intCast(v));
}

fn readInteger(src: []const u8, start: usize, prefix_bits: u3) !struct { usize, usize } {
    if (start >= src.len) return error.HpackTruncated;
    const max = (@as(usize, 1) << prefix_bits) - 1;
    var i = start;
    var value: usize = src[i] & @as(u8, @intCast(max));
    i += 1;
    if (value < max) return .{ value, i };
    var m: usize = 0;
    while (true) {
        if (i >= src.len) return error.HpackTruncated;
        const b = src[i];
        i += 1;
        value += @as(usize, b & 0x7f) << @intCast(m);
        m += 7;
        if (b & 0x80 == 0) break;
        if (m > 28) return error.HpackInteger;
    }
    return .{ value, i };
}

fn writeString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try writeInteger(out, allocator, s.len, 7, 0x00);
    try out.appendSlice(allocator, s);
}

fn readString(allocator: std.mem.Allocator, src: []const u8, start: usize) !struct { []u8, usize } {
    if (start >= src.len) return error.HpackTruncated;
    const huff = src[start] & 0x80 != 0;
    const len, const n = try readInteger(src, start, 7);
    if (n + len > src.len) return error.HpackTruncated;
    const slice = src[n .. n + len];
    if (huff) {
        const dec = try huffman.decode(allocator, slice);
        return .{ dec, n + len };
    }
    return .{ try allocator.dupe(u8, slice), n + len };
}

test "hpack indexed :method GET (C.2.4)" {
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();
    const headers = try dec.decode(&.{0x82});
    defer {
        for (headers) |h| {
            std.testing.allocator.free(h.name);
            std.testing.allocator.free(h.value);
        }
        std.testing.allocator.free(headers);
    }
    try std.testing.expectEqual(@as(usize, 1), headers.len);
    try std.testing.expectEqualStrings(":method", headers[0].name);
    try std.testing.expectEqualStrings("GET", headers[0].value);
}

test "hpack C.3.1 first request without Huffman" {
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();
    const bytes = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };
    const headers = try dec.decode(&bytes);
    defer {
        for (headers) |h| {
            std.testing.allocator.free(h.name);
            std.testing.allocator.free(h.value);
        }
        std.testing.allocator.free(headers);
    }
    try std.testing.expectEqual(@as(usize, 4), headers.len);
    try std.testing.expectEqualStrings(":method", headers[0].name);
    try std.testing.expectEqualStrings("GET", headers[0].value);
    try std.testing.expectEqualStrings(":scheme", headers[1].name);
    try std.testing.expectEqualStrings("http", headers[1].value);
    try std.testing.expectEqualStrings(":path", headers[2].name);
    try std.testing.expectEqualStrings("/", headers[2].value);
    try std.testing.expectEqualStrings(":authority", headers[3].name);
    try std.testing.expectEqualStrings("www.example.com", headers[3].value);
}

test "hpack C.4.1 Huffman authority" {
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();
    const bytes = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    };
    const headers = try dec.decode(&bytes);
    defer {
        for (headers) |h| {
            std.testing.allocator.free(h.name);
            std.testing.allocator.free(h.value);
        }
        std.testing.allocator.free(headers);
    }
    try std.testing.expectEqualStrings("www.example.com", headers[3].value);
}

test "hpack encode GET / https" {
    var enc = Encoder.init();
    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const bytes = try enc.encode(std.testing.allocator, &headers);
    defer std.testing.allocator.free(bytes);
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();
    const got = try dec.decode(bytes);
    defer {
        for (got) |h| {
            std.testing.allocator.free(h.name);
            std.testing.allocator.free(h.value);
        }
        std.testing.allocator.free(got);
    }
    try std.testing.expectEqual(@as(usize, 4), got.len);
    try std.testing.expectEqualStrings("GET", got[0].value);
    try std.testing.expectEqualStrings("https", got[1].value);
}
