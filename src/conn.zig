//! One HTTP/2 connection over a Reader/Writer (prior knowledge / h2c).
const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");

pub const Request = struct {
    method: []const u8,
    scheme: []const u8,
    authority: []const u8,
    path: []const u8,
    extra: []const hpack.Header = &.{},
    body: []const u8 = &.{},
};

pub const Response = struct {
    status: u16,
    headers: []hpack.Header,
    body: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Response) void {
        for (self.headers) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.allocator.free(self.headers);
        self.allocator.free(self.body);
    }
};

fn stripFramePayload(flags: u8, payload: []const u8) ![]const u8 {
    var p = payload;
    if (flags & frame.flags.padded != 0) {
        if (p.len == 0) return error.ShortFrame;
        const pad = p[0];
        p = p[1..];
        if (p.len < pad) return error.ShortFrame;
        p = p[0 .. p.len - pad];
    }
    if (flags & frame.flags.priority != 0) {
        if (p.len < 5) return error.ShortFrame;
        p = p[5..];
    }
    return p;
}

pub const LineStream = struct {
    conn: *Conn,
    sid: u31,
    pending: std.ArrayList(u8),
    headers: std.ArrayList(hpack.Header) = .empty,
    hdr_block: std.ArrayList(u8) = .empty,
    hdr_open: bool = false,
    hdr_end_stream: bool = false,
    ended: bool = false,
    status: u16 = 0,

    pub fn deinit(self: *LineStream) void {
        for (self.headers.items) |h| {
            self.conn.allocator.free(h.name);
            self.conn.allocator.free(h.value);
        }
        self.headers.deinit(self.conn.allocator);
        self.pending.deinit(self.conn.allocator);
        self.hdr_block.deinit(self.conn.allocator);
    }

    pub fn header(self: *const LineStream, name: []const u8) ?[]const u8 {
        for (self.headers.items) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn waitStatus(self: *LineStream) !u16 {
        while (self.status == 0 and !self.ended) try self.pull();
        if (self.status == 0) return error.NoStatus;
        return self.status;
    }

    fn decodeBlock(self: *LineStream, block: []const u8) !void {
        const decoded = try self.conn.decoder.decode(block);
        defer self.conn.allocator.free(decoded);
        for (decoded) |h| {
            if (std.mem.eql(u8, h.name, ":status")) {
                self.status = std.fmt.parseInt(u16, h.value, 10) catch 0;
            }
            try self.headers.append(self.conn.allocator, h);
        }
    }

    /// True when a line (without LF) was written to `dest`. False at END_STREAM.
    pub fn readLine(self: *LineStream, dest: *std.ArrayList(u8)) !bool {
        dest.clearRetainingCapacity();
        while (true) {
            if (std.mem.indexOfScalar(u8, self.pending.items, '\n')) |i| {
                try dest.appendSlice(self.conn.allocator, self.pending.items[0..i]);
                std.mem.copyForwards(u8, self.pending.items[0 .. self.pending.items.len - i - 1], self.pending.items[i + 1 ..]);
                self.pending.items.len -= i + 1;
                return true;
            }
            if (self.ended) {
                if (self.pending.items.len == 0) return false;
                try dest.appendSlice(self.conn.allocator, self.pending.items);
                self.pending.clearRetainingCapacity();
                return true;
            }
            try self.pull();
        }
    }

    fn pull(self: *LineStream) !void {
        const f = try frame.read(self.conn.reader, &self.conn.buf);
        switch (f.typ) {
            .settings => {
                if (f.flags & frame.flags.ack == 0) {
                    try frame.write(self.conn.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
                    try self.conn.writer.flush();
                }
            },
            .ping => {
                try frame.write(self.conn.writer, .{ .typ = .ping, .flags = frame.flags.ack, .stream_id = 0, .payload = f.payload });
                try self.conn.writer.flush();
            },
            .window_update, .priority => {},
            .goaway => return error.GoAway,
            .rst_stream => if (f.stream_id == self.sid) return error.RstStream,
            .headers => {
                if (f.stream_id != self.sid) {
                    // Pushed / other-stream headers: decode to keep the
                    // HPACK table in sync, then ignore.
                    const payload = try stripFramePayload(f.flags, f.payload);
                    try self.conn.discardBlock(payload, f.flags, f.stream_id);
                    return;
                }
                const payload = try stripFramePayload(f.flags, f.payload);
                if (f.flags & frame.flags.end_stream != 0) self.hdr_end_stream = true;
                if (f.flags & frame.flags.end_headers != 0) {
                    try self.decodeBlock(payload);
                    if (self.hdr_end_stream) self.ended = true;
                    self.hdr_end_stream = false;
                } else {
                    // Fragmented header block (RFC 7540 §4.3): accumulate
                    // HEADERS + CONTINUATION payloads, decode once END_HEADERS
                    // arrives. Decoding fragments separately desyncs the
                    // HPACK dynamic table (HpackIndex on reuse).
                    self.hdr_block.clearRetainingCapacity();
                    try self.hdr_block.appendSlice(self.conn.allocator, payload);
                    self.hdr_open = true;
                }
            },
            .continuation => {
                if (f.stream_id == self.sid) {
                    if (!self.hdr_open) return error.HpackTruncated;
                    const payload = try stripFramePayload(f.flags, f.payload);
                    if (f.flags & frame.flags.end_stream != 0) self.hdr_end_stream = true;
                    try self.hdr_block.appendSlice(self.conn.allocator, payload);
                    if (f.flags & frame.flags.end_headers != 0) {
                        try self.decodeBlock(self.hdr_block.items);
                        self.hdr_block.clearRetainingCapacity();
                        self.hdr_open = false;
                        if (self.hdr_end_stream) self.ended = true;
                        self.hdr_end_stream = false;
                    }
                    return;
                }
                // Foreign CONTINUATION outside a discard: protocol error.
                // (CONTINUATIONs consumed by discardBlock never reach here.)
                return error.HpackTruncated;
            },
            .push_promise => {
                // Promised request headers are HPACK state too; decode and
                // drop. Payload: 4-byte promised id + header block fragment.
                const payload = try stripFramePayload(f.flags, f.payload);
                if (payload.len < 4) return error.HpackTruncated;
                try self.conn.discardBlock(payload[4..], f.flags, f.stream_id);
            },
            .data => {
                try self.conn.creditData(f.stream_id, f.payload.len);
                if (f.stream_id != self.sid) return;
                const payload = try stripFramePayload(f.flags, f.payload);
                try self.pending.appendSlice(self.conn.allocator, payload);
                if (f.flags & frame.flags.end_stream != 0) self.ended = true;
            },
            else => {},
        }
    }
};

pub const Conn = struct {
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    next_stream: u31 = 1,
    saw_preface: bool = false,
    decoder: hpack.Decoder,
    encoder: hpack.Encoder,
    buf: [16384]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, reader: *std.Io.Reader, writer: *std.Io.Writer) Conn {
        return .{
            .allocator = allocator,
            .reader = reader,
            .writer = writer,
            .decoder = hpack.Decoder.init(allocator),
            .encoder = hpack.Encoder.init(),
        };
    }

    pub fn deinit(self: *Conn) void {
        self.decoder.deinit();
    }

    pub fn preface(self: *Conn) !void {
        try self.writer.writeAll(frame.preface);
        // SETTINGS_ENABLE_PUSH = 0 (RFC 7540 §6.5.2): this client does not
        // consume pushed responses. Without it nghttp2.org pushes style.css;
        // skipping the pushed header blocks desyncs the HPACK dynamic table
        // and the next response fails with HpackIndex.
        const no_push = [_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 };
        try frame.write(self.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &no_push });
        try self.writer.flush();
        self.saw_preface = true;
    }

    pub fn request(self: *Conn, req: Request) !Response {
        if (!self.saw_preface) try self.preface();
        const sid = self.next_stream;
        self.next_stream += 2;
        var hdrs: std.ArrayList(hpack.Header) = .empty;
        defer hdrs.deinit(self.allocator);
        try hdrs.append(self.allocator, .{ .name = ":method", .value = req.method });
        try hdrs.append(self.allocator, .{ .name = ":scheme", .value = req.scheme });
        try hdrs.append(self.allocator, .{ .name = ":path", .value = req.path });
        try hdrs.append(self.allocator, .{ .name = ":authority", .value = req.authority });
        try hdrs.appendSlice(self.allocator, req.extra);
        const packed_hdr = try self.encoder.encode(self.allocator, hdrs.items);
        defer self.allocator.free(packed_hdr);
        const hflags: u8 = frame.flags.end_headers | (if (req.body.len == 0) frame.flags.end_stream else 0);
        try frame.write(self.writer, .{ .typ = .headers, .flags = hflags, .stream_id = sid, .payload = packed_hdr });
        if (req.body.len != 0) {
            try frame.write(self.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = sid, .payload = req.body });
        }
        try self.writer.flush();
        return self.readResponse(sid);
    }

    /// DATA counts against both the stream and connection windows (RFC 9113
    /// §6.9). Credit the raw frame payload, padding included, or the peer
    /// stops after the initial 65535 bytes.
    fn creditData(self: *Conn, stream_id: u31, payload_len: usize) !void {
        const n = std.math.cast(u31, payload_len) orelse return error.FrameTooLarge;
        if (n == 0) return;
        try self.windowUpdate(0, n);
        if (stream_id != 0) try self.windowUpdate(stream_id, n);
        try self.writer.flush();
    }

    fn windowUpdate(self: *Conn, stream_id: u31, inc: u31) !void {
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, inc, .big);
        try frame.write(self.writer, .{ .typ = .window_update, .flags = 0, .stream_id = stream_id, .payload = &payload });
    }

    /// Decode a header block addressed elsewhere (pushed stream, another
    /// stream's HEADERS, PUSH_PROMISE) and throw it away. The HPACK dynamic
    /// table is connection state: skipping the decode desyncs it, so a
    /// later indexed reference fails with HpackIndex.
    fn discardBlock(self: *Conn, first: []const u8, flags: u8, sid: u31) !void {
        if (flags & frame.flags.end_headers != 0) {
            const dec = try self.decoder.decode(first);
            defer self.allocator.free(dec);
            for (dec) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            return;
        }
        var acc: std.ArrayList(u8) = .empty;
        defer acc.deinit(self.allocator);
        try acc.appendSlice(self.allocator, first);
        var fl = flags;
        while (fl & frame.flags.end_headers == 0) {
            const c = try frame.read(self.reader, &self.buf);
            if (c.typ != .continuation or c.stream_id != sid) return error.HpackTruncated;
            const cp = try stripFramePayload(c.flags, c.payload);
            try acc.appendSlice(self.allocator, cp);
            fl = c.flags;
        }
        const dec = try self.decoder.decode(acc.items);
        defer self.allocator.free(dec);
        for (dec) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
    }

    fn decodeBlock(self: *Conn, headers: *std.ArrayList(hpack.Header), status: *u16, block: []const u8) !void {
        const decoded = try self.decoder.decode(block);
        defer self.allocator.free(decoded);
        for (decoded) |h| {
            if (std.mem.eql(u8, h.name, ":status")) {
                status.* = std.fmt.parseInt(u16, h.value, 10) catch 0;
            }
            try headers.append(self.allocator, h);
        }
    }

    pub fn startLines(self: *Conn, req: Request) !LineStream {
        if (!self.saw_preface) try self.preface();
        const sid = self.next_stream;
        self.next_stream += 2;
        var hdrs: std.ArrayList(hpack.Header) = .empty;
        defer hdrs.deinit(self.allocator);
        try hdrs.append(self.allocator, .{ .name = ":method", .value = req.method });
        try hdrs.append(self.allocator, .{ .name = ":scheme", .value = req.scheme });
        try hdrs.append(self.allocator, .{ .name = ":path", .value = req.path });
        try hdrs.append(self.allocator, .{ .name = ":authority", .value = req.authority });
        try hdrs.appendSlice(self.allocator, req.extra);
        const packed_hdr = try self.encoder.encode(self.allocator, hdrs.items);
        defer self.allocator.free(packed_hdr);
        const hflags: u8 = frame.flags.end_headers | (if (req.body.len == 0) frame.flags.end_stream else 0);
        try frame.write(self.writer, .{ .typ = .headers, .flags = hflags, .stream_id = sid, .payload = packed_hdr });
        if (req.body.len != 0) {
            try frame.write(self.writer, .{ .typ = .data, .flags = frame.flags.end_stream, .stream_id = sid, .payload = req.body });
        }
        try self.writer.flush();
        return .{
            .conn = self,
            .sid = sid,
            .pending = .empty,
        };
    }

    fn readResponse(self: *Conn, sid: u31) !Response {
        var status: u16 = 0;
        var headers: std.ArrayList(hpack.Header) = .empty;
        errdefer {
            for (headers.items) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            headers.deinit(self.allocator);
        }
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var ended = false;
        while (!ended) {
            const f = try frame.read(self.reader, &self.buf);
            switch (f.typ) {
                .settings => {
                    if (f.flags & frame.flags.ack == 0) {
                        try frame.write(self.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
                        try self.writer.flush();
                    }
                },
                .ping => {
                    try frame.write(self.writer, .{ .typ = .ping, .flags = frame.flags.ack, .stream_id = 0, .payload = f.payload });
                    try self.writer.flush();
                },
                .window_update, .priority => {},
                .goaway => return error.GoAway,
                .rst_stream => if (f.stream_id == sid) return error.RstStream,
                .headers => {
                    if (f.stream_id != sid) {
                        // Pushed / other-stream headers: decode to keep the
                        // HPACK table in sync, then ignore.
                        const payload = try stripFramePayload(f.flags, f.payload);
                        try self.discardBlock(payload, f.flags, f.stream_id);
                        continue;
                    }
                    const payload = try stripFramePayload(f.flags, f.payload);
                    var end_stream = f.flags & frame.flags.end_stream != 0;
                    if (f.flags & frame.flags.end_headers != 0) {
                        try decodeBlock(self, &headers, &status, payload);
                    } else {
                        // Fragmented header block (RFC 7540 §4.3): HEADERS
                        // without END_HEADERS is followed by CONTINUATION
                        // frames. Accumulate and decode once, or the HPACK
                        // dynamic table desyncs (HpackIndex on reuse).
                        var hblock: std.ArrayList(u8) = .empty;
                        defer hblock.deinit(self.allocator);
                        try hblock.appendSlice(self.allocator, payload);
                        var hflags: u8 = f.flags;
                        while (hflags & frame.flags.end_headers == 0) {
                            const c = try frame.read(self.reader, &self.buf);
                            switch (c.typ) {
                                .settings => {
                                    if (c.flags & frame.flags.ack == 0) {
                                        try frame.write(self.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
                                        try self.writer.flush();
                                    }
                                },
                                .ping => {
                                    try frame.write(self.writer, .{ .typ = .ping, .flags = frame.flags.ack, .stream_id = 0, .payload = c.payload });
                                    try self.writer.flush();
                                },
                                .window_update, .priority => {},
                                .goaway => return error.GoAway,
                                .rst_stream => if (c.stream_id == sid) return error.RstStream,
                                .continuation => {
                                    if (c.stream_id != sid) return error.HpackTruncated;
                                    const cp = try stripFramePayload(c.flags, c.payload);
                                    try hblock.appendSlice(self.allocator, cp);
                                    if (c.flags & frame.flags.end_stream != 0) end_stream = true;
                                    hflags = c.flags;
                                },
                                else => return error.HpackTruncated,
                            }
                        }
                        try decodeBlock(self, &headers, &status, hblock.items);
                    }
                    if (end_stream) ended = true;
                },
                .continuation => return error.HpackTruncated,
                .push_promise => {
                    // Promised request headers are HPACK state too; decode
                    // and drop. Payload: 4-byte promised id + fragment.
                    const payload = try stripFramePayload(f.flags, f.payload);
                    if (payload.len < 4) return error.HpackTruncated;
                    try self.discardBlock(payload[4..], f.flags, f.stream_id);
                },
                .data => {
                    try self.creditData(f.stream_id, f.payload.len);
                    if (f.stream_id != sid) continue;
                    const payload = try stripFramePayload(f.flags, f.payload);
                    try body.appendSlice(self.allocator, payload);
                    if (f.flags & frame.flags.end_stream != 0) ended = true;
                },
                else => {},
            }
        }
        return .{
            .status = status,
            .headers = try headers.toOwnedSlice(self.allocator),
            .body = try body.toOwnedSlice(self.allocator),
            .allocator = self.allocator,
        };
    }
};

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
