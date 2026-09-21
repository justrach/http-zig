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
    ended: bool = false,
    status: u16 = 0,

    pub fn deinit(self: *LineStream) void {
        self.pending.deinit(self.conn.allocator);
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
            .headers, .continuation => {
                if (f.stream_id != self.sid) return;
                const payload = try stripFramePayload(f.flags, f.payload);
                const decoded = try self.conn.decoder.decode(payload);
                defer self.conn.allocator.free(decoded);
                for (decoded) |h| {
                    if (std.mem.eql(u8, h.name, ":status")) {
                        self.status = std.fmt.parseInt(u16, h.value, 10) catch 0;
                    }
                    self.conn.allocator.free(h.name);
                    self.conn.allocator.free(h.value);
                }
                if (f.flags & frame.flags.end_stream != 0) self.ended = true;
            },
            .data => {
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
        try frame.write(self.writer, .{ .typ = .settings, .flags = 0, .stream_id = 0, .payload = &.{} });
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
                .headers, .continuation => {
                    if (f.stream_id != sid) continue;
                    const payload = try stripFramePayload(f.flags, f.payload);
                    const decoded = try self.decoder.decode(payload);
                    defer self.allocator.free(decoded);
                    for (decoded) |h| {
                        if (std.mem.eql(u8, h.name, ":status")) {
                            status = std.fmt.parseInt(u16, h.value, 10) catch 0;
                        }
                        try headers.append(self.allocator, h);
                    }
                    if (f.flags & frame.flags.end_stream != 0) ended = true;
                },
                .data => {
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
}
