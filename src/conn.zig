//! One HTTP/2 connection over a Reader/Writer (prior knowledge / h2c).
const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const flow_mod = @import("flow.zig");

/// Frames read while waiting for outbound credit before giving up on the peer.
const max_credit_frames: u32 = 64;

/// Header block (HEADERS + CONTINUATION) cap: stops an endless CONTINUATION
/// run from growing memory (RFC 9113 §10.5.1).
pub const max_header_block: usize = 256 * 1024;

/// RST_STREAM / GOAWAY error codes this client acts on (RFC 9113 §7).
const err_no_error: u32 = 0x0;
const err_refused_stream: u32 = 0x7;

fn errorCode(f: frame.Frame) u32 {
    if (f.payload.len < 4) return 0xffff_ffff;
    return std.mem.readInt(u32, f.payload[0..4], .big);
}

/// Map RST_STREAM on our stream to an error. REFUSED_STREAM means the server
/// did no work (RFC 9113 §8.7), so the caller may safely resend.
fn rstError(f: frame.Frame) anyerror {
    return if (errorCode(f) == err_refused_stream) error.StreamRefused else error.RstStream;
}

fn appendBlock(block: *std.ArrayList(u8), gpa: std.mem.Allocator, part: []const u8) !void {
    if (block.items.len + part.len > max_header_block) return error.HeaderBlockTooLarge;
    try block.appendSlice(gpa, part);
}

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

/// Drop padding (DATA, HEADERS, PUSH_PROMISE) and the priority block (HEADERS
/// only). Flags a frame type does not define are ignored (RFC 9113 §4.1): on
/// DATA 0x20 is not PRIORITY, and CONTINUATION carries neither.
fn stripFramePayload(typ: frame.Type, flags: u8, payload: []const u8) ![]const u8 {
    if (typ == .continuation) return payload;
    var p = payload;
    if (flags & frame.flags.padded != 0) {
        if (p.len == 0) return error.ShortFrame;
        const pad = p[0];
        p = p[1..];
        if (p.len < pad) return error.ShortFrame;
        p = p[0 .. p.len - pad];
    }
    if (typ == .headers and flags & frame.flags.priority != 0) {
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
        self.status = try self.conn.decodeInto(&self.headers, block) orelse self.status;
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
        // readFrame absorbs SETTINGS/PING/WINDOW_UPDATE/PRIORITY, so only the
        // frames this stream must act on arrive here.
        const f = try self.conn.readFrame();
        switch (f.typ) {
            .goaway => try self.conn.onGoAway(f, self.sid),
            .rst_stream => if (f.stream_id == self.sid) {
                // A complete response followed by RST_STREAM(NO_ERROR) is how a
                // server stops an upload it no longer needs (RFC 9113 §8.1).
                if (errorCode(f) == err_no_error and self.status != 0) {
                    self.ended = true;
                    return;
                }
                return rstError(f);
            },
            .headers => {
                if (f.stream_id != self.sid) {
                    // Pushed / other-stream headers: decode to keep the
                    // HPACK table in sync, then ignore.
                    const payload = try stripFramePayload(f.typ, f.flags, f.payload);
                    try self.conn.discardBlock(payload, f.flags, f.stream_id);
                    return;
                }
                const payload = try stripFramePayload(f.typ, f.flags, f.payload);
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
                    try appendBlock(&self.hdr_block, self.conn.allocator, payload);
                    self.hdr_open = true;
                }
            },
            .continuation => {
                if (f.stream_id == self.sid) {
                    if (!self.hdr_open) return error.HpackTruncated;
                    // END_STREAM rides on the HEADERS frame, never CONTINUATION.
                    try appendBlock(&self.hdr_block, self.conn.allocator, f.payload);
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
                const payload = try stripFramePayload(f.typ, f.flags, f.payload);
                if (payload.len < 4) return error.HpackTruncated;
                try self.conn.discardBlock(payload[4..], f.flags, f.stream_id);
            },
            .data => {
                try self.conn.creditData(f.stream_id, f.payload.len);
                if (f.stream_id != self.sid) return;
                const payload = try stripFramePayload(f.typ, f.flags, f.payload);
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
    /// Outbound windows and the peer's SETTINGS (RFC 9113 5.2, 6.9).
    flow: flow_mod.Flow = .{},
    /// Frames read while draining for outbound credit mid-send. They belong to
    /// the response, so readRaw replays them instead of dropping them.
    pending_wire: std.ArrayList(u8) = .empty,
    /// Last-stream-id from the peer's GOAWAY: the connection is draining and
    /// takes no new streams (RFC 9113 §6.8).
    goaway_last: ?u31 = null,

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
        self.pending_wire.deinit(self.allocator);
    }

    pub fn acceptsStreams(self: *const Conn) bool {
        return self.goaway_last == null;
    }

    /// GOAWAY (RFC 9113 §6.8): a stream at or below last-stream-id may finish,
    /// so keep reading it. Above it the server never processed the stream, so
    /// error.GoAway means "safe to resend elsewhere".
    fn onGoAway(self: *Conn, f: frame.Frame, sid: u31) !void {
        if (f.payload.len < 8) return error.InvalidGoAway;
        const last: u31 = @truncate(std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff);
        self.goaway_last = if (self.goaway_last) |prev| @min(prev, last) else last;
        if (sid > self.goaway_last.?) return error.GoAway;
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
        const sid = try self.allocStream();
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
        try self.sendBody(sid, req.body);
        return self.readResponse(sid);
    }

    /// Client streams are odd and strictly increasing (RFC 9113 5.1.1), and the
    /// id space is finite. Letting `next_stream` wrap would panic a `u31` add
    /// mid-request; the caller needs a plain error so it can open a new
    /// connection instead.
    fn allocStream(self: *Conn) !u31 {
        if (self.next_stream > std.math.maxInt(u31) - 1) return error.StreamIdsExhausted;
        const sid = self.next_stream;
        self.next_stream += 2;
        self.flow.beginStream(sid);
        return sid;
    }

    /// Send `body` as DATA (RFC 9113 6.1). Two rules a one-shot write breaks:
    /// no frame may exceed SETTINGS_MAX_FRAME_SIZE (initial 16384 -- larger is a
    /// FRAME_SIZE_ERROR connection error), and the total must fit both the
    /// connection and the stream window (else FLOW_CONTROL_ERROR). Chunks that do
    /// not fit yet wait for the peer's WINDOW_UPDATE.
    fn sendBody(self: *Conn, sid: u31, body: []const u8) !void {
        var off: usize = 0;
        while (off < body.len) {
            const n = self.flow.allowed();
            if (n == 0) {
                if (try self.awaitCredit(sid)) return;
                continue;
            }
            const take = @min(n, body.len - off);
            const last = off + take == body.len;
            try frame.write(self.writer, .{ .typ = .data, .flags = if (last) frame.flags.end_stream else 0, .stream_id = sid, .payload = body[off..][0..take] });
            try self.writer.flush();
            self.flow.consume(take);
            off += take;
        }
        try self.writer.flush();
    }

    /// Read frames until the outbound window reopens. A peer that never credits
    /// must not hang the caller, so this gives up after max_credit_frames and
    /// surfaces an error the caller can fall back from. Returns true when the
    /// peer ended our stream with RST_STREAM(NO_ERROR) after answering early
    /// (RFC 9113 §8.1): the upload stops and the stashed response is read.
    fn awaitCredit(self: *Conn, sid: u31) !bool {
        var attempts: u32 = 0;
        while (self.flow.allowed() == 0) {
            attempts += 1;
            if (attempts > max_credit_frames) return error.FlowControlBlocked;
            // Fresh wire frames only. A frame already sitting in the stash is
            // response data waiting to be replayed: pulling it here just to
            // stash it again spins on one frame and never reaches the credit.
            const f = try frame.read(self.reader, &self.buf);
            if (f.typ == .goaway) {
                try self.onGoAway(f, sid);
                continue;
            }
            if (f.typ == .rst_stream and f.stream_id == sid) {
                if (errorCode(f) != err_no_error) return rstError(f);
                try self.stashFrame(f);
                return true;
            }
            if (!try self.absorb(f)) try self.stashFrame(f);
        }
        return false;
    }

    /// Keep a frame that arrived while we were still sending. Its payload points
    /// into `buf`, which the next read would overwrite, so copy the wire bytes.
    fn stashFrame(self: *Conn, f: frame.Frame) !void {
        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        try frame.write(&aw.writer, f);
        try self.pending_wire.appendSlice(self.allocator, aw.written());
    }

    /// One raw frame, replaying anything stashed during a credit drain first.
    fn readRaw(self: *Conn) !frame.Frame {
        if (self.pending_wire.items.len == 0) return frame.read(self.reader, &self.buf);
        var r: std.Io.Reader = .fixed(self.pending_wire.items);
        const f = try frame.read(&r, &self.buf);
        const used = 9 + f.payload.len;
        std.mem.copyForwards(u8, self.pending_wire.items[0 .. self.pending_wire.items.len - used], self.pending_wire.items[used..]);
        self.pending_wire.items.len -= used;
        return f;
    }

    /// Absorb connection-level traffic: SETTINGS is parsed and ACKed (it carries
    /// the windows and frame size this client sends under), PING is ACKed,
    /// WINDOW_UPDATE opens the outbound windows. Returns false for frames a
    /// stream has to act on. Centralised so no call site reimplements it, and a
    /// peer's credit can never be mistaken for silence.
    fn absorb(self: *Conn, f: frame.Frame) !bool {
        switch (f.typ) {
            .settings => {
                if (f.flags & frame.flags.ack == 0) {
                    try self.flow.onSettings(f.payload);
                    try frame.write(self.writer, .{ .typ = .settings, .flags = frame.flags.ack, .stream_id = 0, .payload = &.{} });
                    try self.writer.flush();
                }
            },
            .ping => {
                if (f.flags & frame.flags.ack == 0) {
                    try frame.write(self.writer, .{ .typ = .ping, .flags = frame.flags.ack, .stream_id = 0, .payload = f.payload });
                    try self.writer.flush();
                }
            },
            .window_update => {
                if (f.payload.len < 4) return error.FlowControlBadFrame;
                // The high bit is reserved and must be ignored (RFC 9113 §6.9).
                try self.flow.onWindowUpdate(f.stream_id, std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff);
            },
            .priority => {},
            else => return false,
        }
        return true;
    }

    /// The next frame a stream must act on, with connection-level traffic
    /// absorbed and anything stashed during a credit drain replayed first.
    fn readFrame(self: *Conn) !frame.Frame {
        while (true) {
            const f = try self.readRaw();
            if (!try self.absorb(f)) return f;
        }
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
        try appendBlock(&acc, self.allocator, first);
        var fl = flags;
        while (fl & frame.flags.end_headers == 0) {
            const c = try self.readRaw(); // may already sit in the credit-drain stash
            if (c.typ != .continuation or c.stream_id != sid) return error.HpackTruncated;
            try appendBlock(&acc, self.allocator, c.payload);
            fl = c.flags;
        }
        const dec = try self.decoder.decode(acc.items);
        defer self.allocator.free(dec);
        for (dec) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
    }

    /// Decode one response header block into `headers` and return its
    /// :status. An interim 1xx block (100, 103 Early Hints) is decoded -- the
    /// HPACK table must stay in sync -- and dropped, returning null: the final
    /// response is still coming (RFC 9113 §8.1).
    fn decodeInto(self: *Conn, headers: *std.ArrayList(hpack.Header), block: []const u8) !?u16 {
        const decoded = try self.decoder.decode(block);
        defer self.allocator.free(decoded);
        var status: u16 = 0;
        for (decoded) |h| {
            if (std.mem.eql(u8, h.name, ":status")) status = std.fmt.parseInt(u16, h.value, 10) catch 0;
        }
        const interim = status >= 100 and status < 200;
        var kept: usize = 0;
        errdefer for (decoded[kept..]) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        };
        for (decoded) |h| {
            if (interim) {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            } else try headers.append(self.allocator, h);
            kept += 1;
        }
        if (interim or status == 0) return null;
        return status;
    }

    pub fn startLines(self: *Conn, req: Request) !LineStream {
        if (!self.saw_preface) try self.preface();
        const sid = try self.allocStream();
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
        try self.sendBody(sid, req.body);
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
            const f = try self.readFrame();
            switch (f.typ) {
                .goaway => try self.onGoAway(f, sid),
                .rst_stream => if (f.stream_id == sid) {
                    if (errorCode(f) == err_no_error and status != 0) {
                        ended = true;
                        continue;
                    }
                    return rstError(f);
                },
                .headers => {
                    if (f.stream_id != sid) {
                        // Pushed / other-stream headers: decode to keep the
                        // HPACK table in sync, then ignore.
                        const payload = try stripFramePayload(f.typ, f.flags, f.payload);
                        try self.discardBlock(payload, f.flags, f.stream_id);
                        continue;
                    }
                    const payload = try stripFramePayload(f.typ, f.flags, f.payload);
                    const end_stream = f.flags & frame.flags.end_stream != 0;
                    if (f.flags & frame.flags.end_headers != 0) {
                        status = try self.decodeInto(&headers, payload) orelse status;
                    } else {
                        // Fragmented header block (RFC 7540 §4.3): HEADERS
                        // without END_HEADERS is followed by CONTINUATION
                        // frames. Accumulate and decode once, or the HPACK
                        // dynamic table desyncs (HpackIndex on reuse).
                        var hblock: std.ArrayList(u8) = .empty;
                        defer hblock.deinit(self.allocator);
                        try appendBlock(&hblock, self.allocator, payload);
                        var hflags: u8 = f.flags;
                        while (hflags & frame.flags.end_headers == 0) {
                            const c = try self.readFrame();
                            switch (c.typ) {
                                .continuation => {
                                    if (c.stream_id != sid) return error.HpackTruncated;
                                    try appendBlock(&hblock, self.allocator, c.payload);
                                    hflags = c.flags;
                                },
                                else => return error.HpackTruncated,
                            }
                        }
                        status = try self.decodeInto(&headers, hblock.items) orelse status;
                    }
                    if (end_stream) ended = true;
                },
                .continuation => return error.HpackTruncated,
                .push_promise => {
                    // Promised request headers are HPACK state too; decode
                    // and drop. Payload: 4-byte promised id + fragment.
                    const payload = try stripFramePayload(f.typ, f.flags, f.payload);
                    if (payload.len < 4) return error.HpackTruncated;
                    try self.discardBlock(payload[4..], f.flags, f.stream_id);
                },
                .data => {
                    try self.creditData(f.stream_id, f.payload.len);
                    if (f.stream_id != sid) continue;
                    const payload = try stripFramePayload(f.typ, f.flags, f.payload);
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
