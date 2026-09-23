//! Outbound HTTP/2 flow control (RFC 9113 §5.2, §6.9) and the peer's SETTINGS.
//!
//! DATA counts against BOTH the connection window and the stream window, and no
//! frame may exceed SETTINGS_MAX_FRAME_SIZE. The peer owns all three limits: it
//! opens windows with WINDOW_UPDATE and sets the initial stream window with
//! SETTINGS_INITIAL_WINDOW_SIZE. Senders that ignore them earn
//! FLOW_CONTROL_ERROR / FRAME_SIZE_ERROR and a dead connection -- which an
//! upstream HTTP/1.1 fallback then hides, so the bug never surfaces as a failure.
const std = @import("std");

pub const default_initial_window: u32 = 65535;
pub const default_max_frame: u32 = 16384;

pub const Flow = struct {
    conn_win: i64 = default_initial_window,
    stream_win: i64 = default_initial_window,
    stream_sid: u31 = 0,
    peer_initial: u32 = default_initial_window,
    max_frame: u32 = default_max_frame,

    /// Open `sid` for sending. Its window starts at the peer's
    /// SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.9.2) -- which is not
    /// necessarily 65535, so never assume the default.
    pub fn beginStream(self: *Flow, sid: u31) void {
        self.stream_sid = sid;
        self.stream_win = self.peer_initial;
    }

    /// Largest DATA payload that may go out now: bounded by MAX_FRAME_SIZE and
    /// by whichever window is smaller. Zero means "wait for a WINDOW_UPDATE".
    pub fn allowed(self: Flow) usize {
        const w = @min(self.conn_win, self.stream_win);
        if (w <= 0) return 0;
        return @min(@as(usize, @intCast(w)), self.max_frame);
    }

    /// Both windows shrink by the raw frame payload, padding included.
    pub fn consume(self: *Flow, n: usize) void {
        const d: i64 = @intCast(n);
        self.conn_win -= d;
        self.stream_win -= d;
    }

    /// WINDOW_UPDATE (RFC 9113 §6.9). A zero increment is a stream error of
    /// type PROTOCOL_ERROR, never a silent no-op: it means the peer is stuck.
    pub fn onWindowUpdate(self: *Flow, sid: u31, inc: u32) !void {
        if (inc == 0) return error.FlowControlZeroIncrement;
        const grow: i64 = @intCast(inc);
        // A window above 2^31-1 is a FLOW_CONTROL_ERROR (RFC 9113 §6.9.1).
        const max_win: i64 = 0x7fff_ffff;
        if (sid == 0) {
            if (self.conn_win + grow > max_win) return error.FlowControlOverflow;
            self.conn_win += grow;
        } else if (sid == self.stream_sid) {
            if (self.stream_win + grow > max_win) return error.FlowControlOverflow;
            self.stream_win += grow;
        }
    }

    /// SETTINGS payload (RFC 9113 §6.5.2): a sequence of id/value pairs.
    /// Unknown ids must be ignored; malformed ones are a connection error.
    pub fn onSettings(self: *Flow, payload: []const u8) !void {
        if (payload.len % 6 != 0) return error.SettingsBadLength;
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (id) {
                0x4 => { // SETTINGS_INITIAL_WINDOW_SIZE
                    if (val > 0x7fff_ffff) return error.SettingsWindowTooBig;
                    // The new value shifts every open stream by the DELTA; it
                    // does not reset the window (RFC 9113 §6.9.2).
                    const delta: i64 = @as(i64, val) - @as(i64, self.peer_initial);
                    self.peer_initial = val;
                    self.stream_win += delta;
                },
                0x5 => { // SETTINGS_MAX_FRAME_SIZE
                    if (val < default_max_frame or val > 0xffffff) return error.SettingsBadMaxFrame;
                    self.max_frame = val;
                },
                else => {},
            }
        }
    }
};

test "allowed is bounded by both windows and by MAX_FRAME_SIZE" {
    var f: Flow = .{};
    try std.testing.expectEqual(@as(usize, 16384), f.allowed()); // default window 65535 > 16384
    f.max_frame = 4096;
    try std.testing.expectEqual(@as(usize, 4096), f.allowed());
    f.max_frame = 16384;
    f.stream_win = 100;
    try std.testing.expectEqual(@as(usize, 100), f.allowed());
    f.conn_win = 30;
    try std.testing.expectEqual(@as(usize, 30), f.allowed());
    f.conn_win = -1;
    try std.testing.expectEqual(@as(usize, 0), f.allowed());
}

test "consume shrinks both windows" {
    var f: Flow = .{};
    f.consume(1000);
    try std.testing.expectEqual(@as(i64, 65535 - 1000), f.conn_win);
    try std.testing.expectEqual(@as(i64, 65535 - 1000), f.stream_win);
}

test "a body past the initial window stalls until WINDOW_UPDATE" {
    var f: Flow = .{};
    f.beginStream(1);
    f.consume(65535);
    try std.testing.expectEqual(@as(usize, 0), f.allowed());
    try f.onWindowUpdate(0, 40000);
    try f.onWindowUpdate(1, 40000);
    try std.testing.expectEqual(@as(usize, 16384), f.allowed());
}

test "zero WINDOW_UPDATE increment is a protocol error" {
    var f: Flow = .{};
    try std.testing.expectError(error.FlowControlZeroIncrement, f.onWindowUpdate(0, 0));
    try std.testing.expectError(error.FlowControlZeroIncrement, f.onWindowUpdate(1, 0));
}

test "WINDOW_UPDATE for another stream leaves ours alone" {
    var f: Flow = .{};
    f.beginStream(1);
    try f.onWindowUpdate(3, 5000);
    try std.testing.expectEqual(@as(i64, 65535), f.stream_win);
    try f.onWindowUpdate(1, 5000);
    try std.testing.expectEqual(@as(i64, 65535 + 5000), f.stream_win);
}

test "INITIAL_WINDOW_SIZE shifts the open stream by the delta" {
    var f: Flow = .{};
    f.beginStream(1);
    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 0x4, .big);
    std.mem.writeInt(u32, payload[2..6], 1000, .big);
    try f.onSettings(&payload);
    try std.testing.expectEqual(@as(u32, 1000), f.peer_initial);
    // 1000 - 65535 delta applied to the already-open stream.
    try std.testing.expectEqual(@as(i64, 1000), f.stream_win);
    try std.testing.expectEqual(@as(usize, 1000), f.allowed());
}

test "MAX_FRAME_SIZE bounds the frame and rejects impossible values" {
    var f: Flow = .{};
    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 0x5, .big);
    std.mem.writeInt(u32, payload[2..6], 32768, .big);
    try f.onSettings(&payload);
    f.stream_win = 65535;
    f.conn_win = 65535;
    try std.testing.expectEqual(@as(usize, 32768), f.allowed());

    std.mem.writeInt(u32, payload[2..6], 100, .big);
    try std.testing.expectError(error.SettingsBadMaxFrame, f.onSettings(&payload));
    std.mem.writeInt(u32, payload[2..6], 0x100_0000, .big);
    try std.testing.expectError(error.SettingsBadMaxFrame, f.onSettings(&payload));
}

test "SETTINGS ignores unknown ids and rejects a ragged payload" {
    var f: Flow = .{};
    var payload: [12]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 0x3, .big); // MAX_CONCURRENT_STREAMS
    std.mem.writeInt(u32, payload[2..6], 7, .big);
    std.mem.writeInt(u16, payload[6..8], 0x2, .big); // ENABLE_PUSH
    std.mem.writeInt(u32, payload[8..12], 0, .big);
    try f.onSettings(&payload);
    try std.testing.expectEqual(@as(u32, 65535), f.peer_initial);
    try std.testing.expectError(error.SettingsBadLength, f.onSettings(payload[0..5]));
    try std.testing.expectError(error.SettingsWindowTooBig, blk: {
        std.mem.writeInt(u16, payload[0..2], 0x4, .big);
        std.mem.writeInt(u32, payload[2..6], 0x8000_0000, .big);
        break :blk f.onSettings(payload[0..6]);
    });
}
