//! http-zig: HTTP/2 client primitives for Zig 0.17.
pub const frame = @import("frame.zig");
pub const hpack = @import("hpack.zig");
pub const huffman = @import("huffman.zig");
pub const conn = @import("conn.zig");
pub const client = @import("client.zig");
pub const alpn = @import("alpn.zig");
pub const https = @import("https.zig");
pub const session = @import("session.zig");

pub const Conn = conn.Conn;
pub const Session = session.Session;
pub const Request = conn.Request;
pub const Response = conn.Response;
pub const LineStream = session.LineStream;
pub const Header = hpack.Header;
pub const preface = frame.preface;

test {
    _ = frame;
    _ = hpack;
    _ = huffman;
    _ = conn;
    _ = client;
    _ = alpn;
    _ = https;
    _ = session;
    _ = @import("flow.zig");
    _ = @import("conn_tests.zig");
    // tls_client is reached only through session, which pulls its decls but
    // not its tests: reference it here or those 3 tests compile to nothing.
    _ = @import("tls_client.zig");
}
