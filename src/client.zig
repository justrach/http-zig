//! High-level h2c helper. TLS/ALPN is out of scope until Zig's TLS client
//! can offer the `h2` protocol.
const conn = @import("conn.zig");

pub const Request = conn.Request;
pub const Response = conn.Response;
pub const Conn = conn.Conn;
