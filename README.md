# http-zig

HTTP/2 **client** for Zig 0.17: frames (RFC 7540), HPACK (RFC 7541), prior-knowledge h2c.

Not a web framework. Layout follows the usual split — `frame` / `hpack` / `conn` / `client` — implemented from the RFCs, not vendored from another library.

```zig
const http_zig = @import("http_zig");

// Talk HTTP/2 over any Reader/Writer (cleartext prior knowledge).
var c = http_zig.Conn.init(allocator, reader, writer);
try c.preface();
const res = try c.request(.{
    .method = "GET",
    .scheme = "http",
    .authority = "127.0.0.1",
    .path = "/",
    .body = &.{},
});
```

## What this is

| Piece | Status |
|---|---|
| Client preface, SETTINGS, PING, GOAWAY, RST_STREAM | yes |
| HEADERS + DATA, stream 1+ odd ids | yes |
| HPACK static + dynamic table, Huffman decode | yes |
| Multiplex many streams on one connection | yes (sequential request helper; raw conn is multiplex-capable) |
| HTTP/1.1 fallback | `std.http.Client` — you already have it; this crate does not wrap it |
| HTTPS / ALPN `h2` | **not yet** — Zig `std.crypto.tls.Client` has no ALPN option |

TLS without ALPN is not HTTP/2 over HTTPS. Servers that require `h2` in the handshake will not speak this preface on a 1.1 TLS session. Cleartext h2c (or a future ALPN handshake) is the path.

## Install

```bash
zig fetch --save git+https://github.com/justrach/http-zig
```

```zig
const http_zig = b.dependency("http_zig", .{ .target = target, .optimize = optimize });
mod.addImport("http_zig", http_zig.module("http_zig"));
```

## License

MIT
