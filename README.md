# http-zig

HTTP/2 **client** for Zig 0.17: frames (RFC 7540), HPACK (RFC 7541), HTTPS with ALPN `h2`.

Not a web framework. Layout is `frame` / `hpack` / `conn` / `https`.

```bash
zig build
./zig-out/bin/http-zig-get
# GET https://nghttp2.org/ (HTTP/2)
# status 200  body 6324 bytes
```

```zig
const http_zig = @import("http_zig");

var res = try http_zig.https.get(gpa, io, "https://nghttp2.org/");
defer res.deinit();
```

## What this is

| Piece | Status |
|---|---|
| Client preface, SETTINGS, PING, GOAWAY, RST_STREAM | yes |
| HEADERS + DATA | yes |
| HPACK static + dynamic table, Huffman decode | yes |
| HTTPS + ALPN `h2` | yes (`src/tls_client.zig`, Zig std TLS + ALPN) |
| HTTP/1.1 fallback | not in this crate (`std.http.Client` already does 1.1) |
| Connection pool / many streams at once | sequential `request` helper today |

Zig `std.crypto.tls.Client` does not offer ALPN. HTTP/2 over TLS requires `h2` in the ClientHello **and** in the handshake transcript, so this crate vendors std's TLS client with that extension added (MIT, Zig contributors).

## Install

```bash
zig fetch --save git+https://github.com/justrach/http-zig
```

```zig
const http_zig = b.dependency("http_zig", .{ .target = target, .optimize = optimize });
mod.addImport("http_zig", http_zig.module("http_zig"));
```

## License

MIT. `src/tls_client.zig` is derived from Zig's standard library TLS client (MIT, Zig contributors).
