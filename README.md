# http-zig

HTTP/2 **client** for Zig 0.17: frames (RFC 7540), HPACK (RFC 7541), HTTPS ALPN `h2`, connection reuse, HTTP/1.1 fallback.

```bash
zig build
./zig-out/bin/http-zig-get
# GET #1 stream~1 status 200 body 6324
# GET #2 status 200  (same Session; redials if the peer closed)
```

```zig
const s = try http_zig.Session.open(gpa, io, "nghttp2.org", 443);
defer s.close();
var res = try s.request(.{ .method = "GET", .scheme = "https", .authority = "nghttp2.org", .path = "/" });
```

| Piece | Status |
|---|---|
| Sequential streams on one connection | yes (odd ids) |
| Peer close / GOAWAY | redial h2, then HTTP/1.1 |
| First TLS/ALPN failure | latch `std.http.Client` |
| SSE line stream | `Session.startLines` |
| HTTPS ALPN `h2` | `src/tls_client.zig` (Zig std TLS + ALPN) |

`GRAFF_HTTP2=0` in graff opts out. This crate always prefers h2.

## License

MIT. `src/tls_client.zig` is derived from Zig's standard library TLS client (MIT, Zig contributors).
