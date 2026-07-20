# Client-IP forwarding across the BFF (BUNYIP-311)

How the end-user's browser IP reaches bunyip-api for logging, rate-limiting,
and audit, and the trusted-proxy config each service needs so the chain works
without trusting spoofable headers.

## The two-hop trust chain

```
browser ── X-Forwarded-For ──▶ Traefik ── X-Forwarded-For ──▶ bunyip-web ── X-Forwarded-For ──▶ bunyip-api
                                (edge)                          (SSR BFF)                          (/v1 API)
```

bunyip-web is a server-rendered BFF: the browser talks only to it (through
Traefik), and it calls bunyip-api server-to-server over the internal network.
Without forwarding, bunyip-api's socket peer on those calls is the bunyip-web
process, so the end-user's IP is lost.

Each hop honours a forwarded IP ONLY from the hop immediately in front of it,
which it identifies by socket peer against its own `TRUSTED_PROXY_CIDR`. Any
other peer is untrusted and its forwarding headers are ignored, so a client
cannot spoof its IP.

1. Traefik terminates TLS and sets `X-Forwarded-For` to the browser IP.
2. bunyip-web (`client_ip::forward_client_ip`, `bunyip-web/src/client_ip.rs`)
   resolves the end-user IP from the inbound `X-Forwarded-For` / `X-Real-IP`
   ONLY when its socket peer (Traefik) is inside bunyip-web's
   `TRUSTED_PROXY_CIDR`. It then sets that single IP as `X-Forwarded-For` on
   every outbound `/v1` call (JSON, streaming, and multipart send paths). When
   the peer is untrusted (or no CIDR is configured, the dev default) it
   forwards nothing.
3. bunyip-api (`extract_client_ip`, `crates/bunyip-domain/src/middleware/auth.rs`)
   reads that `X-Forwarded-For` as the external client ONLY when its socket
   peer (bunyip-web) is inside bunyip-api's `TRUSTED_PROXY_CIDR`.

## Required CIDR entries per service

| Service    | Env var                 | Must contain                                                                 |
|------------|-------------------------|------------------------------------------------------------------------------|
| bunyip-web | `WEB_TRUSTED_PROXY_CIDR`| the edge proxy (Traefik) address                                             |
| bunyip-api | `TRUSTED_PROXY_CIDR`    | bunyip-web's internal address AND the edge proxy address (for direct-to-API paths: SSE, OIDC, external RPs) |

In `compose.yml` both map to the in-container `TRUSTED_PROXY_CIDR`; the `web`
service reads the host-level `WEB_TRUSTED_PROXY_CIDR` and the `api` service the
host-level `TRUSTED_PROXY_CIDR` so the two hops can be set independently. Both
are comma-separated CIDR lists parsed identically on each side; invalid entries
are logged and skipped, and an empty list trusts no forwarding headers.

If bunyip-web's address is omitted from bunyip-api's `TRUSTED_PROXY_CIDR`,
bunyip-api ignores the forwarded IP and SSR-proxied `/v1` requests are
attributed to bunyip-web (the pre-BUNYIP-311 behaviour), which is the safe
default rather than trusting an unverified header.

## Why forward nothing when untrusted

bunyip-web resolves and forwards an IP ONLY when its peer is a trusted proxy; a
direct (untrusted) peer forging `X-Forwarded-For` is not honoured and nothing
is forwarded, so bunyip-api never records a fabricated address. This mirrors
bunyip-api's own spoofing defence (BUNYIP-328).

## Access logs and tracing spans (BUNYIP-310)

The same `TRUSTED_PROXY_CIDR`-governed resolution feeds bunyip-api's request
observability, so a single trust decision drives every place a client IP is
recorded:

- The access-log line's leading IP (`bunyip-api/src/access_log.rs`) is
  `extract_client_ip`, not the actix `%a` socket peer. The rest of the line
  (method, path, HTTP version, status, size, referer, user-agent, elapsed) is
  unchanged, so existing log parsing is unaffected.
- The tracing root span's `http.client_ip`
  (`bunyip-api/src/root_span.rs`, `ClientIpRootSpanBuilder`) is
  `extract_client_ip` rather than actix `realip_remote_addr()`, which would
  otherwise trust `X-Forwarded-For` from any peer.

Both honour a forwarded header ONLY when the socket peer is inside
`TRUSTED_PROXY_CIDR`; with the CIDR unset (the dev default) both record the
socket peer, identical to the pre-BUNYIP-310 behaviour, so no config change is
needed to deploy. For access lines and spans to carry the external client IP,
`TRUSTED_PROXY_CIDR` must include the reverse-proxy address range that fronts
the direct-to-API paths (SSE `/v1/events`, `/oauth2/*`, `/.well-known/*`), the
same range the SSR chain above already requires.
