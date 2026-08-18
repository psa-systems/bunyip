# API performance measurements (BUNYIP-559)

Two questions the code could not answer were settled by measurement: whether the
10-connection database pool is bunyip-api's throughput ceiling (F10), and
whether compressing `/v1` responses is worth the layer (F12). This file is the
evidence behind both decisions. Re-run it before changing either.

## Bench environment

Everything below was measured on one host, against one bunyip-api process.

| | |
| --- | --- |
| bunyip-api | `v0.14.1`, `cargo build --release`, `ENVIRONMENT=development` |
| Host | 32 logical CPUs, so actix started **32 worker arbiters** (`main.rs` sets no `.workers(...)`) |
| Database | `postgres:18.2-alpine3.23` in Docker on the same host, stock `max_connections = 100` |
| Pools | primary + the RLS `bunyip_app` pool, `max_connections = 10` each, `acquire_timeout = 5s` |
| Data | 251 users, 502 audit-log rows, 50 active hosted applications |
| Sampling | `DB_POOL_METRICS_INTERVAL_SECS=5` |
| Driver | in-process HTTP client, one connection per session, one HS256 token per user, browse loop `GET /v1/users/me` -> `/v1/applications` -> `/v1/application-groups` -> `/v1/users/me/sessions` |

Sessions use distinct users because the `RateLimitFloor` caps one authenticated
subject at `API_AUTH` = 100 requests / 60 s. The "think" column is the target
duration of one four-request browse cycle, which is what keeps a session inside
that cap; run D deliberately removes it.

## F10: the pool is not the ceiling

### The load runs

| Run | Sessions | Think | req/s | 200 | 429 | p50 | p95 | p99 | max | Pool at sample | Acquire timeouts | `/v1/health` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| A | 20 | 3.0 s | 26.9 | 1,608 | 8 | 1.4 ms | 3.7 ms | 5.6 ms | 9.6 ms | `size=10 idle=10` (12/12) | 0 | <= 1 ms |
| B | 50 | 3.0 s | 69.7 | 4,185 | 0 | 1.2 ms | 6.3 ms | 12.2 ms | 20.8 ms | `size=10 idle=10` (13/13) | 0 | <= 1 ms |
| C | 250 | 2.5 s | 406.4 | 24,419 | 0 | 1.4 ms | 15.8 ms | 34.9 ms | 83.6 ms | `size=10 idle=10` (12/12) | 0 | <= 1 ms |
| D | 250 | none | 6,528.1 | 31,583 | 254,227 | 28.5 ms | 76.9 ms | 87.6 ms | 181.5 ms | `size=10 idle=0` (8/9) | 0 | <= 1 ms |

Runs A and B bracket the 20-to-50 concurrent sessions the issue asked for. Run C
pushes to 250 sessions, 406 req/s of real 200s. Run D removes the think time
entirely: 6,528 req/s, of which the floor rejects 254,227 with a 429 (each 429
still costs two database round trips, so the pool is doing roughly 13,000
operations per second).

Reading the pool column: A, B and C never caught a connection checked out, in 37
consecutive samples. The pool does grow to its full 10 (`size=10`), it is just
never busy at the instant of sampling, because an acquisition lasts one
sub-millisecond query. Only run D held it saturated, `idle=0 in_use=10` in 8 of
9 samples, and even then **no acquisition timed out**: the queue drained well
inside the 5 s `acquire_timeout`. `/v1/health` answered in under a millisecond
throughout every run, including run D, so the arbiters were never stalled
either.

### The decision

`max_connections` stays at **10**, now as the named constant
`DB_POOL_MAX_CONNECTIONS` in `bunyip-api/src/main.rs` with the reasoning
attached. Three things follow from the runs above:

- 32 arbiters multiplexing onto 10 connections is not a bottleneck, because a
  connection is held for the duration of one query, not for the duration of one
  request. Throughput is bounded by the query rate.
- The rate-limit floor binds long before the pool does. A single authenticated
  subject cannot exceed 100 requests/minute, so reaching run D's rate takes
  thousands of distinct users; at that point the pool saturates but still does
  not time out.
- Raising it is not free. Each api process opens **two** pools, so one replica
  costs `2 x DB_POOL_MAX_CONNECTIONS` of PostgreSQL's own `max_connections`
  (100 by default, less `superuser_reserved_connections`). Guessing upward
  trades a bottleneck nobody has hit for a hard server-side limit shared with
  every other replica.

Raise it when `acquire_timeouts` in the pool samples is non-zero, and raise
PostgreSQL's `max_connections` in the same change.

### Reproducing it

Enable sampling and read the `INFO` lines. One per pool per interval:

```nu
$env.DB_POOL_METRICS_INTERVAL_SECS = "5"
```

```
INFO bunyip_api::db_metrics: database pool sample pool="primary" size=10 idle=0 in_use=10 acquire_timeouts=0
INFO bunyip_api::db_metrics: database pool sample pool="rls" size=1 idle=1 in_use=0 acquire_timeouts=0
```

`acquire_timeouts` is a process-wide count of acquisitions that waited out
`acquire_timeout` and returned a 500 instead of a connection. It is collected
whether or not sampling is on, so it is never missing after the fact. To see it
move, take the database away from a running api and issue any authenticated
request:

```nu
docker stop dev-bunyip-postgres-($env.USER)
http get http://127.0.0.1:4401/v1/users/me    # 500 after ~5 s
```

Each such request logs `Database error error=pool timed out while waiting for an
open connection` and the next sample line shows the counter risen (in the
recorded run, five requests raised it by 10: the floor's counter upsert and the
handler's user read each timed out).

## F12: `/v1` responses are worth compressing

### The three payloads, raw and gzipped

Measured with `curl`, once without `Accept-Encoding` and once with
`Accept-Encoding: gzip`, against the api with
`actix_web::middleware::Compress` wired in. "gzip (wire)" is what actually
crossed the socket.

| Payload | Rows | Raw | gzip (wire) | Saved | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| `GET /v1/admin/users?per_page=100` | 100 of 251 | 56,974 B | 6,715 B | 50,259 B | 8.5 : 1 |
| `GET /v1/admin/audit-logs` (default page) | 50 of 502 | 31,974 B | 5,279 B | 26,695 B | 6.1 : 1 |
| `GET /v1/applications` (50-app catalog) | 50 | 24,730 B | 2,889 B | 21,841 B | 8.6 : 1 |

Two further points on the catalog endpoint, because its size depends entirely on
how many applications exist: the six-row seed catalog that ships today answers
967 B raw / 504 B gzipped, so an application entry costs roughly 490 B raw and
50 B gzipped. The 50-row figure above is the large-catalog case the issue asked
about, produced by seeding 48 extra hosted applications.

`GET /v1/admin/audit-logs?per_page=100` was also measured: 64,190 B -> 9,183 B.

### The decision

All three clear the 10 KB threshold the issue set, the two admin lists by 5x,
so compression is wired in:

- `bunyip-api/src/main.rs` wraps `actix_web::middleware::Compress::default()`
  on the primary `HttpServer` stack (innermost, so it sees the final body). The
  OCI registry runs on its own `HttpServer` and is untouched.
- `bunyip-web`'s `reqwest` dependency gains the `gzip` feature. Without it the
  BFF never sends `Accept-Encoding`, so the second hop would have stayed
  uncompressed no matter what the api offered.

### Streamed responses are exempt

actix's `Compress` has no predicate API. Unlike `tower-http` it does **not**
exempt `text/event-stream`, and it runs a streamed body through a deflate
encoder that holds bytes back until it has enough to emit. Every streamed
response on the primary stack therefore calls
`bunyip_api::compress::mark_uncompressed`, which sets `Content-Encoding:
identity`; `Encoder::response` skips any response that already carries a
`Content-Encoding`.

| Streamed response | Stack | Disposition |
| --- | --- | --- |
| `GET /v1/events` (SSE) | primary (compressed) | exempt: compression would defeat incremental delivery |
| `GET /v1/applications/{slug}/downloads/...` | primary (compressed) | exempt: encoding drops the `Content-Length` the handler sets, and release assets are already-compressed archives |
| `GET /v2/<name>/blobs/<digest>` (OCI) | separate `oci` `HttpServer` | not applicable: that server carries no `Compress` |

`every_streamed_primary_response_is_compress_exempt` in
`bunyip-api/src/compress.rs` scans for `.streaming(` sites and fails the build
if a new one appears without the marker, or if the OCI vertical is ever mounted
on the primary router.

Verified against the running api, with the gzip request header set:

```
$ curl --no-buffer --header 'Accept-Encoding: gzip' <api>/v1/events
content-type: text/event-stream
content-encoding: identity

t=  0.0s  ': keepalive\n\n'
t= 25.0s  ': keepalive\n\n'
t= 50.0s  ': keepalive\n\n'
```

Frames arrive at the 25 s keepalive cadence rather than in one block at the end,
which is what a buffered encoder would have produced.
