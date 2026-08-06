# bunyip-web conversion roadmap

This crate is the **Axum SSR** frontend for PSA Systems (Bunyip) - server-rendered HTML
(Maud templates + htmx) backed by the **separate `/v1` API service**. It replaced
an earlier Dioxus/WASM port: the user only needed a web interface and "normal
Rust libraries", so the reactive/WASM layer is gone. The Tailwind v4 theme, the
page designs, and the API data types carried over.

**Architecture:** the browser talks only to this server. It is a **BFF** -
server-side `reqwest` calls hit `<api-origin>/v1/*`, forwarding the apex-scoped
session cookie (`Domain=<apex>`) verbatim, and relaying `Set-Cookie` from auth
endpoints back to the browser. A 401 triggers one `/auth/refresh` + retry with
the merged cookie (see `src/auth.rs`). No CORS (server-to-server), no
`SameSite=None` (subdomains are same-site). Theme/dark-mode is a tiny inline
script; everything else is server-rendered.

**Status: complete and building** (`cargo build` green; verified serving - public
pages 200, protected routes 303 -> /login, 404 works). Remaining items are the
deliberately condensed sub-features in section 6.

Legend: `[x]` done · `[~]` done but condensed (see notes) · `[ ]` not started.

---

## 1. Foundation

- [x] Native Axum crate (`Cargo.toml`): axum, tokio, tower-http (static + gzip), maud, reqwest (rustls), qrcode, tracing
- [x] `src/config.rs` - env config (`BUNYIP_BIND_ADDR`, `BUNYIP_API_URL`, `BUNYIP_APP_DOMAIN`)
- [x] `src/api/` - BFF client (`mod.rs` cookie-forward + Set-Cookie capture + envelope), `auth.rs`, `calls.rs`, `admin.rs`, `types.rs`
- [x] `src/auth.rs` - `authenticate()` (me -> refresh-on-401 -> me, cookie merge + relay), cookie helpers
- [x] `src/web.rs` - `AppState`, response builders (`html`, `redirect`, `*_cookies`, `hx_redirect`)
- [x] `src/views/` - `layout.rs` (document + public/dashboard/admin shells, theme JS, htmx, fonts), `ui.rs` (icons, button classes, badge), `common.rs` (auth card)
- [x] `src/handlers/mod.rs` - guards (`guard`, `admin_guard`: signed-out -> login, admin-without-2FA -> setup, non-admin -> dashboard), response helpers
- [x] Static serving of `/assets` (Tailwind `styles.css`), gzip, 404 fallback, `main.rs` router

## 2. Public + auth pages (`handlers/public.rs`, `content.rs`, `auth_pages.rs`)

- [x] Landing, Pricing, Our Story, Terms, Privacy, Feedback (GET + POST submit)
- [x] Login (+ Set-Cookie relay), Logout, Register, Magic link (request + verify), Password reset (+ confirm)
- [x] 2FA verify (challenge stashed in a short `bunyip_2fa` cookie between login and verify)
- [x] Accept invite (needs-password branch), First-run setup, Confirm email / Verify email (token links)

## 3. Dashboard pages + guards (`handlers/dashboard.rs`)

- [x] Dashboard, Applications, Downloads, Billing, Checkout success, Membership-required
- [x] Membership (view + subscribe/cancel/cancel-now/reactivate actions, cookie relay)
- [x] Settings (account info, change email, change password, 2FA manage, delete account; banner via `?ok=`/`?error=`)
- [x] 2FA setup (QR via the `qrcode` crate -> inline SVG, verify -> recovery codes)
- [x] Guards: signed-out bounce, admin-2FA enforcement

## 4. Admin pages (`handlers/admin.rs`)

- [x] Dashboard (stats + recent activity), Audit logs (query-param pagination + admin-only filter)
- [x] Users (search, pagination, role toggle, delete), Memberships (list)
- [x] Feedback (status transitions), Tier settings (read + save)
- [x] Applications (active/maintenance toggles), Stripe (key + webhook + app-tag config)

## 5. Tooling / delivery

- [x] Dev `Dockerfile` (cargo-watch + Tailwind watcher)
- [x] Prod `oci-build/Dockerfile` (multi-stage -> a running server image; no Caddy/static-files)
- [x] `.env.example`

## 6. Outstanding (deliberately condensed)

| Area | Where | Condensed part |
|------|-------|----------------|
| htmx | all pages | Loaded for progressive enhancement, but interactions are form-POST + full reload + query-param pagination. Swapping in `hx-*` fragment endpoints (live toggles/pagination without reload) is straightforward follow-up. |
| Register | `auth_pages.rs` | Stripe Elements `$0` card-auth step (no-card registration path works) |
| Feedback | `content.rs` | File attachments (text fields + tags + honeypot work) |
| Downloads | `dashboard.rs` | Native `<a download>` (no 429/502 rate-limit messaging) |
| Settings | `dashboard.rs` | Regenerate-recovery-codes + resend-verification |
| Admin Stripe | `admin.rs` | Product / price / webhook managers |
| Admin Apps | `admin.rs` | Create + delete-with-2FA + reorder (toggles work) |
| Admin Memberships | `admin.rs` | Grant / revoke (list works) |
| Admin Dashboard | `admin.rs` | System-health widget (`/admin/health`) |
| Landing | `public.rs` | Scroll-reveal classes forced visible (no IntersectionObserver) |
| Tests | - | Not ported (decide on `axum-test` / handler unit tests) |

---

## Verify

```bash
bun run build:css                 # generate assets/styles.css
cargo build                       # or: cargo build --release
BUNYIP_API_URL=http://localhost:4401 BUNYIP_APP_DOMAIN=localhost cargo run
```
