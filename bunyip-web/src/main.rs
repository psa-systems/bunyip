mod api;
mod auth;
mod branding;
mod client_ip;
mod config;
mod csrf;
mod feature_flags;
mod handlers;
mod routes;
mod security;
mod server_status;
mod skin;
mod ttl_cache;
mod util;
mod views;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::header::{HeaderValue, CACHE_CONTROL};
use axum::routing::get;
use axum::Router;
use tower::ServiceBuilder;
use tower_http::compression::predicate::{DefaultPredicate, NotForContentType};
use tower_http::compression::{CompressionLayer, Predicate};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

/// BUNYIP-554 F9: `/assets/*` is immutable for a year. Every reference in the
/// markup carries a build-derived `?v=` (`views::layout::asset`), so a deploy
/// gets fresh URLs and a repeat navigation issues zero asset requests. Without
/// `Cache-Control` the file service sends only `Last-Modified`, and in a
/// container built from a fresh checkout those mtimes are as young as the
/// deploy, so heuristic freshness starts near zero and every reference was
/// revalidated on the next navigation.
const ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// BUNYIP-554 F4: `DefaultPredicate` compresses everything except gRPC,
/// `image/*`, `text/event-stream` and bodies under 32 bytes, so the BFF ran
/// gzip over every byte of an already-compressed multi-megabyte installer
/// relayed by `handlers::dashboard::download_asset` for a ratio near 1.0 - and
/// engaging the encoder drops the forwarded `Content-Length`, which is what
/// killed the browser's download progress bar. Content type is the property
/// that actually decides whether compression helps, so exempt the types the
/// release pipeline emits rather than splitting the router by route.
fn compression_predicate() -> impl Predicate {
    DefaultPredicate::new()
        .and(NotForContentType::const_new("application/octet-stream"))
        .and(NotForContentType::const_new("application/gzip"))
        .and(NotForContentType::const_new("application/zip"))
        .and(NotForContentType::const_new("application/x-tar"))
        .and(NotForContentType::const_new("application/x-xz"))
        // The vendored webfonts BUNYIP-554 self-hosted are already compressed;
        // `DefaultPredicate` exempts `image/*` but has no equivalent for fonts.
        .and(NotForContentType::const_new("font/"))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Arc::new(config::Config::from_env());
    let api = api::Api::new(&cfg.api_url);
    let bind_addr = cfg.bind_addr.clone();
    // BUNYIP-145: pin the browser-facing bunyip-api origin into the layout
    // module so every authenticated shell can emit an SSE subscriber that
    // connects to `<api_url>/v1/events` without threading the config through
    // 45 handler call sites.
    //
    // BUNYIP-192: use the PUBLIC origin (not the internal `api_url` used by
    // the BFF for outbound server-to-server HTTP). On dev they're the
    // same loopback origin so nothing changes; on prod / dev-sso the
    // internal `api_url` is the docker hostname `bunyip-api-app:4401`
    // which the browser cannot resolve AND is HTTP from an HTTPS page,
    // so the EventSource was Mixed-Content-blocked. `api_public_origin`
    // defaults to `api_url` to preserve dev behaviour and overrides via
    // `BUNYIP_API_PUBLIC_ORIGIN` in production.
    // BUNYIP-589: web-kit's asset() helper reads the consumer's build version
    // through an installed cell (web-kit has no build script of its own).
    views::layout::install_asset_version(env!("ASSET_VERSION"));
    views::layout::install_sse_api_origin(cfg.api_public_origin.clone());
    // BUNYIP-329: gate the Community nav entry on whether a Let's Chat instance
    // is configured (BUNYIP_COMMUNITY_URL).
    views::layout::install_community_enabled(cfg.community_enabled());
    // BUNYIP-568: nothing to install for the palette. The theme CSS and the two
    // browser-chrome colours come from the branding record fetched below, and
    // an empty field omits its markup.
    // The share image an unbranded deployment falls back to. The branding
    // record still wins when an admin has uploaded one.
    views::layout::install_default_share_image(cfg.default_share_image());
    // BUNYIP-561: the product name, tagline, meta description and Open Graph
    // image are the admin-managed branding record, not environment variables.
    // One blocking fetch before the listener binds, so the first render already
    // carries the brand; a failure logs and serves unbranded while the refresh
    // task below keeps retrying. Nothing substitutes a compiled-in literal.
    branding::load_at_startup(&api).await;
    branding::spawn_refresh(api.clone());
    // BUNYIP-493: the organizations and teams switch, read from bunyip-api's
    // feature-flags probe and installed into the cell the nav and the flagged
    // routes read. Same shape as the branding load above: one bounded read
    // before the listener binds, then an interval refresh. An unreadable flag
    // leaves the feature dark rather than guessing it on.
    feature_flags::load_at_startup(&api).await;
    feature_flags::spawn_refresh(api.clone());
    // BUNYIP-243: while bunyip-api is unreachable, poll its /health on an
    // interval and clear the app-wide "service unavailable" banner on recovery.
    // Idle (no network) while healthy; detection itself is reactive in
    // `Api::send`. Uses the internal `api_url` (the BFF's server-to-server
    // origin), not the public SSE origin.
    server_status::spawn_recovery_poll(cfg.api_url.clone());
    let state = web::AppState {
        api,
        cfg: Arc::clone(&cfg),
        // BUNYIP-518: coalesce the per-render /v1/pricing fetch behind a short TTL.
        pricing_cache: Arc::new(ttl_cache::TtlCache::new(
            "/v1/pricing",
            "PricingResponse",
            "the /pricing page and its nav and footer links",
            std::time::Duration::from_secs(ttl_cache::PRICING_CACHE_TTL_SECS),
        )),
        // BUNYIP-555: the same treatment for the other two near-static payloads
        // the chrome reads on every render.
        applications_cache: Arc::new(ttl_cache::TtlCache::new(
            "/v1/applications",
            "Vec<Application>",
            "the public footer's application links",
            std::time::Duration::from_secs(ttl_cache::APPLICATIONS_CACHE_TTL_SECS),
        )),
        setup_status_cache: Arc::new(ttl_cache::TtlCache::new(
            "/v1/auth/setup/status",
            "SetupStatus",
            "the subscribe CTA and the onboarding email gate",
            std::time::Duration::from_secs(ttl_cache::SETUP_STATUS_CACHE_TTL_SECS),
        )),
        // BUNYIP-635: the /docs section menu's application half.
        documented_apps_cache: Arc::new(ttl_cache::TtlCache::new(
            "/v1/application-docs",
            "Vec<DocumentedApp>",
            "the /docs hub's application documentation section",
            std::time::Duration::from_secs(ttl_cache::DOCUMENTED_APPS_CACHE_TTL_SECS),
        )),
    };

    use handlers::{auth_pages as ap, consent, dashboard as dash, health, onboarding};
    // BUNYIP-501: the marketing / legal / docs / landing pages live in the skin.
    use skin::{content, public};

    let app = Router::new()
        // Liveness for the e2e reachability gate + monitoring (BUNYIP-149).
        // Unauthenticated, no DB.
        .route("/healthz", get(health::healthz))
        // Public / marketing
        .route("/", get(public::landing))
        .route("/pricing", get(content::pricing))
        .route("/our-story", get(content::our_story))
        .route("/roadmap", get(content::roadmap))
        .route("/terms", get(content::terms))
        .route("/privacy", get(content::privacy))
        // BUNYIP-385: public docs under /docs (docs subdomain), a temporary home
        // until the dedicated docs app matures.
        .route("/docs", get(content::docs_index))
        .route("/docs/:slug", get(content::docs_page))
        // BUNYIP-388: public per-application documentation.
        .route("/apps/:slug/docs", get(content::app_docs_index))
        .route("/apps/:slug/docs/:doc_slug", get(content::app_docs_page))
        .route(
            "/feedback",
            get(content::feedback_get)
                .post(content::feedback_post)
                .layer(
                    // Raise the default axum 2 MB body limit for this route only
                    // so file attachments fit. The cap matches the API's per-form
                    // ceiling (3 files × 5 MB + form overhead). Other routes stay
                    // on the default.
                    axum::extract::DefaultBodyLimit::max(content::FEEDBACK_BODY_LIMIT_BYTES),
                ),
        )
        // Auth
        .route("/login", get(ap::login_get).post(ap::login_post))
        .route(
            "/login/2fa",
            get(ap::twofa_verify_get).post(ap::twofa_verify_post),
        )
        .route("/logout", get(ap::logout))
        .route("/register", get(ap::register_get).post(ap::register_post))
        .route(
            "/magic-link",
            get(ap::magic_link_get).post(ap::magic_link_post),
        )
        .route(
            "/password-reset",
            get(ap::password_reset_get).post(ap::password_reset_post),
        )
        .route(
            "/password-reset/confirm",
            get(ap::password_reset_confirm_get).post(ap::password_reset_confirm_post),
        )
        .route(
            "/invite/accept",
            get(ap::invite_accept_get).post(ap::invite_accept_post),
        )
        .route("/settings/confirm-email", get(ap::confirm_email))
        .route("/settings/verify-email", get(ap::verify_email))
        // BUNYIP-206: forced post-registration onboarding (name + verified email).
        .route(
            "/onboarding",
            get(onboarding::onboarding_get).post(onboarding::onboarding_post),
        )
        // Dashboard
        .route("/dashboard", get(dash::dashboard))
        .route("/applications", get(dash::applications))
        .route("/downloads", get(dash::downloads))
        .route("/downloads/:slug/:asset", get(dash::download_asset))
        .route("/billing", get(dash::billing))
        .route("/checkout/success", get(dash::checkout_success))
        .route("/membership-required", get(dash::membership_required))
        .route("/membership", get(dash::membership))
        .route("/community", get(dash::community))
        // BUNYIP-493: registered unconditionally and gated inside the handler,
        // so flipping the switch needs no router rebuild. While the flag is off
        // it answers the branded 404, the same page an unrouted path gets.
        .route(
            "/organizations",
            get(handlers::organizations::organizations),
        )
        .route(
            "/membership/subscribe",
            axum::routing::post(dash::membership_subscribe),
        )
        .route(
            "/membership/cancel",
            axum::routing::post(dash::membership_cancel),
        )
        .route(
            "/membership/cancel-now",
            axum::routing::post(dash::membership_cancel_now),
        )
        .route(
            "/membership/reactivate",
            axum::routing::post(dash::membership_reactivate),
        )
        .route("/settings", get(dash::settings))
        // BUNYIP-139
        .route(
            "/settings/profile",
            axum::routing::post(dash::settings_profile),
        )
        // BUNYIP-408: avatar upload / remove + same-origin avatar proxy.
        .route(
            "/settings/avatar",
            axum::routing::post(dash::settings_avatar).layer(
                // Raise the default axum 2 MB body limit so a 2 MiB image plus
                // multipart overhead fits. The API's own MAX_AVATAR_SIZE is the
                // authoritative cap.
                axum::extract::DefaultBodyLimit::max(3 * 1024 * 1024),
            ),
        )
        .route(
            "/settings/avatar/remove",
            axum::routing::post(dash::settings_avatar_remove),
        )
        .route("/me/avatar", get(dash::me_avatar))
        // BUNYIP-560: same-origin proxy for the admin-managed brand images
        // (mark, mascot, derived favicon set). Unauthenticated, like the
        // upstream endpoint: this is site chrome.
        .route("/brand/:kind", get(branding::brand_asset))
        // BUNYIP-140: OIDC consent screen (rendered when /oauth2/authorize
        // on bunyip-api detects a (user, client, scope) combination that has
        // not been consented to yet).
        .route(
            "/oauth2/consent",
            get(consent::consent_get).post(consent::consent_post),
        )
        .route("/settings/email", axum::routing::post(dash::settings_email))
        .route(
            "/settings/password",
            axum::routing::post(dash::settings_password),
        )
        .route(
            "/settings/2fa/disable",
            axum::routing::post(dash::settings_disable_2fa),
        )
        .route(
            "/settings/account/delete",
            axum::routing::post(dash::settings_delete),
        )
        .route(
            "/settings/verify-email/resend",
            axum::routing::post(dash::settings_resend_verification),
        )
        // Active sessions (BUNYIP-137). The literal `revoke-others` route is
        // distinct from `:id/revoke` (different segment count), so ordering is
        // not load-bearing here, but keep them adjacent for readability.
        .route(
            "/settings/sessions/revoke-others",
            axum::routing::post(dash::settings_revoke_other_sessions),
        )
        .route(
            "/settings/sessions/:id/revoke",
            axum::routing::post(dash::settings_revoke_session),
        )
        // Trusted devices (BUNYIP-138)
        .route(
            "/settings/trusted-devices/:id/revoke",
            axum::routing::post(dash::settings_revoke_trusted_device),
        )
        .route(
            "/settings/2fa/setup",
            get(dash::twofa_setup_get).post(dash::twofa_setup_post),
        )
        .route(
            "/settings/2fa/recovery-codes",
            get(dash::twofa_recovery_get).post(dash::twofa_recovery_post),
        )
        .route(
            "/settings/2fa/rekey",
            get(dash::twofa_rekey_get).post(dash::twofa_rekey_post),
        )
        .route(
            "/settings/2fa/rekey/confirm",
            axum::routing::post(dash::twofa_rekey_confirm_post),
        )
        // Admin (DEV-517: the table lives in `routes::admin`).
        .merge(routes::admin::routes())
        // Static + fallback
        .nest_service(
            "/assets",
            ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::if_not_present(
                    CACHE_CONTROL,
                    HeaderValue::from_static(ASSET_CACHE_CONTROL),
                ))
                .service(ServeDir::new("assets")),
        )
        // BUNYIP-339: browsers probe the root /favicon.ico regardless of the
        // <link rel="icon"> tags in <head>, so serve it at the web root too
        // (ServeDir above only answers under /assets). Without this the apex
        // a8n.systems logs a 404 on every page load. BUNYIP-560: it follows the
        // branding record, falling back to the committed file.
        .route("/favicon.ico", get(branding::favicon_ico))
        .fallback(public::not_found)
        // BUNYIP-259: Origin / Referer CSRF defense on every state-
        // changing POST. Refuses cross-origin form submissions before
        // the handler runs. The `/oauth2/*` family is exempted inside
        // the middleware (those endpoints authenticate via PKCE +
        // state + nonce + client_secret per spec). The full
        // synchronizer-token middleware on top of this is a follow-up.
        .layer(axum::middleware::from_fn(csrf::enforce_origin))
        // BUNYIP-311: resolve the end-user IP once per request (honouring
        // bunyip-web's own trusted proxy) and scope it into a task-local so
        // every outbound /v1 call forwards it to bunyip-api as X-Forwarded-For.
        // Needs the socket peer, so `serve` below uses
        // `into_make_service_with_connect_info` to surface `ConnectInfo`.
        .layer(axum::middleware::from_fn_with_state(
            // BUNYIP-589: the moved middleware takes just the trusted-proxy CIDRs.
            Arc::new(cfg.trusted_proxies.clone()),
            client_ip::forward_client_ip,
        ))
        // BUNYIP-232: stamp a Content-Security-Policy onto every response (the
        // remaining security header the edge proxy does not set for bunyip-web).
        .layer(security::csp_layer(&cfg))
        .layer(CompressionLayer::new().compress_when(compression_predicate()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind");

    // Startup banner (the listener is already bound at this point).
    // BUNYIP-561: the brand line comes from the record fetched above, and is
    // dropped when there is nothing to say. The binary name is an identifier,
    // not copy, so it stays.
    let brand = branding::current();
    let brand_line = match (brand.brand_name.as_str(), brand.tagline.as_str()) {
        ("", "") => String::new(),
        (name, "") => format!("  ({name})"),
        ("", tagline) => format!("  ({tagline})"),
        (name, tagline) => format!("  ({name} · {tagline})"),
    };
    println!();
    println!("  ===================================================");
    println!("   bunyip-web{brand_line}");
    println!("   Web listening on  http://{bind_addr}");
    println!("   API backend       {}", cfg.api_url);
    println!("  ===================================================");
    println!();

    tracing::info!("bunyip-web listening on {bind_addr}");
    // BUNYIP-311: `into_make_service_with_connect_info` surfaces the socket
    // peer as `ConnectInfo<SocketAddr>` so `client_ip::forward_client_ip` can
    // check whether the inbound peer is a trusted proxy before honouring its
    // forwarding headers.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
}

#[cfg(test)]
mod compression_tests {
    use super::compression_predicate;
    use axum::body::Body;
    use axum::http::{header::CONTENT_TYPE, Response};
    use tower_http::compression::Predicate;

    fn should_compress(content_type: &str) -> bool {
        let body = Body::from(vec![0u8; 4096]);
        let response = Response::builder()
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .expect("valid test response");
        compression_predicate().should_compress(&response)
    }

    /// BUNYIP-554 F4: gzip over an already-compressed release asset buys a
    /// ratio near 1.0 and costs the forwarded `Content-Length` (and with it the
    /// browser's download progress bar), so every binary content type the
    /// download proxy relays is exempt while the text assets still compress.
    #[test]
    fn already_compressed_payloads_are_never_gzipped() {
        for exempt in [
            "application/octet-stream",
            "application/gzip",
            "application/zip",
            "application/x-tar",
            "application/x-xz",
            "font/woff2",
            "image/webp",
        ] {
            assert!(
                !should_compress(exempt),
                "{exempt} is already compressed and must cross the BFF untouched"
            );
        }
        for compressible in [
            "text/html; charset=utf-8",
            "text/css",
            "text/javascript",
            "application/json",
        ] {
            assert!(
                should_compress(compressible),
                "{compressible} is worth roughly 73 percent and must still compress"
            );
        }
    }
}
