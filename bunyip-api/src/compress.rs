//! Response-compression exemptions for the primary api stack (BUNYIP-559 F12).
//!
//! `actix_web::middleware::Compress` sits under every route of the primary
//! server, because the admin list payloads gzip roughly 10:1 (see
//! `docs/api-performance-measurements.md`). It has no predicate API: unlike
//! `tower-http`, it does NOT exempt `text/event-stream`, and it compresses a
//! streamed body chunk by chunk through a deflate encoder that holds bytes back
//! until it has enough to emit. Two response shapes on this stack must not go
//! through it:
//!
//! - `GET /v1/events` (SSE). Buffered compression defeats incremental
//!   delivery: an event sits in the encoder instead of reaching the browser.
//! - `GET /v1/applications/{slug}/downloads/...` (release assets). Encoding
//!   drops the `Content-Length` the handler set (actix removes it and switches
//!   to chunked), so a client loses the size it needs for a progress bar, and
//!   the assets are already-compressed archives that gain nothing.
//!
//! The framework-sanctioned exemption is an explicit `Content-Encoding` on the
//! response: `Encoder::response` skips a response that already carries one.
//! `identity` is the value that says "no transformation applied", which is what
//! is true here.

use actix_web::http::header::{self, HeaderValue};
use actix_web::HttpResponse;

/// Mark a response so the `Compress` middleware leaves its body alone.
///
/// Call this on every streamed response served by the primary stack;
/// `every_streamed_primary_response_is_compress_exempt` fails the build if a
/// new `.streaming(` site appears without it.
pub fn mark_uncompressed(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::middleware::Compress;
    use actix_web::test as actix_test;
    use actix_web::{web, App, HttpResponse};
    use futures_util::stream;

    /// Every `.streaming(` site served by the primary (compressed) stack must
    /// go through [`mark_uncompressed`]. Scanned by shape rather than by the
    /// two sites known today, so a third one cannot be added silently.
    #[test]
    fn every_streamed_primary_response_is_compress_exempt() {
        fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("readable dir") {
                let path = entry.expect("readable entry").path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&src, &mut files);

        let mut streaming = Vec::new();
        for file in &files {
            let source = std::fs::read_to_string(file).expect("readable source");
            if source.lines().any(|l| {
                !l.trim_start().starts_with("//") && l.contains(".streaming(") && !l.contains("///")
            }) {
                streaming.push((file.clone(), source));
            }
        }

        assert!(
            !streaming.is_empty(),
            "the scan found no `.streaming(` sites; the pattern has drifted"
        );
        let unexempt: Vec<String> = streaming
            .iter()
            .filter(|(_, source)| !source.contains("mark_uncompressed"))
            .map(|(path, _)| path.display().to_string())
            .collect();
        assert!(
            unexempt.is_empty(),
            "streamed responses on the compressed primary stack must call \
             compress::mark_uncompressed (BUNYIP-559 F12): {unexempt:#?}"
        );

        // The OCI blob stream (crates/bunyip-oci) is the one streamed response
        // that needs no marker, because it is served by the separate `oci`
        // HttpServer in main.rs, which carries no Compress. That only holds
        // while the primary router does not mount the OCI vertical.
        let routes = std::fs::read_to_string(src.join("routes/mod.rs")).expect("readable routes");
        assert!(
            !routes.contains("bunyip_oci"),
            "the OCI vertical is now on the primary (compressed) stack; its blob \
             stream needs compress::mark_uncompressed too"
        );
    }

    #[actix_web::test]
    async fn compress_gzips_an_ordinary_json_body_but_not_a_marked_stream() {
        // The real middleware, both branches, on one App: whatever exempts the
        // stream must not also switch compression off for everything else.
        let app = actix_test::init_service(
            App::new()
                .wrap(Compress::default())
                .route(
                    "/json",
                    web::get().to(|| async {
                        HttpResponse::Ok().content_type("application/json").body(
                            "{\"items\":[".to_string() + &"\"aaaaaaaaaa\",".repeat(200) + "\"z\"]}",
                        )
                    }),
                )
                .route(
                    "/sse",
                    web::get().to(|| async {
                        let body = stream::iter(vec![Ok::<_, std::io::Error>(
                            actix_web::web::Bytes::from_static(b"data: hello\n\n"),
                        )]);
                        mark_uncompressed(
                            HttpResponse::Ok()
                                .insert_header((header::CONTENT_TYPE, "text/event-stream"))
                                .streaming(body),
                        )
                    }),
                ),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/json")
            .insert_header((header::ACCEPT_ENCODING, "gzip"))
            .to_request();
        let res = actix_test::call_service(&app, req).await;
        assert_eq!(
            res.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip",
            "an ordinary JSON body must still be compressed"
        );

        let req = actix_test::TestRequest::get()
            .uri("/sse")
            .insert_header((header::ACCEPT_ENCODING, "gzip"))
            .to_request();
        let res = actix_test::call_service(&app, req).await;
        assert_eq!(
            res.headers().get(header::CONTENT_ENCODING).unwrap(),
            "identity",
            "a marked stream must reach the client unencoded"
        );
        let body = actix_test::read_body(res).await;
        assert_eq!(
            &body[..],
            b"data: hello\n\n",
            "the SSE frame must arrive verbatim, not deflated"
        );
    }
}
