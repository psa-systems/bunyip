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
//! - The three binary `/v1` endpoints that answer with stored image bytes and
//!   a stored image MIME (BUNYIP-741): `public_branding_asset`, `get_avatar`,
//!   and the admin feedback-attachment download. Each already-compressed image
//!   would otherwise pay a deflate pass in bunyip-api and an inflate pass in
//!   bunyip-web for a net saving near zero, and encoding strips the
//!   `Content-Length` the handler set.
//!
//! The framework-sanctioned exemption is an explicit `Content-Encoding` on the
//! response: `Encoder::response` skips a response that already carries one.
//! `identity` is the value that says "no transformation applied", which is what
//! is true here.

use actix_web::http::header::{self, HeaderValue};
use actix_web::HttpResponse;

/// Mark a response so the `Compress` middleware leaves its body alone.
///
/// Call this on every streamed response and every response with a runtime
/// (stored, not string-literal) `content_type` served by the primary stack;
/// `every_streamed_primary_response_is_compress_exempt` fails the build on a
/// new `.streaming(` site without it, and
/// `every_runtime_content_type_response_is_compress_exempt` fails it on a new
/// `.content_type(<runtime value>)` site without it.
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

    /// Every response builder whose `content_type` is a runtime value (not a
    /// `text/*` or `application/json` string literal) must call
    /// [`mark_uncompressed`] in the same file (BUNYIP-741). This is the shape
    /// `.streaming(` misses: a `.body()` response carrying a stored MIME type
    /// still pays an encode/decode pass for no size win.
    #[test]
    fn every_runtime_content_type_response_is_compress_exempt() {
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

        /// Returns the argument text of a `.content_type(...)` call starting
        /// at or after `from` in `line`, matching parens so an argument like
        /// `meta.mime_type.clone()` is captured whole.
        fn content_type_arg(line: &str) -> Option<String> {
            let idx = line.find(".content_type(")?;
            let start = idx + ".content_type(".len();
            let bytes = line.as_bytes();
            let mut depth = 1i32;
            let mut i = start;
            while i < bytes.len() {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(line[start..i].trim().to_string());
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&src, &mut files);

        let mut runtime_content_type = Vec::new();
        for file in &files {
            let source = std::fs::read_to_string(file).expect("readable source");
            let has_runtime_content_type = source.lines().any(|l| {
                let trimmed = l.trim_start();
                if trimmed.starts_with("//") {
                    return false;
                }
                match content_type_arg(l) {
                    // A literal string argument (`"text/csv; charset=utf-8"`,
                    // `"application/json"`) is a fixed, already-compressible
                    // type, not a stored binary MIME; an empty argument is not
                    // a response builder at all (e.g. a multipart field's own
                    // `content_type()` getter).
                    Some(arg) if !arg.is_empty() && !arg.starts_with('"') => true,
                    _ => false,
                }
            });
            if has_runtime_content_type {
                runtime_content_type.push((file.clone(), source));
            }
        }

        assert!(
            !runtime_content_type.is_empty(),
            "the scan found no runtime `.content_type(` sites; the pattern has drifted"
        );
        let unexempt: Vec<String> = runtime_content_type
            .iter()
            .filter(|(_, source)| !source.contains("mark_uncompressed"))
            .map(|(path, _)| path.display().to_string())
            .collect();
        assert!(
            unexempt.is_empty(),
            "responses with a runtime content_type on the compressed primary stack \
             must call compress::mark_uncompressed (BUNYIP-741): {unexempt:#?}"
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
