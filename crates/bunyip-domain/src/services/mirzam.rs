//! The Mirzam connection check (BUNYIP-997).
//!
//! An admin connects bunyip to a Mirzam site and names two of its lists: the
//! product-updates list (an ordinary `newsletter` list) and the required
//! account notices list (a `notices` list). The check reads both through
//! Mirzam's REST API, `GET {base_url}/api/v1/lists/{slug}` with the API token
//! as a bearer token, and reports per list either its name and kind or what is
//! wrong: an unreachable address, a refused token, an unknown slug or a list of
//! the wrong kind.
//!
//! Every outcome is a report, never an error: a failing Mirzam is exactly what
//! the admin clicked the button to see.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A slow or unreachable Mirzam fails the check rather than holding the admin
/// page open.
pub const MIRZAM_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Which of the two lists a check is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirzamListRole {
    /// Every account holder is on it unless they leave (opt-out).
    ProductUpdates,
    /// Required account notices, which nobody leaves while they have an account.
    Notices,
}

impl MirzamListRole {
    /// The stable key in the report, matching the settings field name.
    pub fn key(self) -> &'static str {
        match self {
            Self::ProductUpdates => "updates_list",
            Self::Notices => "notices_list",
        }
    }

    /// The `kind` Mirzam must report for this list.
    pub fn expected_kind(self) -> &'static str {
        match self {
            Self::ProductUpdates => "newsletter",
            Self::Notices => "notices",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ProductUpdates => "product-updates",
            Self::Notices => "notices",
        }
    }
}

/// One list's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MirzamListCheck {
    /// `updates_list` or `notices_list`.
    pub list: &'static str,
    pub slug: String,
    pub ok: bool,
    /// The list's name, when Mirzam answered with the list.
    pub name: Option<String>,
    /// The list's kind, when Mirzam answered with the list.
    pub kind: Option<String>,
    /// One admin-facing sentence: what was found, or what is wrong.
    pub message: String,
}

/// Both lists' outcomes. `ok` only when both are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MirzamCheckReport {
    pub ok: bool,
    pub lists: Vec<MirzamListCheck>,
}

/// The part of Mirzam's list answer the check reads.
#[derive(Debug, Deserialize)]
struct ListAnswer {
    name: String,
    kind: String,
}

/// Check both lists against `base_url` with `token`. The two reads run
/// concurrently.
pub async fn check_connection(
    base_url: &str,
    token: &str,
    updates_list: &str,
    notices_list: &str,
) -> MirzamCheckReport {
    let client = match reqwest::Client::builder()
        .timeout(MIRZAM_HTTP_TIMEOUT)
        // A redirect is reported rather than followed: the address the
        // integration saves is the one every later call uses, so a check that
        // passed only by following a redirect would hide a wrong address.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            let message = format!("Could not build the HTTP client: {e}");
            return MirzamCheckReport {
                ok: false,
                lists: [
                    (MirzamListRole::ProductUpdates, updates_list),
                    (MirzamListRole::Notices, notices_list),
                ]
                .into_iter()
                .map(|(role, slug)| failed(role, slug, message.clone()))
                .collect(),
            };
        }
    };

    let (updates, notices) = tokio::join!(
        check_list(
            &client,
            base_url,
            token,
            MirzamListRole::ProductUpdates,
            updates_list
        ),
        check_list(
            &client,
            base_url,
            token,
            MirzamListRole::Notices,
            notices_list
        ),
    );
    MirzamCheckReport {
        ok: updates.ok && notices.ok,
        lists: vec![updates, notices],
    }
}

fn failed(role: MirzamListRole, slug: &str, message: String) -> MirzamListCheck {
    MirzamListCheck {
        list: role.key(),
        slug: slug.to_string(),
        ok: false,
        name: None,
        kind: None,
        message,
    }
}

async fn check_list(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    role: MirzamListRole,
    slug: &str,
) -> MirzamListCheck {
    let base_url = base_url.trim_end_matches('/');
    let url = format!(
        "{base_url}/api/v1/lists/{}",
        urlencoding::encode(slug.trim())
    );
    let response = match client.get(&url).bearer_auth(token).send().await {
        Ok(response) => response,
        Err(e) if e.is_timeout() => {
            return failed(
                role,
                slug,
                format!(
                    "{base_url} did not answer within {} seconds.",
                    MIRZAM_HTTP_TIMEOUT.as_secs()
                ),
            )
        }
        Err(e) => {
            return failed(
                role,
                slug,
                format!("Could not reach {base_url}: {}", without_url(&e)),
            )
        }
    };

    let status = response.status().as_u16();
    match status {
        200 => {}
        301 | 302 | 303 | 307 | 308 => {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("another address")
                .to_string();
            return failed(
                role,
                slug,
                format!(
                    "{base_url} redirects to {location}. Save the address Mirzam is served from."
                ),
            );
        }
        401 => {
            return failed(
                role,
                slug,
                "Mirzam refused the API token (401). Check the token, or make a new one on \
                 Mirzam's API page."
                    .to_string(),
            )
        }
        403 => {
            return failed(
                role,
                slug,
                "Mirzam refused the API token (403). The token cannot read this list.".to_string(),
            )
        }
        404 => {
            return failed(
                role,
                slug,
                format!(
                    "Mirzam has no list with the slug {slug}. Check the slug, and that the \
                     address is the Mirzam site."
                ),
            )
        }
        429 => {
            return failed(
                role,
                slug,
                "Mirzam is rate limiting this token (429). Try again in a minute.".to_string(),
            )
        }
        other => return failed(role, slug, format!("Mirzam answered with status {other}.")),
    }

    let answer: ListAnswer = match response.json().await {
        Ok(answer) => answer,
        Err(_) => {
            return failed(
                role,
                slug,
                format!(
                    "{base_url} answered, but not with a Mirzam list. Check that the address is \
                     the Mirzam site."
                ),
            )
        }
    };

    let expected = role.expected_kind();
    let ok = answer.kind == expected;
    let message = if ok {
        format!("Found {} ({}).", answer.name, answer.kind)
    } else {
        format!(
            "{} is a {} list, but the {} list must be a {expected} list.",
            answer.name,
            answer.kind,
            role.label()
        )
    };
    MirzamListCheck {
        list: role.key(),
        slug: slug.to_string(),
        ok,
        name: Some(answer.name),
        kind: Some(answer.kind),
        message,
    }
}

/// A transport error's cause without the request URL reqwest prefixes it with,
/// since the message already names the address.
pub(crate) fn without_url(e: &reqwest::Error) -> String {
    let mut cause: &dyn std::error::Error = e;
    while let Some(source) = cause.source() {
        cause = source;
    }
    cause.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn list(server: &MockServer, slug: &str, status: u16, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/lists/{slug}")))
            .and(header("authorization", "Bearer mzm_token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn both_lists_of_the_right_kind_pass() {
        let server = MockServer::start().await;
        list(
            &server,
            "product-updates",
            200,
            serde_json::json!({"slug": "product-updates", "name": "Product Updates", "kind": "newsletter"}),
        )
        .await;
        list(
            &server,
            "notices",
            200,
            serde_json::json!({"slug": "notices", "name": "Account Notices", "kind": "notices"}),
        )
        .await;

        let report =
            check_connection(&server.uri(), "mzm_token", "product-updates", "notices").await;
        assert!(report.ok, "{report:#?}");
        assert_eq!(report.lists[0].list, "updates_list");
        assert_eq!(report.lists[0].name.as_deref(), Some("Product Updates"));
        assert_eq!(report.lists[0].kind.as_deref(), Some("newsletter"));
        assert_eq!(report.lists[1].list, "notices_list");
        assert_eq!(report.lists[1].kind.as_deref(), Some("notices"));
    }

    #[tokio::test]
    async fn a_list_of_the_wrong_kind_fails_and_names_both_kinds() {
        let server = MockServer::start().await;
        list(
            &server,
            "product-updates",
            200,
            serde_json::json!({"name": "Product Updates", "kind": "notices"}),
        )
        .await;
        list(
            &server,
            "notices",
            200,
            serde_json::json!({"name": "Account Notices", "kind": "newsletter"}),
        )
        .await;

        let report =
            check_connection(&server.uri(), "mzm_token", "product-updates", "notices").await;
        assert!(!report.ok);
        let updates = &report.lists[0];
        assert!(!updates.ok);
        assert_eq!(updates.kind.as_deref(), Some("notices"));
        assert!(
            updates.message.contains("must be a newsletter list"),
            "{}",
            updates.message
        );
        assert!(report.lists[1].message.contains("must be a notices list"));
    }

    #[tokio::test]
    async fn a_refused_token_and_an_unknown_slug_are_named() {
        let server = MockServer::start().await;
        list(
            &server,
            "product-updates",
            401,
            serde_json::json!({"error": {"code": "unauthorized"}}),
        )
        .await;
        list(
            &server,
            "notices",
            404,
            serde_json::json!({"error": {"code": "not_found"}}),
        )
        .await;

        let report =
            check_connection(&server.uri(), "mzm_token", "product-updates", "notices").await;
        assert!(!report.ok);
        assert!(report.lists[0]
            .message
            .contains("refused the API token (401)"));
        assert!(report.lists[1]
            .message
            .contains("no list with the slug notices"));
    }

    #[tokio::test]
    async fn a_forbidden_token_is_named() {
        let server = MockServer::start().await;
        list(&server, "a", 403, serde_json::json!({})).await;
        list(&server, "b", 403, serde_json::json!({})).await;
        let report = check_connection(&server.uri(), "mzm_token", "a", "b").await;
        assert!(report.lists[0].message.contains("(403)"));
    }

    #[tokio::test]
    async fn an_answer_that_is_not_a_list_is_named() {
        let server = MockServer::start().await;
        list(&server, "a", 200, serde_json::json!({"hello": "world"})).await;
        list(&server, "b", 200, serde_json::json!([])).await;
        let report = check_connection(&server.uri(), "mzm_token", "a", "b").await;
        assert!(!report.ok);
        assert!(report.lists[0].message.contains("not with a Mirzam list"));
    }

    #[tokio::test]
    async fn an_unreachable_address_is_named_on_both_lists() {
        // Port 0 never accepts a connection.
        let report = check_connection("http://127.0.0.1:0", "mzm_token", "a", "b").await;
        assert!(!report.ok);
        for list in &report.lists {
            assert!(
                list.message
                    .starts_with("Could not reach http://127.0.0.1:0"),
                "{}",
                list.message
            );
        }
    }

    #[tokio::test]
    async fn a_redirect_is_reported_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(301).insert_header("location", "https://news.example.com/"),
            )
            .mount(&server)
            .await;
        let report = check_connection(&server.uri(), "mzm_token", "a", "b").await;
        assert!(!report.ok);
        assert!(
            report.lists[0]
                .message
                .contains("redirects to https://news.example.com/"),
            "{}",
            report.lists[0].message
        );
    }

    #[tokio::test]
    async fn the_report_never_carries_the_token() {
        let server = MockServer::start().await;
        list(&server, "a", 401, serde_json::json!({})).await;
        list(&server, "b", 404, serde_json::json!({})).await;
        let report = check_connection(&server.uri(), "mzm_token", "a", "b").await;
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("mzm_token"), "{json}");
    }
}
