//! Web-edge form validators.
//!
//! BUNYIP-112 / 113 / 115 (and BUNYIP-117 as a follow-up sweep) called out a
//! shared gap: form handlers in this crate posted unbounded / unformatted
//! input to the API, so over-length values surfaced as raw 500s when they hit
//! DB VARCHAR caps, malformed values round-tripped, and numeric inputs
//! silently coerced to 0 on a parse failure.
//!
//! These helpers run BEFORE the API call so the handler can render a clean
//! inline error via the existing `error_box` pattern. They mirror the DB
//! column caps (`VARCHAR(N)`) and the regex shapes the domain layer expects
//! (e.g. `slug` is load-bearing for OCI repo paths in
//! `Application::oci_pull_image`).

/// Trim + bound a text field to a max byte length. Returns the trimmed value
/// on success; an inline error message on empty / over-length input.
pub fn trim_bounded<'a>(value: &'a str, field: &str, max: usize) -> Result<&'a str, String> {
    let t = value.trim();
    if t.is_empty() {
        return Err(format!("{field} is required"));
    }
    if t.len() > max {
        return Err(format!("{field} must be {max} characters or fewer"));
    }
    Ok(t)
}

/// Optional text field. Empty / whitespace becomes `None`; otherwise the
/// trimmed value subject to the same max-length check. The caller decides
/// whether to omit the JSON key for `None` or send `null`.
pub fn trim_bounded_opt<'a>(
    value: &'a str,
    field: &str,
    max: usize,
) -> Result<Option<&'a str>, String> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.len() > max {
        return Err(format!("{field} must be {max} characters or fewer"));
    }
    Ok(Some(t))
}

/// Slug grammar: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`. Lowercase letters / digits
/// with hyphens as internal separators only; bounded length matches the DB
/// caps in `application_groups.slug` / `applications.slug` (64 chars).
pub fn slug<'a>(value: &'a str, field: &str) -> Result<&'a str, String> {
    let t = value.trim();
    if t.is_empty() {
        return Err(format!("{field} is required"));
    }
    if t.len() > 64 {
        return Err(format!("{field} must be 64 characters or fewer"));
    }
    let bytes = t.as_bytes();
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(format!(
            "{field} must not start or end with a hyphen (use a-z, 0-9, internal hyphens)"
        ));
    }
    for &b in bytes {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(format!(
                "{field} must contain only lowercase letters, digits, and internal hyphens"
            ));
        }
    }
    Ok(t)
}

/// Optional URL. Empty -> `None`. Non-empty MUST parse as an absolute
/// `http(s)://...` URL and stay under the byte cap. The scheme allow-list
/// matches the values these fields persist (`icon_url`, `source_code_url`,
/// `health_check_url`, `webhook_url` are all browser-renderable).
pub fn url_opt<'a>(value: &'a str, field: &str, max: usize) -> Result<Option<&'a str>, String> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.len() > max {
        return Err(format!("{field} must be {max} characters or fewer"));
    }
    let parsed = ::url::Url::parse(t).map_err(|_| format!("{field} must be a valid URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("{field} must start with http:// or https://"));
    }
    if !parsed.has_host() {
        return Err(format!("{field} must include a host"));
    }
    Ok(Some(t))
}

/// `i32` parse with explicit range + numeric guards. Used for sort_order
/// (BUNYIP-113) where the column is `INTEGER` and the prior code did
/// `parse::<i64>().unwrap_or(0)`, silently mapping `"abc"` to `0` and
/// truncating `> i32::MAX`.
pub fn parse_i32(value: &str, field: &str) -> Result<i32, String> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(0);
    }
    t.parse::<i32>().map_err(|_| {
        format!("{field} must be a whole number between -2,147,483,648 and 2,147,483,647")
    })
}

/// Optional `i32` parse - blank is `None`, otherwise the parsed value.
/// Mirrors `parse_i32` for forms where a missing value means "don't send".
pub fn parse_i32_opt(value: &str, field: &str) -> Result<Option<i32>, String> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<i32>().map(Some).map_err(|_| {
        format!("{field} must be a whole number between -2,147,483,648 and 2,147,483,647")
    })
}

/// BUNYIP-115: minimal RFC-5321-ish email shape check. Bounded at 254 bytes
/// (the RFC 5321 max), and the simple rule "exactly one `@`, non-empty on
/// both sides, dot in the domain" is enough to reject "garbage" / typos at
/// the edge. The real authoritative check happens at delivery time; this is
/// a UX guard, not a security boundary.
pub fn email<'a>(value: &'a str, field: &str) -> Result<&'a str, String> {
    let t = value.trim();
    if t.is_empty() {
        return Err(format!("{field} is required"));
    }
    if t.len() > 254 {
        return Err(format!("{field} must be 254 characters or fewer"));
    }
    let (local, domain) = match t.split_once('@') {
        Some(pair) => pair,
        None => return Err(format!("{field} must contain an @")),
    };
    if local.is_empty() || domain.is_empty() {
        return Err(format!("{field} must have characters on both sides of @"));
    }
    if !domain.contains('.') {
        return Err(format!("{field} domain must contain a dot"));
    }
    if t.chars().any(|c| c.is_whitespace()) {
        return Err(format!("{field} must not contain whitespace"));
    }
    Ok(t)
}

/// BUNYIP-115: optional email. Empty -> Ok(None); non-empty subject to the
/// same shape check.
pub fn email_opt<'a>(value: &'a str, field: &str) -> Result<Option<&'a str>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    email(value, field).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rejects_whitespace_and_symbols() {
        assert!(slug(" $$$ ", "slug").is_err());
        assert!(slug("foo bar", "slug").is_err());
        assert!(slug("FOO", "slug").is_err());
        assert!(slug("-foo", "slug").is_err());
        assert!(slug("foo-", "slug").is_err());
    }

    #[test]
    fn slug_accepts_canonical_shapes() {
        assert_eq!(slug("foo", "slug").unwrap(), "foo");
        assert_eq!(slug("foo-bar-baz", "slug").unwrap(), "foo-bar-baz");
        assert_eq!(slug("v2", "slug").unwrap(), "v2");
        assert_eq!(slug("  foo-bar  ", "slug").unwrap(), "foo-bar");
    }

    #[test]
    fn url_opt_rejects_non_url() {
        assert!(url_opt("not a url", "icon_url", 512).is_err());
        assert!(url_opt("ftp://example.com", "icon_url", 512).is_err());
        assert!(url_opt("https://", "icon_url", 512).is_err());
    }

    #[test]
    fn url_opt_accepts_valid() {
        assert_eq!(
            url_opt("https://example.com/icon.png", "icon_url", 512)
                .unwrap()
                .unwrap(),
            "https://example.com/icon.png"
        );
        assert!(url_opt("", "icon_url", 512).unwrap().is_none());
    }

    #[test]
    fn parse_i32_rejects_non_numeric_and_out_of_range() {
        assert!(parse_i32("abc", "sort_order").is_err());
        assert!(parse_i32("9999999999", "sort_order").is_err());
        assert!(parse_i32("-9999999999", "sort_order").is_err());
    }

    #[test]
    fn parse_i32_blank_is_zero() {
        assert_eq!(parse_i32("", "sort_order").unwrap(), 0);
        assert_eq!(parse_i32("  ", "sort_order").unwrap(), 0);
    }

    #[test]
    fn email_rejects_garbage_and_overlength() {
        assert!(email("garbage", "email").is_err());
        assert!(email("a@b", "email").is_err());
        assert!(email("@example.com", "email").is_err());
        assert!(email("a b@example.com", "email").is_err());
        let huge = format!("{}@example.com", "a".repeat(260));
        assert!(email(&huge, "email").is_err());
    }

    #[test]
    fn email_accepts_typical() {
        assert_eq!(email("a@b.co", "email").unwrap(), "a@b.co");
        assert_eq!(
            email("user.name+tag@example.com", "email").unwrap(),
            "user.name+tag@example.com"
        );
    }

    #[test]
    fn trim_bounded_rejects_empty_and_over_length() {
        assert!(trim_bounded("", "name", 10).is_err());
        assert!(trim_bounded("   ", "name", 10).is_err());
        assert!(trim_bounded("12345678901", "name", 10).is_err());
        assert_eq!(trim_bounded("hello", "name", 10).unwrap(), "hello");
    }
}
