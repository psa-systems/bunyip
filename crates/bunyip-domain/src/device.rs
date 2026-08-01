//! BUNYIP-409: derive a short, human-readable device label from a raw
//! User-Agent string for the Active Sessions list.
//!
//! The session rows store the raw User-Agent (`device_info`); showing that
//! verbatim is unreadable, and showing nothing reads as "Unknown device". This
//! maps the UA to "<browser> on <os>" (e.g. "Chrome on macOS") using simple
//! substring detection - enough per the ticket ("browser plus operating system
//! is enough") without pulling in a full UA-parsing dependency. Returns `None`
//! when the UA is absent or unrecognisable, so the caller keeps its
//! "Unknown device" fallback.

/// Best-effort browser name from a User-Agent. Order matters: several UAs nest
/// tokens (Edge and Opera both carry `Chrome`; Chrome carries `Safari`), so the
/// more specific token is checked first.
fn browser_name(ua: &str) -> Option<&'static str> {
    if ua.contains("Edg/") || ua.contains("Edge/") {
        Some("Edge")
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        Some("Opera")
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        Some("Firefox")
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        Some("Chrome")
    } else if ua.contains("Safari/") {
        Some("Safari")
    } else {
        None
    }
}

/// Best-effort operating-system name from a User-Agent. iOS/Android are checked
/// before the desktop families they can otherwise match (an iPhone UA contains
/// `like Mac OS X`).
fn os_name(ua: &str) -> Option<&'static str> {
    if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        Some("iOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("Windows NT") || ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    }
}

/// Derive a friendly device label from a raw User-Agent, or `None` when it is
/// absent, blank, or unrecognisable (the caller then shows "Unknown device").
///
/// - both parts known  -> "Chrome on macOS"
/// - only browser known -> "Firefox"
/// - only OS known      -> "Windows"
/// - neither known      -> `None`
pub fn device_label(user_agent: Option<&str>) -> Option<String> {
    let ua = user_agent?.trim();
    if ua.is_empty() {
        return None;
    }
    match (browser_name(ua), os_name(ua)) {
        (Some(browser), Some(os)) => Some(format!("{browser} on {os}")),
        (Some(browser), None) => Some(browser.to_string()),
        (None, Some(os)) => Some(os.to_string()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::device_label;

    #[test]
    fn chrome_on_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(device_label(Some(ua)).as_deref(), Some("Chrome on macOS"));
    }

    #[test]
    fn firefox_on_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
        assert_eq!(
            device_label(Some(ua)).as_deref(),
            Some("Firefox on Windows")
        );
    }

    #[test]
    fn safari_on_ios_beats_macos_and_chrome_tokens() {
        // An iPhone Safari UA carries "like Mac OS X" and "Safari/" but no
        // "Chrome/": it must read as Safari on iOS, not Chrome on macOS.
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 \
                  (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1";
        assert_eq!(device_label(Some(ua)).as_deref(), Some("Safari on iOS"));
    }

    #[test]
    fn edge_beats_chrome_token() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        assert_eq!(device_label(Some(ua)).as_deref(), Some("Edge on Windows"));
    }

    #[test]
    fn chrome_on_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
        assert_eq!(device_label(Some(ua)).as_deref(), Some("Chrome on Android"));
    }

    #[test]
    fn unknown_and_absent_uas_return_none() {
        // A non-browser client (e.g. bunyip-web's own HTTP client) and an absent
        // or blank UA both fall back to None -> "Unknown device".
        assert_eq!(device_label(Some("reqwest/0.12.0")), None);
        assert_eq!(device_label(Some("")), None);
        assert_eq!(device_label(Some("   ")), None);
        assert_eq!(device_label(None), None);
    }

    #[test]
    fn os_only_when_browser_unrecognised() {
        // A UA with a recognisable OS but no known browser token yields the OS
        // alone (browser UAs capitalise "Linux", e.g. "X11; Linux x86_64").
        assert_eq!(
            device_label(Some("Mozilla/5.0 (X11; Linux x86_64)")).as_deref(),
            Some("Linux")
        );
    }
}
