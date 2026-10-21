//! BUNYIP-934: composite spam classifier for feedback intake.
//!
//! Three signals, each a weak contributor; the composite flags when any
//! one fires. Each firing contributes a short human-readable fragment to
//! the returned `spam_reason` so the admin UI can show WHY. All three
//! signals are pure functions of the submitted row, so the classifier
//! itself holds no state and no DB round-trip.
//!
//! The three signals, filed as [BUNYIP-932](research) + [BUNYIP-934]
//! (implementation):
//!
//! 1. **Sender-domain mimicry.** The sender's email domain contains the
//!    recipient's registrable word AND differs (e.g. `search-psa.systems`
//!    vs `psa.systems`). Catches the illustrating case from 2026-10-15.
//! 2. **URL + >=3 tags.** The submission names a URL in the body AND sets
//!    three or more tags. SEO fan-out submissions set every tag because
//!    they do not know which category applies.
//! 3. **Hosting-range IP.** The source IP's resolved ASN name matches a
//!    short list of hosting providers (Interserver, OVH, Linode,
//!    DigitalOcean, AWS, Hetzner). A hosting IP alone does not block
//!    (CGNAT edge cases exist) but adds to the score.
//!
//! The classifier short-circuits on the FIRST firing signal and does not
//! enumerate every match: a submission that trips all three is still one
//! `spam_reason` row keyed on its first match's label. Rationale: an
//! admin reviewing a flagged row needs to know whether to trust the
//! classifier, not the full enumeration; and the "which signal fired
//! first" ordering (strongest -> weakest) means a flagged row has the
//! most specific reason attached.

use std::collections::HashSet;

/// Inputs the classifier reads. Each one comes from either the submitted
/// multipart form (`sender_email`, `message`, `tags`), the deployment's
/// branding record (`recipient_domain_registrable_word`), or the request
/// enrichment pipeline (`ip_asn_name`). Kept as borrowed slices so the
/// caller can pass whatever it already has without allocating.
pub struct SpamClassifierInput<'a> {
    /// Sender's email as submitted. `None` for an anonymous submission;
    /// the mimicry signal cannot fire without one.
    pub sender_email: Option<&'a str>,
    /// Message body as submitted.
    pub message: &'a str,
    /// Canonical tag list after `normalize_tags`.
    pub tags: &'a [String],
    /// IP2Proxy-resolved ASN name for the submitter's IP (if the dataset
    /// is loaded; `None` for a deployment without BUNYIP-474). The
    /// hosting-range signal cannot fire without this.
    pub ip_asn_name: Option<&'a str>,
    /// The registrable word of the deployment's own apex domain (`psa`
    /// for a deployment at `psa.systems`). The mimicry signal compares
    /// the sender's domain against this.
    pub recipient_domain_registrable_word: Option<&'a str>,
    /// The deployment's full apex host (`psa.systems`). Used by the
    /// mimicry signal to tell "contains the registrable word elsewhere"
    /// (`search-psa.systems`) apart from "a legitimate subdomain of the
    /// recipient" (`staff.psa.systems`).
    pub recipient_domain_apex: Option<&'a str>,
}

/// Classifier output. `None` for a clean submission; `Some(reason)` for a
/// flagged one. Caller writes `spam_reason` iff `Some`, and sets
/// `is_spam = true`.
pub fn classify_feedback_spam(input: &SpamClassifierInput<'_>) -> Option<String> {
    if let Some(reason) = check_sender_mimicry(input) {
        return Some(reason);
    }
    if let Some(reason) = check_urls_plus_tags(input) {
        return Some(reason);
    }
    if let Some(reason) = check_hosting_asn(input) {
        return Some(reason);
    }
    None
}

/// Signal 1: sender's email domain contains the recipient's registrable
/// word AND is not the recipient domain itself (apex or any subdomain
/// of it). Catches the `search-psa.systems` vs `psa.systems` shape
/// without a public-suffix list by comparing the registrable word, with
/// the apex domain carried alongside so a legitimate subdomain of the
/// recipient stays clean.
fn check_sender_mimicry(input: &SpamClassifierInput<'_>) -> Option<String> {
    let sender = input.sender_email?;
    let recipient_word = input.recipient_domain_registrable_word?.trim();
    let recipient_apex = input.recipient_domain_apex?.trim();
    if recipient_word.is_empty() || recipient_apex.is_empty() {
        return None;
    }
    let (_, domain) = sender.rsplit_once('@')?;
    let domain = domain.trim().to_ascii_lowercase();
    let recipient_word = recipient_word.to_ascii_lowercase();
    let recipient_apex = recipient_apex.to_ascii_lowercase();
    // First-party: the sender's domain IS the recipient apex, or a
    // subdomain of it. Clean.
    if domain == recipient_apex || domain.ends_with(&format!(".{recipient_apex}")) {
        return None;
    }
    // Mimic iff a dot-separated segment of the sender's domain contains
    // the recipient's registrable word. `search-psa.systems` has a
    // segment `search-psa` that contains `psa`; `example.com` does not.
    if !domain.split('.').any(|seg| seg.contains(&recipient_word)) {
        return None;
    }
    Some(format!(
        "sender domain {domain} mimics the recipient's registrable word {recipient_word}"
    ))
}

/// Signal 2: message contains at least one URL AND submitter set three or
/// more tags. Simple URL regex: `https?://` plus one non-whitespace char.
/// Does not need to be fancy; the signal is "any URL at all".
fn check_urls_plus_tags(input: &SpamClassifierInput<'_>) -> Option<String> {
    let tag_count = input.tags.len();
    if tag_count < 3 {
        return None;
    }
    if !message_has_url(input.message) {
        return None;
    }
    Some(format!(
        "message carries a URL and {tag_count} tags; SEO fan-out shape"
    ))
}

/// True iff the message contains `http://` or `https://` followed by
/// one non-whitespace character. Keeps the check cheap and dependency
/// free; a false positive on `https://` typed by a legitimate reporter
/// cannot flag alone (the >=3 tag requirement must also hold).
fn message_has_url(message: &str) -> bool {
    message_has_url_inner(message).unwrap_or(false)
}

fn message_has_url_inner(message: &str) -> Option<bool> {
    let m = message.to_ascii_lowercase();
    let marker_http = m.find("http://");
    let marker_https = m.find("https://");
    let marker = match (marker_http, marker_https) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }?;
    let after = &m[marker..];
    let scheme_end = after.find("://")? + 3;
    Some(
        after
            .get(scheme_end..scheme_end + 1)
            .is_some_and(|c| !c.chars().all(char::is_whitespace)),
    )
}

/// Signal 3: the submitter's IP resolved ASN name matches a hosting
/// provider. Hosting IPs are not conclusive on their own (a real ops
/// person on Linode exists) but, for a feedback form that primarily
/// serves residential users, the hit rate is low enough to be a useful
/// weak signal. The list intentionally covers the major hosting
/// providers only; a VPN or CGNAT is a different signal class.
fn check_hosting_asn(input: &SpamClassifierInput<'_>) -> Option<String> {
    let asn = input.ip_asn_name?.trim();
    if asn.is_empty() {
        return None;
    }
    let asn_lower = asn.to_ascii_lowercase();
    let hosting: HashSet<&str> = [
        "interserver",
        "ovh",
        "linode",
        "digitalocean",
        "amazon",
        "aws",
        "hetzner",
        "google cloud",
        "microsoft azure",
        "oracle cloud",
        "vultr",
        "contabo",
    ]
    .into_iter()
    .collect();
    hosting
        .iter()
        .find(|pattern| asn_lower.contains(*pattern))
        .map(|pattern| format!("submitted from hosting-range IP (ASN names {pattern})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        sender: Option<&'a str>,
        message: &'a str,
        tags: &'a [String],
        ip_asn: Option<&'a str>,
        recipient_word: Option<&'a str>,
    ) -> SpamClassifierInput<'a> {
        SpamClassifierInput {
            sender_email: sender,
            message,
            tags,
            ip_asn_name: ip_asn,
            recipient_domain_registrable_word: recipient_word,
            recipient_domain_apex: match recipient_word {
                Some("psa") => Some("psa.systems"),
                _ => None,
            },
        }
    }

    /// The 2026-10-15 illustrating case: sender `d***@search-psa.systems`,
    /// recipient domain `psa.systems`, four tags, URL in body. The
    /// mimicry signal fires first and names the domain.
    #[test]
    fn search_psa_systems_submission_flags_as_mimicry() {
        let tags = vec![
            "Bug".to_string(),
            "Feature".to_string(),
            "Flow".to_string(),
            "Idea".to_string(),
        ];
        let got = classify_feedback_spam(&input(
            Some("d.lease@search-psa.systems"),
            "Add psa.systems in Google's Search Index to appear in online search results! Include psa.systems today: https://indexhelper.live",
            &tags,
            Some("Interserver, LLC"),
            Some("psa"),
        ));
        let reason = got.expect("classifier flagged");
        assert!(
            reason.contains("search-psa.systems") && reason.contains("mimics"),
            "mimicry reason names the domain: {reason}"
        );
    }

    /// A legitimate first-time submission from an unrelated domain with
    /// one URL and one tag does NOT flag.
    #[test]
    fn legitimate_first_time_submission_passes_cleanly() {
        let tags = vec!["Bug".to_string()];
        let got = classify_feedback_spam(&input(
            Some("ada@lovelace.example"),
            "Clicking Save on the pricing page shows https://example.com for a split-second before loading.",
            &tags,
            Some("Comcast Cable Communications"),
            Some("psa"),
        ));
        assert!(
            got.is_none(),
            "legitimate submission does not flag: {got:?}"
        );
    }

    /// A known-sender submission (same domain as the recipient) with four
    /// tags does NOT flag. The tags-alone signal needs a URL too; the
    /// mimicry signal explicitly excludes the exact recipient domain.
    #[test]
    fn known_sender_with_four_tags_passes_cleanly() {
        let tags = vec![
            "Bug".to_string(),
            "Feature".to_string(),
            "Flow".to_string(),
            "Idea".to_string(),
        ];
        // Message with no URL + four tags: tag count alone must not flag.
        let got = classify_feedback_spam(&input(
            Some("admin@psa.systems"),
            "Across the board, the dashboard rows feel one tap off.",
            &tags,
            Some("Comcast"),
            Some("psa"),
        ));
        assert!(
            got.is_none(),
            "known sender + 4 tags + no URL does not flag: {got:?}"
        );
    }

    /// A hosting-ASN + URL + >=3 tags submission from a NON-mimicking
    /// domain flags on the URL+tags signal (mimicry does not fire).
    #[test]
    fn hosting_asn_plus_urls_and_tags_flags_on_urls_signal() {
        let tags = vec!["Bug".to_string(), "Feature".to_string(), "Flow".to_string()];
        let got = classify_feedback_spam(&input(
            Some("promo@unrelated.example"),
            "Check out https://buylinks.cheap for backlinks!",
            &tags,
            Some("Linode, LLC"),
            Some("psa"),
        ));
        let reason = got.expect("classifier flagged");
        assert!(
            reason.contains("URL") && reason.contains("tags"),
            "URL+tags reason: {reason}"
        );
    }

    /// A hosting-ASN alone (no URL, only one tag, non-mimicking domain)
    /// flags only on the hosting-ASN signal.
    #[test]
    fn hosting_asn_alone_flags_on_asn_signal() {
        let tags = vec!["Bug".to_string()];
        let got = classify_feedback_spam(&input(
            Some("ops@unrelated.example"),
            "The dashboard spinner takes a beat to show.",
            &tags,
            Some("DigitalOcean, LLC"),
            Some("psa"),
        ));
        let reason = got.expect("classifier flagged");
        assert!(
            reason.contains("hosting-range IP"),
            "hosting ASN reason: {reason}"
        );
    }

    /// Mimicry does NOT fire when the sender's domain is the exact
    /// recipient domain (a first-party submission from the deployment's
    /// own hosts).
    #[test]
    fn exact_recipient_domain_is_not_mimicry() {
        let tags = vec!["Bug".to_string()];
        let got = classify_feedback_spam(&input(
            Some("someone@psa.systems"),
            "A note from inside the house.",
            &tags,
            None,
            Some("psa"),
        ));
        assert!(got.is_none(), "exact recipient domain passes: {got:?}");
    }

    /// Mimicry does NOT fire on a subdomain of the recipient domain
    /// (e.g. `staff.psa.systems`), which stays a first-party case.
    #[test]
    fn recipient_subdomain_is_not_mimicry() {
        let tags = vec!["Bug".to_string()];
        let got = classify_feedback_spam(&input(
            Some("teammate@staff.psa.systems"),
            "A note from a subdomain.",
            &tags,
            None,
            Some("psa"),
        ));
        assert!(got.is_none(), "recipient subdomain passes: {got:?}");
    }

    /// The URL check matches `http://` as well as `https://`.
    #[test]
    fn url_check_catches_http_and_https() {
        assert!(message_has_url("look at http://cheap.example"));
        assert!(message_has_url("look at https://cheap.example"));
        assert!(!message_has_url("look at example.com"));
        assert!(!message_has_url("look at https:// nothing"));
    }

    /// Without any inputs, the classifier returns clean.
    #[test]
    fn empty_input_is_clean() {
        let got = classify_feedback_spam(&input(None, "", &[], None, None));
        assert!(got.is_none());
    }
}
