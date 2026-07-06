//! `gen-demo-seed` - deterministically generate the `demo-msp` seed template (PSA-51).
//!
//! Emits a canonical seed JSON (schema per PSA-50) sized to populate every admin
//! and member surface in the demo video: ~42 users across roles/statuses/tiers,
//! a small app catalog with groups + entitlements, and a support inbox. The
//! output is a pure function of fixed input data (no RNG, no clock), so it is
//! byte-stable: re-running regenerates an identical `demo-msp.json`. It never
//! touches a database - it only writes a file the `seed` loader consumes.
//!
//! Usage:
//!   gen-demo-seed [path]   write the template to `path` (default: stdout)

use serde_json::{json, Value};

/// Shared login for every demo account (the loader hashes it). Not a secret -
/// this is throwaway demo data under the reserved seed domain.
const DEFAULT_PASSWORD: &str = "demo-access-2026";

/// 42 first / last names (computing pioneers) -> deterministic, unique emails.
#[rustfmt::skip]
const FIRSTS: [&str; 42] = [
    "Ada", "Grace", "Alan", "Linus", "Barbara", "Katherine", "Dennis", "Margaret", "Ken", "Radia",
    "Tim", "Shafi", "Leslie", "Frances", "John", "Anita", "Guido", "Adele", "Bjarne", "Hedy",
    "Donald", "Joan", "Vint", "Karen", "Brian", "Sophie", "James", "Evelyn", "Rob", "Carla", "Doug",
    "Mary", "Niklaus", "Erna", "Edsger", "Ruth", "Bill", "Annie", "Steve", "Lynn", "Dan", "Jean",
];
#[rustfmt::skip]
const LASTS: [&str; 42] = [
    "Lovelace", "Hopper", "Turing", "Torvalds", "Liskov", "Johnson", "Ritchie", "Hamilton",
    "Thompson", "Perlman", "Bernerslee", "Goldwasser", "Lamport", "Allen", "McCarthy", "Borg",
    "Vanrossum", "Goldstine", "Stroustrup", "Lamarr", "Knuth", "Clarke", "Cerf", "Sparck",
    "Kernighan", "Wilson", "Gosling", "Boyd", "Pike", "Meyer", "Engelbart", "Keller", "Wirth",
    "Schneider", "Dijkstra", "Teitelbaum", "Gates", "Easley", "Wozniak", "Conway", "Bricklin",
    "Sammet",
];

/// (slug, display name, group slug, restricted).
const APPS: [(&str, &str, &str, bool); 8] = [
    ("mokosh", "Mokosh", "core", false),
    ("bunyip", "Bunyip", "core", false),
    ("lets-chat", "Let's Chat", "core", false),
    ("vault", "Vault", "add-ons", true),
    ("backup", "Backup", "add-ons", false),
    ("monitor", "Monitor", "add-ons", false),
    ("labs", "Labs", "beta", true),
    ("insights", "Insights", "beta", false),
];

fn email(i: usize) -> String {
    format!(
        "{}.{}@demo.psa-systems.test",
        FIRSTS[i].to_ascii_lowercase(),
        LASTS[i].to_ascii_lowercase()
    )
}

/// Build the whole template deterministically and pretty-print it (trailing
/// newline). Fixed input order + serde_json's stable key ordering make the
/// output byte-stable.
fn generate() -> String {
    let groups: Vec<Value> = [("core", "Core", 0), ("add-ons", "Add-ons", 1), ("beta", "Beta", 2)]
        .iter()
        .map(|(slug, name, order)| {
            json!({"slug": slug, "name": slug, "display_name": name, "sort_order": order})
        })
        .collect();

    let applications: Vec<Value> = APPS
        .iter()
        .map(|(slug, display, group, restricted)| {
            json!({
                "slug": slug,
                "name": slug,
                "display_name": display,
                "container_name": slug,
                "group_slug": group,
                "restricted": restricted,
                "description": format!("{display} for your MSP"),
            })
        })
        .collect();

    let mut users: Vec<Value> = Vec::with_capacity(42);
    let mut price_locked_count = 0;
    for i in 0..42usize {
        let role = if i < 2 { "admin" } else { "subscriber" };
        let lifetime = (2..=4).contains(&i);
        let (status, mut tier) = if lifetime {
            ("active", "lifetime")
        } else if (5..=7).contains(&i) {
            ("past_due", "standard")
        } else if (8..=9).contains(&i) {
            ("grace_period", "standard")
        } else if (10..=11).contains(&i) {
            ("canceled", "standard")
        } else if (12..=14).contains(&i) {
            ("none", "free")
        } else {
            ("active", "standard")
        };

        // Price-lock the first 12 active, non-lifetime accounts as early
        // adopters, so the admin views show a spread of locked prices.
        let mut membership = json!({
            "status": status,
            "tier": tier,
            "lifetime": lifetime,
            "price_locked": false,
        });
        if status == "active" && !lifetime && price_locked_count < 12 {
            tier = "early_adopter";
            membership["tier"] = json!(tier);
            membership["price_locked"] = json!(true);
            membership["locked_price_amount"] = json!(4900);
            price_locked_count += 1;
        }

        // Two unverified accounts, to exercise the unverified state.
        let verified = !(i == 20 || i == 21);

        users.push(json!({
            "email": email(i),
            "role": role,
            "verified": verified,
            "first_name": FIRSTS[i],
            "last_name": LASTS[i],
            "membership": membership,
        }));
    }

    // Grant the two restricted apps (vault, labs) to six specific users.
    let entitlements: Vec<Value> = [
        (0usize, "vault"),
        (2, "vault"),
        (15, "vault"),
        (3, "labs"),
        (16, "labs"),
        (17, "labs"),
    ]
    .iter()
    .map(|(i, slug)| json!({"user_email": email(*i), "app_slug": slug}))
    .collect();

    // Support inbox: six genuine entries plus one obvious spam.
    let feedback = vec![
        json!({"email": email(5), "subject": "Love the new dashboard", "message": "The launcher is so much faster now. Great work.", "tags": ["praise"]}),
        json!({"email": email(6), "subject": "Question about billing", "message": "How do I update the card on my account?", "tags": ["billing", "question"]}),
        json!({"email": email(7), "subject": "Feature request: dark mode everywhere", "message": "A few admin pages still flash white. Could they follow the theme?", "tags": ["feature"]}),
        json!({"email": email(8), "subject": "Small bug on mobile", "message": "The downloads list overflows sideways on my phone.", "tags": ["bug"]}),
        json!({"email": email(9), "subject": "Thank you", "message": "The lifetime plan sold me. Locked my price and never looked back.", "tags": ["praise"]}),
        json!({"email": email(10), "subject": "Integration idea", "message": "Would love an SSO hook into our internal wiki.", "tags": ["feature", "integration"]}),
        json!({"email": email(11), "subject": "WIN A FREE PRIZE NOW", "message": "Click here to claim your reward!!!", "tags": [], "is_spam": true}),
    ];

    let doc = json!({
        "version": 1,
        "default_password": DEFAULT_PASSWORD,
        "application_groups": groups,
        "applications": applications,
        "users": users,
        "entitlements": entitlements,
        "feedback": feedback,
    });

    let mut out = serde_json::to_string_pretty(&doc).expect("serialize demo seed");
    out.push('\n');
    out
}

fn main() -> std::io::Result<()> {
    let doc = generate();
    match std::env::args().nth(1) {
        Some(path) => {
            std::fs::write(&path, doc)?;
            eprintln!("wrote {path}");
        }
        None => print!("{doc}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::generate;

    #[test]
    fn committed_template_is_up_to_date() {
        // The committed demo-msp.json must be exactly what the generator emits;
        // an edit to the generator without regenerating fails here.
        assert_eq!(
            generate(),
            include_str!("../../seed/demo-msp.json"),
            "demo-msp.json is stale: run `cargo run --bin gen-demo-seed -- bunyip-api/seed/demo-msp.json`"
        );
    }

    #[test]
    fn generated_template_parses_and_validates() {
        let file = bunyip_api::seed::parse(&generate()).expect("demo template must validate");
        assert_eq!(file.application_groups.len(), 3);
        assert_eq!(file.applications.len(), 8);
        assert_eq!(file.users.len(), 42);
        assert_eq!(file.entitlements.len(), 6);
        assert_eq!(file.feedback.len(), 7);
        assert_eq!(
            file.users.iter().filter(|u| u.membership.lifetime).count(),
            3
        );
        assert_eq!(
            file.users
                .iter()
                .filter(|u| u.membership.price_locked)
                .count(),
            12
        );
        assert_eq!(file.users.iter().filter(|u| u.role == "admin").count(), 2);
        assert!(file.feedback.iter().any(|f| f.is_spam));
    }
}
