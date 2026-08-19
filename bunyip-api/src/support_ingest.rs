//! BUNYIP-571 slice 3b: poll the support IMAP mailbox and ingest replies into
//! the support queue.
//!
//! The poller is always spawned; each tick re-reads `email_config`, so an admin
//! enabling IMAP (or changing the host/credentials) takes effect without a
//! restart. A disabled or unconfigured mailbox is a no-op. Fetching uses
//! `BODY.PEEK[]` and marks a message `\Seen` only after it is successfully
//! ingested, so a transient failure leaves it for the next poll.

use std::time::Duration;

use bunyip_domain::config::{Config, EmailConfig, GovernedSecret};
use bunyip_domain::models::NewInboundMessage;
use bunyip_domain::repositories::{EmailConfigRepository, SupportRepository};
use bunyip_domain::services::AppKeySet;
use futures_util::StreamExt;
use mail_parser::{HeaderValue, MessageParser};
use sqlx::PgPool;

/// Strip the angle brackets from a Message-ID so an inbound id, its
/// `In-Reply-To` / `References`, and our own sent ids all compare in one form.
fn strip_brackets(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

/// The (bracket-stripped) Message-IDs in an `In-Reply-To` / `References` header.
fn header_ids(value: &HeaderValue) -> Vec<String> {
    match value {
        HeaderValue::Text(t) => vec![strip_brackets(t)],
        HeaderValue::TextList(list) => list.iter().map(|s| strip_brackets(s)).collect(),
        _ => Vec::new(),
    }
}

/// Parse a raw RFC 822 message into the fields the support queue threads on.
/// Returns `None` only when the bytes do not parse as a message at all.
pub fn parse_inbound(raw: &[u8]) -> Option<NewInboundMessage> {
    let msg = MessageParser::default().parse(raw)?;

    let (from_email, from_name) = msg
        .from()
        .and_then(|addr| addr.first())
        .map(|a| {
            (
                a.address().unwrap_or_default().to_string(),
                a.name().map(|n| n.to_string()).filter(|n| !n.is_empty()),
            )
        })
        .unwrap_or_default();

    let subject = msg.subject().unwrap_or("(no subject)").to_string();
    let message_id = msg.message_id().map(strip_brackets);
    let in_reply_to = header_ids(msg.in_reply_to()).into_iter().next();
    let references = header_ids(msg.references());
    // Prefer the plain-text body; fall back to the HTML so a text-less message
    // still lands with something readable.
    let body_text = msg
        .body_text(0)
        .map(|c| c.to_string())
        .or_else(|| msg.body_html(0).map(|c| c.to_string()))
        .unwrap_or_default();
    let body_html = msg.body_html(0).map(|c| c.to_string());

    Some(NewInboundMessage {
        subject,
        from_email,
        from_name,
        to_email: None,
        body_text,
        body_html,
        message_id,
        in_reply_to,
        references,
    })
}

/// One poll: connect, ingest every unseen message, and mark each ingested one
/// `\Seen`. Returns the count ingested; a disabled or unconfigured mailbox is a
/// no-op returning 0.
pub async fn poll_once(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
) -> anyhow::Result<usize> {
    let row = EmailConfigRepository::get(pool).await?;
    let cfg = EmailConfig::from_db_row(&row, None, config.is_production());
    if !cfg.imap_enabled || cfg.imap_host.is_empty() || cfg.imap_username.is_empty() {
        return Ok(0);
    }
    let Some(password) =
        crate::secrets::read_secret(pool, config, key_set, GovernedSecret::SupportImapPassword)
            .await?
    else {
        return Ok(0);
    };

    let tcp = tokio::net::TcpStream::connect((cfg.imap_host.as_str(), cfg.imap_port)).await?;
    let tls_stream = async_native_tls::TlsConnector::new()
        .connect(cfg.imap_host.as_str(), tcp)
        .await?;
    let client = async_imap::Client::new(tls_stream);
    let mut session = client
        .login(&cfg.imap_username, &password)
        .await
        .map_err(|(e, _client)| e)?;
    session.select(&cfg.imap_mailbox).await?;

    let unseen = session.search("UNSEEN").await?;
    if unseen.is_empty() {
        let _ = session.logout().await;
        return Ok(0);
    }

    // Drain the fetch stream first (it borrows the session mutably), collecting
    // each body with its sequence number, then ingest and mark seen.
    let seq_set = unseen
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut bodies: Vec<(u32, Vec<u8>)> = Vec::new();
    {
        let mut stream = session.fetch(&seq_set, "BODY.PEEK[]").await?;
        while let Some(item) = stream.next().await {
            let fetch = item?;
            if let Some(body) = fetch.body() {
                bodies.push((fetch.message, body.to_vec()));
            }
        }
    }

    let mut ingested = 0usize;
    for (seq, raw) in bodies {
        match parse_inbound(&raw) {
            Some(parsed) => {
                if let Err(e) = SupportRepository::ingest_inbound(pool, &parsed).await {
                    tracing::warn!(error = %e, seq, "support ingest failed; leaving unseen for retry");
                    continue;
                }
                mark_seen(&mut session, seq).await;
                ingested += 1;
            }
            None => {
                tracing::warn!(
                    seq,
                    "support message did not parse; marking seen to skip it"
                );
                mark_seen(&mut session, seq).await;
            }
        }
    }

    let _ = session.logout().await;
    Ok(ingested)
}

/// Set `\Seen` on one message, draining the store response stream. Best-effort:
/// a store failure only means the message is re-fetched next poll, and the
/// Message-ID unique index makes a re-ingest a no-op.
async fn mark_seen<S>(session: &mut async_imap::Session<S>, seq: u32)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    match session.store(seq.to_string(), "+FLAGS (\\Seen)").await {
        Ok(mut stream) => while stream.next().await.is_some() {},
        Err(e) => tracing::warn!(error = %e, seq, "failed to mark support message seen"),
    }
}

/// Spawn the support-mailbox poller. Always spawned; each tick re-reads the
/// config so enabling IMAP from the admin page takes effect without a restart.
pub fn spawn(pool: PgPool, config: Config, key_set: AppKeySet) {
    let secs = config.email.imap_poll_secs.max(10);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        ticker.tick().await; // the first tick fires immediately; skip it.
        loop {
            ticker.tick().await;
            match poll_once(&pool, &config, &key_set).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(ingested = n, "support mailbox poll ingested messages"),
                Err(e) => tracing::warn!(error = %e, "support mailbox poll failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inbound_extracts_threading_fields() {
        let raw = b"From: Jane Doe <jane@ext.example>\r\n\
Subject: Re: Welcome\r\n\
Message-ID: <reply-2@ext.example>\r\n\
In-Reply-To: <welcome-1@psa.systems>\r\n\
References: <welcome-1@psa.systems> <ack-0@psa.systems>\r\n\
Content-Type: text/plain\r\n\
\r\n\
Thanks, this worked!\r\n";
        let parsed = parse_inbound(raw).expect("parses");
        assert_eq!(parsed.from_email, "jane@ext.example");
        assert_eq!(parsed.from_name.as_deref(), Some("Jane Doe"));
        assert_eq!(parsed.subject, "Re: Welcome");
        // Ids are stored bracket-stripped so inbound, header and sent ids match.
        assert_eq!(parsed.message_id.as_deref(), Some("reply-2@ext.example"));
        assert_eq!(parsed.in_reply_to.as_deref(), Some("welcome-1@psa.systems"));
        assert_eq!(
            parsed.references,
            vec![
                "welcome-1@psa.systems".to_string(),
                "ack-0@psa.systems".to_string()
            ]
        );
        assert!(parsed.body_text.contains("Thanks, this worked!"));
    }

    #[test]
    fn parse_inbound_tolerates_a_bare_message() {
        // No From, no threading headers: still ingestible (an unknown sender is
        // still a support item per the acceptance criteria).
        let parsed = parse_inbound(b"Subject: Help\r\n\r\nplease help").expect("parses");
        assert_eq!(parsed.subject, "Help");
        assert!(parsed.message_id.is_none());
        assert!(parsed.in_reply_to.is_none());
        assert!(parsed.references.is_empty());
    }
}
