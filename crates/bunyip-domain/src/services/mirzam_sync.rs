//! Keeping account holders on Mirzam's two lists (BUNYIP-998).
//!
//! When the Mirzam integration is switched on and fully configured (address,
//! both list slugs, API token), bunyip mirrors three account events onto the
//! product-updates and notices lists through Mirzam's REST API
//! (`docs/account-sync.md` in the Mirzam repository is the design):
//!
//! - **email verified**: the address is added to both lists;
//! - **account reactivated** (an admin clears a deactivation or a delete): the
//!   same adds as on verification, when the address is verified;
//! - **email changed**: the subscriber's address is changed in place
//!   (`PATCH`), falling back to add-new-and-unsubscribe-old when Mirzam already
//!   has the new address, or to add-new when it never had the old one;
//! - **account deleted**: the address is unsubscribed from both lists, and
//!   nothing is erased.
//!
//! An account that never verified its address never reaches Mirzam.
//!
//! The two lists differ on re-adding someone who is unsubscribed. The
//! product-updates add sends `keep_unsubscribed: true`, so a sync never undoes
//! a reader's own opt-out (an admin removal cannot be told apart from one, and
//! for opt-out mail bunyip errs on the side of not mailing). The notices add
//! leaves the flag out, so Mirzam takes it as new consent and re-confirms the
//! address: nobody leaves the notices list by their own choice (Mirzam's
//! preference centre never offers it and its unsubscribe links refuse it), so
//! an unsubscribed notices membership can only be bunyip's own removal, as on
//! a deactivation. Deactivating removes the account from both lists;
//! reactivating rejoins notices, and rejoins product updates only if the
//! person had not left it themselves.
//!
//! Every call runs OFF the request path: [`MirzamSync::notify`] spawns a task
//! and returns at once, so a Mirzam outage can never fail or slow a sign-up,
//! a verification, an email change or a delete. Each call is retried a bounded
//! number of times with backoff when the failure looks transient. A call that
//! runs out of attempts is logged at `warn` (user id only) and recorded in
//! `mirzam_config.last_error`, which the admin Mirzam page and the integration
//! status show; the next call that succeeds clears it. The recorded text names
//! the operation, the list, the account's user id and Mirzam's answer, and
//! never the API token or the address.
//!
//! [`MirzamClient`] and the `*_account` functions are the reusable half: the
//! backfill makes the same "email verified" calls with them.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::models::mirzam::MirzamConfigRow;
use crate::models::User;
use crate::repositories::{MirzamConfigRepository, UserRepository};
use crate::services::mirzam::{without_url, MIRZAM_HTTP_TIMEOUT};

/// The waits between attempts: three attempts in all, after 1s and then 4s,
/// like the account-delete webhook's bounded retries.
pub const MIRZAM_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

/// The consent record Mirzam stores with an account holder's subscription.
pub const MIRZAM_CONSENT_NOTE: &str = "Account holder";

/// How much of Mirzam's answer a recorded failure keeps.
const ANSWER_SUMMARY_MAX_CHARS: usize = 200;

/// A Mirzam call that failed. `Display` is the admin-facing summary; it is
/// built with the token and the addresses of the call already redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirzamCallError {
    /// Mirzam's HTTP status, `None` when no answer arrived.
    pub status: Option<u16>,
    /// What went wrong: Mirzam's error message, or the transport failure.
    pub detail: String,
}

impl MirzamCallError {
    fn transport(detail: impl Into<String>) -> Self {
        Self {
            status: None,
            detail: detail.into(),
        }
    }

    /// Worth another attempt: no answer, a timeout, a rate limit or a server
    /// error. A refused token or a rejected body fails the same way again.
    pub fn is_transient(&self) -> bool {
        match self.status {
            None => true,
            Some(status) => status == 408 || status == 429 || status >= 500,
        }
    }
}

impl std::fmt::Display for MirzamCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.status, self.detail.is_empty()) {
            (Some(status), true) => write!(f, "Mirzam answered {status}."),
            (Some(status), false) => write!(f, "Mirzam answered {status}: {}", self.detail),
            (None, _) => write!(f, "{}", self.detail),
        }
    }
}

/// `POST /api/v1/subscribers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// 201: added and confirmed.
    Added,
    /// 409: already on the list.
    AlreadyOn,
    /// 409: the address unsubscribed from the list and `keep_unsubscribed`
    /// left it as it is.
    LeftAlone,
}

/// The error code Mirzam (v0.38.0 and later) gives a `409` to an add that
/// left an unsubscribed address alone; "already on" keeps code `conflict`.
const LEFT_ALONE_CODE: &str = "unsubscribed";

/// `PATCH /api/v1/subscribers/{old}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveOutcome {
    /// 200: the subscriber now has the new address, subscriptions kept.
    Moved,
    /// 409: the new address already belongs to another subscriber.
    NewAddressTaken,
    /// 404: Mirzam has no subscriber with the old address.
    OldAddressUnknown,
}

/// `POST /api/v1/subscribers/{email}/unsubscribe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// 200: unsubscribed.
    Removed,
    /// 409: was not on the list.
    NotSubscribed,
    /// 404: Mirzam has no subscriber with the address.
    UnknownAddress,
}

#[derive(Serialize)]
struct AddBody<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    list: &'a str,
    consent: &'static str,
    consent_note: &'static str,
    /// Sent only when true: without it, Mirzam re-subscribes an address that
    /// had unsubscribed from the list.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    keep_unsubscribed: bool,
}

/// A small Mirzam API client: one attempt per call, no redirects followed
/// (like the connection check, so a wrong saved address fails loudly), a short
/// per-request timeout. Retrying is [`with_retries`]'s job.
#[derive(Clone)]
pub struct MirzamClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl MirzamClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self, MirzamCallError> {
        let http = reqwest::Client::builder()
            .timeout(MIRZAM_HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                MirzamCallError::transport(format!("Could not build the HTTP client: {e}"))
            })?;
        Ok(Self {
            http,
            base_url: base_url.trim().trim_end_matches('/').to_string(),
            token: token.trim().to_string(),
        })
    }

    fn subscriber_url(&self, email: &str) -> String {
        format!(
            "{}/api/v1/subscribers/{}",
            self.base_url,
            urlencoding::encode(email)
        )
    }

    /// Send one request and return Mirzam's status, or the failure with the
    /// token and `addresses` redacted from anything that could carry them.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        addresses: &[&str],
    ) -> Result<(u16, String), MirzamCallError> {
        let response = match request.bearer_auth(&self.token).send().await {
            Ok(response) => response,
            Err(e) if e.is_timeout() => {
                return Err(MirzamCallError::transport(format!(
                    "Mirzam did not answer within {} seconds.",
                    MIRZAM_HTTP_TIMEOUT.as_secs()
                )))
            }
            // The reqwest error names the request URL, which carries the
            // address; the root cause alone does not.
            Err(e) => {
                return Err(MirzamCallError::transport(self.redact(
                    &format!("Could not reach Mirzam: {}", without_url(&e)),
                    addresses,
                )))
            }
        };
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        Ok((status, body))
    }

    fn failure(&self, status: u16, body: &str, addresses: &[&str]) -> MirzamCallError {
        MirzamCallError {
            status: Some(status),
            detail: summarize_answer(&self.redact(body, addresses)),
        }
    }

    /// Replace the token and every address with a placeholder. Done on the
    /// whole text, before any truncation, so no prefix of either survives.
    fn redact(&self, text: &str, addresses: &[&str]) -> String {
        let mut text = text.to_string();
        if !self.token.is_empty() {
            text = text.replace(&self.token, "[token]");
        }
        for address in addresses.iter().filter(|a| !a.is_empty()) {
            text = text.replace(address, "[address]");
            text = text.replace(&address.to_lowercase(), "[address]");
            text = text.replace(urlencoding::encode(address).as_ref(), "[address]");
        }
        text
    }

    /// Add `email` to the list `list_slug`, confirmed at once on the account
    /// holder consent record. With `keep_unsubscribed`, an address that left
    /// the list is left as it is; without it, Mirzam re-subscribes it.
    pub async fn add(
        &self,
        email: &str,
        name: Option<&str>,
        list_slug: &str,
        keep_unsubscribed: bool,
    ) -> Result<AddOutcome, MirzamCallError> {
        let body = AddBody {
            email,
            name,
            list: list_slug,
            consent: "recorded",
            consent_note: MIRZAM_CONSENT_NOTE,
            keep_unsubscribed,
        };
        let request = self
            .http
            .post(format!("{}/api/v1/subscribers", self.base_url))
            .json(&body);
        match self.send(request, &[email]).await? {
            (status, _) if (200..300).contains(&status) => Ok(AddOutcome::Added),
            (409, body) if error_code(&body).as_deref() == Some(LEFT_ALONE_CODE) => {
                Ok(AddOutcome::LeftAlone)
            }
            (409, _) => Ok(AddOutcome::AlreadyOn),
            (status, body) => Err(self.failure(status, &body, &[email])),
        }
    }

    /// Change the subscriber `old_email` to `new_email`, keeping every
    /// subscription. A taken new address and an unknown old one are outcomes,
    /// not errors: the caller decides the fallback.
    pub async fn move_address(
        &self,
        old_email: &str,
        new_email: &str,
    ) -> Result<MoveOutcome, MirzamCallError> {
        let request = self
            .http
            .patch(self.subscriber_url(old_email))
            .json(&serde_json::json!({ "email": new_email }));
        let addresses = [old_email, new_email];
        match self.send(request, &addresses).await? {
            (status, _) if (200..300).contains(&status) => Ok(MoveOutcome::Moved),
            (409, _) => Ok(MoveOutcome::NewAddressTaken),
            (404, _) => Ok(MoveOutcome::OldAddressUnknown),
            (status, body) => Err(self.failure(status, &body, &addresses)),
        }
    }

    /// Unsubscribe `email` from the list `list_slug`. Never erases anything.
    pub async fn remove(
        &self,
        email: &str,
        list_slug: &str,
    ) -> Result<RemoveOutcome, MirzamCallError> {
        let request = self
            .http
            .post(format!("{}/unsubscribe", self.subscriber_url(email)))
            .json(&serde_json::json!({ "list": list_slug }));
        match self.send(request, &[email]).await? {
            (status, _) if (200..300).contains(&status) => Ok(RemoveOutcome::Removed),
            (409, _) => Ok(RemoveOutcome::NotSubscribed),
            (404, _) => Ok(RemoveOutcome::UnknownAddress),
            (status, body) => Err(self.failure(status, &body, &[email])),
        }
    }
}

/// One line of Mirzam's answer: its `error.message` (or `error.code`) when the
/// body is Mirzam's JSON error shape, otherwise the text itself, whitespace
/// collapsed and cut to [`ANSWER_SUMMARY_MAX_CHARS`].
/// The `error.code` of a Mirzam error answer, if it has one.
fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("error")?
        .get("code")?
        .as_str()
        .map(str::to_string)
}

fn summarize_answer(body: &str) -> String {
    let from_json = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let error = v.get("error").unwrap_or(&v);
            error
                .get("message")
                .or_else(|| error.get("code"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        });
    let text = from_json.unwrap_or_else(|| body.to_string());
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > ANSWER_SUMMARY_MAX_CHARS {
        let cut: String = text.chars().take(ANSWER_SUMMARY_MAX_CHARS).collect();
        format!("{cut}…")
    } else {
        text
    }
}

/// Run `op` until it succeeds, fails for good, or the attempts run out: one
/// attempt plus one more after each of `delays`, retrying only failures that
/// look transient.
pub async fn with_retries<T, F, Fut>(delays: &[Duration], mut op: F) -> Result<T, MirzamCallError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, MirzamCallError>>,
{
    let mut waits = delays.iter();
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(e) if e.is_transient() => match waits.next() {
                Some(wait) => tokio::time::sleep(*wait).await,
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
}

/// The two list slugs the account holder is kept on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirzamLists {
    pub updates: String,
    pub notices: String,
}

impl MirzamLists {
    fn both(&self) -> [&str; 2] {
        [&self.updates, &self.notices]
    }
}

/// What the two "email verified" adds answered: each list's outcome, or the
/// admin-facing sentence for a call that failed for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAdd {
    pub updates: Result<AddOutcome, String>,
    pub notices: Result<AddOutcome, String>,
}

impl AccountAdd {
    /// The sentences of the calls that failed for good, product updates first.
    pub fn errors(self) -> Vec<String> {
        [self.updates, self.notices]
            .into_iter()
            .filter_map(Result::err)
            .collect()
    }
}

/// The "email verified" calls, also made on a reactivation, by the email
/// change fallbacks and by the backfill: add `email` to the product-updates
/// list keeping an unsubscribe (the reader may have left it themselves) and to
/// the notices list re-subscribing (only bunyip ever removes anyone from it).
pub async fn add_account(
    client: &MirzamClient,
    lists: &MirzamLists,
    delays: &[Duration],
    user_id: Uuid,
    email: &str,
    name: Option<&str>,
) -> AccountAdd {
    let failed = |list: &str, e: MirzamCallError| {
        format!("Adding user {user_id} to list {list} failed: {e}")
    };
    let updates = with_retries(delays, || client.add(email, name, &lists.updates, true))
        .await
        .map_err(|e| failed(&lists.updates, e));
    let notices = with_retries(delays, || client.add(email, name, &lists.notices, false))
        .await
        .map_err(|e| failed(&lists.notices, e));
    AccountAdd { updates, notices }
}

/// The "account deleted" calls: unsubscribe `email` from both lists.
pub async fn remove_account(
    client: &MirzamClient,
    lists: &MirzamLists,
    delays: &[Duration],
    user_id: Uuid,
    email: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    for list in lists.both() {
        if let Err(e) = with_retries(delays, || client.remove(email, list)).await {
            errors.push(format!(
                "Removing user {user_id} from list {list} failed: {e}"
            ));
        }
    }
    errors
}

/// The "email changed" calls for an account verified on both sides: change the
/// address in place; when Mirzam already has the new address, add it to both
/// lists and unsubscribe the old one; when Mirzam never had the old one, add
/// the new one.
pub async fn move_account(
    client: &MirzamClient,
    lists: &MirzamLists,
    delays: &[Duration],
    user_id: Uuid,
    old_email: &str,
    new_email: &str,
    name: Option<&str>,
) -> Vec<String> {
    match with_retries(delays, || client.move_address(old_email, new_email)).await {
        Ok(MoveOutcome::Moved) => Vec::new(),
        Ok(MoveOutcome::NewAddressTaken) => {
            let mut errors = add_account(client, lists, delays, user_id, new_email, name)
                .await
                .errors();
            errors.extend(remove_account(client, lists, delays, user_id, old_email).await);
            errors
        }
        Ok(MoveOutcome::OldAddressUnknown) => {
            add_account(client, lists, delays, user_id, new_email, name)
                .await
                .errors()
        }
        Err(e) => vec![format!(
            "Moving user {user_id} to a new address failed: {e}"
        )],
    }
}

/// An account event that may change what Mirzam should hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountChange {
    /// The account's verified address belongs on both lists: it became
    /// verified, or the account was reactivated. The address and name are read
    /// when the task runs, and nothing happens unless the account is still
    /// live and verified then.
    Verified { user_id: Uuid },
    /// The account's address changed, with its verified state either side.
    EmailChanged {
        user_id: Uuid,
        old_email: String,
        was_verified: bool,
        new_email: String,
        now_verified: bool,
    },
    /// The account was deleted. The address is captured before the row goes.
    Deleted {
        user_id: Uuid,
        email: String,
        was_verified: bool,
    },
}

impl AccountChange {
    /// Whether this change can lead to a call at all, decided before a task
    /// is spawned: an address that was never verified never reaches Mirzam.
    fn may_call(&self) -> bool {
        match self {
            Self::Verified { .. } => true,
            Self::EmailChanged {
                was_verified,
                now_verified,
                ..
            } => *was_verified || *now_verified,
            Self::Deleted { was_verified, .. } => *was_verified,
        }
    }

    fn user_id(&self) -> Uuid {
        match self {
            Self::Verified { user_id }
            | Self::EmailChanged { user_id, .. }
            | Self::Deleted { user_id, .. } => *user_id,
        }
    }
}

/// Where the API token comes from. bunyip-api implements it over the
/// governed-secret providers, which live in that crate.
#[async_trait]
pub trait MirzamTokenSource: Send + Sync {
    /// `Ok(None)` (or blank) when no token is set, which leaves the
    /// integration incomplete and makes no call. `Err` when the declared
    /// provider could not be read, which is recorded as a failure.
    async fn token(&self) -> Result<Option<String>, String>;
}

/// The settings a sync runs with, when the integration is on and complete.
pub fn active_lists(row: &MirzamConfigRow) -> Option<MirzamLists> {
    (row.enabled && row.settings_complete()).then(|| MirzamLists {
        updates: row.updates_list.trim().to_string(),
        notices: row.notices_list.trim().to_string(),
    })
}

/// The account's display name for Mirzam: first and last name, either alone,
/// or none.
pub fn account_display_name(user: &User) -> Option<String> {
    let name = [user.first_name.as_deref(), user.last_name.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!name.is_empty()).then_some(name)
}

/// What one change asks of Mirzam, resolved against the database.
enum Plan {
    Add {
        email: String,
        name: Option<String>,
    },
    Remove {
        email: String,
    },
    Move {
        old_email: String,
        new_email: String,
        name: Option<String>,
    },
}

#[derive(Default)]
struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

/// Decrements the in-flight count when a spawned sync task ends, however it
/// ends.
struct InFlightGuard(Arc<InFlight>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// The handle every account-event path holds. Cheap to clone.
#[derive(Clone)]
pub struct MirzamSync {
    pool: PgPool,
    token_source: Arc<dyn MirzamTokenSource>,
    retry_delays: Arc<[Duration]>,
    in_flight: Arc<InFlight>,
}

impl MirzamSync {
    pub fn new(pool: PgPool, token_source: Arc<dyn MirzamTokenSource>) -> Self {
        Self {
            pool,
            token_source,
            retry_delays: Arc::from(&MIRZAM_RETRY_DELAYS[..]),
            in_flight: Arc::default(),
        }
    }

    /// Replace the waits between attempts (tests use milliseconds).
    pub fn with_retry_delays(mut self, delays: &[Duration]) -> Self {
        self.retry_delays = delays.into();
        self
    }

    /// Mirror `change` onto Mirzam in a spawned task and return at once. The
    /// caller's request never waits for Mirzam.
    pub fn notify(&self, change: AccountChange) {
        if !change.may_call() {
            return;
        }
        self.in_flight.count.fetch_add(1, Ordering::SeqCst);
        let guard = InFlightGuard(self.in_flight.clone());
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            this.apply(change).await;
        });
    }

    /// Resolve once every task [`Self::notify`] spawned has finished. Tests
    /// await this instead of sleeping.
    pub async fn idle(&self) {
        loop {
            let notified = self.in_flight.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight.count.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Apply `change` now, awaiting every call: the body of the spawned task.
    /// Nothing is called while the integration is off or incomplete.
    pub async fn apply(&self, change: AccountChange) {
        let user_id = change.user_id();
        let row = match MirzamConfigRepository::get(&self.pool).await {
            Ok(row) => row,
            Err(e) => {
                tracing::warn!(error = %e, user_id = %user_id, "Mirzam sync: could not read mirzam_config; nothing sent");
                return;
            }
        };
        let Some(lists) = active_lists(&row) else {
            return;
        };
        let token = match self.token_source.token().await {
            Ok(Some(token)) if !token.trim().is_empty() => token,
            Ok(_) => return,
            Err(e) => {
                self.finish(
                    user_id,
                    vec![format!(
                        "Reading the Mirzam API token for user {user_id} failed: {e}"
                    )],
                )
                .await;
                return;
            }
        };
        let plan = match self.plan(change).await {
            Ok(Some(plan)) => plan,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, user_id = %user_id, "Mirzam sync: could not read the account; nothing sent");
                return;
            }
        };
        let client = match MirzamClient::new(&row.base_url, &token) {
            Ok(client) => client,
            Err(e) => {
                self.finish(
                    user_id,
                    vec![format!("Calling Mirzam for user {user_id} failed: {e}")],
                )
                .await;
                return;
            }
        };
        let delays = &self.retry_delays[..];
        let errors = match &plan {
            Plan::Add { email, name } => {
                add_account(&client, &lists, delays, user_id, email, name.as_deref())
                    .await
                    .errors()
            }
            Plan::Remove { email } => remove_account(&client, &lists, delays, user_id, email).await,
            Plan::Move {
                old_email,
                new_email,
                name,
            } => {
                move_account(
                    &client,
                    &lists,
                    delays,
                    user_id,
                    old_email,
                    new_email,
                    name.as_deref(),
                )
                .await
            }
        };
        self.finish(user_id, errors).await;
    }

    /// Turn a change into the calls it needs, or none.
    async fn plan(&self, change: AccountChange) -> Result<Option<Plan>, crate::errors::AppError> {
        Ok(match change {
            AccountChange::Verified { user_id } => {
                match UserRepository::find_by_id(&self.pool, user_id).await? {
                    Some(user) if user.email_verified => Some(Plan::Add {
                        name: account_display_name(&user),
                        email: user.email,
                    }),
                    _ => None,
                }
            }
            AccountChange::EmailChanged {
                user_id,
                old_email,
                was_verified,
                new_email,
                now_verified,
            } => {
                let same = old_email.eq_ignore_ascii_case(&new_email);
                let name = || async {
                    UserRepository::find_by_id(&self.pool, user_id)
                        .await
                        .map(|user| user.as_ref().and_then(account_display_name))
                };
                match (was_verified, now_verified) {
                    (true, true) if same => None,
                    (true, true) => Some(Plan::Move {
                        old_email,
                        new_email,
                        name: name().await?,
                    }),
                    (false, true) => Some(Plan::Add {
                        email: new_email,
                        name: name().await?,
                    }),
                    (true, false) => Some(Plan::Remove { email: old_email }),
                    (false, false) => None,
                }
            }
            AccountChange::Deleted {
                email,
                was_verified,
                ..
            } => was_verified.then_some(Plan::Remove { email }),
        })
    }

    /// Record the outcome: clear the stored failure after a clean run, or log
    /// and store this run's failures.
    async fn finish(&self, user_id: Uuid, errors: Vec<String>) {
        let outcome = if errors.is_empty() {
            MirzamConfigRepository::clear_sync_error(&self.pool).await
        } else {
            for error in &errors {
                tracing::warn!(user_id = %user_id, error = %error, "Mirzam sync call failed");
            }
            MirzamConfigRepository::record_sync_error(&self.pool, &errors.join(" ")).await
        };
        if let Err(e) = outcome {
            tracing::warn!(error = %e, user_id = %user_id, "Mirzam sync: could not record the outcome in mirzam_config");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "mzm_sync_secret_token";
    const FAST: [Duration; 2] = [Duration::from_millis(5), Duration::from_millis(5)];

    fn lists() -> MirzamLists {
        MirzamLists {
            updates: "product-updates".to_string(),
            notices: "notices".to_string(),
        }
    }

    fn client(server: &MockServer) -> MirzamClient {
        MirzamClient::new(&format!("{}/", server.uri()), TOKEN).unwrap()
    }

    async fn respond(server: &MockServer, verb: &str, at: &str, status: u16) {
        Mock::given(method(verb))
            .and(path(at))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status).set_body_json(serde_json::json!({})))
            .mount(server)
            .await;
    }

    async fn requests(server: &MockServer) -> Vec<wiremock::Request> {
        server.received_requests().await.unwrap_or_default()
    }

    #[tokio::test]
    async fn add_sends_the_account_holder_consent_and_keep_unsubscribed_only_when_asked() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/subscribers"))
            .and(body_json(serde_json::json!({
                "email": "ada@example.test",
                "name": "Ada Lovelace",
                "list": "product-updates",
                "consent": "recorded",
                "consent_note": "Account holder",
                "keep_unsubscribed": true,
            })))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/subscribers"))
            .and(body_json(serde_json::json!({
                "email": "ada@example.test",
                "name": "Ada Lovelace",
                "list": "notices",
                "consent": "recorded",
                "consent_note": "Account holder",
            })))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let c = client(&server);
        let outcome = c
            .add(
                "ada@example.test",
                Some("Ada Lovelace"),
                "product-updates",
                true,
            )
            .await;
        assert_eq!(outcome, Ok(AddOutcome::Added));
        let outcome = c
            .add("ada@example.test", Some("Ada Lovelace"), "notices", false)
            .await;
        assert_eq!(outcome, Ok(AddOutcome::Added));
    }

    /// Product updates keep a reader's own unsubscribe; the notices list,
    /// which only bunyip ever removes anyone from, is re-subscribed.
    #[tokio::test]
    async fn add_account_keeps_unsubscribed_on_updates_only() {
        let server = MockServer::start().await;
        respond(&server, "POST", "/api/v1/subscribers", 201).await;
        let errors = add_account(
            &client(&server),
            &lists(),
            &FAST,
            Uuid::nil(),
            "ada@example.test",
            None,
        )
        .await
        .errors();
        assert!(errors.is_empty(), "{errors:?}");
        let sent: Vec<serde_json::Value> = requests(&server)
            .await
            .iter()
            .map(|r| r.body_json().unwrap())
            .collect();
        assert_eq!(sent[0]["list"], "product-updates");
        assert_eq!(sent[0]["keep_unsubscribed"], true, "{}", sent[0]);
        assert_eq!(sent[1]["list"], "notices");
        assert!(sent[1].get("keep_unsubscribed").is_none(), "{}", sent[1]);
    }

    #[tokio::test]
    async fn add_treats_201_and_409_as_success_and_omits_a_missing_name() {
        let server = MockServer::start().await;
        respond(&server, "POST", "/api/v1/subscribers", 409).await;
        let outcome = client(&server)
            .add("ada@example.test", None, "notices", true)
            .await;
        assert_eq!(outcome, Ok(AddOutcome::AlreadyOn));
        let sent: serde_json::Value = requests(&server).await[0].body_json().unwrap();
        assert!(sent.get("name").is_none(), "{sent}");

        let errors = add_account(
            &client(&server),
            &lists(),
            &FAST,
            Uuid::nil(),
            "ada@example.test",
            None,
        )
        .await
        .errors();
        assert!(errors.is_empty(), "{errors:?}");
        let lists_sent: Vec<String> = requests(&server).await[1..]
            .iter()
            .map(|r| r.body_json::<serde_json::Value>().unwrap()["list"].to_string())
            .collect();
        assert_eq!(lists_sent, ["\"product-updates\"", "\"notices\""]);
    }

    /// Mirzam's two `409` answers to an add, told apart by the code alone:
    /// the message never decides.
    #[tokio::test]
    async fn an_add_tells_already_on_from_left_alone() {
        for (code, message, expected) in [
            (
                "conflict",
                "This address is already on that list (confirmed).",
                AddOutcome::AlreadyOn,
            ),
            ("unsubscribed", "Reworded.", AddOutcome::LeftAlone),
            (
                "conflict",
                "This address unsubscribed from that list (unsubscribed); left as it is.",
                AddOutcome::AlreadyOn,
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(409).set_body_json(
                    serde_json::json!({"error": {"code": code, "message": message}}),
                ))
                .mount(&server)
                .await;
            let outcome = client(&server)
                .add("ada@example.test", None, "product-updates", true)
                .await;
            assert_eq!(outcome, Ok(expected), "{code}: {message}");
        }
    }

    #[tokio::test]
    async fn remove_treats_200_409_and_404_as_success() {
        for (status, expected) in [
            (200, RemoveOutcome::Removed),
            (409, RemoveOutcome::NotSubscribed),
            (404, RemoveOutcome::UnknownAddress),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/v1/subscribers/a%2Bb%40example.test/unsubscribe"))
                .and(body_json(serde_json::json!({"list": "notices"})))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let outcome = client(&server).remove("a+b@example.test", "notices").await;
            assert_eq!(outcome, Ok(expected), "status {status}");
        }
    }

    #[tokio::test]
    async fn a_move_that_mirzam_accepts_makes_one_call() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/subscribers/old%40example.test"))
            .and(body_json(serde_json::json!({"email": "new@example.test"})))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let errors = move_account(
            &client(&server),
            &lists(),
            &FAST,
            Uuid::nil(),
            "old@example.test",
            "new@example.test",
            None,
        )
        .await;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(requests(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn a_taken_new_address_is_added_and_the_old_one_unsubscribed() {
        let server = MockServer::start().await;
        respond(
            &server,
            "PATCH",
            "/api/v1/subscribers/old%40example.test",
            409,
        )
        .await;
        respond(&server, "POST", "/api/v1/subscribers", 201).await;
        respond(
            &server,
            "POST",
            "/api/v1/subscribers/old%40example.test/unsubscribe",
            200,
        )
        .await;
        let errors = move_account(
            &client(&server),
            &lists(),
            &FAST,
            Uuid::nil(),
            "old@example.test",
            "new@example.test",
            Some("Ada"),
        )
        .await;
        assert!(errors.is_empty(), "{errors:?}");
        let calls: Vec<(String, String)> = requests(&server)
            .await
            .iter()
            .map(|r| (r.method.to_string(), r.url.path().to_string()))
            .collect();
        assert_eq!(
            calls,
            [
                ("PATCH", "/api/v1/subscribers/old%40example.test"),
                ("POST", "/api/v1/subscribers"),
                ("POST", "/api/v1/subscribers"),
                ("POST", "/api/v1/subscribers/old%40example.test/unsubscribe"),
                ("POST", "/api/v1/subscribers/old%40example.test/unsubscribe"),
            ]
            .map(|(m, p)| (m.to_string(), p.to_string()))
        );
        let added: serde_json::Value = requests(&server).await[1].body_json().unwrap();
        assert_eq!(added["email"], "new@example.test");
        assert_eq!(added["name"], "Ada");
        assert_eq!(added["keep_unsubscribed"], true, "{added}");
        let notices: serde_json::Value = requests(&server).await[2].body_json().unwrap();
        assert_eq!(notices["list"], "notices");
        assert!(notices.get("keep_unsubscribed").is_none(), "{notices}");
    }

    #[tokio::test]
    async fn an_unknown_old_address_adds_the_new_one() {
        let server = MockServer::start().await;
        respond(
            &server,
            "PATCH",
            "/api/v1/subscribers/old%40example.test",
            404,
        )
        .await;
        respond(&server, "POST", "/api/v1/subscribers", 201).await;
        let errors = move_account(
            &client(&server),
            &lists(),
            &FAST,
            Uuid::nil(),
            "old@example.test",
            "new@example.test",
            None,
        )
        .await;
        assert!(errors.is_empty(), "{errors:?}");
        let received = requests(&server).await;
        assert_eq!(received.len(), 3);
        assert!(received[1..]
            .iter()
            .all(|r| r.url.path() == "/api/v1/subscribers"));
    }

    #[tokio::test]
    async fn a_server_error_is_retried_then_reported_with_operation_list_and_user() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/subscribers"))
            .respond_with(ResponseTemplate::new(503).set_body_json(
                serde_json::json!({"error": {"code": "unavailable", "message": "Down for maintenance"}}),
            ))
            .mount(&server)
            .await;
        let user_id = Uuid::from_u128(998);
        let errors = add_account(
            &client(&server),
            &lists(),
            &FAST,
            user_id,
            "ada@example.test",
            None,
        )
        .await
        .errors();
        // Three attempts per list.
        assert_eq!(requests(&server).await.len(), 6);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert_eq!(
            errors[0],
            format!(
                "Adding user {user_id} to list product-updates failed: Mirzam answered 503: \
                 Down for maintenance"
            )
        );
        assert!(errors[1].contains("list notices"), "{}", errors[1]);
    }

    #[tokio::test]
    async fn a_refused_token_is_not_retried() {
        let server = MockServer::start().await;
        respond(&server, "POST", "/api/v1/subscribers", 401).await;
        let outcome = with_retries(&FAST, || {
            let c = client(&server);
            async move { c.add("ada@example.test", None, "notices", true).await }
        })
        .await;
        assert_eq!(outcome.unwrap_err().status, Some(401));
        assert_eq!(requests(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn the_recorded_error_never_carries_the_token_or_the_address() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(422).set_body_string(format!(
                "bad request from Bearer {TOKEN} for ADA@example.test and ada@example.test"
            )))
            .mount(&server)
            .await;
        let errors = add_account(
            &client(&server),
            &lists(),
            &FAST,
            Uuid::nil(),
            "ADA@example.test",
            None,
        )
        .await
        .errors();
        assert_eq!(errors.len(), 2);
        for error in &errors {
            assert!(!error.contains(TOKEN), "{error}");
            assert!(
                !error.to_lowercase().contains("ada@example.test"),
                "{error}"
            );
            assert!(error.contains("Mirzam answered 422"), "{error}");
        }

        // A transport failure names neither, though reqwest's own message
        // carries the request URL with the address in it.
        let unreachable = MirzamClient::new("http://127.0.0.1:0", TOKEN).unwrap();
        let errors =
            remove_account(&unreachable, &lists(), &[], Uuid::nil(), "ada@example.test").await;
        assert_eq!(errors.len(), 2);
        for error in &errors {
            assert!(error.contains("Could not reach Mirzam"), "{error}");
            assert!(!error.contains("ada"), "{error}");
            assert!(!error.contains(TOKEN), "{error}");
        }
    }

    #[test]
    fn a_long_answer_is_cut() {
        let summary = summarize_answer(&"x ".repeat(400));
        assert_eq!(summary.chars().count(), ANSWER_SUMMARY_MAX_CHARS + 1);
        assert!(summary.ends_with('…'));
    }

    fn row(enabled: bool, base_url: &str, updates: &str, notices: &str) -> MirzamConfigRow {
        MirzamConfigRow {
            id: 1,
            enabled,
            base_url: base_url.to_string(),
            updates_list: updates.to_string(),
            notices_list: notices.to_string(),
            api_token: None,
            api_token_nonce: None,
            key_version: 1,
            updated_at: Utc::now(),
            updated_by: None,
            last_error: None,
            last_error_at: None,
        }
    }

    #[test]
    fn nothing_is_synced_while_the_integration_is_off_or_incomplete() {
        assert_eq!(
            active_lists(&row(true, "https://news.example.com", "updates", "notices")),
            Some(MirzamLists {
                updates: "updates".to_string(),
                notices: "notices".to_string(),
            })
        );
        assert_eq!(
            active_lists(&row(
                false,
                "https://news.example.com",
                "updates",
                "notices"
            )),
            None
        );
        assert_eq!(active_lists(&row(true, "", "updates", "notices")), None);
        assert_eq!(
            active_lists(&row(true, "https://news.example.com", " ", "notices")),
            None
        );
        assert_eq!(
            active_lists(&row(true, "https://news.example.com", "updates", "")),
            None
        );
    }

    #[test]
    fn an_address_that_was_never_verified_never_spawns_a_call() {
        let user_id = Uuid::nil();
        assert!(!AccountChange::Deleted {
            user_id,
            email: "a@example.test".into(),
            was_verified: false,
        }
        .may_call());
        assert!(!AccountChange::EmailChanged {
            user_id,
            old_email: "a@example.test".into(),
            was_verified: false,
            new_email: "b@example.test".into(),
            now_verified: false,
        }
        .may_call());
        assert!(AccountChange::Deleted {
            user_id,
            email: "a@example.test".into(),
            was_verified: true,
        }
        .may_call());
    }
}
