//! Hibira Approvals (<https://hibira.io/approvals>): ask a person for a
//! decision from your app, an agent or a job, and read the answer.

use serde::{Deserialize, Serialize};

use crate::signing::hmac_sha256_verify;

/// An approval request and its status.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Approval {
    pub approval_id: String,
    #[serde(default)]
    pub title: String,
    /// `pending`, `approved`, `rejected` or `expired`.
    pub status: String,
    /// The answer page to share with whoever decides.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub awaiting_reply: bool,
    /// Every other field.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Approval {
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
    pub fn is_approved(&self) -> bool {
        self.status == "approved"
    }
}

/// A new approval. Only `title` is required.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NewApproval {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// 2 to 4 choices; the first approves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// 1 to 10080 (default 60).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_minutes: Option<u32>,
    /// A private channel that gets an `approval` event on request and decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interests: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_users: Option<Vec<String>>,
    /// Who is asking, such as the agent's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approvers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum: Option<u32>,
    /// Receives a signed POST when decided; check it with [`verify_callback`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

impl NewApproval {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Self::default()
        }
    }
}

/// A callback delivery: `approval.decided` or `approval.expired`.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub data: EventData,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventData {
    pub approval: Approval,
}

/// How old (seconds) a callback's timestamp may be.
pub const CALLBACK_TOLERANCE: i64 = 300;

/// Checks a callback_url delivery (signed with the app secret) or an Approvals
/// workspace webhook (with that endpoint's secret) and returns its event.
/// `header` is the `Hibira-Signature` header, `t=<unix>,v1=<hex>`; `body` the
/// raw body; `now` Unix seconds (`None` for now).
pub fn verify_callback(secret: &str, header: &str, body: &[u8], now: Option<i64>) -> Option<Event> {
    if secret.is_empty() {
        return None;
    }
    let mut ts = None;
    let mut sigs = Vec::new();
    for part in header.split(',') {
        if let Some((k, v)) = part.trim().split_once('=') {
            match k {
                "t" => ts = Some(v),
                "v1" => sigs.push(v),
                _ => {}
            }
        }
    }
    let ts = ts?;
    let t: i64 = ts.parse().ok()?;
    let now = now.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    if (now - t).abs() > CALLBACK_TOLERANCE || sigs.is_empty() {
        return None;
    }
    let mut message = format!("{ts}.").into_bytes();
    message.extend_from_slice(body);
    let ok = sigs.iter().any(|s| {
        hex::decode(s).is_ok_and(|sig| hmac_sha256_verify(secret.as_bytes(), &message, &sig))
    });
    if !ok {
        return None;
    }
    serde_json::from_slice(body).ok()
}

#[cfg(feature = "client")]
pub use client::Approvals;

#[cfg(feature = "client")]
mod client {
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::{Approval, NewApproval};
    use crate::client::{seg, Client};
    use crate::Error;

    const MAX_WAIT: u64 = 25;

    /// Approvals through the app's credentials, from [`Client::approvals`].
    #[derive(Debug, Clone, Copy)]
    pub struct Approvals<'a> {
        pub(crate) client: &'a Client,
    }

    impl Approvals<'_> {
        /// Creates an approval; share its `url` with whoever decides.
        pub async fn request(&self, approval: &NewApproval) -> Result<Approval, Error> {
            if approval.title.trim().is_empty() {
                return Err(Error::Invalid("title is required".into()));
            }
            let body = serde_json::to_value(approval).map_err(|e| Error::Invalid(e.to_string()))?;
            self.client
                .request("POST", "/approvals", &[], Some(&body))
                .await
        }

        /// An approval's status. `wait_secs` (up to 25) holds the request until it is answered.
        pub async fn get(&self, approval_id: &str, wait_secs: u64) -> Result<Approval, Error> {
            let wait = wait_secs.min(MAX_WAIT);
            let query = if wait > 0 {
                vec![("wait", wait.to_string())]
            } else {
                vec![]
            };
            self.client
                .request_with_timeout(
                    "GET",
                    &format!("/approvals/{}", seg(approval_id)?),
                    &query,
                    None,
                    Some(Duration::from_secs(wait + 15)),
                )
                .await
        }

        /// Answers an approver's question; `details`, when given, replaces the request's details.
        pub async fn reply(
            &self,
            approval_id: &str,
            message: &str,
            details: Option<&str>,
        ) -> Result<Approval, Error> {
            if message.trim().is_empty() {
                return Err(Error::Invalid("message is required".into()));
            }
            let mut body = json!({ "message": message });
            if let Some(d) = details {
                body["details"] = d.into();
            }
            self.client
                .request(
                    "POST",
                    &format!("/approvals/{}/replies", seg(approval_id)?),
                    &[],
                    Some(&body),
                )
                .await
        }

        /// Polls until the approval is no longer pending, or `timeout` passes.
        pub async fn wait(&self, approval_id: &str, timeout: Duration) -> Result<Approval, Error> {
            let deadline = Instant::now() + timeout;
            loop {
                let left = deadline.saturating_duration_since(Instant::now()).as_secs();
                let approval = self.get(approval_id, left.min(MAX_WAIT)).await?;
                if !approval.is_pending() || left <= MAX_WAIT {
                    return Ok(approval);
                }
            }
        }

        /// [`super::verify_callback`] with the app secret.
        pub fn verify_callback(&self, header: &str, body: &[u8]) -> Option<super::Event> {
            super::verify_callback(&self.client.config().secret, header, body, None)
        }
    }
}
