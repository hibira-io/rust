//! Channel authorization, user sign-in and webhook verification. These need
//! no network; [`crate::Client::trigger`] publishes events.

use serde::Deserialize;

use crate::signing::{hmac_sha256_hex, hmac_sha256_verify};

/// The auth for a private or presence channel subscription: the JSON body to
/// return from your auth endpoint. `channel_data` is the presence member
/// (`{"user_id":"1","user_info":{...}}`) for presence channels.
pub fn authorize_channel(
    key: &str,
    secret: &str,
    socket_id: &str,
    channel: &str,
    channel_data: Option<&str>,
) -> Result<serde_json::Value, crate::Error> {
    check_socket_id(socket_id)?;
    let mut message = format!("{socket_id}:{channel}");
    if let Some(data) = channel_data {
        message.push(':');
        message.push_str(data);
    }
    let auth = format!(
        "{key}:{}",
        hmac_sha256_hex(secret.as_bytes(), message.as_bytes())
    );
    Ok(match channel_data {
        Some(data) => serde_json::json!({ "auth": auth, "channel_data": data }),
        None => serde_json::json!({ "auth": auth }),
    })
}

/// The response to pusher-js `signin()`: `user_data` is the user's JSON, with
/// at least an `id`.
pub fn authenticate_user(
    key: &str,
    secret: &str,
    socket_id: &str,
    user_data: &str,
) -> Result<serde_json::Value, crate::Error> {
    check_socket_id(socket_id)?;
    let sig = hmac_sha256_hex(
        secret.as_bytes(),
        format!("{socket_id}::user::{user_data}").as_bytes(),
    );
    Ok(serde_json::json!({ "auth": format!("{key}:{sig}"), "user_data": user_data }))
}

fn check_socket_id(socket_id: &str) -> Result<(), crate::Error> {
    let ok = socket_id.split_once('.').is_some_and(|(a, b)| {
        !a.is_empty()
            && !b.is_empty()
            && a.bytes().all(|c| c.is_ascii_digit())
            && b.bytes().all(|c| c.is_ascii_digit())
    });
    if ok {
        Ok(())
    } else {
        Err(crate::Error::Invalid(format!(
            "invalid socket_id {socket_id:?}"
        )))
    }
}

/// A verified webhook delivery.
#[derive(Debug, Clone, Deserialize)]
pub struct Webhook {
    pub time_ms: i64,
    pub events: Vec<WebhookEvent>,
}

/// One webhook event, such as `channel_occupied` or `member_added`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookEvent {
    pub name: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub socket_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

/// Checks a webhook's `X-Pusher-Key` and `X-Pusher-Signature`
/// (hex HMAC-SHA256 of the raw body) and parses it. Returns `None` when
/// anything is wrong.
pub fn verify_webhook(
    key: &str,
    secret: &str,
    header_key: Option<&str>,
    header_signature: Option<&str>,
    body: &[u8],
) -> Option<Webhook> {
    if header_key? != key {
        return None;
    }
    let sig = hex::decode(header_signature?).ok()?;
    if !hmac_sha256_verify(secret.as_bytes(), body, &sig) {
        return None;
    }
    serde_json::from_slice(body).ok()
}
