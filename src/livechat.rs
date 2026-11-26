//! Hibira Live Chat verified visitors.

use serde::Serialize;

use crate::signing::hmac_sha256_hex;

/// The Live Chat widget script.
pub const SCRIPT_URL: &str = "https://chat.hibira.io/w/v1.js";

/// hex(HMAC-SHA256(identity secret, user ID)): the widget's `data-user-hash`.
pub fn user_hash(identity_secret: &str, user_id: &str) -> String {
    hmac_sha256_hex(identity_secret.as_bytes(), user_id.as_bytes())
}

/// Verified-visitor fields for a single-page app: pass them to
/// `HibiraLiveChat.identify()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    pub id: String,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// The identity for a user, or `None` without a secret or an ID.
pub fn identity(
    identity_secret: &str,
    user_id: &str,
    name: Option<&str>,
    email: Option<&str>,
) -> Option<Identity> {
    if identity_secret.is_empty() || user_id.is_empty() {
        return None;
    }
    Some(Identity {
        id: user_id.to_string(),
        hash: user_hash(identity_secret, user_id),
        name: name.filter(|s| !s.is_empty()).map(str::to_string),
        email: email.filter(|s| !s.is_empty()).map(str::to_string),
    })
}

/// Options for [`script_tag`].
#[derive(Debug, Clone, Default)]
pub struct ScriptOptions<'a> {
    pub workspace: &'a str,
    pub identity: Option<&'a Identity>,
    pub color: Option<&'a str>,
    pub lang: Option<&'a str>,
    /// `false` hides the launcher button.
    pub hide_launcher: bool,
    pub nonce: Option<&'a str>,
}

/// The widget's `<script>` tag, HTML-escaped, or "" without a workspace.
pub fn script_tag(o: &ScriptOptions<'_>) -> String {
    if o.workspace.is_empty() {
        return String::new();
    }
    let mut attrs: Vec<(&str, &str)> = vec![("src", SCRIPT_URL), ("data-workspace", o.workspace)];
    if let Some(c) = o.color {
        attrs.push(("data-color", c));
    }
    if let Some(l) = o.lang {
        attrs.push(("data-lang", l));
    }
    if o.hide_launcher {
        attrs.push(("data-launcher", "none"));
    }
    if let Some(who) = o.identity {
        attrs.push(("data-user-id", &who.id));
        attrs.push(("data-user-hash", &who.hash));
        if let Some(n) = &who.name {
            attrs.push(("data-user-name", n));
        }
        if let Some(e) = &who.email {
            attrs.push(("data-user-email", e));
        }
    }
    if let Some(n) = o.nonce {
        attrs.push(("nonce", n));
    }
    let body = attrs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("<script async {body}></script>")
}

fn escape(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
