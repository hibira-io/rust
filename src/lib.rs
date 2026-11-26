#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod approvals;
pub mod livechat;
pub mod realtime;
pub mod signing;
pub mod waiting_room;

#[cfg(feature = "client")]
mod chat;
#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use chat::{Chat, ConversationFields, SendMessageOptions};
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use client::Client;
pub use waiting_room::{Guard, Pass};

/// App credentials and the API host.
#[derive(Clone)]
pub struct Config {
    pub app_id: String,
    pub key: String,
    /// Never send it to a browser.
    pub secret: String,
    /// As shown on the app page; defaults to `ws.hibira.io`.
    pub host: String,
    pub port: Option<u16>,
    pub use_tls: bool,
    /// Live Chat › Settings › Widget › Verified visitors secret.
    pub livechat_identity_secret: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("app_id", &self.app_id)
            .field("key", &self.key)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("use_tls", &self.use_tls)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Credentials for an app on the default host.
    pub fn new(
        app_id: impl Into<String>,
        key: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            key: key.into(),
            secret: secret.into(),
            host: "ws.hibira.io".into(),
            port: None,
            use_tls: true,
            livechat_identity_secret: None,
        }
    }

    /// Reads HIBIRA_APP_ID, HIBIRA_KEY, HIBIRA_SECRET, HIBIRA_HOST,
    /// HIBIRA_PORT, HIBIRA_USE_TLS and HIBIRA_LIVECHAT_IDENTITY_SECRET.
    pub fn from_env() -> Result<Self, Error> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let missing: Vec<&str> = ["HIBIRA_APP_ID", "HIBIRA_KEY", "HIBIRA_SECRET"]
            .into_iter()
            .filter(|k| var(k).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(Error::Config(format!("set {}", missing.join(", "))));
        }
        let mut c = Self::new(
            var("HIBIRA_APP_ID").unwrap_or_default(),
            var("HIBIRA_KEY").unwrap_or_default(),
            var("HIBIRA_SECRET").unwrap_or_default(),
        );
        if let Some(h) = var("HIBIRA_HOST") {
            c.host = h;
        }
        c.port = var("HIBIRA_PORT").and_then(|p| p.parse().ok());
        c.use_tls = var("HIBIRA_USE_TLS").is_none_or(|v| v != "false");
        c.livechat_identity_secret = var("HIBIRA_LIVECHAT_IDENTITY_SECRET");
        Ok(c)
    }

    /// The auth for a private or presence channel; see [`realtime::authorize_channel`].
    pub fn authorize_channel(
        &self,
        socket_id: &str,
        channel: &str,
        channel_data: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        realtime::authorize_channel(&self.key, &self.secret, socket_id, channel, channel_data)
    }

    /// The pusher-js `signin()` response; see [`realtime::authenticate_user`].
    pub fn authenticate_user(
        &self,
        socket_id: &str,
        user_data: &str,
    ) -> Result<serde_json::Value, Error> {
        realtime::authenticate_user(&self.key, &self.secret, socket_id, user_data)
    }

    /// Checks and parses a webhook; see [`realtime::verify_webhook`].
    pub fn verify_webhook(
        &self,
        header_key: Option<&str>,
        header_signature: Option<&str>,
        body: &[u8],
    ) -> Option<realtime::Webhook> {
        realtime::verify_webhook(&self.key, &self.secret, header_key, header_signature, body)
    }

    /// A Live Chat verified-visitor identity, with the configured identity secret.
    pub fn livechat_identity(
        &self,
        user_id: &str,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Option<livechat::Identity> {
        livechat::identity(
            self.livechat_identity_secret.as_deref()?,
            user_id,
            name,
            email,
        )
    }

    /// A waiting room [`Guard`] for `room`, with this app's key and secret.
    pub fn waiting_room(&self, room: impl Into<String>) -> Guard {
        let mut g = Guard::new(self.key.clone(), self.secret.clone(), room);
        g.app_id = Some(self.app_id.clone());
        g
    }
}

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Missing credentials.
    #[error("Hibira is not configured: {0}")]
    Config(String),
    /// A bad argument.
    #[error("{0}")]
    Invalid(String),
    /// The API answered with an error status.
    #[error("Hibira API {status}: {message}")]
    Api {
        status: u16,
        message: String,
        body: String,
    },
    /// The request did not complete.
    #[cfg(feature = "client")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
