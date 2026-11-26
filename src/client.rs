use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::approvals::Approvals;
use crate::chat::Chat;
use crate::{signing, Config, Error};

/// The Hibira HTTP API client: trigger events, the Chat API and Approvals.
///
/// ```no_run
/// # async fn run() -> Result<(), hibira::Error> {
/// let hibira = hibira::Client::new(hibira::Config::from_env()?);
/// hibira.trigger(&["orders"], "order.shipped", &serde_json::json!({ "id": 1042 })).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    config: Config,
    http: reqwest::Client,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self::with_http_client(
            config,
            reqwest::Client::builder()
                .timeout(Duration::from_secs(40))
                .build()
                .unwrap_or_default(),
        )
    }

    /// Uses your own reqwest client (proxies, timeouts).
    pub fn with_http_client(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The Chat API.
    pub fn chat(&self) -> Chat<'_> {
        Chat { client: self }
    }

    /// Hibira Approvals.
    pub fn approvals(&self) -> Approvals<'_> {
        Approvals { client: self }
    }

    /// Publishes an event to up to 100 channels. `data` is serialized to JSON.
    pub async fn trigger<T: Serialize + ?Sized>(
        &self,
        channels: &[&str],
        event: &str,
        data: &T,
    ) -> Result<Value, Error> {
        self.trigger_excluding(channels, event, data, None).await
    }

    /// Like [`Client::trigger`], leaving out the sender's own connection.
    pub async fn trigger_excluding<T: Serialize + ?Sized>(
        &self,
        channels: &[&str],
        event: &str,
        data: &T,
        socket_id: Option<&str>,
    ) -> Result<Value, Error> {
        if channels.is_empty() || channels.len() > 100 {
            return Err(Error::Invalid("trigger takes 1 to 100 channels".into()));
        }
        let data = serde_json::to_string(data).map_err(|e| Error::Invalid(e.to_string()))?;
        let mut body = serde_json::json!({ "name": event, "channels": channels, "data": data });
        if let Some(id) = socket_id {
            body["socket_id"] = id.into();
        }
        self.request("POST", "/events", &[], Some(&body)).await
    }

    /// Any signed API call: `resource` is relative to /apps/APP_ID, such as
    /// `/channels`. Answers the JSON, or `{}` for an empty body.
    pub async fn request<R: DeserializeOwned>(
        &self,
        method: &str,
        resource: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<R, Error> {
        self.request_with_timeout(method, resource, query, body, None)
            .await
    }

    pub(crate) async fn request_with_timeout<R: DeserializeOwned>(
        &self,
        method: &str,
        resource: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        timeout: Option<Duration>,
    ) -> Result<R, Error> {
        let c = &self.config;
        let missing: Vec<&str> = [
            ("HIBIRA_APP_ID", &c.app_id),
            ("HIBIRA_KEY", &c.key),
            ("HIBIRA_SECRET", &c.secret),
        ]
        .into_iter()
        .filter(|(_, v)| v.is_empty())
        .map(|(k, _)| k)
        .collect();
        if !missing.is_empty() {
            return Err(Error::Config(format!("set {}", missing.join(", "))));
        }
        if !resource.starts_with('/') {
            return Err(Error::Invalid("resource must start with \"/\"".into()));
        }
        let method = method.to_uppercase();
        let path = format!("/apps/{}{}", c.app_id, resource);
        let json = body.map(|b| serde_json::to_vec(b).expect("a Value serializes"));
        let decoded = percent_encoding::percent_decode_str(&path)
            .decode_utf8_lossy()
            .into_owned();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let qs = signing::signed_query(
            &method,
            &decoded,
            query,
            json.as_deref(),
            &c.key,
            &c.secret,
            ts,
        );
        let scheme = if c.use_tls { "https" } else { "http" };
        let port = c.port.map(|p| format!(":{p}")).unwrap_or_default();
        let url = format!("{scheme}://{}{port}{path}?{qs}", c.host);
        let verb = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let mut req = self.http.request(verb, url).header(
            "user-agent",
            concat!("hibira-rust/", env!("CARGO_PKG_VERSION")),
        );
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if let Some(json) = json {
            req = req.header("content-type", "application/json").body(json);
        }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            let message = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| {
                    if text.trim().is_empty() {
                        status.canonical_reason().unwrap_or("").to_string()
                    } else {
                        text.trim().to_string()
                    }
                });
            return Err(Error::Api {
                status: status.as_u16(),
                message,
                body: text,
            });
        }
        let text = if text.trim().is_empty() { "{}" } else { &text };
        serde_json::from_str(text).map_err(|e| Error::Api {
            status: status.as_u16(),
            message: format!("invalid JSON: {e}"),
            body: text.to_string(),
        })
    }
}

/// Encodes one path segment and refuses an empty ID.
pub(crate) fn seg(id: &str) -> Result<String, Error> {
    if id.is_empty() {
        return Err(Error::Invalid("an ID is required".into()));
    }
    Ok(percent_encoding::utf8_percent_encode(id, UNRESERVED).to_string())
}

/// What encodeURIComponent escapes.
const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');
