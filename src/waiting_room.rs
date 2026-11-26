//! Hibira waiting rooms: check the signed passes visitors bring back from the
//! hosted queue, and protect pages with a [`Guard`].
//!
//! A visitor without a valid pass is redirected to the hosted waiting page (a
//! request other than GET or HEAD gets a 403). The `?hibira_pass=...` a
//! visitor brings back is checked, stored in the HttpOnly cookie
//! `hibira_wr_<room>` and removed from the URL. This matches
//! `@hibira-io/waiting-room/server`, the Go module and the framework packages.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::{header, HeaderMap, Method, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

use crate::signing::{hmac_sha256, hmac_sha256_verify};

/// Serves the hosted waiting page.
pub const DEFAULT_HOST: &str = "https://ws.hibira.io";
const PASS_PURPOSE: &str = "hibira-waitroom-pass.";
const USER_PURPOSE: &str = "hibira-waitroom-user.";
const PARAM: &str = "hibira_pass";
const MAX_PASS_LEN: usize = 1024;

/// Characters Go's url.PathEscape leaves alone.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b':')
    .remove(b'=')
    .remove(b'@');

/// A verified waiting room pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pass {
    pub app_id: String,
    pub room: String,
    /// The visitor's queue number.
    pub number: i64,
    /// The queue ticket's ID: record it to allow one checkout per number.
    pub ticket_id: String,
    /// The signed user ID, in rooms with one place per signed-in customer.
    pub user_id: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct Claims {
    v: i64,
    #[serde(default)]
    app: String,
    #[serde(default)]
    room: String,
    #[serde(default)]
    n: i64,
    #[serde(default)]
    tid: String,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    iat: i64,
    exp: Option<i64>,
}

/// Which passes [`verify`] accepts.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions<'a> {
    /// The app secret; give the old and the new one during a rotation.
    pub secrets: &'a [String],
    /// When set, must match the pass.
    pub room: Option<&'a str>,
    /// When set, must match the pass.
    pub app_id: Option<&'a str>,
    /// Unix seconds; defaults to now.
    pub now: Option<i64>,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Checks a pass. Returns `None` when it is missing, forged, expired, or for
/// another room or app.
pub fn verify(pass: &str, o: &VerifyOptions<'_>) -> Option<Pass> {
    if o.secrets.is_empty() || pass.is_empty() || pass.len() > MAX_PASS_LEN {
        return None;
    }
    let (payload, sig) = pass.split_once('.')?;
    if payload.is_empty() {
        return None;
    }
    let sig = URL_SAFE_NO_PAD.decode(sig).ok()?;
    if sig.len() != 32 {
        return None;
    }
    let message = format!("{PASS_PURPOSE}{payload}");
    if !o
        .secrets
        .iter()
        .filter(|s| !s.is_empty())
        .any(|s| hmac_sha256_verify(s.as_bytes(), message.as_bytes(), &sig))
    {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let c: Claims = serde_json::from_slice(&raw).ok()?;
    let exp = c.exp?;
    if c.v != 1 || o.now.unwrap_or_else(unix_now) >= exp {
        return None;
    }
    if o.room.is_some_and(|r| !r.is_empty() && r != c.room)
        || o.app_id.is_some_and(|a| !a.is_empty() && a != c.app)
    {
        return None;
    }
    Some(Pass {
        app_id: c.app,
        room: c.room,
        number: c.n,
        ticket_id: c.tid,
        user_id: c.sub,
        issued_at: c.iat,
        expires_at: exp,
    })
}

/// Signs a user token for rooms with one place per signed-in customer: the
/// same user ID gets the same place in every browser. `user_id` is 1 to 128
/// characters without "."; `ttl_secs` is capped at 7 days (0 means 1 hour).
pub fn sign_user(
    secret: &str,
    room: &str,
    user_id: &str,
    ttl_secs: u64,
    now: Option<i64>,
) -> Result<String, crate::Error> {
    if user_id.is_empty() || user_id.len() > 128 || user_id.contains('.') {
        return Err(crate::Error::Invalid(
            r#"user_id must be 1 to 128 characters without ".""#.into(),
        ));
    }
    let ttl = if ttl_secs == 0 {
        3600
    } else {
        ttl_secs.min(7 * 24 * 3600)
    } as i64;
    let exp = now.unwrap_or_else(unix_now) + ttl;
    let sig = hmac_sha256(
        secret.as_bytes(),
        format!("{USER_PURPOSE}{room}.{user_id}.{exp}").as_bytes(),
    );
    Ok(format!("{user_id}.{exp}.{}", hex::encode(sig)))
}

/// The hosted waiting page for a room.
#[derive(Debug, Clone, Default)]
pub struct UrlOptions<'a> {
    pub app_key: &'a str,
    pub room: &'a str,
    pub return_url: Option<&'a str>,
    /// Defaults to [`DEFAULT_HOST`].
    pub host: Option<&'a str>,
    /// en, zh-TW, zh-CN, ja, ko, th, vi, it or fr.
    pub lang: Option<&'a str>,
    /// A token from [`sign_user`].
    pub user: Option<&'a str>,
}

/// The hosted waiting page address for a room.
pub fn waiting_room_url(o: &UrlOptions<'_>) -> String {
    let host = o
        .host
        .filter(|h| !h.is_empty())
        .unwrap_or(DEFAULT_HOST)
        .trim_end_matches('/');
    let mut url = format!(
        "{host}/wait/{}/{}",
        utf8_percent_encode(o.app_key, PATH_SEGMENT),
        utf8_percent_encode(o.room, PATH_SEGMENT)
    );
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    let mut any = false;
    for (k, v) in [("lang", o.lang), ("return", o.return_url), ("user", o.user)] {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            q.append_pair(k, v);
            any = true;
        }
    }
    if any {
        url.push('?');
        url.push_str(&q.finish());
    }
    url
}

/// Protects pages with one waiting room.
#[derive(Clone, Default)]
pub struct Guard {
    pub app_key: String,
    /// The app secret; give the old and the new one during a rotation.
    pub secrets: Vec<String>,
    pub room: String,
    /// When set, must match the pass.
    pub app_id: Option<String>,
    /// Defaults to [`DEFAULT_HOST`].
    pub host: Option<String>,
    pub lang: Option<String>,
    /// Defaults to `hibira_wr_<room>`.
    pub cookie_name: Option<String>,
    /// Returns a [`sign_user`] token for the request's signed-in customer.
    #[allow(clippy::type_complexity)]
    pub user: Option<std::sync::Arc<dyn Fn(&HeaderMap) -> Option<String> + Send + Sync>>,
    /// Unix seconds; defaults to now (for tests).
    pub now: Option<i64>,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("app_key", &self.app_key)
            .field("room", &self.room)
            .finish_non_exhaustive()
    }
}

/// What to do with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Serve the page.
    Allow(Pass),
    /// Answer 302 to `location` with `Cache-Control: no-store`, setting `set_cookie` when given.
    Redirect {
        location: String,
        set_cookie: Option<String>,
        pass: Option<Pass>,
    },
    /// Answer 403 with [`DENY_BODY`]: a request other than GET or HEAD without a pass.
    Deny,
}

/// The JSON body of a [`Decision::Deny`] response.
pub const DENY_BODY: &str = r#"{"error":"waiting_room","message":"join the waiting room first"}"#;

impl Guard {
    /// A guard for `room`, with the app key and secret.
    pub fn new(
        app_key: impl Into<String>,
        secret: impl Into<String>,
        room: impl Into<String>,
    ) -> Self {
        Self {
            app_key: app_key.into(),
            secrets: vec![secret.into()],
            room: room.into(),
            ..Self::default()
        }
    }

    /// The pass cookie's name.
    pub fn cookie_name(&self) -> String {
        self.cookie_name
            .clone()
            .unwrap_or_else(|| format!("hibira_wr_{}", self.room))
    }

    /// Works out what to do with a request. `https` is whether the request
    /// came over TLS; `X-Forwarded-Proto: https` also counts.
    pub fn decide(&self, method: &Method, uri: &Uri, headers: &HeaderMap, https: bool) -> Decision {
        let now = self.now.unwrap_or_else(unix_now);
        let vo = VerifyOptions {
            secrets: &self.secrets,
            room: Some(&self.room),
            app_id: self.app_id.as_deref(),
            now: Some(now),
        };
        let forwarded = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"));
        let scheme = if https || forwarded { "https" } else { "http" };
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| uri.authority().map(|a| a.to_string()))
            .unwrap_or_else(|| "localhost".into());
        let path = uri.path();
        let mut from_queue = None;
        let mut kept = url::form_urlencoded::Serializer::new(String::new());
        let mut kept_any = false;
        for (k, v) in url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
            if k == PARAM {
                if from_queue.is_none() {
                    from_queue = Some(v.into_owned());
                }
            } else {
                kept.append_pair(&k, &v);
                kept_any = true;
            }
        }
        let kept = kept.finish();
        let here = if kept_any {
            format!("{scheme}://{host}{path}?{kept}")
        } else {
            format!("{scheme}://{host}{path}")
        };

        if let Some(token) = from_queue.filter(|t| !t.is_empty()) {
            if let Some(pass) = verify(&token, &vo) {
                let max_age = (pass.expires_at - now).max(1);
                let secure = if scheme == "https" { "; Secure" } else { "" };
                let cookie = format!(
                    "{}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}",
                    self.cookie_name()
                );
                return Decision::Redirect {
                    location: here,
                    set_cookie: Some(cookie),
                    pass: Some(pass),
                };
            }
        }
        let name = self.cookie_name();
        for value in headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
        {
            for c in cookie::Cookie::split_parse(value).flatten() {
                if c.name() == name {
                    if let Some(pass) = verify(c.value(), &vo) {
                        return Decision::Allow(pass);
                    }
                }
            }
        }
        if method != Method::GET && method != Method::HEAD {
            return Decision::Deny;
        }
        let user = self.user.as_ref().and_then(|f| f(headers));
        Decision::Redirect {
            location: waiting_room_url(&UrlOptions {
                app_key: &self.app_key,
                room: &self.room,
                return_url: Some(&here),
                host: self.host.as_deref(),
                lang: self.lang.as_deref(),
                user: user.as_deref(),
            }),
            set_cookie: None,
            pass: None,
        }
    }
}

/// Axum middleware: `axum::middleware::from_fn_with_state(Arc::new(guard), hibira::waiting_room::axum_guard)`.
/// The handler gets the pass with `Extension<Pass>`.
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub async fn axum_guard(
    axum::extract::State(guard): axum::extract::State<std::sync::Arc<Guard>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let https = request.uri().scheme_str() == Some("https");
    match guard.decide(request.method(), request.uri(), request.headers(), https) {
        Decision::Allow(pass) => {
            request.extensions_mut().insert(pass);
            next.run(request).await
        }
        Decision::Deny => (
            http::StatusCode::FORBIDDEN,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::CONTENT_TYPE, "application/json"),
            ],
            DENY_BODY,
        )
            .into_response(),
        Decision::Redirect {
            location,
            set_cookie,
            ..
        } => {
            let mut res = (
                http::StatusCode::FOUND,
                [(header::CACHE_CONTROL, "no-store")],
            )
                .into_response();
            if let Ok(v) = http::HeaderValue::from_str(&location) {
                res.headers_mut().insert(header::LOCATION, v);
            }
            if let Some(c) = set_cookie.and_then(|c| http::HeaderValue::from_str(&c).ok()) {
                res.headers_mut().insert(header::SET_COOKIE, c);
            }
            res
        }
    }
}

/// Actix Web middleware, for `actix_web::middleware::from_fn(hibira::waiting_room::actix_guard)`
/// with the guard registered as `app_data(web::Data::new(guard))`. The handler
/// gets the pass with `web::ReqData<Pass>`.
#[cfg(feature = "actix")]
#[cfg_attr(docsrs, doc(cfg(feature = "actix")))]
pub async fn actix_guard<B: actix_web::body::MessageBody + 'static>(
    request: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<B>,
) -> Result<actix_web::dev::ServiceResponse<actix_web::body::EitherBody<B>>, actix_web::Error> {
    use actix_web::HttpMessage;
    let Some(guard) = request.app_data::<actix_web::web::Data<Guard>>().cloned() else {
        return Err(actix_web::error::ErrorInternalServerError(
            "hibira waiting room: register the Guard with app_data(web::Data::new(guard))",
        ));
    };
    let https = request.connection_info().scheme() == "https";
    let method = Method::from_bytes(request.method().as_str().as_bytes()).unwrap_or(Method::GET);
    let uri: Uri = request.uri().to_string().parse().unwrap_or_default();
    let mut headers = HeaderMap::new();
    for (k, v) in request.headers() {
        if let (Ok(k), Ok(v)) = (
            http::HeaderName::from_bytes(k.as_str().as_bytes()),
            http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            headers.append(k, v);
        }
    }
    let response = match guard.decide(&method, &uri, &headers, https) {
        Decision::Allow(pass) => {
            request.extensions_mut().insert(pass);
            return Ok(next.call(request).await?.map_into_left_body());
        }
        Decision::Deny => actix_web::HttpResponse::Forbidden()
            .insert_header(("cache-control", "no-store"))
            .content_type("application/json")
            .body(DENY_BODY),
        Decision::Redirect {
            location,
            set_cookie,
            ..
        } => {
            let mut res = actix_web::HttpResponse::Found();
            res.insert_header(("cache-control", "no-store"))
                .insert_header(("location", location));
            if let Some(c) = set_cookie {
                res.insert_header(("set-cookie", c));
            }
            res.finish()
        }
    };
    Ok(request.into_response(response).map_into_right_body())
}
