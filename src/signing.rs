//! Signing for the Channels-protocol HTTP API (auth_version 1.0).

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// hex(HMAC-SHA256(secret, message)).
pub fn hmac_sha256_hex(secret: &[u8], message: &[u8]) -> String {
    hex::encode(hmac_sha256(secret, message))
}

pub(crate) fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Constant-time check of an HMAC-SHA256 over `message`.
pub(crate) fn hmac_sha256_verify(secret: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(message);
    mac.verify_slice(signature).is_ok()
}

/// The signed query string of a Channels-protocol HTTP API request: the
/// caller's query plus auth_key, auth_timestamp, auth_version, body_md5 (when
/// there is a body) and auth_signature, where auth_signature is
/// hex(HMAC-SHA256(secret, "METHOD\npath\nsorted k=v&...")).
///
/// `path` is the decoded request path, such as `/apps/123/events`.
pub fn signed_query(
    method: &str,
    path: &str,
    query: &[(&str, String)],
    body: Option<&[u8]>,
    key: &str,
    secret: &str,
    timestamp: u64,
) -> String {
    let mut params: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    params.push(("auth_key".into(), key.into()));
    params.push(("auth_timestamp".into(), timestamp.to_string()));
    params.push(("auth_version".into(), "1.0".into()));
    if let Some(body) = body {
        params.push(("body_md5".into(), hex::encode(Md5::digest(body))));
    }
    params.sort();
    let sorted = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let signature = hmac_sha256_hex(
        secret.as_bytes(),
        format!("{}\n{}\n{}", method.to_uppercase(), path, sorted).as_bytes(),
    );
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &params {
        out.append_pair(k, v);
    }
    out.append_pair("auth_signature", &signature);
    out.finish()
}
