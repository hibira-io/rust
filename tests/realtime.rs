use hibira::livechat::{identity, script_tag, user_hash, ScriptOptions};
use hibira::signing::{hmac_sha256_hex, signed_query};
use hibira::{approvals, Config};

fn config() -> Config {
    Config::new("1", "278d425bdf160c739803", "7ad3773142a6692b25b8")
}

#[test]
fn channel_auth_matches_the_pusher_docs() {
    // https://pusher.com/docs/channels/library_auth_reference/auth-signatures/
    let auth = config()
        .authorize_channel("1234.1234", "private-foobar", None)
        .unwrap();
    assert_eq!(
        auth["auth"],
        "278d425bdf160c739803:58df8b0c36d6982b82c3ecf6b4662e34fe8c25bba48f5369f135bf843651c3a4"
    );
    let data = r#"{"user_id":10,"user_info":{"name":"Mr. Channels"}}"#;
    let auth = config()
        .authorize_channel("1234.1234", "presence-foobar", Some(data))
        .unwrap();
    assert_eq!(
        auth["auth"],
        "278d425bdf160c739803:31935e7d86dba64c2a90aed31fdc61869f9b22ba9d8863bba239c03ca481bc80"
    );
    assert_eq!(auth["channel_data"], data);
    assert!(config()
        .authorize_channel("nope", "private-x", None)
        .is_err());
}

#[test]
fn user_signin() {
    let out = config()
        .authenticate_user("1234.1234", r#"{"id":"7"}"#)
        .unwrap();
    let sig = hmac_sha256_hex(b"7ad3773142a6692b25b8", br#"1234.1234::user::{"id":"7"}"#);
    assert_eq!(out["auth"], format!("278d425bdf160c739803:{sig}"));
}

#[test]
fn webhooks() {
    let body = br#"{"time_ms":1,"events":[{"name":"channel_occupied","channel":"orders"}]}"#;
    let sig = hmac_sha256_hex(b"7ad3773142a6692b25b8", body);
    let c = config();
    let hook = c
        .verify_webhook(Some("278d425bdf160c739803"), Some(&sig), body)
        .unwrap();
    assert_eq!(hook.events[0].channel.as_deref(), Some("orders"));
    assert!(c.verify_webhook(Some("other"), Some(&sig), body).is_none());
    assert!(c
        .verify_webhook(Some("278d425bdf160c739803"), Some("00"), body)
        .is_none());
    assert!(c.verify_webhook(None, Some(&sig), body).is_none());
}

#[test]
fn signed_query_is_sorted_and_signed() {
    let qs = signed_query(
        "POST",
        "/apps/3/events",
        &[],
        Some(br#"{"name":"foo","channels":["project-3"],"data":"{\"some\":\"data\"}"}"#),
        "278d425bdf160c739803",
        "7ad3773142a6692b25b8",
        1353088179,
    );
    // The worked example in the Pusher HTTP API reference.
    assert_eq!(
        qs,
        "auth_key=278d425bdf160c739803&auth_timestamp=1353088179&auth_version=1.0&body_md5=ec365a775a4cd0599faeb73354201b6f&auth_signature=da454824c97ba181a32ccc17a72625ba02771f50b50e1e7430e47a1f3f457e6c"
    );
}

#[test]
fn live_chat() {
    let h = hmac_sha256_hex(b"idsecret", b"42");
    assert_eq!(user_hash("idsecret", "42"), h);
    let who = identity("idsecret", "42", Some("A \"B\" <c>"), Some("")).unwrap();
    assert_eq!(who.email, None);
    assert!(identity("", "42", None, None).is_none());
    let tag = script_tag(&ScriptOptions {
        workspace: "ws_1",
        identity: Some(&who),
        hide_launcher: true,
        nonce: Some("n1"),
        ..Default::default()
    });
    assert_eq!(
        tag,
        format!(
            r#"<script async src="https://chat.hibira.io/w/v1.js" data-workspace="ws_1" data-launcher="none" data-user-id="42" data-user-hash="{h}" data-user-name="A &quot;B&quot; &lt;c&gt;" nonce="n1"></script>"#
        )
    );
    assert_eq!(script_tag(&ScriptOptions::default()), "");
    let mut c = config();
    c.livechat_identity_secret = Some("idsecret".into());
    assert_eq!(c.livechat_identity("42", None, None).unwrap().hash, h);
}

#[test]
fn approval_callbacks() {
    let body = br#"{"id":"evt_1","type":"approval.decided","created_at":"2026-11-26T00:00:00Z","data":{"approval":{"approval_id":"apr_1","status":"approved"}}}"#;
    let t = 1800000000i64;
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    let sig = hmac_sha256_hex(b"whsec", &msg);
    let header = format!("t={t},v1={sig}");
    let e = approvals::verify_callback("whsec", &header, body, Some(t + 1)).unwrap();
    assert_eq!(
        (e.kind.as_str(), e.data.approval.is_approved()),
        ("approval.decided", true)
    );
    assert!(
        approvals::verify_callback("whsec", &format!("t={t},v1=00,v1={sig}"), body, Some(t))
            .is_some()
    );
    assert!(approvals::verify_callback("other", &header, body, Some(t)).is_none());
    assert!(approvals::verify_callback("whsec", &header, b"{}", Some(t)).is_none());
    assert!(approvals::verify_callback("whsec", &header, body, Some(t + 301)).is_none());
    assert!(approvals::verify_callback("", &header, body, Some(t)).is_none());
}
