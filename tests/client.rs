#![cfg(feature = "client")]

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use hibira::approvals::NewApproval;
use hibira::signing::hmac_sha256_hex;
use hibira::{Client, Config, ConversationFields, SendMessageOptions};
use md5::{Digest, Md5};

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    body: String,
}

type Log = Arc<Mutex<(Vec<Seen>, Vec<(u16, String)>)>>;

async fn record(State(log): State<Log>, req: Request) -> impl IntoResponse {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        .into_owned()
        .collect();
    let body: Bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap();
    let mut g = log.lock().unwrap();
    g.0.push(Seen {
        method,
        path,
        query,
        body: String::from_utf8(body.to_vec()).unwrap(),
    });
    let (status, body) = if g.1.is_empty() {
        (200, "{}".to_string())
    } else {
        g.1.remove(0)
    };
    (StatusCode::from_u16(status).unwrap(), body)
}

async fn fake(responses: Vec<(u16, &str)>) -> (Client, Log) {
    let log: Log = Arc::new(Mutex::new((
        vec![],
        responses
            .into_iter()
            .map(|(s, b)| (s, b.to_string()))
            .collect(),
    )));
    let app = axum::Router::new().fallback(record).with_state(log.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut c = Config::new("1", "app-key", "app-secret");
    c.host = "127.0.0.1".into();
    c.port = Some(port);
    c.use_tls = false;
    (Client::new(c), log)
}

fn assert_signed(s: &Seen) {
    let mut q: Vec<(String, String)> = s
        .query
        .iter()
        .filter(|(k, _)| k != "auth_signature")
        .cloned()
        .collect();
    q.sort();
    let sig = &s
        .query
        .iter()
        .find(|(k, _)| k == "auth_signature")
        .unwrap()
        .1;
    let sorted = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let path = percent_encoding::percent_decode_str(&s.path).decode_utf8_lossy();
    assert_eq!(
        sig,
        &hmac_sha256_hex(
            b"app-secret",
            format!("{}\n{}\n{}", s.method, path, sorted).as_bytes()
        )
    );
    let md5 = q
        .iter()
        .find(|(k, _)| k == "body_md5")
        .map(|(_, v)| v.clone());
    if s.body.is_empty() {
        assert_eq!(md5, None);
    } else {
        assert_eq!(md5.unwrap(), hex::encode(Md5::digest(s.body.as_bytes())));
    }
}

fn user_query(s: &Seen) -> Vec<(String, String)> {
    s.query
        .iter()
        .filter(|(k, _)| !k.starts_with("auth_") && k != "body_md5")
        .cloned()
        .collect()
}

fn json(s: &Seen) -> serde_json::Value {
    serde_json::from_str(&s.body).unwrap()
}

#[tokio::test]
async fn trigger_posts_a_signed_event() {
    let (hibira, log) = fake(vec![]).await;
    hibira
        .trigger(
            &["orders"],
            "order.shipped",
            &serde_json::json!({ "id": 1042 }),
        )
        .await
        .unwrap();
    let s = log.lock().unwrap().0[0].clone();
    assert_eq!(
        (s.method.as_str(), s.path.as_str()),
        ("POST", "/apps/1/events")
    );
    assert_eq!(
        json(&s),
        serde_json::json!({ "name": "order.shipped", "channels": ["orders"], "data": "{\"id\":1042}" })
    );
    assert_signed(&s);
    assert!(hibira.trigger(&[], "x", &1).await.is_err());
}

#[tokio::test]
async fn chat_routes() {
    let (hibira, log) = fake(vec![]).await;
    let chat = hibira.chat();
    chat.put_conversation(
        "order 1",
        &ConversationFields {
            name: Some("Order 1".into()),
            members: Some(vec!["u1".into(), "u2".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    chat.get_conversation("order 1").await.unwrap();
    chat.delete_conversation("order 1").await.unwrap();
    chat.add_members("c1", &["u3"]).await.unwrap();
    chat.remove_member("c1", "u/3").await.unwrap();
    chat.send_message(
        "c1",
        "u1",
        "Hi",
        &SendMessageOptions {
            push: Some("offline".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    chat.list_messages("c1", Some(5), Some(20), None)
        .await
        .unwrap();
    chat.mark_read("c1", "u1", 7).await.unwrap();
    chat.system_message("c1", "Alice joined").await.unwrap();
    chat.user_conversations("u1", Some(10), Some("c9"))
        .await
        .unwrap();
    chat.request("post", "conversations/c1/typing", &[], None)
        .await
        .unwrap();
    let s = log.lock().unwrap().0.clone();
    assert_eq!(
        (s[0].method.as_str(), s[0].path.as_str()),
        ("PUT", "/apps/1/chat/conversations/order%201")
    );
    assert_eq!(
        json(&s[0]),
        serde_json::json!({ "name": "Order 1", "members": ["u1", "u2"] })
    );
    assert_eq!((s[1].method.as_str(), s[1].body.as_str()), ("GET", ""));
    assert_eq!(s[2].method, "DELETE");
    assert_eq!(json(&s[3]), serde_json::json!({ "user_ids": ["u3"] }));
    assert_eq!(s[4].path, "/apps/1/chat/conversations/c1/members/u%2F3");
    assert_eq!(
        json(&s[5]),
        serde_json::json!({ "user_id": "u1", "text": "Hi", "push": "offline" })
    );
    assert_eq!(
        user_query(&s[6]),
        vec![("after".into(), "5".into()), ("limit".into(), "20".into())]
    );
    assert_eq!(
        json(&s[7]),
        serde_json::json!({ "user_id": "u1", "seq": 7 })
    );
    assert_eq!(json(&s[8]), serde_json::json!({ "text": "Alice joined" }));
    assert_eq!(s[9].path, "/apps/1/chat/users/u1/conversations");
    assert_eq!(
        (s[10].path.as_str(), s[10].body.as_str()),
        ("/apps/1/chat/conversations/c1/typing", "{}")
    );
    s.iter().for_each(assert_signed);
}

#[tokio::test]
async fn approvals_and_errors() {
    let pending = r#"{"approval_id":"apr_1","title":"Refund?","status":"pending","url":"https://approvals.hibira.io/a/apr_1"}"#;
    let approved = r#"{"approval_id":"apr_1","title":"Refund?","status":"approved","url":"u"}"#;
    let (hibira, log) = fake(vec![
        (201, pending),
        (200, pending),
        (200, approved),
        (201, pending),
        (402, r#"{"error":"Approvals is not on this plan"}"#),
    ])
    .await;
    let mut a = NewApproval::new("Refund?");
    a.options = Some(vec!["Refund".into(), "Decline".into()]);
    a.expires_in_minutes = Some(120);
    let out = hibira.approvals().request(&a).await.unwrap();
    assert_eq!(out.url, "https://approvals.hibira.io/a/apr_1");
    let done = hibira
        .approvals()
        .wait("apr_1", std::time::Duration::from_secs(600))
        .await
        .unwrap();
    assert!(done.is_approved());
    hibira
        .approvals()
        .reply("apr_1", "Staging only.", None)
        .await
        .unwrap();
    let err = hibira.approvals().get("apr_1", 0).await.unwrap_err();
    assert!(
        matches!(err, hibira::Error::Api { status: 402, ref message, .. } if message.contains("not on this plan")),
        "{err}"
    );
    let s = log.lock().unwrap().0.clone();
    assert_eq!(
        json(&s[0]),
        serde_json::json!({ "title": "Refund?", "options": ["Refund", "Decline"], "expires_in_minutes": 120 })
    );
    assert_eq!(user_query(&s[1]), vec![("wait".into(), "25".into())]);
    assert_eq!(s[3].path, "/apps/1/approvals/apr_1/replies");
    assert!(user_query(&s[4]).is_empty());
    s.iter().for_each(assert_signed);
    assert!(hibira
        .approvals()
        .request(&NewApproval::new(" "))
        .await
        .is_err());
}

#[tokio::test]
async fn missing_credentials_name_the_variables() {
    let hibira = Client::new(Config::new("", "", ""));
    let err = hibira.approvals().get("apr_1", 0).await.unwrap_err();
    assert!(err
        .to_string()
        .contains("HIBIRA_APP_ID, HIBIRA_KEY, HIBIRA_SECRET"));
}
