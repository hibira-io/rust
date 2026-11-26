# hibira

The [Hibira](https://hibira.io) server SDK for Rust.

- **Realtime** (Pusher protocol): trigger events, authorize private and presence channels, answer pusher-js `signin()`, verify webhooks.
- **Waiting rooms**: verify the signed passes visitors bring back from the hosted queue, with middleware for **Axum** and **Actix Web**.
- **Chat API**: conversations with stored history, read receipts and offline push.
- **Approvals**: ask a person for a decision from your app, an agent or a job, and read the answer.
- **Live Chat**: verified visitors for the Hibira Live Chat widget.

## Using an AI coding assistant?

Add the [Hibira MCP server](https://hibira.io/guides) to Claude Code, Cursor
or Codex and ask it to "add Hibira to this Axum app": `setup_project` creates
the app and env values, and `get_integration_guide` hands the assistant these
steps.

## Install

```toml
[dependencies]
hibira = { version = "0.1", features = ["axum"] } # or "actix"
```

Features: `client` (default: the HTTP client, using reqwest with rustls),
`axum`, `actix`. Without `client`, the crate has no network code: signing,
channel auth, webhooks, waiting room passes and Live Chat hashes only.

Set the app's credentials from the Hibira console:

```sh
HIBIRA_APP_ID=123
HIBIRA_KEY=...
HIBIRA_SECRET=...            # server only
HIBIRA_HOST=ws.hibira.io     # as shown on the app page
```

## Realtime

```rust,ignore
let config = hibira::Config::from_env()?;
let hibira = hibira::Client::new(config.clone());
hibira.trigger(&["orders"], "order.shipped", &serde_json::json!({ "id": 1042 })).await?;

// POST /pusher/auth: socket_id and channel_name from the form body
let auth = config.authorize_channel(&socket_id, &channel_name, None)?;
// presence: Some(r#"{"user_id":"7","user_info":{"name":"Ann"}}"#)

// webhooks: the raw body and the X-Pusher-Key / X-Pusher-Signature headers
if let Some(hook) = config.verify_webhook(key_header, signature_header, &body) {
    for event in hook.events { /* channel_occupied, member_added, ... */ }
}
```

## Waiting rooms

Create a room in the Hibira console (or with the MCP `set_waiting_room`
tool), then put the guard in front of the pages it protects. Visitors without
a pass go to the hosted waiting page; the pass they bring back is stored in an
HttpOnly cookie, and the handler receives it.

**Axum**

```rust,ignore
use std::sync::Arc;
use axum::{middleware, routing::get, Extension, Router};
use hibira::{waiting_room::axum_guard, Pass};

let guard = Arc::new(config.waiting_room("presale"));
let app = Router::new()
    .route("/drop", get(|Extension(pass): Extension<Pass>| async move { format!("You are number {}", pass.number) }))
    .layer(middleware::from_fn_with_state(guard, axum_guard));
```

**Actix Web**

```rust,ignore
use actix_web::{middleware::from_fn, web, App, HttpResponse};
use hibira::{waiting_room::actix_guard, Pass};

App::new()
    .app_data(web::Data::new(config.waiting_room("presale")))
    .wrap(from_fn(actix_guard))
    .route("/drop", web::get().to(|pass: web::ReqData<Pass>| async move { HttpResponse::Ok().body(format!("number {}", pass.number)) }));
```

For any other framework, `Guard::decide(method, uri, headers, https)` returns
`Allow(pass)`, `Redirect { location, set_cookie, .. }` or `Deny`, and
`waiting_room::verify(pass, &options)` checks a pass anywhere. Record
`pass.ticket_id` to allow one checkout per queue number. For rooms with one
place per signed-in customer, set `guard.user` to return
`waiting_room::sign_user(secret, room, user_id, ttl, None)`.

## Chat API

```rust,ignore
use hibira::{ConversationFields, SendMessageOptions};

let chat = hibira.chat();
chat.put_conversation("order-1042", &ConversationFields {
    name: Some("Order #1042".into()),
    members: Some(vec!["buyer-7".into(), "seller-3".into()]),
    ..Default::default()
}).await?;
chat.send_message("order-1042", "seller-3", "Shipped today!", &SendMessageOptions::default()).await?;
let page = chat.list_messages("order-1042", Some(0), Some(50), None).await?;
chat.mark_read("order-1042", "buyer-7", 12).await?;
```

`get_conversation`, `delete_conversation`, `add_members`, `remove_member`,
`system_message`, `user_conversations` and `request` (any other route) cover
the rest. See the [reference](https://hibira.io/chat-api/reference).

## Approvals

```rust,ignore
use hibira::approvals::NewApproval;

let mut ask = NewApproval::new("Refund order #1042 for $89?");
ask.options = Some(vec!["Refund".into(), "Decline".into()]); // the first option approves
let approval = hibira.approvals().request(&ask).await?;
// share approval.url with whoever decides, then
let approval = hibira.approvals().wait(&approval.approval_id, std::time::Duration::from_secs(600)).await?;
if approval.is_approved() { refund().await?; }
```

With `callback_url` set, Hibira POSTs `approval.decided` or
`approval.expired`, signed with the app secret: check it with
`hibira::approvals::verify_callback(secret, signature_header, &body, None)`.

## Live Chat

```rust,ignore
use hibira::livechat::{identity, script_tag, ScriptOptions};

let who = identity(&identity_secret, &user.id, Some(&user.name), Some(&user.email));
let tag = script_tag(&ScriptOptions { workspace: "ws_...", identity: who.as_ref(), ..Default::default() });
```

The identity secret is in Live Chat › Settings › Widget › Verified visitors.
For a single-page app, return `identity(...)` as JSON and call
`HibiraLiveChat.identify(it)` in the browser.

## 中文摘要

`hibira` 是 [Hibira](https://hibira.io) 的 Rust 伺服器端 SDK：

- **即時（Pusher 協定）**：發送事件、私有與 presence 頻道授權、pusher-js `signin()`、驗證 webhook。
- **等候室**：驗證訪客從託管排隊頁帶回的簽名 pass，提供 Axum 與 Actix Web middleware；其他框架可用 `Guard::decide()`。
- **Chat API**：建立對話、發訊息、讀取歷史、標記已讀。
- **Approvals**：發出需要人決定的請求並等待結果，`verify_callback()` 驗證 callback 簽名。
- **Live Chat**：`identity()`、`script_tag()` 讓登入使用者以驗證過的身分聊天。
- 安裝：`hibira = { version = "0.1", features = ["axum"] }`，設定 `HIBIRA_APP_ID` / `HIBIRA_KEY` / `HIBIRA_SECRET`。關閉 `client` feature 時沒有任何網路程式碼。
