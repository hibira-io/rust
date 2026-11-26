use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::client::{seg, Client};
use crate::Error;

/// The Chat API (<https://hibira.io/chat-api>): conversations with stored
/// history, read receipts and offline push. Clients receive `chat.*` events on
/// `#server-to-user-<user_id>` after pusher-js `signin()`.
#[derive(Debug, Clone, Copy)]
pub struct Chat<'a> {
    pub(crate) client: &'a Client,
}

/// Fields of [`Chat::put_conversation`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct ConversationFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User IDs; `None` keeps the current members.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// `{ user_id: role }`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Map<String, Value>>,
    /// Up to 10 private or presence channels that also receive the events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Vec<String>>,
}

/// Options of [`Chat::send_message`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendMessageOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// `offline` (default), `always` or `never`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_url: Option<String>,
    /// Up to 5 roles that may see the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible_to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

fn object<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_else(|_| json!({}))
}

impl Chat<'_> {
    /// Any Chat API call, signed. `path` is relative to /apps/APP_ID/chat,
    /// such as `/conversations/c1/typing`.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, Error> {
        let method = method.to_uppercase();
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let body = body.or_else(|| matches!(method.as_str(), "POST" | "PUT").then(|| json!({})));
        self.client
            .request(&method, &format!("/chat{path}"), query, body.as_ref())
            .await
    }

    /// Creates or replaces a conversation.
    pub async fn put_conversation(
        &self,
        id: &str,
        fields: &ConversationFields,
    ) -> Result<Value, Error> {
        self.request(
            "PUT",
            &format!("/conversations/{}", seg(id)?),
            &[],
            Some(object(fields)),
        )
        .await
    }

    pub async fn get_conversation(&self, id: &str) -> Result<Value, Error> {
        self.request("GET", &format!("/conversations/{}", seg(id)?), &[], None)
            .await
    }

    /// Deletes a conversation with its members, messages and files.
    pub async fn delete_conversation(&self, id: &str) -> Result<Value, Error> {
        self.request("DELETE", &format!("/conversations/{}", seg(id)?), &[], None)
            .await
    }

    pub async fn add_members(&self, id: &str, user_ids: &[&str]) -> Result<Value, Error> {
        self.request(
            "POST",
            &format!("/conversations/{}/members", seg(id)?),
            &[],
            Some(json!({ "user_ids": user_ids })),
        )
        .await
    }

    pub async fn remove_member(&self, id: &str, user_id: &str) -> Result<Value, Error> {
        self.request(
            "DELETE",
            &format!("/conversations/{}/members/{}", seg(id)?, seg(user_id)?),
            &[],
            None,
        )
        .await
    }

    /// Posts a message as a member.
    pub async fn send_message(
        &self,
        id: &str,
        user_id: &str,
        text: &str,
        options: &SendMessageOptions,
    ) -> Result<Value, Error> {
        let mut body = object(options);
        body["user_id"] = user_id.into();
        body["text"] = text.into();
        self.request(
            "POST",
            &format!("/conversations/{}/messages", seg(id)?),
            &[],
            Some(body),
        )
        .await
    }

    /// Messages oldest first: after a seq (with limit), or the last n.
    pub async fn list_messages(
        &self,
        id: &str,
        after: Option<u64>,
        limit: Option<u32>,
        last: Option<u32>,
    ) -> Result<Value, Error> {
        let mut q = Vec::new();
        if let Some(v) = after {
            q.push(("after", v.to_string()));
        }
        if let Some(v) = limit {
            q.push(("limit", v.to_string()));
        }
        if let Some(v) = last {
            q.push(("last", v.to_string()));
        }
        self.request(
            "GET",
            &format!("/conversations/{}/messages", seg(id)?),
            &q,
            None,
        )
        .await
    }

    pub async fn mark_read(&self, id: &str, user_id: &str, seq: u64) -> Result<Value, Error> {
        self.request(
            "POST",
            &format!("/conversations/{}/read", seg(id)?),
            &[],
            Some(json!({ "user_id": user_id, "seq": seq })),
        )
        .await
    }

    /// A message with no sender, such as "Alice joined".
    pub async fn system_message(&self, id: &str, text: &str) -> Result<Value, Error> {
        self.request(
            "POST",
            &format!("/conversations/{}/system", seg(id)?),
            &[],
            Some(json!({ "text": text })),
        )
        .await
    }

    /// A user's conversations, latest activity first, each with its unread count.
    pub async fn user_conversations(
        &self,
        user_id: &str,
        limit: Option<u32>,
        before: Option<&str>,
    ) -> Result<Value, Error> {
        let mut q = Vec::new();
        if let Some(v) = limit {
            q.push(("limit", v.to_string()));
        }
        if let Some(v) = before {
            q.push(("before", v.to_string()));
        }
        self.request(
            "GET",
            &format!("/users/{}/conversations", seg(user_id)?),
            &q,
            None,
        )
        .await
    }
}
