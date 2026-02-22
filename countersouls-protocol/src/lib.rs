use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ClientMessage {
    Auth { password: String, name: String },
    Update { count: u64 },
    RequestAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ServerMessage {
    AuthOk,
    AuthError { reason: String },
    All { counts: BTreeMap<String, u64> },
    Update { name: String, count: u64 },
}
