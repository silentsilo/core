//! A fake Dropbox for the tests: both hosts on one server (`/api/2`,
//! `/content/2`), paths compared without case as Dropbox does, and the same
//! switches as the fake Graph.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use crate::fake::{Reply, Request, serve};

#[derive(Default)]
pub struct DropboxState {
    /// Lower-case path to (path as written, bytes).
    pub files: BTreeMap<String, (String, Vec<u8>)>,
    sessions: HashMap<String, Vec<u8>>,
    next_id: u64,
    tokens_issued: u64,
    pub throttle: usize,
    pub refuse_first_token: bool,
    refused: bool,
    pub page_size: usize,
    pub violations: Vec<String>,
    pub api_calls: usize,
}

pub struct FakeDropbox {
    pub api: String,
    pub content: String,
    pub token_url: String,
    pub state: Arc<Mutex<DropboxState>>,
}

impl FakeDropbox {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(DropboxState {
            page_size: 3,
            ..Default::default()
        }));
        let handler: Arc<dyn Fn(Request) -> Reply + Send + Sync> = {
            let state = state.clone();
            Arc::new(move |request| handle(&mut state.lock().unwrap(), request))
        };
        let url = serve(handler).await;
        Self {
            api: format!("{url}/api/2"),
            content: format!("{url}/content/2"),
            token_url: format!("{url}/token"),
            state,
        }
    }
}

fn conflict(summary: &str) -> Reply {
    Reply::json(
        409,
        serde_json::json!({ "error_summary": summary, "error": {} }),
    )
}

fn text(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn is_folder(files: &BTreeMap<String, (String, Vec<u8>)>, path: &str) -> bool {
    let prefix = format!("{}/", path.to_lowercase());
    files.keys().any(|k| k.starts_with(&prefix))
}

fn handle(state: &mut DropboxState, request: Request) -> Reply {
    let path = request.target.split('?').next().unwrap_or("").to_string();
    if path == "/token" {
        state.tokens_issued += 1;
        let n = state.tokens_issued;
        return Reply::json(
            200,
            serde_json::json!({ "access_token": format!("at-{n}"), "expires_in": 14400 }),
        );
    }
    state.api_calls += 1;
    let Some(auth) = request.headers.get("authorization") else {
        state
            .violations
            .push(format!("call without a token: {path}"));
        return Reply::status(401);
    };
    if state.refuse_first_token && !state.refused && auth == "Bearer at-1" {
        state.refused = true;
        return Reply::status(401);
    }
    if state.throttle > 0 {
        state.throttle -= 1;
        let mut reply = Reply::status(429);
        reply.headers.push(("Retry-After".into(), "0".into()));
        return reply;
    }
    let arg: serde_json::Value = match request.headers.get("dropbox-api-arg") {
        Some(header) => {
            if !header.is_ascii() {
                state.violations.push("a non-ASCII Dropbox-API-Arg".into());
            }
            serde_json::from_str(header).unwrap_or_default()
        }
        None => serde_json::from_slice(&request.body).unwrap_or_default(),
    };

    match path.as_str() {
        "/content/2/files/upload" => {
            let p = text(&arg, "path");
            state.files.insert(p.to_lowercase(), (p, request.body));
            Reply::json(200, serde_json::json!({}))
        }
        "/content/2/files/download" => {
            let p = text(&arg, "path").to_lowercase();
            let Some((_, bytes)) = state.files.get(&p) else {
                return conflict("path/not_found/...");
            };
            if let Some(end) = request
                .headers
                .get("range")
                .and_then(|r| r.strip_prefix("bytes=0-"))
                .and_then(|e| e.parse::<usize>().ok())
            {
                let mut reply = Reply::status(206);
                reply.body = bytes[..(end + 1).min(bytes.len())].to_vec();
                return reply;
            }
            let mut reply = Reply::status(200);
            reply.body = bytes.clone();
            reply
        }
        "/content/2/files/upload_session/start" => {
            state.next_id += 1;
            let id = format!("s{}", state.next_id);
            state.sessions.insert(id.clone(), request.body);
            Reply::json(200, serde_json::json!({ "session_id": id }))
        }
        "/content/2/files/upload_session/append_v2" | "/content/2/files/upload_session/finish" => {
            let cursor = arg.get("cursor").cloned().unwrap_or_default();
            let id = text(&cursor, "session_id");
            let offset = cursor
                .get("offset")
                .and_then(|o| o.as_u64())
                .unwrap_or(u64::MAX);
            let Some(received) = state.sessions.get_mut(&id) else {
                return conflict("lookup_failed/not_found/");
            };
            if received.len() as u64 != offset {
                return conflict("lookup_failed/incorrect_offset/");
            }
            received.extend_from_slice(&request.body);
            if path.ends_with("finish") {
                let bytes = state.sessions.remove(&id).unwrap_or_default();
                let commit = arg.get("commit").cloned().unwrap_or_default();
                let p = text(&commit, "path");
                state.files.insert(p.to_lowercase(), (p, bytes));
            }
            Reply::json(200, serde_json::json!({}))
        }
        "/api/2/files/get_metadata" => {
            let p = text(&arg, "path");
            match state.files.get(&p.to_lowercase()) {
                Some((_, bytes)) => Reply::json(
                    200,
                    serde_json::json!({ ".tag": "file", "size": bytes.len() }),
                ),
                None if is_folder(&state.files, &p) => {
                    Reply::json(200, serde_json::json!({ ".tag": "folder" }))
                }
                None => conflict("path/not_found/.."),
            }
        }
        "/api/2/files/delete_v2" => {
            let p = text(&arg, "path").to_lowercase();
            let prefix = format!("{p}/");
            let before = state.files.len();
            state
                .files
                .retain(|k, _| k != &p && !k.starts_with(&prefix));
            if state.files.len() == before {
                conflict("path_lookup/not_found/..")
            } else {
                Reply::json(200, serde_json::json!({}))
            }
        }
        "/api/2/files/list_folder" | "/api/2/files/list_folder/continue" => {
            let (root, skip) = if path.ends_with("continue") {
                let cursor = text(&arg, "cursor");
                let (skip, root) = cursor.split_once('|').unwrap_or(("0", ""));
                (root.to_string(), skip.parse().unwrap_or(0))
            } else {
                (text(&arg, "path"), 0usize)
            };
            if !is_folder(&state.files, &root) {
                return conflict("path/not_found/..");
            }
            let prefix = format!("{}/", root.to_lowercase());
            let entries: Vec<serde_json::Value> = state
                .files
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, (display, bytes))| {
                    serde_json::json!({ ".tag": "file", "path_display": display, "size": bytes.len() })
                })
                .collect();
            let page: Vec<_> = entries
                .iter()
                .skip(skip)
                .take(state.page_size)
                .cloned()
                .collect();
            let more = skip + state.page_size < entries.len();
            Reply::json(
                200,
                serde_json::json!({
                    "entries": page,
                    "has_more": more,
                    "cursor": format!("{}|{root}", skip + state.page_size),
                }),
            )
        }
        _ => Reply::status(404),
    }
}
