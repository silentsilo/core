//! A fake Google Drive v3 for the tests: ids, parents, names that may
//! repeat in one folder, the `q` clauses the store sends, multipart and
//! resumable uploads, and throttling as Drive does it (403
//! `rateLimitExceeded`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::fake::{Reply, Request, serve};

const FOLDER: &str = "application/vnd.google-apps.folder";

#[derive(Clone)]
pub struct Item {
    pub id: String,
    pub name: String,
    pub parents: Vec<String>,
    pub folder: bool,
    pub bytes: Vec<u8>,
    pub created: u64,
    pub modified: u64,
}

#[derive(Default)]
pub struct DriveState {
    pub items: Vec<Item>,
    sessions: HashMap<String, (Option<String>, serde_json::Value, u64, Vec<u8>)>,
    clock: u64,
    next_id: u64,
    tokens_issued: u64,
    /// The next this many API calls answer 403 `rateLimitExceeded`.
    pub throttle: usize,
    pub page_size: usize,
    pub violations: Vec<String>,
    /// Requests other than the token endpoint, to hold the cost of a write.
    pub api_calls: usize,
    /// The next this many upload chunks keep only their first half, as Drive
    /// may, and say so in the `Range` of the 308.
    pub keep_half: usize,
}

impl DriveState {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn new_id(&mut self) -> String {
        self.next_id += 1;
        format!("id{:06}", self.next_id)
    }

    /// Adds a file directly, as another client would: the tests' way to
    /// make a duplicate.
    pub fn add_file(&mut self, name: &str, parent: &str, bytes: Vec<u8>) -> String {
        let id = self.new_id();
        let now = self.tick();
        self.items.push(Item {
            id: id.clone(),
            name: name.into(),
            parents: vec![parent.into()],
            folder: false,
            bytes,
            created: now,
            modified: now,
        });
        id
    }

    /// The id of the folder at `path` (names from My Drive), the first if
    /// several share it.
    pub fn folder_id(&self, path: &str) -> Option<String> {
        let mut parent = "root".to_string();
        for name in path.split('/') {
            parent = self
                .items
                .iter()
                .filter(|i| i.folder && i.name == name && i.parents.contains(&parent))
                .min_by_key(|i| (i.created, i.id.clone()))?
                .id
                .clone();
        }
        Some(parent)
    }
}

pub struct FakeDrive {
    pub api: String,
    pub upload: String,
    pub token_url: String,
    pub state: Arc<Mutex<DriveState>>,
}

impl FakeDrive {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(DriveState {
            page_size: 3,
            ..Default::default()
        }));
        let base = Arc::new(Mutex::new(String::new()));
        let handler: Arc<dyn Fn(Request) -> Reply + Send + Sync> = {
            let state = state.clone();
            let base = base.clone();
            Arc::new(move |request| {
                let base = base.lock().unwrap().clone();
                handle(&mut state.lock().unwrap(), &base, request)
            })
        };
        let url = serve(handler).await;
        *base.lock().unwrap() = url.clone();
        Self {
            api: format!("{url}/drive/v3"),
            upload: format!("{url}/upload/drive/v3"),
            token_url: format!("{url}/token"),
            state,
        }
    }
}

fn stamp(tick: u64) -> String {
    format!("2026-09-30T00:00:00.{tick:09}Z")
}

fn item_json(item: &Item) -> serde_json::Value {
    serde_json::json!({
        "id": item.id,
        "name": item.name,
        "mimeType": if item.folder { FOLDER } else { "application/octet-stream" },
        "size": item.bytes.len().to_string(),
        "modifiedTime": stamp(item.modified),
        "createdTime": stamp(item.created),
    })
}

/// The clauses of a `q`, split on ` and ` outside quotes.
fn clauses(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let chars: Vec<char> = q.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if escaped {
            current.push(c);
            escaped = false;
        } else if c == '\\' {
            current.push(c);
            escaped = true;
        } else if c == '\'' {
            quoted = !quoted;
            current.push(c);
        } else if !quoted && q[q.char_indices().nth(i).unwrap().0..].starts_with(" and ") {
            out.push(current.trim().to_string());
            current.clear();
            i += 5;
            continue;
        } else {
            current.push(c);
        }
        i += 1;
    }
    out.push(current.trim().to_string());
    out
}

fn literal(clause: &str) -> String {
    let start = clause.find('\'').unwrap_or(0) + 1;
    let end = clause.rfind('\'').unwrap_or(clause.len());
    let mut out = String::new();
    let mut escaped = false;
    for c in clause[start..end].chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn matches(item: &Item, q: &str) -> bool {
    clauses(q).iter().all(|clause| {
        if clause.ends_with(" in parents") {
            item.parents.contains(&literal(clause))
        } else if clause == "trashed = false" {
            true
        } else if clause.starts_with("name = ") {
            item.name == literal(clause)
        } else if clause.starts_with("mimeType != ") {
            !(item.folder && literal(clause) == FOLDER)
        } else if clause.starts_with("mimeType = ") {
            item.folder == (literal(clause) == FOLDER)
        } else {
            false
        }
    })
}

fn query_param(query: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// The metadata and the bytes of a `multipart/related` body.
fn multipart(content_type: &str, body: &[u8]) -> Option<(serde_json::Value, Vec<u8>)> {
    let boundary = content_type.split("boundary=").nth(1)?.trim();
    let marker = format!("--{boundary}");
    let text = body;
    let find = |from: usize, needle: &[u8]| {
        text[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    let first = find(0, marker.as_bytes())?;
    let meta_start = find(first, b"\r\n\r\n")? + 4;
    let meta_end = find(meta_start, format!("\r\n{marker}").as_bytes())?;
    let metadata = serde_json::from_slice(&text[meta_start..meta_end]).ok()?;
    let data_start = find(meta_end + 2, b"\r\n\r\n")? + 4;
    let data_end = find(data_start, format!("\r\n{marker}--").as_bytes())?;
    Some((metadata, text[data_start..data_end].to_vec()))
}

fn handle(state: &mut DriveState, base: &str, request: Request) -> Reply {
    let (path, query) = request
        .target
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((request.target.clone(), String::new()));
    if path == "/token" {
        state.tokens_issued += 1;
        let n = state.tokens_issued;
        return Reply::json(
            200,
            serde_json::json!({ "access_token": format!("at-{n}"), "expires_in": 3600 }),
        );
    }

    state.api_calls += 1;

    // The resumable session address: no token expected.
    if path == "/upload/drive/v3/files" && query_param(&query, "upload_id").is_some() {
        if request.headers.contains_key("authorization") {
            state
                .violations
                .push("token sent to a resumable upload address".into());
        }
        let id = query_param(&query, "upload_id").unwrap_or_default();
        if request.method == "DELETE" {
            state.sessions.remove(&id);
            return Reply::status(499);
        }
        let keep = if state.keep_half > 0 && state.sessions.contains_key(&id) {
            state.keep_half -= 1;
            request.body.len() / 2
        } else {
            request.body.len()
        };
        let Some((_, _, total, received)) = state.sessions.get_mut(&id) else {
            return Reply::status(404);
        };
        let range = request
            .headers
            .get("content-range")
            .cloned()
            .unwrap_or_default();
        let start: u64 = range
            .strip_prefix("bytes ")
            .and_then(|r| r.split('-').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        if start != received.len() as u64 {
            return Reply::status(400);
        }
        received.extend_from_slice(&request.body[..keep]);
        let done = received.len() as u64 == *total;
        if !done {
            let mut reply = Reply::status(308);
            if !received.is_empty() {
                reply
                    .headers
                    .push(("Range".into(), format!("bytes=0-{}", received.len() - 1)));
            }
            return reply;
        }
        let (existing, metadata, _, bytes) = state.sessions.remove(&id).unwrap();
        let now = state.tick();
        let file_id = match existing {
            Some(file_id) => {
                if let Some(item) = state.items.iter_mut().find(|i| i.id == file_id) {
                    item.bytes = bytes;
                    item.modified = now;
                }
                file_id
            }
            None => {
                let file_id = state.new_id();
                state.items.push(Item {
                    id: file_id.clone(),
                    name: metadata["name"].as_str().unwrap_or("").into(),
                    parents: metadata["parents"]
                        .as_array()
                        .map(|p| {
                            p.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                    folder: false,
                    bytes,
                    created: now,
                    modified: now,
                });
                file_id
            }
        };
        return Reply::json(200, serde_json::json!({ "id": file_id }));
    }

    if !request.headers.contains_key("authorization") {
        state
            .violations
            .push(format!("API call without a token: {path}"));
        return Reply::status(401);
    }
    if state.throttle > 0 {
        state.throttle -= 1;
        return Reply::json(
            403,
            serde_json::json!({ "error": { "errors": [{ "reason": "rateLimitExceeded" }] } }),
        );
    }

    let method = request.method.as_str();
    if path == "/drive/v3/about" {
        return Reply::json(
            200,
            serde_json::json!({
                "user": { "permissionId": "perm-1", "emailAddress": "ana@gmail.com" },
                "storageQuota": { "limit": "16106127360", "usage": "106127360" },
            }),
        );
    }
    if path == "/drive/v3/files" && method == "GET" {
        let q = query_param(&query, "q").unwrap_or_default();
        let skip: usize = query_param(&query, "pageToken")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        let hits: Vec<&Item> = state.items.iter().filter(|i| matches(i, &q)).collect();
        let page: Vec<serde_json::Value> = hits
            .iter()
            .skip(skip)
            .take(state.page_size)
            .map(|i| item_json(i))
            .collect();
        let mut body = serde_json::json!({ "files": page });
        if skip + state.page_size < hits.len() {
            body["nextPageToken"] = serde_json::Value::String((skip + state.page_size).to_string());
        }
        return Reply::json(200, body);
    }
    if path == "/drive/v3/files" && method == "POST" {
        let metadata: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let id = state.new_id();
        let now = state.tick();
        state.items.push(Item {
            id: id.clone(),
            name: metadata["name"].as_str().unwrap_or("").into(),
            parents: metadata["parents"]
                .as_array()
                .map(|p| {
                    p.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            folder: metadata["mimeType"].as_str() == Some(FOLDER),
            bytes: Vec::new(),
            created: now,
            modified: now,
        });
        return Reply::json(200, serde_json::json!({ "id": id }));
    }
    if let Some(id) = path.strip_prefix("/drive/v3/files/") {
        let id = id.to_string();
        if method == "DELETE" {
            let before = state.items.len();
            let mut gone = vec![id.clone()];
            // A folder takes what is in it.
            while let Some(parent) = gone.pop() {
                let inside: Vec<String> = state
                    .items
                    .iter()
                    .filter(|i| i.parents.contains(&parent))
                    .map(|i| i.id.clone())
                    .collect();
                state.items.retain(|i| i.id != parent);
                gone.extend(inside);
            }
            return Reply::status(if state.items.len() < before { 204 } else { 404 });
        }
        let Some(item) = state.items.iter().find(|i| i.id == id) else {
            return Reply::status(404);
        };
        if query_param(&query, "alt").as_deref() == Some("media") {
            if let Some(end) = request
                .headers
                .get("range")
                .and_then(|r| r.strip_prefix("bytes=0-"))
                .and_then(|e| e.parse::<usize>().ok())
            {
                let mut reply = Reply::status(206);
                reply.body = item.bytes[..(end + 1).min(item.bytes.len())].to_vec();
                return reply;
            }
            let mut reply = Reply::status(200);
            reply.body = item.bytes.clone();
            return reply;
        }
        return Reply::json(200, item_json(item));
    }
    if path == "/upload/drive/v3/files" || path.starts_with("/upload/drive/v3/files/") {
        let existing = path
            .strip_prefix("/upload/drive/v3/files/")
            .map(str::to_string);
        let kind = query_param(&query, "uploadType").unwrap_or_default();
        if kind == "resumable" {
            let metadata: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_default();
            let total: u64 = request
                .headers
                .get("x-upload-content-length")
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
            let id = state.new_id();
            state
                .sessions
                .insert(id.clone(), (existing, metadata, total, Vec::new()));
            let mut reply = Reply::status(200);
            reply.headers.push((
                "Location".into(),
                format!("{base}/upload/drive/v3/files?uploadType=resumable&upload_id={id}"),
            ));
            return reply;
        }
        if kind == "media" && method == "PATCH" {
            let now = state.tick();
            let Some(item) = state
                .items
                .iter_mut()
                .find(|i| Some(&i.id) == existing.as_ref())
            else {
                return Reply::status(404);
            };
            item.bytes = request.body;
            item.modified = now;
            return Reply::json(200, serde_json::json!({ "id": item.id }));
        }
        if kind == "multipart" {
            let content_type = request
                .headers
                .get("content-type")
                .cloned()
                .unwrap_or_default();
            let Some((metadata, bytes)) = multipart(&content_type, &request.body) else {
                return Reply::status(400);
            };
            let id = state.new_id();
            let now = state.tick();
            state.items.push(Item {
                id: id.clone(),
                name: metadata["name"].as_str().unwrap_or("").into(),
                parents: metadata["parents"]
                    .as_array()
                    .map(|p| {
                        p.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                folder: false,
                bytes,
                created: now,
                modified: now,
            });
            return Reply::json(200, serde_json::json!({ "id": id }));
        }
    }
    Reply::status(404)
}
