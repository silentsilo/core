//! A minimal HTTP server for the tests, and a fake Microsoft Graph on it:
//! the token endpoint, path-addressed items, upload sessions and paged
//! listings, with the misbehaviour the real one shows now and then
//! (throttling, an access token that stops working) switchable on.
//!
//! It also watches the client: a token sent to a pre-authenticated upload or
//! download address, or an API call without one, is recorded as a violation.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
        }
    }
}

type Handler = Arc<dyn Fn(Request) -> Reply + Send + Sync>;

/// Serves `handler` on a free port of 127.0.0.1; returns `http://127.0.0.1:port`.
pub async fn serve(handler: Handler) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut socket).await else {
                    return;
                };
                let reply = handler(request);
                let mut head = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&reply.body).await;
            });
        }
    });
    base
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<Request> {
    let mut raw = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let header_end = loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);
    let mut body = raw[header_end + 4..].to_vec();
    while body.len() < length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Some(Request {
        method,
        target,
        headers,
        body,
    })
}

fn decode(path: &str) -> String {
    percent_encoding::percent_decode_str(path)
        .decode_utf8_lossy()
        .to_string()
}

#[derive(Default)]
pub struct GraphState {
    pub files: BTreeMap<String, Vec<u8>>,
    sessions: HashMap<u64, (String, u64, Vec<u8>)>,
    next_id: u64,
    tokens_issued: u64,
    /// The next this many API calls answer 429 with `Retry-After: 0`.
    pub throttle: usize,
    /// The first access token is refused once with a 401, as an expired one.
    pub refuse_first_token: bool,
    refused: bool,
    /// Listings return this many items a page.
    pub page_size: usize,
    /// Every page's `nextLink` points at another host.
    pub foreign_next_link: bool,
    pub violations: Vec<String>,
    pub api_calls: usize,
    /// What `/me/drive` says the drive is; `personal` when unset.
    pub drive_type: Option<String>,
}

pub struct FakeGraph {
    pub api: String,
    pub token_url: String,
    pub state: Arc<Mutex<GraphState>>,
}

impl FakeGraph {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(GraphState {
            page_size: 3,
            ..Default::default()
        }));
        let base = Arc::new(Mutex::new(String::new()));
        let handler: Handler = {
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
            api: format!("{url}/v1.0"),
            token_url: format!("{url}/token"),
            state,
        }
    }
}

fn handle(state: &mut GraphState, base: &str, request: Request) -> Reply {
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
            serde_json::json!({ "access_token": format!("at-{n}"), "refresh_token": format!("rt-{n}"), "expires_in": 3600 }),
        );
    }

    // Pre-authenticated addresses: a token here is a leak.
    if let Some(rest) = path.strip_prefix("/download/") {
        if request.headers.contains_key("authorization") {
            state
                .violations
                .push(format!("token sent to a download address: {path}"));
        }
        let key = decode(rest);
        let Some(bytes) = state.files.get(&key) else {
            return Reply::status(404);
        };
        if let Some(range) = request.headers.get("range")
            && let Some(end) = range
                .strip_prefix("bytes=0-")
                .and_then(|e| e.parse::<usize>().ok())
        {
            let end = (end + 1).min(bytes.len());
            let mut reply = Reply::status(206);
            reply.body = bytes[..end].to_vec();
            return reply;
        }
        let mut reply = Reply::status(200);
        reply.body = bytes.clone();
        return reply;
    }
    if let Some(id) = path.strip_prefix("/upload/") {
        if request.headers.contains_key("authorization") {
            state
                .violations
                .push(format!("token sent to an upload address: {path}"));
        }
        let id: u64 = id.parse().unwrap_or(u64::MAX);
        if request.method == "DELETE" {
            state.sessions.remove(&id);
            return Reply::status(204);
        }
        let Some((_, total, received)) = state.sessions.get_mut(&id) else {
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
        let whole: u64 = range
            .rsplit('/')
            .next()
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        if *total == 0 {
            *total = whole;
        }
        if start != received.len() as u64 || whole != *total {
            return Reply::status(416);
        }
        received.extend_from_slice(&request.body);
        let done = received.len() as u64 == *total;
        let so_far = received.len();
        if done {
            let (key, total, bytes) = state.sessions.remove(&id).unwrap();
            state.files.insert(key, bytes);
            return Reply::json(201, serde_json::json!({ "size": total }));
        }
        return Reply::json(
            202,
            serde_json::json!({ "nextExpectedRanges": [format!("{so_far}-")] }),
        );
    }

    if path == "/v1.0/me/drive" {
        if !request.headers.contains_key("authorization") {
            return Reply::status(401);
        }
        return Reply::json(
            200,
            serde_json::json!({
                "id": "drive-1",
                "driveType": state.drive_type.clone().unwrap_or_else(|| "personal".into()),
                "owner": { "user": { "displayName": "Ana Pop" } },
                "quota": { "total": 1000, "remaining": 400 },
            }),
        );
    }
    if path == "/v1.0/me/drive/special/approot/children" {
        if !request.headers.contains_key("authorization") {
            return Reply::status(401);
        }
        let mut folders: Vec<String> = state
            .files
            .keys()
            .filter_map(|k| Some(k.split_once('/')?.0.to_string()))
            .collect();
        folders.dedup();
        let value: Vec<serde_json::Value> = folders
            .iter()
            .map(|name| serde_json::json!({ "name": name, "folder": {} }))
            .chain(std::iter::once(
                serde_json::json!({ "name": "stray.txt", "file": {} }),
            ))
            .collect();
        return Reply::json(200, serde_json::json!({ "value": value }));
    }

    let Some(item) = path.strip_prefix("/v1.0/me/drive/special/approot:/") else {
        return Reply::status(400);
    };
    state.api_calls += 1;
    let Some(auth) = request.headers.get("authorization") else {
        state
            .violations
            .push(format!("API call without a token: {path}"));
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

    let (key, suffix) = match item.split_once(':') {
        Some((k, s)) => (decode(k), s.to_string()),
        None => (decode(item), String::new()),
    };
    let is_folder = |files: &BTreeMap<String, Vec<u8>>, key: &str| {
        let prefix = format!("{key}/");
        files.keys().any(|k| k.starts_with(&prefix))
    };

    match (request.method.as_str(), suffix.as_str()) {
        ("PUT", "/content") => {
            state.files.insert(key, request.body);
            Reply::json(201, serde_json::json!({}))
        }
        ("GET", "/content") => {
            if !state.files.contains_key(&key) {
                return Reply::status(404);
            }
            let mut reply = Reply::status(302);
            reply.headers.push((
                "Location".into(),
                format!(
                    "{base}/download/{}",
                    percent_encoding::utf8_percent_encode(&key, percent_encoding::NON_ALPHANUMERIC)
                ),
            ));
            reply
        }
        ("POST", "/createUploadSession") => {
            state.next_id += 1;
            let id = state.next_id;
            // The total is learned from the first chunk's Content-Range.
            state.sessions.insert(id, (key, 0, Vec::new()));
            Reply::json(
                200,
                serde_json::json!({ "uploadUrl": format!("{base}/upload/{id}") }),
            )
        }
        ("GET", "/children") => {
            if !is_folder(&state.files, &key) {
                return Reply::status(404);
            }
            let prefix = format!("{key}/");
            let mut children: Vec<(String, Option<u64>)> = Vec::new();
            for (name, bytes) in state.files.range(prefix.clone()..) {
                let Some(rest) = name.strip_prefix(&prefix) else {
                    break;
                };
                match rest.split_once('/') {
                    Some((folder, _)) => {
                        if children.last().map(|(n, _)| n.as_str()) != Some(folder) {
                            children.push((folder.to_string(), None));
                        }
                    }
                    None => children.push((rest.to_string(), Some(bytes.len() as u64))),
                }
            }
            children.dedup_by(|a, b| a.0 == b.0 && a.1.is_none() && b.1.is_none());
            let skip: usize = query
                .split('&')
                .find_map(|p| p.strip_prefix("$skiptoken="))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let page: Vec<serde_json::Value> = children
                .iter()
                .skip(skip)
                .take(state.page_size)
                .map(|(name, size)| match size {
                    Some(size) => serde_json::json!({ "name": name, "size": size, "file": {} }),
                    None => serde_json::json!({ "name": name, "folder": {} }),
                })
                .collect();
            let mut body = serde_json::json!({ "value": page });
            if skip + state.page_size < children.len() {
                let host = if state.foreign_next_link {
                    "http://127.0.0.2:1/v1.0".to_string()
                } else {
                    format!("{base}/v1.0")
                };
                let encoded: Vec<String> = key
                    .split('/')
                    .map(|p| {
                        percent_encoding::utf8_percent_encode(p, percent_encoding::NON_ALPHANUMERIC)
                            .to_string()
                    })
                    .collect();
                body["@odata.nextLink"] = serde_json::Value::String(format!(
                    "{host}/me/drive/special/approot:/{}:/children?$skiptoken={}",
                    encoded.join("/"),
                    skip + state.page_size
                ));
            }
            Reply::json(200, body)
        }
        ("GET", _) => match state.files.get(&key) {
            Some(bytes) => Reply::json(200, serde_json::json!({ "size": bytes.len(), "file": {} })),
            None if is_folder(&state.files, &key) => {
                Reply::json(200, serde_json::json!({ "folder": {} }))
            }
            None => Reply::status(404),
        },
        ("DELETE", "") => {
            let prefix = format!("{key}/");
            let before = state.files.len();
            state
                .files
                .retain(|k, _| k != &key && !k.starts_with(&prefix));
            if state.files.len() == before {
                Reply::status(404)
            } else {
                Reply::status(204)
            }
        }
        _ => Reply::status(405),
    }
}
