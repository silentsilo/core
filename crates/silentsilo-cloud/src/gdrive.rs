//! Google Drive through the v3 API with the `drive.file` permission: the
//! app sees only what it created. A `SilentSilo` folder in My Drive, one
//! subfolder per silo, and under it real folders for the key's path
//! (`ops/`, `blobs/` ...), so a folder downloaded from drive.google.com has
//! the layout `silentsilo-extract` reads.
//!
//! Drive addresses by id and lets two files share a name in one folder. So:
//! every lookup is by name inside a parent, and when a name is held more than
//! once (two writers at the same moment, or two devices creating a folder)
//! the copy that sorts last by (modified time, id) is the object. A writer
//! removes only the copies that sort before its own, so two writers never
//! remove each other's; listings show each key once; `delete` removes every
//! copy. Duplicate folders are read as one: listings merge them, and writes
//! go to the one that sorts first by (created time, id), whichever device
//! asks.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{Method, Response, StatusCode};
use silentsilo_store::{CloudConfig, ObjectStore, Progress, StoreError, StoredObject};

use crate::TokenSource;
use crate::http::{Http, read_at, stream_to_file, transport, trusted_address};

const API: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3";
const FOLDER: &str = "application/vnd.google-apps.folder";
/// The app's own folder in My Drive.
const ROOT_NAME: &str = "SilentSilo";
/// At or under this, one multipart call; over it, a resumable upload.
const SMALL: u64 = 5 * 1024 * 1024;
/// A multiple of 256 KiB, as Drive requires.
const CHUNK: u64 = 32 * 256 * 1024;
const MAX_PAGES: usize = 100_000;

/// One file or folder as Drive lists it.
#[derive(Debug, Clone)]
struct Item {
    id: String,
    name: String,
    folder: bool,
    size: i64,
    modified: String,
    created: String,
}

impl Item {
    fn from_json(value: &serde_json::Value) -> Option<Self> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let id = text("id");
        if id.is_empty() {
            return None;
        }
        Some(Self {
            id,
            name: text("name"),
            folder: text("mimeType") == FOLDER,
            // Drive sends the size as a string.
            size: value
                .get("size")
                .and_then(|s| {
                    s.as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| s.as_i64())
                })
                .unwrap_or(0),
            modified: text("modifiedTime"),
            created: text("createdTime"),
        })
    }

    /// The copy of a file name that is the object: last by this order.
    fn file_order(&self) -> (&str, &str) {
        (&self.modified, &self.id)
    }

    /// The folder writes go to: first by this order.
    fn folder_order(&self) -> (&str, &str) {
        (&self.created, &self.id)
    }
}

/// A query literal: Drive escapes `'` and `\` with a backslash.
fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

pub struct GoogleDriveStore {
    http: Http,
    api: String,
    upload: String,
    folder: String,
    account: String,
    /// Folder path (relative to My Drive, `SilentSilo/<silo>/ops`) to the
    /// ids that hold that name, sorted: the first is where writes go.
    folders: Mutex<HashMap<String, Vec<String>>>,
    /// Folder paths found missing, and keys found nowhere, since this store
    /// was opened. A sync pass asks about each new record and blob before it
    /// writes it, and the write asks again: without these, every one cost a
    /// walk and a search on a folder already known not to be there. Another
    /// device's write in the meantime is seen by the next pass, as with a
    /// listing; a duplicate it causes is one the rules above settle.
    absent_dirs: Mutex<HashSet<String>>,
    absent_keys: Mutex<HashSet<String>>,
}

impl GoogleDriveStore {
    pub fn new(config: CloudConfig, tokens: Arc<TokenSource>) -> Result<Self, StoreError> {
        Self::with_hosts(API, UPLOAD, config, tokens)
    }

    /// Pointed at other hosts: the tests' fake.
    pub fn with_hosts(
        api: &str,
        upload: &str,
        config: CloudConfig,
        tokens: Arc<TokenSource>,
    ) -> Result<Self, StoreError> {
        let folder = config.folder.trim_matches('/').to_string();
        if folder.is_empty() || folder.split('/').any(|part| part == "." || part == "..") {
            return Err(StoreError::Other(
                "the Google Drive folder name is not usable".into(),
            ));
        }
        Ok(Self {
            http: Http::new(tokens, "Google Drive")?,
            api: api.trim_end_matches('/').to_string(),
            upload: upload.trim_end_matches('/').to_string(),
            folder,
            account: config.account_label,
            folders: Mutex::new(HashMap::new()),
            absent_dirs: Mutex::new(HashSet::new()),
            absent_keys: Mutex::new(HashSet::new()),
        })
    }

    /// Drive signals throttling with a 403 whose reason names a rate limit,
    /// as well as with 429: both are waited out. A 403 for a full Drive is
    /// said in words.
    async fn call(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&[u8]>,
        key: &str,
    ) -> Result<Response, StoreError> {
        for attempt in 1..=6u32 {
            let response = self.http.send(method.clone(), url, headers, body).await?;
            if response.status() != StatusCode::FORBIDDEN {
                return Ok(response);
            }
            let reason = self
                .http
                .json(response)
                .await
                .ok()
                .and_then(|v| {
                    v.pointer("/error/errors/0/reason")
                        .and_then(|r| r.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            match reason.as_str() {
                "rateLimitExceeded" | "userRateLimitExceeded" if attempt < 6 => {
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(attempt))).await;
                }
                "storageQuotaExceeded" => {
                    return Err(StoreError::Other("Google Drive is full".into()));
                }
                "dailyLimitExceeded" | "uploadLimitExceeded" => {
                    return Err(StoreError::Other(
                        "Google Drive's daily upload limit is reached; it resumes tomorrow".into(),
                    ));
                }
                _ => return Err(self.http.status_error(StatusCode::FORBIDDEN, key)),
            }
        }
        Err(StoreError::Unreachable(
            "Google Drive kept refusing: too many requests".into(),
        ))
    }

    /// Every item matching `query`, all pages.
    async fn search(&self, query: &str) -> Result<Vec<Item>, StoreError> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..MAX_PAGES {
            let mut url = url::Url::parse(&format!("{}/files", self.api))
                .map_err(|e| StoreError::Other(e.to_string()))?;
            {
                let mut pairs = url.query_pairs_mut();
                pairs
                    .append_pair("q", query)
                    .append_pair("pageSize", "1000")
                    .append_pair("spaces", "drive")
                    .append_pair(
                        "fields",
                        "nextPageToken,files(id,name,mimeType,size,modifiedTime,createdTime)",
                    );
                if let Some(token) = &token {
                    pairs.append_pair("pageToken", token);
                }
            }
            let response = self
                .call(Method::GET, url.as_str(), &[], None, query)
                .await?;
            if !response.status().is_success() {
                return Err(self.http.status_error(response.status(), "a listing"));
            }
            let page = self.http.json(response).await?;
            out.extend(
                page.get("files")
                    .and_then(|f| f.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(Item::from_json),
            );
            match page.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(next) if !next.is_empty() && seen.insert(next.to_string()) => {
                    token = Some(next.to_string());
                }
                Some(_) => {
                    return Err(StoreError::Other(
                        "Google Drive sent a listing that does not end".into(),
                    ));
                }
                None => return Ok(out),
            }
        }
        Err(StoreError::Other(
            "Google Drive sent a listing that does not end".into(),
        ))
    }

    async fn children(
        &self,
        parent: &str,
        name: Option<&str>,
        folders: Option<bool>,
    ) -> Result<Vec<Item>, StoreError> {
        let mut query = format!("{} in parents and trashed = false", quoted(parent));
        if let Some(name) = name {
            query.push_str(&format!(" and name = {}", quoted(name)));
        }
        match folders {
            Some(true) => query.push_str(&format!(" and mimeType = {}", quoted(FOLDER))),
            Some(false) => query.push_str(&format!(" and mimeType != {}", quoted(FOLDER))),
            None => {}
        }
        self.search(&query).await
    }

    /// The segments of a folder path from My Drive: `SilentSilo`, the silo,
    /// then the key's own folders.
    fn segments(&self, dir: &str) -> Vec<String> {
        std::iter::once(ROOT_NAME.to_string())
            .chain(self.folder.split('/').map(str::to_string))
            .chain(dir.split('/').filter(|s| !s.is_empty()).map(str::to_string))
            .collect()
    }

    /// Every folder id that holds the folder path `dir` of the silo, sorted
    /// so the first is where writes go. Empty when some part does not
    /// exist and `create` is false.
    ///
    /// `fresh` asks Drive rather than the cache: a twin folder another
    /// device made after the cache was filled holds files a read must see.
    /// Writes may use the cache, since the folder that sorts first by
    /// creation stays first.
    async fn resolve(
        &self,
        dir: &str,
        create: bool,
        fresh: bool,
    ) -> Result<Vec<String>, StoreError> {
        let segments = self.segments(dir);
        let mut parents = vec!["root".to_string()];
        let mut path = String::new();
        for segment in segments {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(&segment);
            if !fresh
                && let Some(ids) = self.folders.lock().ok().and_then(|f| f.get(&path).cloned())
            {
                parents = ids;
                continue;
            }
            if !fresh
                && !create
                && self
                    .absent_dirs
                    .lock()
                    .is_ok_and(|absent| absent.contains(&path))
            {
                return Ok(Vec::new());
            }
            let mut found = Vec::new();
            for parent in &parents {
                found.extend(self.children(parent, Some(&segment), Some(true)).await?);
            }
            if found.is_empty() {
                if !create {
                    if let Ok(mut absent) = self.absent_dirs.lock() {
                        absent.insert(path);
                    }
                    return Ok(Vec::new());
                }
                self.create_folder(&segment, &parents[0]).await?;
                if let Ok(mut absent) = self.absent_dirs.lock() {
                    absent.clear();
                }
                // Read back rather than trusted: another device may have
                // made the same folder at the same moment.
                for parent in &parents {
                    found.extend(self.children(parent, Some(&segment), Some(true)).await?);
                }
            }
            found.sort_by(|a, b| a.folder_order().cmp(&b.folder_order()));
            let ids: Vec<String> = found.into_iter().map(|item| item.id).collect();
            if ids.is_empty() {
                return Err(StoreError::Other(
                    "Google Drive did not keep a new folder".into(),
                ));
            }
            if let Ok(mut folders) = self.folders.lock() {
                folders.insert(path.clone(), ids.clone());
            }
            parents = ids;
        }
        Ok(parents)
    }

    fn forget_folders(&self) {
        if let Ok(mut folders) = self.folders.lock() {
            folders.clear();
        }
        if let Ok(mut absent) = self.absent_dirs.lock() {
            absent.clear();
        }
        if let Ok(mut absent) = self.absent_keys.lock() {
            absent.clear();
        }
    }

    fn known_absent(&self, key: &str) -> bool {
        self.absent_keys
            .lock()
            .is_ok_and(|absent| absent.contains(key))
    }

    fn mark_absent(&self, key: &str, absent: bool) {
        if let Ok(mut keys) = self.absent_keys.lock() {
            if absent {
                keys.insert(key.to_string());
            } else {
                keys.remove(key);
            }
        }
    }

    async fn create_folder(&self, name: &str, parent: &str) -> Result<(), StoreError> {
        let body = serde_json::json!({ "name": name, "mimeType": FOLDER, "parents": [parent] });
        let response = self
            .call(
                Method::POST,
                &format!("{}/files?fields=id", self.api),
                &[("Content-Type", "application/json".into())],
                Some(body.to_string().as_bytes()),
                name,
            )
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(self.http.status_error(response.status(), name))
        }
    }

    fn split(key: &str) -> (&str, &str) {
        match key.rfind('/') {
            Some(at) => (&key[..at], &key[at + 1..]),
            None => ("", key),
        }
    }

    /// Every copy of `key`'s file, the object last. Found nowhere through
    /// the cached folders, the name is searched for once across what the app
    /// can see, and only a hit somewhere is worth fresh folders: a twin
    /// another device made may hold it. A plain miss, the common case for
    /// every new record and blob, stays two calls.
    async fn copies(&self, key: &str) -> Result<Vec<Item>, StoreError> {
        if self.known_absent(key) {
            return Ok(Vec::new());
        }
        let (dir, name) = Self::split(key);
        let parents = self.resolve(dir, false, false).await?;
        // No folder, no file: nothing to search for.
        if parents.is_empty() {
            self.mark_absent(key, true);
            return Ok(Vec::new());
        }
        let copies = self.copies_under(&parents, name).await?;
        if !copies.is_empty() {
            return Ok(copies);
        }
        let query = format!(
            "name = {} and trashed = false and mimeType != {}",
            quoted(name),
            quoted(FOLDER)
        );
        if self.search(&query).await?.is_empty() {
            self.mark_absent(key, true);
            return Ok(Vec::new());
        }
        self.copies_in(key, true).await
    }

    async fn copies_under(&self, parents: &[String], name: &str) -> Result<Vec<Item>, StoreError> {
        let mut copies = Vec::new();
        for parent in parents {
            copies.extend(self.children(parent, Some(name), Some(false)).await?);
        }
        copies.sort_by(|a, b| a.file_order().cmp(&b.file_order()));
        Ok(copies)
    }

    async fn copies_in(&self, key: &str, fresh: bool) -> Result<Vec<Item>, StoreError> {
        let (dir, name) = Self::split(key);
        let parents = self.resolve(dir, false, fresh).await?;
        self.copies_under(&parents, name).await
    }

    async fn current(&self, key: &str) -> Result<Option<Item>, StoreError> {
        Ok(self.copies(key).await?.pop())
    }

    /// Removes the copies of `key` that sort before `mine`: never a newer
    /// one, so two writers cannot remove each other's.
    async fn tidy(&self, key: &str, mine: &str) -> Result<(), StoreError> {
        let copies = self.copies(key).await?;
        let Some(mine) = copies.iter().find(|c| c.id == mine).cloned() else {
            return Ok(());
        };
        for older in copies.iter().filter(|c| c.file_order() < mine.file_order()) {
            self.delete_id(&older.id).await?;
        }
        Ok(())
    }

    async fn delete_id(&self, id: &str) -> Result<(), StoreError> {
        let response = self
            .call(
                Method::DELETE,
                &format!("{}/files/{id}", self.api),
                &[],
                None,
                id,
            )
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(()),
            status if status.is_success() => Ok(()),
            status => Err(self.http.status_error(status, id)),
        }
    }

    /// One call: metadata and bytes together, so the file never exists empty.
    async fn upload_small(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let (dir, name) = Self::split(key);
        let response = match self.current(key).await? {
            // Replaced in place: no second copy appears.
            Some(existing) => {
                self.call(
                    Method::PATCH,
                    &format!(
                        "{}/files/{}?uploadType=media&fields=id",
                        self.upload, existing.id
                    ),
                    &[("Content-Type", "application/octet-stream".into())],
                    Some(bytes),
                    key,
                )
                .await?
            }
            None => {
                let parent = self.resolve(dir, true, false).await?.remove(0);
                let boundary = format!("silentsilo-{}", crate::pkce::random_state());
                let metadata = serde_json::json!({ "name": name, "parents": [parent] });
                let mut body = Vec::new();
                body.extend_from_slice(
                    format!(
                        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(bytes);
                body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
                self.call(
                    Method::POST,
                    &format!("{}/files?uploadType=multipart&fields=id", self.upload),
                    &[(
                        "Content-Type",
                        format!("multipart/related; boundary={boundary}"),
                    )],
                    Some(&body),
                    key,
                )
                .await?
            }
        };
        if !response.status().is_success() {
            self.forget_folders();
            return Err(self.http.status_error(response.status(), key));
        }
        let id = self
            .http
            .json(response)
            .await?
            .get("id")
            .and_then(|i| i.as_str())
            .map(str::to_string)
            .unwrap_or_default();
        self.mark_absent(key, false);
        self.tidy(key, &id).await
    }

    /// A resumable upload: the file appears only when the last byte is in.
    async fn upload_resumable(
        &self,
        key: &str,
        total: u64,
        read: &mut (dyn FnMut(u64, usize) -> Result<Vec<u8>, StoreError> + Send),
        progress: Progress<'_>,
    ) -> Result<(), StoreError> {
        let (dir, name) = Self::split(key);
        let (method, url, metadata) = match self.current(key).await? {
            Some(existing) => (
                Method::PATCH,
                format!(
                    "{}/files/{}?uploadType=resumable&fields=id",
                    self.upload, existing.id
                ),
                serde_json::json!({}),
            ),
            None => {
                let parent = self.resolve(dir, true, false).await?.remove(0);
                (
                    Method::POST,
                    format!("{}/files?uploadType=resumable&fields=id", self.upload),
                    serde_json::json!({ "name": name, "parents": [parent] }),
                )
            }
        };
        let response = self
            .call(
                method,
                &url,
                &[
                    ("Content-Type", "application/json; charset=UTF-8".into()),
                    ("X-Upload-Content-Length", total.to_string()),
                ],
                Some(metadata.to_string().as_bytes()),
                key,
            )
            .await?;
        if !response.status().is_success() {
            return Err(self.http.status_error(response.status(), key));
        }
        let session = response
            .headers()
            .get("Location")
            .and_then(|l| l.to_str().ok())
            .filter(|l| trusted_address(l, &self.api))
            .map(str::to_string)
            .ok_or_else(|| {
                StoreError::Other("Google Drive gave no usable upload address".into())
            })?;

        let mut offset = 0u64;
        let mut id = String::new();
        while offset < total {
            let chunk = read(offset, CHUNK.min(total - offset) as usize)?;
            let end = offset + chunk.len() as u64 - 1;
            // The session address stands for the upload: no token with it.
            let response = self
                .http
                .send_plain(
                    Method::PUT,
                    &session,
                    &[("Content-Range", format!("bytes {offset}-{end}/{total}"))],
                    Some(&chunk),
                )
                .await?;
            let status = response.status();
            offset += chunk.len() as u64;
            if status.is_success() {
                id = self
                    .http
                    .json(response)
                    .await?
                    .get("id")
                    .and_then(|i| i.as_str())
                    .map(str::to_string)
                    .unwrap_or_default();
            } else if status.as_u16() != 308 {
                let _ = self.http.plain.delete(&session).send().await;
                return Err(self.http.status_error(status, key));
            }
            if progress(chunk.len() as u64).is_break() {
                if offset < total {
                    let _ = self.http.plain.delete(&session).send().await;
                }
                return Err(StoreError::Cancelled);
            }
        }
        self.mark_absent(key, false);
        self.tidy(key, &id).await
    }

    async fn download(&self, key: &str, range: Option<u64>) -> Result<Response, StoreError> {
        let item = self
            .current(key)
            .await?
            .ok_or_else(|| StoreError::NotFound(key.to_string()))?;
        let headers: Vec<(&str, String)> = match range {
            Some(len) => vec![("Range", format!("bytes=0-{}", len - 1))],
            None => Vec::new(),
        };
        let response = self
            .call(
                Method::GET,
                &format!("{}/files/{}?alt=media", self.api, item.id),
                &headers,
                None,
                key,
            )
            .await?;
        let status = response.status();
        if status.is_success() {
            Ok(response)
        } else if status == StatusCode::RANGE_NOT_SATISFIABLE {
            Box::pin(self.download(key, None)).await
        } else {
            Err(self.http.status_error(status, key))
        }
    }
}

#[async_trait::async_trait]
impl crate::Probe for GoogleDriveStore {
    async fn account(&self) -> Result<crate::Account, StoreError> {
        let url = format!(
            "{}/about?fields=user(permissionId,emailAddress,displayName),storageQuota(limit,usage)",
            self.api
        );
        let response = self
            .call(Method::GET, &url, &[], None, "the account")
            .await?;
        if !response.status().is_success() {
            return Err(self.http.status_error(response.status(), "the account"));
        }
        let about = self.http.json(response).await?;
        let id = about
            .pointer("/user/permissionId")
            .and_then(|i| i.as_str())
            .filter(|i| !i.is_empty())
            .ok_or_else(|| StoreError::Other("Google Drive did not say which account".into()))?;
        let label = ["/user/emailAddress", "/user/displayName"]
            .iter()
            .find_map(|at| about.pointer(at)?.as_str().filter(|s| !s.is_empty()))
            .unwrap_or("Google Drive");
        // Drive gives the numbers as strings; no limit means unlimited.
        let number = |at: &str| about.pointer(at)?.as_str()?.parse::<u64>().ok();
        let total = number("/storageQuota/limit");
        let used = number("/storageQuota/usage");
        Ok(crate::Account {
            id: id.to_string(),
            label: label.to_string(),
            free_bytes: total
                .zip(used)
                .map(|(total, used)| total.saturating_sub(used)),
            total_bytes: total,
        })
    }

    async fn silo_folders(&self) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();
        for root in self.children("root", Some(ROOT_NAME), Some(true)).await? {
            names.extend(
                self.children(&root.id, None, Some(true))
                    .await?
                    .into_iter()
                    .map(|item| item.name),
            );
        }
        // Twin folders from two devices are one silo.
        names.sort();
        names.dedup();
        Ok(names)
    }
}

#[async_trait::async_trait]
impl ObjectStore for GoogleDriveStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        let total = bytes.len() as u64;
        if total <= SMALL {
            return self.upload_small(key, &bytes).await;
        }
        let mut read = |offset: u64, length: usize| {
            Ok(bytes[offset as usize..offset as usize + length].to_vec())
        };
        self.upload_resumable(key, total, &mut read, &mut |_| ControlFlow::Continue(()))
            .await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        Ok(self
            .download(key, None)
            .await?
            .bytes()
            .await
            .map_err(|e| transport("Google Drive", &e))?
            .to_vec())
    }

    async fn get_prefix(&self, key: &str, len: u64) -> Result<Vec<u8>, StoreError> {
        if len == 0 {
            self.head(key)
                .await?
                .ok_or_else(|| StoreError::NotFound(key.to_string()))?;
            return Ok(Vec::new());
        }
        let mut bytes = self
            .download(key, Some(len))
            .await?
            .bytes()
            .await
            .map_err(|e| transport("Google Drive", &e))?
            .to_vec();
        bytes.truncate(len as usize);
        Ok(bytes)
    }

    async fn put_from_file(&self, key: &str, path: &Path) -> Result<(), StoreError> {
        self.put_from_file_reporting(key, path, &mut |_| ControlFlow::Continue(()))
            .await
    }

    async fn put_from_file_reporting(
        &self,
        key: &str,
        path: &Path,
        progress: Progress<'_>,
    ) -> Result<(), StoreError> {
        let total = std::fs::metadata(path)
            .map_err(|e| StoreError::Other(format!("{}: {e}", path.display())))?
            .len();
        if total <= SMALL {
            let bytes = std::fs::read(path)
                .map_err(|e| StoreError::Other(format!("{}: {e}", path.display())))?;
            self.upload_small(key, &bytes).await?;
            if progress(total).is_break() {
                return Err(StoreError::Cancelled);
            }
            return Ok(());
        }
        let file = std::fs::File::open(path)
            .map_err(|e| StoreError::Other(format!("{}: {e}", path.display())))?;
        let mut read = move |offset: u64, length: usize| {
            let mut chunk = vec![0u8; length];
            read_at(&file, &mut chunk, offset)
                .map_err(|e| StoreError::Other(format!("reading the file: {e}")))?;
            Ok(chunk)
        };
        self.upload_resumable(key, total, &mut read, progress).await
    }

    async fn get_to_file(&self, key: &str, dest: &Path) -> Result<(), StoreError> {
        self.get_to_file_reporting(key, dest, &mut |_| ControlFlow::Continue(()))
            .await
    }

    async fn get_to_file_reporting(
        &self,
        key: &str,
        dest: &Path,
        progress: Progress<'_>,
    ) -> Result<(), StoreError> {
        let response = self.download(key, None).await?;
        stream_to_file(response, dest, progress, "Google Drive").await
    }

    async fn head(&self, key: &str) -> Result<Option<i64>, StoreError> {
        Ok(self.current(key).await?.map(|item| item.size))
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        // Every copy: a delete that left an older one would bring it back.
        for copy in self.copies(key).await? {
            self.delete_id(&copy.id).await?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, StoreError> {
        let dir = match prefix.rfind('/') {
            Some(at) => &prefix[..at],
            None => "",
        };
        let base = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        // Key to its object: the copy that sorts last.
        let mut found: HashMap<String, Item> = HashMap::new();
        let mut folders: Vec<(String, String)> = self
            .resolve(dir, false, true)
            .await?
            .into_iter()
            .map(|id| (base.clone(), id))
            .collect();
        while let Some((path, id)) = folders.pop() {
            for item in self.children(&id, None, None).await? {
                let key = format!("{path}{}", item.name);
                if item.folder {
                    folders.push((format!("{key}/"), item.id));
                    continue;
                }
                if !key.starts_with(prefix) {
                    continue;
                }
                match found.get(&key) {
                    Some(held) if held.file_order() >= item.file_order() => {}
                    _ => {
                        found.insert(key, item);
                    }
                }
            }
        }
        let mut objects: Vec<StoredObject> = found
            .into_iter()
            .map(|(key, item)| StoredObject {
                key,
                size: item.size,
            })
            .collect();
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(objects)
    }

    fn describe(&self) -> String {
        if self.account.is_empty() {
            "Google Drive".into()
        } else {
            format!("Google Drive ({})", self.account)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_gdrive::{DriveState, FakeDrive};
    use crate::{OAuth, PersistToken, Provider};

    struct Forget;

    impl PersistToken for Forget {
        fn save(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    async fn store_in(folder: &str) -> (GoogleDriveStore, Arc<Mutex<DriveState>>) {
        let fake = FakeDrive::start().await;
        let oauth = OAuth::with_token_url(Provider::GoogleDrive, &fake.token_url).unwrap();
        let tokens = Arc::new(TokenSource::new(oauth, "rt-0".into(), Arc::new(Forget)));
        let config = CloudConfig {
            account_id: "perm-1".into(),
            account_label: "ana@example.com".into(),
            folder: folder.into(),
        };
        let store = GoogleDriveStore::with_hosts(&fake.api, &fake.upload, config, tokens).unwrap();
        (store, fake.state)
    }

    async fn fake_store() -> Box<dyn ObjectStore> {
        Box::new(store_in("Silo").await.0)
    }

    // Every rule the other backends pass, against the fake Drive.
    silentsilo_store::contract_tests!(fake_store());

    fn big() -> Vec<u8> {
        (0..(2 * CHUNK as usize + 1024 * 1024 + 19))
            .map(|i| (i % 251) as u8)
            .collect()
    }

    fn assert_clean(state: &Arc<Mutex<DriveState>>) {
        let violations = state.lock().unwrap().violations.clone();
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[tokio::test]
    async fn the_account_and_the_silo_folders_are_read() {
        use crate::Probe;
        let (store, state) = store_in("Silo").await;
        store.put("vault.json", vec![1]).await.unwrap();
        // A twin of the silo folder, made by another device.
        {
            let mut state = state.lock().unwrap();
            let root = state.folder_id("SilentSilo").unwrap();
            let twin = state.add_file("Silo", &root, Vec::new());
            state
                .items
                .iter_mut()
                .find(|i| i.id == twin)
                .unwrap()
                .folder = true;
        }

        let account = store.account().await.unwrap();
        assert_eq!(account.id, "perm-1");
        assert_eq!(account.label, "ana@gmail.com");
        assert_eq!(account.total_bytes, Some(16106127360));
        assert_eq!(account.free_bytes, Some(16000000000));
        assert_eq!(store.silo_folders().await.unwrap(), vec!["Silo"]);
    }

    #[tokio::test]
    async fn google_is_never_asked_to_end_the_grant() {
        // Google's revocation ends every sign-in of the app to that account,
        // other computers' included.
        let (store, _) = store_in("Silo").await;
        store.http.tokens.revoke().await.unwrap();
    }

    #[tokio::test]
    async fn the_layout_is_real_folders_a_download_can_be_read_from() {
        let (store, state) = store_in("Silo").await;
        store.put("blobs/a.sslo", vec![1]).await.unwrap();
        store.put("vault.json", vec![2]).await.unwrap();

        let state = state.lock().unwrap();
        let blobs = state
            .folder_id("SilentSilo/Silo/blobs")
            .expect("a blobs folder");
        let silo = state.folder_id("SilentSilo/Silo").unwrap();
        assert!(
            state
                .items
                .iter()
                .any(|i| i.name == "a.sslo" && i.parents == vec![blobs.clone()])
        );
        assert!(
            state
                .items
                .iter()
                .any(|i| i.name == "vault.json" && i.parents == vec![silo.clone()])
        );
    }

    #[tokio::test]
    async fn a_large_file_goes_up_resumably_and_comes_back_whole() {
        let (store, state) = store_in("Silo").await;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("big.sslo");
        let back = dir.path().join("back.sslo");
        let bytes = big();
        std::fs::write(&source, &bytes).unwrap();

        let mut reported = 0u64;
        store
            .put_from_file_reporting("blobs/big.sslo", &source, &mut |n| {
                reported += n;
                ControlFlow::Continue(())
            })
            .await
            .unwrap();
        assert_eq!(reported, bytes.len() as u64);
        store.get_to_file("blobs/big.sslo", &back).await.unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), bytes);

        // Rewritten in place, not added beside the first.
        store.put("blobs/big.sslo", bytes.clone()).await.unwrap();
        assert_eq!(
            state
                .lock()
                .unwrap()
                .items
                .iter()
                .filter(|i| i.name == "big.sslo")
                .count(),
            1
        );
        assert_clean(&state);
    }

    #[tokio::test]
    async fn a_stopped_upload_leaves_no_file() {
        let (store, state) = store_in("Silo").await;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("big.sslo");
        std::fs::write(&source, big()).unwrap();

        let stopped = store
            .put_from_file_reporting("blobs/stopped.sslo", &source, &mut |_| {
                ControlFlow::Break(())
            })
            .await;

        assert!(matches!(stopped, Err(StoreError::Cancelled)));
        assert_eq!(store.head("blobs/stopped.sslo").await.unwrap(), None);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn drives_way_of_throttling_is_waited_out() {
        let (store, state) = store_in("Silo").await;
        store.put("ops/1.op", vec![1]).await.unwrap();
        state.lock().unwrap().throttle = 2;
        assert_eq!(store.get("ops/1.op").await.unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn of_two_files_with_one_name_the_newer_is_the_object() {
        let (store, state) = store_in("Silo").await;
        store.put("vault.json", b"first".to_vec()).await.unwrap();
        // Another device wrote the same name a moment later.
        {
            let mut state = state.lock().unwrap();
            let silo = state.folder_id("SilentSilo/Silo").unwrap();
            state.add_file("vault.json", &silo, b"second".to_vec());
        }

        assert_eq!(store.get("vault.json").await.unwrap(), b"second");
        assert_eq!(
            store.list("").await.unwrap().len(),
            1,
            "one key, listed once"
        );

        // The next write keeps the newer and tidies the older away.
        store.put("vault.json", b"third".to_vec()).await.unwrap();
        assert_eq!(store.get("vault.json").await.unwrap(), b"third");
        assert_eq!(
            state
                .lock()
                .unwrap()
                .items
                .iter()
                .filter(|i| i.name == "vault.json")
                .count(),
            1
        );

        // A delete takes every copy, so none comes back.
        {
            let mut state = state.lock().unwrap();
            let silo = state.folder_id("SilentSilo/Silo").unwrap();
            state.add_file("vault.json", &silo, b"stray".to_vec());
        }
        store.delete("vault.json").await.unwrap();
        assert_eq!(store.head("vault.json").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_new_small_object_costs_a_few_calls_not_a_folder_walk() {
        let (store, state) = store_in("Silo").await;
        // Folders made and cached, as they are after the first writes.
        store.put("ops/a.op", vec![1]).await.unwrap();
        state.lock().unwrap().api_calls = 0;

        assert_eq!(store.head("ops/b.op").await.unwrap(), None);
        let for_head = std::mem::take(&mut state.lock().unwrap().api_calls);
        store.put("ops/b.op", vec![2]).await.unwrap();
        let for_put = state.lock().unwrap().api_calls;

        // A folder lookup and a name search; then only the upload and the
        // check for an older copy, the miss being known.
        assert!(for_head <= 2, "a missing key took {for_head} calls");
        assert!(for_put <= 2, "a new small object took {for_put} calls");

        // A folder known missing is not asked about again.
        state.lock().unwrap().api_calls = 0;
        assert_eq!(store.head("blobs/x.sslo").await.unwrap(), None);
        let first = std::mem::take(&mut state.lock().unwrap().api_calls);
        assert_eq!(store.head("blobs/y.sslo").await.unwrap(), None);
        let second = state.lock().unwrap().api_calls;
        assert!(first >= 1, "the first miss asks");
        assert_eq!(
            second, 0,
            "the second miss in a missing folder asks nothing"
        );
    }

    #[tokio::test]
    async fn two_folders_with_one_name_are_read_as_one() {
        // Two devices created `blobs` at the same moment.
        let (store, state) = store_in("Silo").await;
        store.put("blobs/a.sslo", vec![1]).await.unwrap();
        {
            let mut state = state.lock().unwrap();
            let silo = state.folder_id("SilentSilo/Silo").unwrap();
            let now_id = state.add_file("blobs", &silo, Vec::new());
            let twin = state.items.iter_mut().find(|i| i.id == now_id).unwrap();
            twin.folder = true;
            state.add_file("b.sslo", &now_id, vec![2]);
        }

        let keys: Vec<String> = store
            .list("blobs/")
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .collect();
        assert_eq!(keys, vec!["blobs/a.sslo", "blobs/b.sslo"]);
        assert_eq!(store.get("blobs/b.sslo").await.unwrap(), vec![2]);
    }

    #[test]
    fn a_name_with_a_quote_is_escaped_in_the_query() {
        assert_eq!(quoted("it's"), "'it\\'s'");
        assert_eq!(quoted("a\\b"), "'a\\\\b'");
    }
}
