//! Dropbox through its v2 API, in the app folder (`Apps/SilentSilo`, which
//! the API calls `/`), one subfolder per silo.
//!
//! Addressed by path like OneDrive. Dropbox paths ignore case; the keys are
//! lower case already, and listings are read back from `path_display`.

use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;

use reqwest::{Method, Response, StatusCode};
use silentsilo_store::{CloudConfig, ObjectStore, Progress, StoreError, StoredObject};

use crate::TokenSource;
use crate::http::{Http, read_at, stream_to_file, transport};

const API: &str = "https://api.dropboxapi.com/2";
const CONTENT: &str = "https://content.dropboxapi.com/2";
/// At or under this, one upload call; over it, an upload session.
const SMALL: u64 = 8 * 1024 * 1024;
const CHUNK: u64 = 8 * 1024 * 1024;
const MAX_PAGES: usize = 100_000;

pub struct DropboxStore {
    http: Http,
    api: String,
    content: String,
    folder: String,
    account: String,
}

/// `Dropbox-API-Arg` is a header, so the JSON in it must be ASCII: anything
/// else is written as a `\u` escape, which the API reads back.
fn header_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    for c in value.to_string().chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

impl DropboxStore {
    pub fn new(config: CloudConfig, tokens: Arc<TokenSource>) -> Result<Self, StoreError> {
        Self::with_hosts(API, CONTENT, config, tokens)
    }

    /// Pointed at other hosts: the tests' fake.
    pub fn with_hosts(
        api: &str,
        content: &str,
        config: CloudConfig,
        tokens: Arc<TokenSource>,
    ) -> Result<Self, StoreError> {
        let folder = config.folder.trim_matches('/').to_string();
        if folder.is_empty() || folder.split('/').any(|part| part == "." || part == "..") {
            return Err(StoreError::Other(
                "the Dropbox folder name is not usable".into(),
            ));
        }
        Ok(Self {
            http: Http::new(tokens, "Dropbox")?,
            api: api.trim_end_matches('/').to_string(),
            content: content.trim_end_matches('/').to_string(),
            folder,
            account: config.account_label,
        })
    }

    fn path(&self, key: &str) -> String {
        let key = key.trim_matches('/');
        if key.is_empty() {
            format!("/{}", self.folder)
        } else {
            format!("/{}/{key}", self.folder)
        }
    }

    /// A call to the RPC host with a JSON body.
    async fn rpc(&self, endpoint: &str, body: serde_json::Value) -> Result<Response, StoreError> {
        self.http
            .send(
                Method::POST,
                &format!("{}/{endpoint}", self.api),
                &[("Content-Type", "application/json".into())],
                Some(body.to_string().as_bytes()),
            )
            .await
    }

    /// A call to the content host, arguments in the header.
    async fn content_call(
        &self,
        endpoint: &str,
        arg: serde_json::Value,
        extra: &[(&str, String)],
        body: Option<&[u8]>,
    ) -> Result<Response, StoreError> {
        let mut headers = vec![("Dropbox-API-Arg", header_json(&arg))];
        if body.is_some() {
            headers.push(("Content-Type", "application/octet-stream".into()));
        }
        headers.extend(extra.iter().cloned());
        self.http
            .send(
                Method::POST,
                &format!("{}/{endpoint}", self.content),
                &headers,
                body,
            )
            .await
    }

    /// A 409 is Dropbox's "this call's own error": read its summary, which
    /// names the case (`path/not_found/..`, `path/insufficient_space/..`).
    async fn summary(&self, response: Response) -> String {
        self.http
            .json(response)
            .await
            .ok()
            .and_then(|v| v.get("error_summary")?.as_str().map(str::to_string))
            .unwrap_or_default()
    }

    async fn failure(&self, response: Response, key: &str) -> StoreError {
        let status = response.status();
        if status != StatusCode::CONFLICT {
            return self.http.status_error(status, key);
        }
        let summary = self.summary(response).await;
        if summary.contains("not_found") {
            StoreError::NotFound(key.to_string())
        } else if summary.contains("insufficient_space") {
            StoreError::Other("Dropbox is full".into())
        } else {
            let code: String = summary
                .chars()
                .take_while(|c| *c != '.')
                .filter(|c| c.is_ascii_alphanumeric() || *c == '/' || *c == '_')
                .take(60)
                .collect();
            StoreError::Other(format!("Dropbox refused it ({code})"))
        }
    }

    fn commit(&self, key: &str) -> serde_json::Value {
        serde_json::json!({
            "path": self.path(key),
            "mode": "overwrite",
            "autorename": false,
            "mute": true,
        })
    }

    async fn upload_small(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let response = self
            .content_call("files/upload", self.commit(key), &[], Some(bytes))
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(self.failure(response, key).await)
        }
    }

    /// An upload session: nothing is committed until `finish`, so a stop
    /// leaves no object (the session lapses on its own after a week). Only
    /// for more than one chunk, so the last call is always `finish`.
    async fn upload_session(
        &self,
        key: &str,
        total: u64,
        read: &mut (dyn FnMut(u64, usize) -> Result<Vec<u8>, StoreError> + Send),
        progress: Progress<'_>,
    ) -> Result<(), StoreError> {
        let first = read(0, CHUNK.min(total) as usize)?;
        let response = self
            .content_call(
                "files/upload_session/start",
                serde_json::json!({ "close": false }),
                &[],
                Some(&first),
            )
            .await?;
        if !response.status().is_success() {
            return Err(self.failure(response, key).await);
        }
        let session_id = self
            .http
            .json(response)
            .await?
            .get("session_id")
            .and_then(|s| s.as_str())
            .map(str::to_string)
            .ok_or_else(|| StoreError::Other("Dropbox started no upload session".into()))?;
        let mut offset = first.len() as u64;
        if progress(offset).is_break() {
            return Err(StoreError::Cancelled);
        }

        while offset < total {
            let chunk = read(offset, CHUNK.min(total - offset) as usize)?;
            let last = offset + chunk.len() as u64 == total;
            let response = if last {
                self.content_call(
                    "files/upload_session/finish",
                    serde_json::json!({
                        "cursor": { "session_id": session_id, "offset": offset },
                        "commit": self.commit(key),
                    }),
                    &[],
                    Some(&chunk),
                )
                .await?
            } else {
                self.content_call(
                    "files/upload_session/append_v2",
                    serde_json::json!({
                        "cursor": { "session_id": session_id, "offset": offset },
                        "close": false,
                    }),
                    &[],
                    Some(&chunk),
                )
                .await?
            };
            if !response.status().is_success() {
                return Err(self.failure(response, key).await);
            }
            offset += chunk.len() as u64;
            if progress(chunk.len() as u64).is_break() {
                return Err(StoreError::Cancelled);
            }
        }
        Ok(())
    }

    async fn download(&self, key: &str, range: Option<u64>) -> Result<Response, StoreError> {
        let extra: Vec<(&str, String)> = match range {
            Some(len) => vec![("Range", format!("bytes=0-{}", len - 1))],
            None => Vec::new(),
        };
        let response = self
            .content_call(
                "files/download",
                serde_json::json!({ "path": self.path(key) }),
                &extra,
                None,
            )
            .await?;
        let status = response.status();
        if status.is_success() {
            Ok(response)
        } else if status == StatusCode::RANGE_NOT_SATISFIABLE && range.is_some() {
            Box::pin(self.download(key, None)).await
        } else {
            Err(self.failure(response, key).await)
        }
    }

    /// The silo folder's prefix in `path_display`, compared without case, as
    /// Dropbox compares names. Split on characters: a byte count could land
    /// inside a non-ASCII letter, and slicing there panicked.
    fn relative(&self, display: &str) -> Option<String> {
        let root = format!("/{}/", self.folder);
        let (at, _) = display.char_indices().nth(root.chars().count())?;
        let (head, rest) = display.split_at(at);
        (head.to_lowercase() == root.to_lowercase()).then(|| rest.to_string())
    }
}

impl DropboxStore {
    /// An RPC call that takes no argument: no body, as Dropbox asks.
    async fn rpc_bare(&self, endpoint: &str) -> Result<serde_json::Value, StoreError> {
        let response = self
            .http
            .send(Method::POST, &format!("{}/{endpoint}", self.api), &[], None)
            .await?;
        if !response.status().is_success() {
            return Err(self.failure(response, endpoint).await);
        }
        self.http.json(response).await
    }
}

#[async_trait::async_trait]
impl crate::Probe for DropboxStore {
    async fn account(&self) -> Result<crate::Account, StoreError> {
        let account = self.rpc_bare("users/get_current_account").await?;
        let id = account
            .get("account_id")
            .and_then(|i| i.as_str())
            .filter(|i| !i.is_empty())
            .ok_or_else(|| StoreError::Other("Dropbox did not say which account".into()))?;
        let label = ["/email", "/name/display_name"]
            .iter()
            .find_map(|at| account.pointer(at)?.as_str().filter(|s| !s.is_empty()))
            .unwrap_or("Dropbox");
        let space = self.rpc_bare("users/get_space_usage").await?;
        let used = space.get("used").and_then(|u| u.as_u64());
        let total = space
            .pointer("/allocation/allocated")
            .and_then(|a| a.as_u64());
        Ok(crate::Account {
            id: id.to_string(),
            label: label.to_string(),
            free_bytes: used
                .zip(total)
                .map(|(used, total)| total.saturating_sub(used)),
            total_bytes: total,
        })
    }

    async fn silo_folders(&self) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();
        // The app folder is the root this app sees.
        let mut response = self
            .rpc(
                "files/list_folder",
                serde_json::json!({ "path": "", "recursive": false, "limit": 2000 }),
            )
            .await?;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..MAX_PAGES {
            if !response.status().is_success() {
                return match self.failure(response, "the app folder").await {
                    StoreError::NotFound(_) => Ok(Vec::new()),
                    other => Err(other),
                };
            }
            let page = self.http.json(response).await?;
            names.extend(
                page.get("entries")
                    .and_then(|e| e.as_array())
                    .into_iter()
                    .flatten()
                    .filter(|e| e.get(".tag").and_then(|t| t.as_str()) == Some("folder"))
                    .filter_map(|e| e.get("name")?.as_str().map(str::to_string)),
            );
            let more = page.get("has_more").and_then(|m| m.as_bool()) == Some(true);
            let cursor = page.get("cursor").and_then(|c| c.as_str()).unwrap_or("");
            if !more {
                names.sort();
                return Ok(names);
            }
            if !seen.insert(cursor.to_string()) {
                break;
            }
            response = self
                .rpc(
                    "files/list_folder/continue",
                    serde_json::json!({ "cursor": cursor }),
                )
                .await?;
        }
        Err(StoreError::Other(
            "Dropbox sent a listing that does not end".into(),
        ))
    }
}

#[async_trait::async_trait]
impl ObjectStore for DropboxStore {
    async fn get_small(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>, StoreError> {
        match self.download(key, None).await {
            Ok(response) => crate::http::read_capped(response, key, max, "Dropbox")
                .await
                .map(Some),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        let total = bytes.len() as u64;
        if total <= SMALL {
            return self.upload_small(key, &bytes).await;
        }
        let mut read = |offset: u64, length: usize| {
            Ok(bytes[offset as usize..offset as usize + length].to_vec())
        };
        self.upload_session(key, total, &mut read, &mut |_| ControlFlow::Continue(()))
            .await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let response = self.download(key, None).await?;
        Ok(response
            .bytes()
            .await
            .map_err(|e| transport("Dropbox", &e))?
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
            .map_err(|e| transport("Dropbox", &e))?
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
        self.upload_session(key, total, &mut read, progress).await
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
        stream_to_file(response, dest, progress, "Dropbox").await
    }

    async fn head(&self, key: &str) -> Result<Option<i64>, StoreError> {
        let response = self
            .rpc(
                "files/get_metadata",
                serde_json::json!({ "path": self.path(key) }),
            )
            .await?;
        if response.status().is_success() {
            let item = self.http.json(response).await?;
            if item.get(".tag").and_then(|t| t.as_str()) != Some("file") {
                return Ok(None);
            }
            return Ok(Some(item.get("size").and_then(|s| s.as_i64()).unwrap_or(0)));
        }
        match self.failure(response, key).await {
            StoreError::NotFound(_) => Ok(None),
            other => Err(other),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let response = self
            .rpc(
                "files/delete_v2",
                serde_json::json!({ "path": self.path(key) }),
            )
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        match self.failure(response, key).await {
            StoreError::NotFound(_) => Ok(()),
            other => Err(other),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, StoreError> {
        let dir = match prefix.rfind('/') {
            Some(at) => &prefix[..at],
            None => "",
        };
        let mut objects = Vec::new();
        let mut response = self
            .rpc(
                "files/list_folder",
                serde_json::json!({ "path": self.path(dir), "recursive": true, "limit": 2000 }),
            )
            .await?;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..MAX_PAGES {
            if !response.status().is_success() {
                return match self.failure(response, prefix).await {
                    // Nothing was ever written under it.
                    StoreError::NotFound(_) => Ok(Vec::new()),
                    other => Err(other),
                };
            }
            let page = self.http.json(response).await?;
            for entry in page
                .get("entries")
                .and_then(|e| e.as_array())
                .into_iter()
                .flatten()
            {
                if entry.get(".tag").and_then(|t| t.as_str()) != Some("file") {
                    continue;
                }
                let Some(key) = entry
                    .get("path_display")
                    .and_then(|p| p.as_str())
                    .and_then(|p| self.relative(p))
                else {
                    continue;
                };
                if key.starts_with(prefix) {
                    objects.push(StoredObject {
                        key,
                        size: entry.get("size").and_then(|s| s.as_i64()).unwrap_or(0),
                    });
                }
            }
            if page.get("has_more").and_then(|h| h.as_bool()) != Some(true) {
                objects.sort_by(|a, b| a.key.cmp(&b.key));
                return Ok(objects);
            }
            let cursor = page
                .get("cursor")
                .and_then(|c| c.as_str())
                .unwrap_or_default()
                .to_string();
            if cursor.is_empty() || !seen.insert(cursor.clone()) {
                break;
            }
            response = self
                .rpc(
                    "files/list_folder/continue",
                    serde_json::json!({ "cursor": cursor }),
                )
                .await?;
        }
        Err(StoreError::Other(
            "Dropbox sent a listing that does not end".into(),
        ))
    }

    fn describe(&self) -> String {
        if self.account.is_empty() {
            "Dropbox".into()
        } else {
            format!("Dropbox ({})", self.account)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_dropbox::{DropboxState, FakeDropbox};
    use crate::{OAuth, PersistToken, Provider};
    use std::sync::Mutex;

    struct Forget;

    impl PersistToken for Forget {
        fn save(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    async fn store_in(folder: &str) -> (DropboxStore, Arc<Mutex<DropboxState>>) {
        let fake = FakeDropbox::start().await;
        let oauth = OAuth::with_token_url(Provider::Dropbox, &fake.token_url).unwrap();
        let tokens = Arc::new(TokenSource::new(oauth, "rt-0".into(), Arc::new(Forget)));
        let config = CloudConfig {
            account_id: "dbid:1".into(),
            account_label: "ana@example.com".into(),
            folder: folder.into(),
        };
        let store = DropboxStore::with_hosts(&fake.api, &fake.content, config, tokens).unwrap();
        (store, fake.state)
    }

    async fn fake_store() -> Box<dyn ObjectStore> {
        Box::new(store_in("Silo").await.0)
    }

    // Every rule the other backends pass, against the fake Dropbox.
    silentsilo_store::contract_tests!(fake_store());

    #[tokio::test]
    async fn a_path_is_read_by_letters_whatever_their_bytes() {
        // Cut by bytes, "/aéé/" split inside the second é and panicked.
        let (store, _) = store_in("abc").await;
        assert_eq!(store.relative("/aéé/ops/1.op"), None);
        let (store, _) = store_in("Siloț").await;
        assert_eq!(
            store.relative("/SILOȚ/ops/1.op").as_deref(),
            Some("ops/1.op")
        );
        assert_eq!(store.relative("/Siloț/"), None);
    }

    fn big() -> Vec<u8> {
        (0..(2 * CHUNK as usize + 1024 * 1024 + 17))
            .map(|i| (i % 251) as u8)
            .collect()
    }

    fn assert_clean(state: &Arc<Mutex<DropboxState>>) {
        let violations = state.lock().unwrap().violations.clone();
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[tokio::test]
    async fn the_account_space_and_silo_folders_are_read() {
        use crate::Probe;
        let (store, state) = store_in("Silo").await;
        store.put("vault.json", vec![1]).await.unwrap();

        let account = store.account().await.unwrap();
        assert_eq!(account.id, "dbid:1");
        assert_eq!(account.label, "ana@example.com");
        assert_eq!(
            (account.free_bytes, account.total_bytes),
            (Some(1700), Some(2000))
        );
        assert_eq!(store.silo_folders().await.unwrap(), vec!["Silo"]);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn removing_the_target_ends_the_sign_in_at_dropbox() {
        let (store, state) = store_in("Silo").await;
        store.http.tokens.revoke().await.unwrap();
        assert_eq!(state.lock().unwrap().revoked, vec!["at-1"]);
    }

    #[tokio::test]
    async fn a_large_file_goes_up_in_a_session_and_comes_back_whole() {
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
        store.put("blobs/big2.sslo", bytes.clone()).await.unwrap();
        assert_eq!(store.get("blobs/big2.sslo").await.unwrap(), bytes);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn a_stopped_session_commits_nothing() {
        let (store, _) = store_in("Silo").await;
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
    }

    #[tokio::test]
    async fn throttling_and_an_expired_token_are_ridden_out() {
        let (store, state) = store_in("Silo").await;
        {
            let mut state = state.lock().unwrap();
            state.throttle = 2;
            state.refuse_first_token = true;
        }
        store.put("ops/1.op", vec![4]).await.unwrap();
        assert_eq!(store.get("ops/1.op").await.unwrap(), vec![4]);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn a_folder_name_outside_ascii_is_sent_escaped() {
        let (store, state) = store_in("Siloz personal \u{103}\u{ee}\u{219}").await;
        store.put("ops/1.op", vec![1]).await.unwrap();
        assert_eq!(store.get("ops/1.op").await.unwrap(), vec![1]);
        assert_eq!(store.list("ops/").await.unwrap().len(), 1);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn a_listing_with_other_case_in_the_folder_still_maps_to_keys() {
        let (store, state) = store_in("Silo").await;
        store.put("blobs/a.sslo", vec![1]).await.unwrap();
        // Written by another client as /silo/...: Dropbox keeps that case.
        state.lock().unwrap().files.insert(
            "/silo/blobs/b.sslo".into(),
            ("/silo/blobs/b.sslo".into(), vec![2]),
        );
        let keys: Vec<String> = store
            .list("blobs/")
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .collect();
        assert_eq!(keys, vec!["blobs/a.sslo", "blobs/b.sslo"]);
    }
}
