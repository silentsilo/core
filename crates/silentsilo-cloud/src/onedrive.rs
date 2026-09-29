//! OneDrive through Microsoft Graph, in the app's own folder
//! (`/me/drive/special/approot`, `Apps/SilentSilo`), one subfolder per silo.
//!
//! Addressed by path, so the keys are the object layout itself and a folder
//! downloaded from onedrive.com has the same shape as a local copy.

use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, StatusCode};
use silentsilo_store::{CloudConfig, ObjectStore, Progress, StoreError, StoredObject};
use tokio::io::AsyncWriteExt;

use crate::TokenSource;
use crate::http::{Http, transport, trusted_address};

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
/// At or under this, one PUT; over it, an upload session.
const SMALL: u64 = 4 * 1024 * 1024;
/// 32 times 320 KiB: Graph wants multiples of 320 KiB, and advises 5 to 10.
const CHUNK: u64 = 32 * 320 * 1024;
/// A listing that pages on for ever is a broken answer, not a big silo.
const MAX_PAGES: usize = 100_000;

/// Everything but the unreserved characters is escaped in a path segment.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct OneDriveStore {
    http: Http,
    api: String,
    folder: String,
    account: String,
}

impl OneDriveStore {
    pub fn new(config: CloudConfig, tokens: Arc<TokenSource>) -> Result<Self, StoreError> {
        Self::with_api(GRAPH, config, tokens)
    }

    /// Pointed at another Graph: the tests' fake.
    pub fn with_api(
        api: &str,
        config: CloudConfig,
        tokens: Arc<TokenSource>,
    ) -> Result<Self, StoreError> {
        let folder = config.folder.trim_matches('/').to_string();
        if folder.is_empty() || folder.split('/').any(|part| part == "." || part == "..") {
            return Err(StoreError::Other(
                "the OneDrive folder name is not usable".into(),
            ));
        }
        Ok(Self {
            http: Http::new(tokens, "OneDrive")?,
            api: api.trim_end_matches('/').to_string(),
            folder,
            account: config.account_label,
        })
    }

    /// The Graph address of `key` in the silo folder, `suffix` appended
    /// after the path (`":/content"`, `":/createUploadSession"`).
    fn item(&self, key: &str, suffix: &str) -> String {
        let path: Vec<String> = self
            .folder
            .split('/')
            .chain(key.split('/').filter(|part| !part.is_empty()))
            .map(|part| utf8_percent_encode(part, SEGMENT).to_string())
            .collect();
        format!(
            "{}/me/drive/special/approot:/{}{suffix}",
            self.api,
            path.join("/")
        )
    }

    async fn upload_small(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let url = self.item(key, ":/content?@microsoft.graph.conflictBehavior=replace");
        let response = self
            .http
            .send(
                Method::PUT,
                &url,
                &[("Content-Type", "application/octet-stream".into())],
                Some(bytes),
            )
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(self.http.status_error(response.status(), key))
        }
    }

    /// An upload session, fed chunk by chunk from `read`. The file appears
    /// only once the last byte is in, so a stop leaves nothing behind.
    async fn upload_session(
        &self,
        key: &str,
        total: u64,
        read: &mut (dyn FnMut(u64, usize) -> Result<Vec<u8>, StoreError> + Send),
        progress: Progress<'_>,
    ) -> Result<(), StoreError> {
        let response = self
            .http
            .send(
                Method::POST,
                &self.item(key, ":/createUploadSession"),
                &[("Content-Type", "application/json".into())],
                Some(br#"{"item":{"@microsoft.graph.conflictBehavior":"replace"}}"#),
            )
            .await?;
        if !response.status().is_success() {
            return Err(self.http.status_error(response.status(), key));
        }
        let session = self.http.json(response).await?;
        let upload_url = session
            .get("uploadUrl")
            .and_then(|u| u.as_str())
            .filter(|u| trusted_address(u, &self.api))
            .ok_or_else(|| StoreError::Other("OneDrive gave no usable upload address".into()))?
            .to_string();

        let mut offset = 0u64;
        while offset < total {
            let length = CHUNK.min(total - offset) as usize;
            let chunk = read(offset, length)?;
            let end = offset + chunk.len() as u64 - 1;
            // Pre-authenticated: Graph refuses a token here, and it must not
            // travel to another host anyway.
            let response = self
                .http
                .send_plain(
                    Method::PUT,
                    &upload_url,
                    &[("Content-Range", format!("bytes {offset}-{end}/{total}"))],
                    Some(&chunk),
                )
                .await?;
            let status = response.status();
            if !status.is_success() {
                let _ = self.http.plain.delete(&upload_url).send().await;
                return Err(self.http.status_error(status, key));
            }
            offset += chunk.len() as u64;
            if progress(chunk.len() as u64).is_break() {
                if offset < total {
                    let _ = self.http.plain.delete(&upload_url).send().await;
                }
                return Err(StoreError::Cancelled);
            }
        }
        Ok(())
    }

    /// Where to fetch `key`'s bytes: Graph answers `/content` with a
    /// redirect to a pre-authenticated address, fetched without the token.
    async fn download_address(&self, key: &str) -> Result<String, StoreError> {
        let response = self
            .http
            .send(Method::GET, &self.item(key, ":/content"), &[], None)
            .await?;
        let status = response.status();
        if status.is_redirection() {
            return response
                .headers()
                .get("Location")
                .and_then(|l| l.to_str().ok())
                .filter(|l| trusted_address(l, &self.api))
                .map(str::to_string)
                .ok_or_else(|| {
                    StoreError::Other("OneDrive gave no usable download address".into())
                });
        }
        Err(self.http.status_error(status, key))
    }

    async fn download(
        &self,
        key: &str,
        range: Option<u64>,
    ) -> Result<reqwest::Response, StoreError> {
        let address = self.download_address(key).await?;
        let headers: Vec<(&str, String)> = match range {
            Some(len) => vec![("Range", format!("bytes=0-{}", len - 1))],
            None => Vec::new(),
        };
        let response = self
            .http
            .send_plain(Method::GET, &address, &headers, None)
            .await?;
        let status = response.status();
        if status.is_success() {
            Ok(response)
        } else if status == StatusCode::RANGE_NOT_SATISFIABLE {
            // Asked for more than there is: the whole object is the answer.
            Box::pin(self.download(key, None)).await
        } else {
            Err(self.http.status_error(status, key))
        }
    }

    /// Every file under the folder `dir` (a key prefix ending in `/`, or
    /// empty for the silo folder), with its full key.
    async fn walk(&self, dir: &str) -> Result<Vec<StoredObject>, StoreError> {
        let mut out = Vec::new();
        let mut folders = vec![dir.to_string()];
        let mut pages = 0usize;
        while let Some(folder) = folders.pop() {
            let mut next = Some(self.item(
                folder.trim_end_matches('/'),
                ":/children?$top=1000&$select=name,size,folder,file",
            ));
            let mut seen = std::collections::HashSet::new();
            while let Some(url) = next.take() {
                pages += 1;
                // The next page must be Graph's own address: this request
                // carries the token.
                if pages > MAX_PAGES || !url.starts_with(&self.api) || !seen.insert(url.clone()) {
                    return Err(StoreError::Other(
                        "OneDrive sent a listing that does not end".into(),
                    ));
                }
                let response = self.http.send(Method::GET, &url, &[], None).await?;
                let status = response.status();
                if status == StatusCode::NOT_FOUND {
                    // Nothing was ever written under it.
                    break;
                }
                if !status.is_success() {
                    return Err(self.http.status_error(status, &folder));
                }
                let page = self.http.json(response).await?;
                for item in page
                    .get("value")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    let Some(name) = item.get("name").and_then(|n| n.as_str()) else {
                        continue;
                    };
                    let key = format!("{folder}{name}");
                    if item.get("folder").is_some() {
                        folders.push(format!("{key}/"));
                    } else {
                        out.push(StoredObject {
                            key,
                            size: item.get("size").and_then(|s| s.as_i64()).unwrap_or(0),
                        });
                    }
                }
                next = page
                    .get("@odata.nextLink")
                    .and_then(|n| n.as_str())
                    .map(str::to_string);
            }
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl ObjectStore for OneDriveStore {
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
        let bytes = response
            .bytes()
            .await
            .map_err(|e| transport("OneDrive", &e))?;
        Ok(bytes.to_vec())
    }

    async fn get_prefix(&self, key: &str, len: u64) -> Result<Vec<u8>, StoreError> {
        if len == 0 {
            self.head(key)
                .await?
                .ok_or_else(|| StoreError::NotFound(key.to_string()))?;
            return Ok(Vec::new());
        }
        let response = self.download(key, Some(len)).await?;
        let mut bytes = response
            .bytes()
            .await
            .map_err(|e| transport("OneDrive", &e))?
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
        let mut response = self.download(key, None).await?;
        let partial = dest.with_extension("part");
        let result = async {
            let mut file = tokio::fs::File::create(&partial)
                .await
                .map_err(|e| StoreError::Other(format!("{}: {e}", partial.display())))?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| transport("OneDrive", &e))?
            {
                file.write_all(&chunk)
                    .await
                    .map_err(|e| StoreError::Other(e.to_string()))?;
                if progress(chunk.len() as u64).is_break() {
                    return Err(StoreError::Cancelled);
                }
            }
            file.sync_all()
                .await
                .map_err(|e| StoreError::Other(e.to_string()))?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => tokio::fs::rename(&partial, dest)
                .await
                .map_err(|e| StoreError::Other(format!("{}: {e}", dest.display()))),
            Err(e) => {
                let _ = tokio::fs::remove_file(&partial).await;
                Err(e)
            }
        }
    }

    async fn head(&self, key: &str) -> Result<Option<i64>, StoreError> {
        let response = self
            .http
            .send(
                Method::GET,
                &self.item(key, ":?$select=size,file"),
                &[],
                None,
            )
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let item = self.http.json(response).await?;
                if item.get("file").is_none() {
                    return Ok(None);
                }
                Ok(Some(item.get("size").and_then(|s| s.as_i64()).unwrap_or(0)))
            }
            status => Err(self.http.status_error(status, key)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let response = self
            .http
            .send(Method::DELETE, &self.item(key, ""), &[], None)
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(()),
            status if status.is_success() => Ok(()),
            status => Err(self.http.status_error(status, key)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, StoreError> {
        // The folder that holds everything the prefix can match.
        let dir = match prefix.rfind('/') {
            Some(at) => &prefix[..=at],
            None => "",
        };
        let mut objects: Vec<StoredObject> = self
            .walk(dir)
            .await?
            .into_iter()
            .filter(|object| object.key.starts_with(prefix))
            .collect();
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(objects)
    }

    fn describe(&self) -> String {
        if self.account.is_empty() {
            "OneDrive".into()
        } else {
            format!("OneDrive ({})", self.account)
        }
    }
}

#[cfg(windows)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        done += n;
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeGraph, GraphState};
    use crate::{OAuth, PersistToken, Provider};
    use std::sync::Mutex;

    struct Forget;

    impl PersistToken for Forget {
        fn save(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    async fn store_in(folder: &str) -> (OneDriveStore, Arc<Mutex<GraphState>>) {
        let fake = FakeGraph::start().await;
        let oauth = OAuth::with_token_url(Provider::OneDrive, &fake.token_url).unwrap();
        let tokens = Arc::new(TokenSource::new(oauth, "rt-0".into(), Arc::new(Forget)));
        let config = CloudConfig {
            account_id: "a1".into(),
            account_label: "ana@example.com".into(),
            folder: folder.into(),
        };
        let store = OneDriveStore::with_api(&fake.api, config, tokens).unwrap();
        (store, fake.state)
    }

    async fn fake_store() -> Box<dyn ObjectStore> {
        Box::new(store_in("Silo").await.0)
    }

    // Every rule the other backends pass, against the fake Graph.
    silentsilo_store::contract_tests!(fake_store());

    fn assert_clean(state: &Arc<Mutex<GraphState>>) {
        let violations = state.lock().unwrap().violations.clone();
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// Bigger than one upload session chunk, and not a multiple of it.
    fn big() -> Vec<u8> {
        (0..(CHUNK as usize + 2 * 1024 * 1024 + 13))
            .map(|i| (i % 251) as u8)
            .collect()
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
        assert_eq!(
            store.head("blobs/big.sslo").await.unwrap(),
            Some(bytes.len() as i64)
        );
        store.get_to_file("blobs/big.sslo", &back).await.unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), bytes);

        // The buffer-shaped upload takes the same path.
        store.put("blobs/big2.sslo", bytes.clone()).await.unwrap();
        assert_eq!(store.get("blobs/big2.sslo").await.unwrap(), bytes);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn a_stopped_session_leaves_no_object() {
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
    async fn throttling_is_waited_out() {
        let (store, state) = store_in("Silo").await;
        state.lock().unwrap().throttle = 3;

        store.put("ops/1.op", vec![1, 2, 3]).await.unwrap();

        assert_eq!(store.get("ops/1.op").await.unwrap(), vec![1, 2, 3]);
        assert!(state.lock().unwrap().api_calls >= 4);
    }

    #[tokio::test]
    async fn an_access_token_that_stops_working_is_replaced_once() {
        let (store, state) = store_in("Silo").await;
        state.lock().unwrap().refuse_first_token = true;

        store.put("ops/1.op", vec![7]).await.unwrap();

        assert_eq!(store.get("ops/1.op").await.unwrap(), vec![7]);
        assert_clean(&state);
    }

    #[tokio::test]
    async fn a_next_page_on_another_host_is_refused() {
        // Following it would send the token there.
        let (store, state) = store_in("Silo").await;
        for n in 0..5 {
            store.put(&format!("ops/{n}.op"), vec![n]).await.unwrap();
        }
        state.lock().unwrap().foreign_next_link = true;

        assert!(store.list("ops/").await.is_err());
    }

    #[tokio::test]
    async fn a_listing_follows_every_page_and_every_folder() {
        let (store, _) = store_in("Silo").await;
        for n in 0..8 {
            store
                .put(&format!("blobs/{n}.sslo"), vec![n])
                .await
                .unwrap();
        }
        store.put("ops/1.op", vec![1]).await.unwrap();
        store.put("vault.json", vec![1]).await.unwrap();

        let all = store.list("").await.unwrap();
        assert_eq!(all.len(), 10);
        let blobs = store.list("blobs/").await.unwrap();
        assert_eq!(blobs.len(), 8);
        assert_eq!(blobs[0].key, "blobs/0.sslo");
    }

    #[tokio::test]
    async fn the_folder_name_is_escaped_and_the_silo_stays_inside_it() {
        let (store, state) = store_in("My Silo").await;
        store.put("ops/1.op", vec![1]).await.unwrap();
        assert!(state.lock().unwrap().files.contains_key("My Silo/ops/1.op"));

        let config = |folder: &str| CloudConfig {
            account_id: "a".into(),
            account_label: String::new(),
            folder: folder.into(),
        };
        let tokens = || {
            Arc::new(TokenSource::new(
                OAuth::new(Provider::OneDrive).unwrap(),
                "rt".into(),
                Arc::new(Forget),
            ))
        };
        assert!(OneDriveStore::new(config(".."), tokens()).is_err());
        assert!(OneDriveStore::new(config(""), tokens()).is_err());
    }
}
