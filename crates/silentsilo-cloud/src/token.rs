//! Keeping one target's sign-in alive while the app runs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::CloudError;
use crate::oauth::OAuth;

/// Refreshed this long before it runs out, so a request started with it
/// does not meet an expired token halfway.
const MARGIN: Duration = Duration::from_secs(120);

/// Where a refresh token the provider replaced is written: the keyring,
/// through the vault. The access token is never stored.
pub trait PersistToken: Send + Sync {
    fn save(&self, refresh_token: &str) -> Result<(), String>;
}

struct State {
    refresh: Zeroizing<String>,
    /// A replaced refresh token not yet written. Kept in memory and written
    /// on the next call rather than dropped: the one on disk may already be
    /// spent.
    unsaved: bool,
    access: Option<(Zeroizing<String>, Instant)>,
}

/// The access token for one target. One refresh at a time: transfers in
/// parallel wait for it rather than each spending the refresh token.
pub struct TokenSource {
    oauth: OAuth,
    state: tokio::sync::Mutex<State>,
    persist: Arc<dyn PersistToken>,
}

impl std::fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSource")
            .field("provider", &self.oauth.provider())
            .finish_non_exhaustive()
    }
}

impl TokenSource {
    pub fn new(oauth: OAuth, refresh_token: String, persist: Arc<dyn PersistToken>) -> Self {
        Self {
            oauth,
            state: tokio::sync::Mutex::new(State {
                refresh: Zeroizing::new(refresh_token),
                unsaved: false,
                access: None,
            }),
            persist,
        }
    }

    pub fn provider(&self) -> crate::Provider {
        self.oauth.provider()
    }

    /// A valid access token, refreshed first when it is missing or about to
    /// run out.
    pub async fn bearer(&self) -> Result<Zeroizing<String>, CloudError> {
        let mut state = self.state.lock().await;
        if state.unsaved && self.persist.save(&state.refresh).is_ok() {
            state.unsaved = false;
        }
        if let Some((token, until)) = &state.access
            && Instant::now() + MARGIN < *until
        {
            return Ok(token.clone());
        }

        let fresh = self.oauth.refresh(&state.refresh).await?;
        if let Some(replaced) = fresh.refresh
            && *replaced != *state.refresh
        {
            state.refresh = replaced;
            state.unsaved = self.persist.save(&state.refresh).is_err();
        }
        state.access = Some((fresh.access.clone(), Instant::now() + fresh.expires_in));
        Ok(fresh.access)
    }

    /// After a 401 for `stale`: forgotten, so the next [`bearer`] refreshes.
    /// Another caller may already have replaced it, and that one is kept.
    ///
    /// [`bearer`]: TokenSource::bearer
    pub async fn reject(&self, stale: &str) {
        let mut state = self.state.lock().await;
        if state
            .access
            .as_ref()
            .is_some_and(|(token, _)| token.as_str() == stale)
        {
            state.access = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provider;
    use crate::oauth::tests::FakeTokenEndpoint;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Saved {
        tokens: std::sync::Mutex<Vec<String>>,
        fail: AtomicBool,
    }

    impl PersistToken for Saved {
        fn save(&self, refresh_token: &str) -> Result<(), String> {
            if self.fail.load(Ordering::SeqCst) {
                return Err("keyring refused".into());
            }
            self.tokens.lock().unwrap().push(refresh_token.to_string());
            Ok(())
        }
    }

    /// Hands out a new access token and a new refresh token on every call,
    /// the way Microsoft rotates them.
    async fn rotating() -> FakeTokenEndpoint {
        let n = Arc::new(AtomicUsize::new(0));
        FakeTokenEndpoint::start(move |_| {
            let i = n.fetch_add(1, Ordering::SeqCst) + 1;
            (
                200,
                format!(
                    r#"{{"access_token":"at-{i}","refresh_token":"rt-{i}","expires_in":3600}}"#
                ),
            )
        })
        .await
    }

    fn source(endpoint: &FakeTokenEndpoint, saved: Arc<Saved>) -> TokenSource {
        TokenSource::new(
            OAuth::with_token_url(Provider::OneDrive, &endpoint.url).unwrap(),
            "rt-0".into(),
            saved,
        )
    }

    #[tokio::test]
    async fn parallel_transfers_share_one_refresh() {
        let endpoint = rotating().await;
        let tokens = Arc::new(source(&endpoint, Arc::new(Saved::default())));

        let mut waits = Vec::new();
        for _ in 0..8 {
            let tokens = tokens.clone();
            waits.push(tokio::spawn(async move { tokens.bearer().await.unwrap() }));
        }
        for wait in waits {
            assert_eq!(wait.await.unwrap().as_str(), "at-1");
        }
        assert_eq!(endpoint.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_rotated_refresh_token_is_written_and_used_next() {
        let endpoint = rotating().await;
        let saved = Arc::new(Saved::default());
        let tokens = source(&endpoint, saved.clone());

        let first = tokens.bearer().await.unwrap();
        tokens.reject(&first).await;
        tokens.bearer().await.unwrap();

        assert_eq!(*saved.tokens.lock().unwrap(), vec!["rt-1", "rt-2"]);
        let bodies = endpoint.bodies.lock().unwrap();
        assert!(bodies[0].contains("refresh_token=rt-0"));
        assert!(bodies[1].contains("refresh_token=rt-1"));
    }

    #[tokio::test]
    async fn a_token_the_keyring_would_not_take_is_kept_and_written_later() {
        let endpoint = rotating().await;
        let saved = Arc::new(Saved::default());
        saved.fail.store(true, Ordering::SeqCst);
        let tokens = source(&endpoint, saved.clone());

        tokens.bearer().await.unwrap();
        assert!(saved.tokens.lock().unwrap().is_empty());

        // The keyring works again: the next call writes what it missed,
        // without asking the provider for anything.
        saved.fail.store(false, Ordering::SeqCst);
        tokens.bearer().await.unwrap();
        assert_eq!(*saved.tokens.lock().unwrap(), vec!["rt-1"]);
        assert_eq!(endpoint.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_rejected_token_is_replaced_once() {
        let endpoint = rotating().await;
        let tokens = source(&endpoint, Arc::new(Saved::default()));

        let first = tokens.bearer().await.unwrap();
        tokens.reject(&first).await;
        let second = tokens.bearer().await.unwrap();
        // A second rejection of the old token changes nothing.
        tokens.reject(&first).await;
        assert_eq!(tokens.bearer().await.unwrap().as_str(), second.as_str());
        assert_eq!(endpoint.hits.load(Ordering::SeqCst), 2);
    }
}
