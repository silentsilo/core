//! One sign-in from start to finish: a listener on this computer for the
//! redirect, the provider's page in the user's own browser, the code traded
//! for tokens, and the account those tokens reach.
//!
//! The listener takes loopback connections only, answers nothing but the
//! redirect that carries this sign-in's `state`, and closes when the
//! sign-in ends, fails, is cancelled (the future dropped) or times out.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::{Account, AuthRequest, CloudError, OAuth, PersistToken, Provider, TokenSource};

/// How long the provider's page may stay open before the sign-in is dropped.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// A connection that sends no request line within this is dropped. Browsers
/// open spare connections they may never use.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a redirect request may carry before it is refused.
const MAX_REQUEST: usize = 16 * 1024;

/// A finished sign-in: whose account, and the tokens for it. The tokens
/// stay in the process; only the account is shown.
pub struct SignedIn {
    pub account: Account,
    pub tokens: Arc<TokenSource>,
}

impl std::fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// The listener for one sign-in, bound before the browser opens.
pub struct Loopback {
    request: AuthRequest,
    listeners: Vec<TcpListener>,
}

impl Loopback {
    /// Binds the port the provider will redirect to.
    pub async fn bind(provider: Provider) -> Result<Self, CloudError> {
        let fixed = provider.fixed_ports();
        let primary = if fixed.is_empty() {
            TcpListener::bind(("127.0.0.1", 0)).await.ok()
        } else {
            let mut bound = None;
            for port in fixed {
                if let Ok(listener) = TcpListener::bind(("127.0.0.1", *port)).await {
                    bound = Some(listener);
                    break;
                }
            }
            bound
        };
        let primary = primary.ok_or_else(|| {
            CloudError::Other(format!(
                "no free port for the {} sign-in; close other sign-ins and try again",
                provider.name()
            ))
        })?;
        let port = primary
            .local_addr()
            .map_err(|e| CloudError::Other(e.to_string()))?
            .port();
        let mut listeners = vec![primary];
        // `localhost` may resolve to ::1 first. The same port there too, when
        // it is free; the browser falls back to 127.0.0.1 otherwise.
        if provider.redirect_uri(port).contains("localhost")
            && let Ok(v6) = TcpListener::bind(("::1", port)).await
        {
            listeners.push(v6);
        }
        Ok(Self {
            request: AuthRequest::new(provider, port)?,
            listeners,
        })
    }

    /// The provider's page, for the user's browser.
    pub fn url(&self) -> &str {
        &self.request.url
    }

    /// Waits for the redirect, trades its code and asks who signed in.
    /// `account_of` is [`crate::account`] outside the tests.
    pub async fn finish<F, Fut>(
        self,
        oauth: OAuth,
        persist: Arc<dyn PersistToken>,
        account_of: F,
    ) -> Result<SignedIn, CloudError>
    where
        F: FnOnce(Arc<TokenSource>) -> Fut,
        Fut: std::future::Future<Output = Result<Account, silentsilo_store::StoreError>>,
    {
        let provider = self.request.provider();
        let (code, mut browser) = self.wait_for_code().await?;
        // Answered before the code is traded: on a phone the app may have no
        // network until the person switches back to it, and a tab spinning
        // meanwhile would not tell them to. Whatever fails after this, the
        // app says.
        respond(
            &mut browser,
            "200 OK",
            &page(
                &format!("Signed in to {}", provider.name()),
                "Go back to SilentSilo to finish. This tab is no longer needed, you can close it.",
                true,
            ),
        )
        .await;
        drop(browser);
        async {
            let tokens = oauth.exchange(&self.request, &code).await?;
            let email = tokens.email.clone();
            let tokens = Arc::new(TokenSource::signed_in(oauth, tokens, persist)?);
            let mut account = account_of(tokens.clone()).await.map_err(|e| match e {
                silentsilo_store::StoreError::Denied(message) => CloudError::Refused(message),
                silentsilo_store::StoreError::Unreachable(what) => CloudError::Unreachable(what),
                other => CloudError::Other(other.to_string()),
            })?;
            // The ID token's address, where the provider sent one: Graph
            // gives the app folder permission no way to read it.
            if let Some(email) = email {
                account.label = email;
            }
            Ok(SignedIn { account, tokens })
        }
        .await
    }

    /// The code from the first request that carries this sign-in's state.
    /// Anything else on the port is refused and the wait goes on.
    async fn wait_for_code(&self) -> Result<(Zeroizing<String>, TcpStream), CloudError> {
        let (sender, mut received) = mpsc::channel::<(String, TcpStream)>(8);
        loop {
            tokio::select! {
                accepted = accept_any(&self.listeners) => {
                    if let Ok((stream, peer)) = accepted
                        && peer.ip().is_loopback()
                    {
                        let sender = sender.clone();
                        tokio::spawn(async move {
                            if let Some(read) = read_target(stream).await {
                                let _ = sender.send(read).await;
                            }
                        });
                    }
                }
                Some((target, mut stream)) = received.recv() => {
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    if path != "/" || !self.request.state_matches(query) {
                        respond(&mut stream, "404 Not Found", &page("Nothing here", "", false)).await;
                        continue;
                    }
                    match self.request.code_from(query) {
                        Ok(code) => return Ok((code, stream)),
                        Err(e) => {
                            respond(
                                &mut stream,
                                "200 OK",
                                &page(
                                    "The sign-in did not finish",
                                    "Go back to SilentSilo to see why and try again. You can close this tab.",
                                    false,
                                ),
                            )
                            .await;
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

/// Signs in to `provider`: binds the listener, hands its page to `open`
/// (the system browser, never a webview), and finishes within
/// [`SIGN_IN_TIMEOUT`]. Dropping the future cancels it and frees the port.
pub async fn sign_in(
    provider: Provider,
    persist: Arc<dyn PersistToken>,
    open: impl FnOnce(&str) -> Result<(), String>,
) -> Result<SignedIn, CloudError> {
    let loopback = Loopback::bind(provider).await?;
    open(loopback.url())
        .map_err(|e| CloudError::Other(format!("could not open the browser: {e}")))?;
    let oauth = OAuth::new(provider)?;
    tokio::time::timeout(
        SIGN_IN_TIMEOUT,
        loopback.finish(oauth, persist, |tokens| crate::account(provider, tokens)),
    )
    .await
    .map_err(|_| CloudError::Refused("the sign-in took too long; try again".into()))?
}

async fn accept_any(
    listeners: &[TcpListener],
) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
    match listeners {
        [one] => one.accept().await,
        [one, two, ..] => tokio::select! {
            a = one.accept() => a,
            b = two.accept() => b,
        },
        [] => std::future::pending().await,
    }
}

/// The request target of a GET, or nothing for anything else.
async fn read_target(mut stream: TcpStream) -> Option<(String, TcpStream)> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 2048];
    let read = tokio::time::timeout(READ_TIMEOUT, async {
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(());
            }
            if raw.len() > MAX_REQUEST {
                return None;
            }
        }
    })
    .await;
    if !matches!(read, Ok(Some(()))) {
        return None;
    }
    let head = String::from_utf8_lossy(&raw);
    let mut first = head.lines().next()?.split_whitespace();
    if first.next()? != "GET" {
        return None;
    }
    let target = first.next()?.to_string();
    Some((target, stream))
}

/// A page of fixed text: nothing from the request is echoed back. Styled
/// inline, since the policy it is sent with lets nothing else load.
fn page(title: &str, message: &str, done: bool) -> String {
    let (mark, tint) = if done {
        ("&#10003;", "#16a34a")
    } else {
        ("!", "#dc2626")
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - SilentSilo</title><style>
:root{{color-scheme:light dark}}
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f4f5fb;color:#161a2e}}
main{{max-width:26rem;margin:1.5rem;padding:2rem 1.75rem;border-radius:16px;background:#fff;box-shadow:0 8px 30px rgba(20,24,60,.10);text-align:center}}
.mark{{width:3rem;height:3rem;margin:0 auto 1rem;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:700;color:#fff;background:{tint}}}
h1{{margin:0 0 .6rem;font-size:1.35rem}}
p{{margin:0;line-height:1.5;color:#4a5068}}
.brand{{margin-top:1.5rem;font-size:.85rem;color:#8a90a8}}
@media (prefers-color-scheme:dark){{body{{background:#0f1220;color:#e8eaf4}}main{{background:#181c2e;box-shadow:none}}p{{color:#aeb3c8}}}}
</style></head><body><main><div class="mark">{mark}</div><h1>{title}</h1><p>{message}</p><div class="brand">SilentSilo</div></main></body></html>"#
    )
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::tests::FakeTokenEndpoint;

    struct Forget;

    impl PersistToken for Forget {
        fn save(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn param(url: &str, name: &str) -> String {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .unwrap()
    }

    /// What the browser does after the provider's page: a GET to the
    /// redirect. Returns the status line and the page.
    async fn visit(port: u16, target: &str) -> (String, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        let status = reply.lines().next().unwrap_or("").to_string();
        (status, reply)
    }

    fn account() -> Account {
        Account {
            id: "drive-1".into(),
            label: "ana@outlook.com".into(),
            free_bytes: Some(10),
            total_bytes: Some(20),
        }
    }

    async fn endpoint() -> FakeTokenEndpoint {
        FakeTokenEndpoint::start(|_| {
            (
                200,
                r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}"#.into(),
            )
        })
        .await
    }

    #[tokio::test]
    async fn a_redirect_with_the_right_state_signs_in() {
        let endpoint = endpoint().await;
        let loopback = Loopback::bind(Provider::OneDrive).await.unwrap();
        let state = param(loopback.url(), "state");
        let port: u16 = param(loopback.url(), "redirect_uri")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let oauth = OAuth::with_token_url(Provider::OneDrive, &endpoint.url).unwrap();
        let finishing =
            tokio::spawn(loopback.finish(oauth, Arc::new(Forget), |_| async { Ok(account()) }));

        // A stray request and one with another state change nothing.
        let (status, _) = visit(port, "/favicon.ico").await;
        assert!(status.contains("404"));
        let (status, _) = visit(port, "/?code=stolen&state=guess").await;
        assert!(status.contains("404"));

        let (status, page) = visit(port, &format!("/?code=c-1&state={state}")).await;
        assert!(status.contains("200"));
        assert!(page.contains("Signed in to OneDrive"));
        assert!(!page.contains("c-1"), "the page echoes nothing");

        let signed_in = finishing.await.unwrap().unwrap();
        assert_eq!(signed_in.account, account());
        assert_eq!(signed_in.tokens.refresh_token().await.as_str(), "rt-1");
        // The access token from the exchange is used, not refreshed at once.
        assert_eq!(signed_in.tokens.bearer().await.unwrap().as_str(), "at-1");
        assert_eq!(endpoint.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        let sent = endpoint.bodies.lock().unwrap()[0].clone();
        assert!(sent.contains("code=c-1") && sent.contains("code_verifier="));
    }

    #[tokio::test]
    async fn the_address_in_the_id_token_names_the_account() {
        use base64::Engine;
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"email":"ana@outlook.com"}"#);
        let body = format!(
            r#"{{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"id_token":"x.{claims}.y"}}"#
        );
        let endpoint = FakeTokenEndpoint::start(move |_| (200, body.clone())).await;
        let loopback = Loopback::bind(Provider::OneDrive).await.unwrap();
        let state = param(loopback.url(), "state");
        let port: u16 = param(loopback.url(), "redirect_uri")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let oauth = OAuth::with_token_url(Provider::OneDrive, &endpoint.url).unwrap();
        let finishing = tokio::spawn(loopback.finish(oauth, Arc::new(Forget), |_| async {
            Ok(Account {
                id: "drive-1".into(),
                label: "OneDrive".into(),
                free_bytes: None,
                total_bytes: None,
            })
        }));
        visit(port, &format!("/?code=c-1&state={state}")).await;
        let signed_in = finishing.await.unwrap().unwrap();
        assert_eq!(signed_in.account.label, "ana@outlook.com");
    }

    #[tokio::test]
    async fn a_refusal_in_the_browser_ends_the_sign_in() {
        let endpoint = endpoint().await;
        let loopback = Loopback::bind(Provider::GoogleDrive).await.unwrap();
        let state = param(loopback.url(), "state");
        let port: u16 = param(loopback.url(), "redirect_uri")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let oauth = OAuth::with_token_url(Provider::GoogleDrive, &endpoint.url).unwrap();
        let finishing =
            tokio::spawn(loopback.finish(oauth, Arc::new(Forget), |_| async { Ok(account()) }));

        let (_, page) = visit(
            port,
            &format!("/?error=access_denied&error_description=%3Cscript%3E&state={state}"),
        )
        .await;
        assert!(!page.contains("script"));
        match finishing.await.unwrap() {
            Err(CloudError::Refused(message)) => assert!(message.contains("cancelled")),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(endpoint.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_account_that_is_refused_fails_the_sign_in() {
        let endpoint = endpoint().await;
        let loopback = Loopback::bind(Provider::OneDrive).await.unwrap();
        let state = param(loopback.url(), "state");
        let port: u16 = param(loopback.url(), "redirect_uri")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let oauth = OAuth::with_token_url(Provider::OneDrive, &endpoint.url).unwrap();
        let finishing = tokio::spawn(loopback.finish(oauth, Arc::new(Forget), |_| async {
            Err(silentsilo_store::StoreError::Denied(
                "OneDrive for work or school accounts is not supported yet".into(),
            ))
        }));

        visit(port, &format!("/?code=c-1&state={state}")).await;
        match finishing.await.unwrap() {
            Err(CloudError::Refused(message)) => assert!(message.contains("work or school")),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_dropped_sign_in_frees_its_port() {
        let loopback = Loopback::bind(Provider::GoogleDrive).await.unwrap();
        let port: u16 = param(loopback.url(), "redirect_uri")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        drop(loopback);
        assert!(TcpListener::bind(("127.0.0.1", port)).await.is_ok());
    }
}
