//! The authorization code flow: the address the browser opens, the check on
//! what comes back, and the two calls to the token endpoint.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::CloudError;
use crate::pkce::{Pkce, random_state};
use crate::provider::Provider;

/// One sign-in in progress.
pub struct AuthRequest {
    provider: Provider,
    /// Opened in the user's own browser, never in the app's webview.
    pub url: String,
    state: String,
    verifier: Zeroizing<String>,
    redirect_uri: String,
}

impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("provider", &self.provider)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

impl AuthRequest {
    /// A sign-in whose redirect comes back to `port` on this computer.
    pub fn new(provider: Provider, port: u16) -> Result<Self, CloudError> {
        let pkce = Pkce::new();
        let state = random_state();
        let redirect_uri = provider.redirect_uri(port);
        let mut url = url::Url::parse(provider.authorize_url())
            .map_err(|e| CloudError::Other(e.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", provider.client_id())
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("state", &state);
            if let Some(scope) = provider.scope() {
                query.append_pair("scope", scope);
            }
            for (key, value) in provider.extra_authorize_params() {
                query.append_pair(key, value);
            }
        }
        Ok(Self {
            provider,
            url: url.into(),
            state,
            verifier: pkce.verifier,
            redirect_uri,
        })
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Whether a redirect carries this sign-in's `state`. Anything else
    /// reaching the listener is not an answer to it.
    pub(crate) fn state_matches(&self, query: &str) -> bool {
        url::form_urlencoded::parse(query.as_bytes())
            .any(|(key, value)| key == "state" && value == self.state.as_str())
    }

    /// The code from the query string the browser brought back. Refused
    /// unless the `state` is this sign-in's, so a redirect something else
    /// started cannot sign this app in to someone else's account.
    pub fn code_from(&self, query: &str) -> Result<Zeroizing<String>, CloudError> {
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "code" => code = Some(Zeroizing::new(value.into_owned())),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                _ => {}
            }
        }
        if state.as_deref() != Some(self.state.as_str()) {
            return Err(CloudError::Refused(
                "the answer did not come from this sign-in".into(),
            ));
        }
        if let Some(error) = error {
            return Err(refusal(self.provider, &error));
        }
        code.filter(|code| !code.is_empty())
            .ok_or_else(|| CloudError::Refused(format!("{} sent no code", self.provider.name())))
    }
}

/// A refusal in words, from the provider's error code only: the description
/// next to it is free text from the network and is not shown.
fn refusal(provider: Provider, error: &str) -> CloudError {
    match error {
        "access_denied" => CloudError::Refused("the sign-in was cancelled".into()),
        "invalid_grant" => CloudError::Revoked,
        other => {
            let code: String = other
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(40)
                .collect();
            CloudError::Refused(format!("{} refused the sign-in ({code})", provider.name()))
        }
    }
}

/// How long a token request that cannot get out is tried again.
const UNREACHABLE_FOR: Duration = Duration::from_secs(60);

/// What the token endpoint hands back.
pub struct Tokens {
    pub access: Zeroizing<String>,
    /// Absent when the provider keeps the one already held (Google after the
    /// first sign-in, Dropbox on refresh).
    pub refresh: Option<Zeroizing<String>>,
    pub expires_in: Duration,
    /// The address in the ID token, when one came (Microsoft, asked for it).
    pub email: Option<String>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("refresh", &self.refresh.as_ref().map(|_| "<held>"))
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// The token endpoint of one provider.
pub struct OAuth {
    provider: Provider,
    token_url: String,
    revoke_url: Option<String>,
    http: reqwest::Client,
}

impl OAuth {
    pub fn new(provider: Provider) -> Result<Self, CloudError> {
        Self::with_token_url(provider, provider.token_url())
    }

    /// Pointed somewhere else: the tests' fake token endpoint.
    pub fn with_token_url(provider: Provider, token_url: &str) -> Result<Self, CloudError> {
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(
                silentsilo_s3::tls::client_config().map_err(CloudError::Other)?,
            )
            // A token request is never redirected: following one would send
            // a code or a refresh token somewhere the app did not choose.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| CloudError::Other(e.to_string()))?;
        // The tests' fake answers revocations beside its token endpoint.
        let revoke_url = provider.revoke_url().map(|real| {
            if token_url == provider.token_url() {
                real.to_string()
            } else {
                format!("{token_url}/revoke")
            }
        });
        Ok(Self {
            provider,
            token_url: token_url.to_string(),
            revoke_url,
            http,
        })
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Trades the code from the redirect for the first tokens.
    pub async fn exchange(&self, request: &AuthRequest, code: &str) -> Result<Tokens, CloudError> {
        self.post(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &request.redirect_uri),
            ("code_verifier", &request.verifier),
        ])
        .await
    }

    /// A new access token for a refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, CloudError> {
        self.post(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    async fn post(&self, fields: &[(&str, &str)]) -> Result<Tokens, CloudError> {
        // Built in a block: the serializer is not `Send` and must not live
        // across the request.
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("client_id", self.provider.client_id());
            if let Some(secret) = self.provider.client_secret() {
                form.append_pair("client_secret", secret);
            }
            for (key, value) in fields {
                form.append_pair(key, value);
            }
            Zeroizing::new(form.finish())
        };

        let name = self.provider.name();
        // A phone keeps the app off the network while the browser is in
        // front, and the code arrives exactly then: a request that never got
        // out is tried again until the app is back, for up to a minute. One
        // that got out is not, since the code may be spent.
        let deadline = std::time::Instant::now() + UNREACHABLE_FOR;
        let mut pause = Duration::from_millis(500);
        let response = loop {
            let sent = self
                .http
                .post(&self.token_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .body(body.to_string())
                .send()
                .await;
            match sent {
                Ok(response) => break response,
                Err(e) if e.is_connect() && std::time::Instant::now() + pause < deadline => {
                    tokio::time::sleep(pause).await;
                    pause = (pause * 2).min(Duration::from_secs(4));
                }
                // The error text names the host, never the body.
                Err(e) => {
                    return Err(CloudError::Unreachable(format!(
                        "{name} ({})",
                        crate::http::cause(&e)
                    )));
                }
            }
        };
        let status = response.status();
        let bytes = Zeroizing::new(
            response
                .bytes()
                .await
                .map_err(|e| {
                    CloudError::Unreachable(format!("{name} ({})", crate::http::cause(&e)))
                })?
                .to_vec(),
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| CloudError::Other(format!("{name} answered something unreadable")))?;

        if !status.is_success() {
            if status.is_server_error() {
                return Err(CloudError::Unreachable(format!(
                    "{name} (answered {})",
                    status.as_u16()
                )));
            }
            let error = json.get("error").and_then(|e| e.as_str()).unwrap_or("");
            return Err(refusal(self.provider, error));
        }

        let access = json
            .get("access_token")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| CloudError::Other(format!("{name} sent no access token")))?;
        let refresh = json
            .get("refresh_token")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty());
        // One hour when unsaid, the shortest any of them uses.
        let expires_in = json
            .get("expires_in")
            .and_then(|e| e.as_u64())
            .unwrap_or(3600);
        Ok(Tokens {
            access: Zeroizing::new(access.to_string()),
            refresh: refresh.map(|t| Zeroizing::new(t.to_string())),
            expires_in: Duration::from_secs(expires_in),
            email: json
                .get("id_token")
                .and_then(|t| t.as_str())
                .and_then(email_in),
        })
    }

    /// Ends a sign-in at the provider, where that is possible without
    /// touching other sign-ins (see [`Provider::revoke_url`]). Dropbox
    /// revokes by the access token, which takes its refresh token along.
    pub async fn revoke(&self, access_token: &str) -> Result<(), CloudError> {
        let Some(url) = self.revoke_url.as_deref() else {
            return Ok(());
        };
        let name = self.provider.name();
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| CloudError::Unreachable(format!("{name} ({})", crate::http::cause(&e))))?;
        match response.status() {
            status if status.is_success() => Ok(()),
            // Already ended: what was asked for.
            reqwest::StatusCode::UNAUTHORIZED => Ok(()),
            status if status.is_server_error() => Err(CloudError::Unreachable(format!(
                "{name} (answered {})",
                status.as_u16()
            ))),
            status => Err(CloudError::Refused(format!(
                "{name} did not end the sign-in ({})",
                status.as_u16()
            ))),
        }
    }
}

/// The `email` (or `preferred_username`) claim of an ID token. It came
/// straight from the token endpoint over TLS, so the signature is not what
/// vouches for it (OpenID Connect Core 3.1.3.7). Only ever shown as a label.
fn email_in(id_token: &str) -> Option<String> {
    use base64::Engine;
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    ["email", "preferred_username"]
        .iter()
        .filter_map(|claim| claims.get(*claim)?.as_str())
        .find(|value| value.contains('@'))
        .map(|value| {
            value
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect()
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A token endpoint on this machine that answers every POST with
    /// `answer(body)`, and counts them.
    pub(crate) struct FakeTokenEndpoint {
        pub url: String,
        pub hits: Arc<AtomicUsize>,
        pub bodies: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl FakeTokenEndpoint {
        pub async fn start(answer: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/token", listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
            let answer = Arc::new(answer);
            let (h, b) = (hits.clone(), bodies.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        return;
                    };
                    let (h, b, answer) = (h.clone(), b.clone(), answer.clone());
                    tokio::spawn(async move {
                        let body = read_body(&mut socket).await;
                        h.fetch_add(1, Ordering::SeqCst);
                        b.lock().unwrap().push(body.clone());
                        // Slow enough that concurrent refreshes would overlap.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let (status, json) = answer(&body);
                        let reply = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                            json.len()
                        );
                        let _ = socket.write_all(reply.as_bytes()).await;
                    });
                }
            });
            Self { url, hits, bodies }
        }
    }

    async fn read_body(socket: &mut tokio::net::TcpStream) -> String {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = socket.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&raw).to_string();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text[..split]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if raw.len() >= split + 4 + length {
                    return text[split + 4..split + 4 + length].to_string();
                }
            }
        }
        String::new()
    }

    fn field(body: &str, name: &str) -> Option<String> {
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    #[test]
    fn the_browser_address_carries_pkce_and_no_secret() {
        for provider in [Provider::OneDrive, Provider::Dropbox, Provider::GoogleDrive] {
            let request = AuthRequest::new(provider, 49152).unwrap();
            let url = url::Url::parse(&request.url).unwrap();
            let get = |key: &str| {
                url.query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned())
            };
            assert_eq!(url.scheme(), "https");
            assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
            assert_eq!(get("code_challenge").map(|c| c.len()), Some(43));
            assert_eq!(get("state").as_deref(), Some(request.state.as_str()));
            assert!(get("redirect_uri").unwrap().contains("49152"));
            assert!(get("client_secret").is_none());
            // The verifier never leaves the process.
            assert!(!request.url.contains(request.verifier.as_str()));
        }
    }

    #[test]
    fn only_the_redirect_this_sign_in_started_is_accepted() {
        let request = AuthRequest::new(Provider::OneDrive, 49152).unwrap();
        let good = format!("code=abc&state={}", request.state);
        assert_eq!(request.code_from(&good).unwrap().as_str(), "abc");

        assert!(request.code_from("code=abc&state=someone-else").is_err());
        assert!(request.code_from("code=abc").is_err());
        assert!(
            request
                .code_from(&format!("state={}", request.state))
                .is_err()
        );

        let cancelled = format!("error=access_denied&state={}", request.state);
        match request.code_from(&cancelled) {
            Err(CloudError::Refused(message)) => assert!(message.contains("cancelled")),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_provider_error_is_named_by_its_code_and_nothing_else() {
        let request = AuthRequest::new(Provider::Dropbox, 53682).unwrap();
        let query = format!(
            "error=server_error%3Cscript%3E&error_description=anything+at+all&state={}",
            request.state
        );
        let message = request.code_from(&query).unwrap_err().to_string();
        assert!(!message.contains('<'));
        assert!(!message.contains("anything"));
    }

    #[tokio::test]
    async fn the_code_is_exchanged_with_its_verifier() {
        let endpoint = FakeTokenEndpoint::start(|_| {
            (
                200,
                r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3599}"#.into(),
            )
        })
        .await;
        let request = AuthRequest::new(Provider::OneDrive, 49152).unwrap();
        let oauth = OAuth::with_token_url(Provider::OneDrive, &endpoint.url).unwrap();

        let tokens = oauth.exchange(&request, "the-code").await.unwrap();

        assert_eq!(tokens.access.as_str(), "at-1");
        assert_eq!(tokens.refresh.as_deref().map(|r| r.as_str()), Some("rt-1"));
        let body = endpoint.bodies.lock().unwrap()[0].clone();
        assert_eq!(
            field(&body, "grant_type").as_deref(),
            Some("authorization_code")
        );
        assert_eq!(field(&body, "code").as_deref(), Some("the-code"));
        assert_eq!(
            field(&body, "code_verifier").as_deref(),
            Some(request.verifier.as_str())
        );
        assert_eq!(
            field(&body, "client_id").as_deref(),
            Some(Provider::OneDrive.client_id())
        );
    }

    #[tokio::test]
    async fn a_revoked_refresh_token_says_so_and_leaks_nothing() {
        let endpoint = FakeTokenEndpoint::start(|_| {
            (
                400,
                r#"{"error":"invalid_grant","error_description":"token rt-secret-123 was revoked"}"#
                    .into(),
            )
        })
        .await;
        let oauth = OAuth::with_token_url(Provider::GoogleDrive, &endpoint.url).unwrap();

        let error = oauth.refresh("rt-secret-123").await.unwrap_err();

        assert!(matches!(error, CloudError::Revoked));
        assert!(!format!("{error} {error:?}").contains("rt-secret-123"));
    }

    #[tokio::test]
    async fn a_server_error_is_unreachable_not_a_refusal() {
        let endpoint =
            FakeTokenEndpoint::start(|_| (503, r#"{"error":"temporarily_unavailable"}"#.into()))
                .await;
        let oauth = OAuth::with_token_url(Provider::Dropbox, &endpoint.url).unwrap();

        assert!(matches!(
            oauth.refresh("rt").await,
            Err(CloudError::Unreachable(_))
        ));
    }

    #[test]
    fn the_address_comes_from_the_id_token_and_nothing_else_does() {
        use base64::Engine;
        let token = |claims: serde_json::Value| {
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());
            format!("eyJhbGciOiJub25lIn0.{body}.sig")
        };
        assert_eq!(
            email_in(&token(serde_json::json!({ "email": "ana@outlook.com" }))).as_deref(),
            Some("ana@outlook.com")
        );
        assert_eq!(
            email_in(&token(
                serde_json::json!({ "preferred_username": "ana@live.com" })
            ))
            .as_deref(),
            Some("ana@live.com")
        );
        assert_eq!(email_in(&token(serde_json::json!({ "name": "Ana" }))), None);
        assert_eq!(email_in("not a token"), None);
    }

    #[test]
    fn the_debug_form_holds_no_token() {
        let tokens = Tokens {
            access: Zeroizing::new("at-secret".into()),
            refresh: Some(Zeroizing::new("rt-secret".into())),
            expires_in: Duration::from_secs(60),
            email: None,
        };
        let shown = format!("{tokens:?}");
        assert!(!shown.contains("secret"));
        let request = AuthRequest::new(Provider::OneDrive, 1).unwrap();
        assert!(!format!("{request:?}").contains(request.verifier.as_str()));
    }
}
