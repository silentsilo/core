//! What the three backends share: the two HTTP clients, the retry loop that
//! signs requests, and turning answers into `StoreError`s.

use std::time::Duration;

use reqwest::{Method, Response, StatusCode};
use silentsilo_store::StoreError;

use crate::{CloudError, TokenSource};

/// How many times one request is tried before the pass gives up on it.
const ATTEMPTS: u32 = 6;
/// Never wait longer than this on a provider's `Retry-After`.
const MAX_WAIT: Duration = Duration::from_secs(60);

fn client(redirects: bool) -> Result<reqwest::Client, StoreError> {
    reqwest::Client::builder()
        .tls_backend_preconfigured(silentsilo_s3::tls::client_config().map_err(StoreError::Other)?)
        // Redirects are followed by hand where they are expected, so the
        // token is never carried to a host this code did not check.
        .redirect(if redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .connect_timeout(Duration::from_secs(30))
        // Per read, not per request: a large transfer is not cut off.
        .read_timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| StoreError::Other(e.to_string()))
}

/// The API client, which carries the token, and the plain one for
/// pre-authenticated upload and download addresses, which never does.
pub(crate) struct Http {
    api: reqwest::Client,
    pub plain: reqwest::Client,
    pub tokens: std::sync::Arc<TokenSource>,
    /// For messages: "OneDrive".
    pub name: &'static str,
}

impl Http {
    pub fn new(
        tokens: std::sync::Arc<TokenSource>,
        name: &'static str,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            api: client(false)?,
            plain: client(false)?,
            tokens,
            name,
        })
    }

    /// A signed request, retried on throttling, a server error or a
    /// dropped connection, and once after a 401 with a fresh token.
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&[u8]>,
    ) -> Result<Response, StoreError> {
        let mut refreshed = false;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let token = self
                .tokens
                .bearer()
                .await
                .map_err(|e| self.token_error(e))?;
            let mut request = self
                .api
                .request(method.clone(), url)
                .bearer_auth(token.as_str());
            for (name, value) in headers {
                request = request.header(*name, value.as_str());
            }
            if let Some(body) = body {
                request = request.body(body.to_vec());
            }
            match request.send().await {
                Err(e) if attempt < ATTEMPTS && retryable(&e) => {
                    tokio::time::sleep(backoff(attempt)).await;
                }
                Err(e) => return Err(transport(self.name, &e)),
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED && !refreshed => {
                    refreshed = true;
                    self.tokens.reject(&token).await;
                }
                Ok(response) if throttled(response.status()) && attempt < ATTEMPTS => {
                    tokio::time::sleep(wait_for(&response, attempt)).await;
                }
                Ok(response) => return Ok(response),
            }
        }
    }

    /// An unsigned request to a pre-authenticated address, with the same
    /// retries.
    pub async fn send_plain(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&[u8]>,
    ) -> Result<Response, StoreError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut request = self.plain.request(method.clone(), url);
            for (name, value) in headers {
                request = request.header(*name, value.as_str());
            }
            if let Some(body) = body {
                request = request.body(body.to_vec());
            }
            match request.send().await {
                Err(e) if attempt < ATTEMPTS && retryable(&e) => {
                    tokio::time::sleep(backoff(attempt)).await;
                }
                Err(e) => return Err(transport(self.name, &e)),
                Ok(response) if throttled(response.status()) && attempt < ATTEMPTS => {
                    tokio::time::sleep(wait_for(&response, attempt)).await;
                }
                Ok(response) => return Ok(response),
            }
        }
    }

    pub fn token_error(&self, error: CloudError) -> StoreError {
        match error {
            CloudError::Revoked => StoreError::Denied(format!("Sign in to {} again", self.name)),
            CloudError::Unreachable(what) => StoreError::Unreachable(what),
            CloudError::Refused(message) => StoreError::Denied(message),
            CloudError::Other(message) => StoreError::Other(message),
        }
    }

    /// A status that is not success, in words. Never the body: it can echo
    /// what was sent.
    pub fn status_error(&self, status: StatusCode, key: &str) -> StoreError {
        match status {
            StatusCode::NOT_FOUND => StoreError::NotFound(key.to_string()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                StoreError::Denied(format!("{} refused access", self.name))
            }
            StatusCode::INSUFFICIENT_STORAGE => StoreError::Other(format!("{} is full", self.name)),
            status if status.is_server_error() => {
                StoreError::Unreachable(format!("{} answered {}", self.name, status.as_u16()))
            }
            status => StoreError::Other(format!("{} answered {}", self.name, status.as_u16())),
        }
    }

    pub async fn json(&self, response: Response) -> Result<serde_json::Value, StoreError> {
        let bytes = response
            .bytes()
            .await
            .map_err(|e| transport(self.name, &e))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| StoreError::Other(format!("{} answered something unreadable", self.name)))
    }
}

fn throttled(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn retryable(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_request()
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250 * 2u64.pow(attempt.min(6)))
}

/// The provider's own `Retry-After` when it gives one, capped; else a
/// growing pause.
fn wait_for(response: &Response, attempt: u32) -> Duration {
    response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs).min(MAX_WAIT))
        .unwrap_or_else(|| backoff(attempt))
}

pub(crate) fn transport(name: &str, error: &reqwest::Error) -> StoreError {
    if error.is_connect() || error.is_timeout() {
        StoreError::Unreachable(format!("could not reach {name}"))
    } else {
        StoreError::Other(format!("{name}: the connection failed"))
    }
}

/// Whether a URL the provider handed back may be used: `https`, or, when
/// the API itself is plain http on this machine (the tests' fake), the same.
pub(crate) fn trusted_address(url: &str, api: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "https" => true,
        "http" => api.starts_with("http://127.0.0.1") && parsed.host_str() == Some("127.0.0.1"),
        _ => false,
    }
}
