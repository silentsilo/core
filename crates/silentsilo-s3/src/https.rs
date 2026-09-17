//! The S3 SDK's HTTP client with the platform verifier, for Android. The
//! SDK's own client reads native roots from files, which a phone does not
//! have, and takes no custom verifier.

use std::time::Duration;

use aws_smithy_runtime_api::client::http::{
    HttpConnector, HttpConnectorFuture, SharedHttpClient, SharedHttpConnector, http_client_fn,
};
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_types::body::SdkBody;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector as TcpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};

type Inner = Client<hyper_rustls::HttpsConnector<TcpConnector>, SdkBody>;

/// An SDK client that verifies with [`crate::tls::client_config`]. The
/// connect and read timeouts come from the SDK's timeout settings.
pub(crate) fn platform_client() -> Result<SharedHttpClient, String> {
    let tls = crate::tls::client_config()?;
    Ok(http_client_fn(move |settings, _components| {
        let mut tcp = TcpConnector::new();
        tcp.enforce_http(false);
        tcp.set_connect_timeout(settings.connect_timeout());
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .wrap_connector(tcp);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build(https);
        SharedHttpConnector::new(Connector {
            client,
            read_timeout: settings.read_timeout(),
        })
    }))
}

#[derive(Debug, Clone)]
struct Connector {
    client: Inner,
    /// Until the response head arrives, as the SDK's own client counts it.
    read_timeout: Option<Duration>,
}

impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let request = match request.try_into_http1x() {
            Ok(request) => request,
            Err(e) => return HttpConnectorFuture::ready(Err(ConnectorError::user(e.into()))),
        };
        let sent = self.client.request(request);
        let read_timeout = self.read_timeout;
        HttpConnectorFuture::new(async move {
            let response = match read_timeout {
                Some(limit) => tokio::time::timeout(limit, sent)
                    .await
                    .map_err(|_| ConnectorError::timeout("no response in time".into()))?,
                None => sent.await,
            }
            .map_err(|e| {
                if e.is_connect() {
                    ConnectorError::io(e.into())
                } else {
                    ConnectorError::other(e.into(), None)
                }
            })?;
            HttpResponse::try_from(response.map(SdkBody::from_body_1_x))
                .map_err(|e| ConnectorError::other(e.into(), None))
        })
    }
}
