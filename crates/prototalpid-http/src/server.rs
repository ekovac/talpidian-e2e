//! Shared HTTPS `axum` server runner, CLI TLS flags, and JSON response helpers
//! used by both `prototalpid-anchor` and `prototalpid-moderator-proxy`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use axum::Json;
use axum::Router;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use url::Url;

use crate::config::canonical_https_origin;
use crate::tls::{generate_self_signed_server, load_server_config_from_pem};

const MAX_CONCURRENT_CONNECTIONS: usize = 1_024;
const MAX_HTTP2_CONCURRENT_STREAMS: u32 = 100;
const MAX_REQUEST_HEADERS: usize = 100;
const MAX_HEADER_BYTES: usize = 128 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared CLI flags for loading PEM server certificates or generating a local self-signed cert.
#[derive(Clone, Debug, clap::Args)]
pub struct TlsServerArgs {
    /// Path to server TLS certificate chain PEM file.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Path to server TLS private key PEM file.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Generate an ephemeral self-signed TLS certificate for local testing.
    #[arg(long)]
    pub tls_self_signed: bool,
}

impl TlsServerArgs {
    /// Resolves a `rustls::ServerConfig` from the CLI arguments.
    pub fn load_server_config(&self) -> anyhow::Result<Arc<ServerConfig>> {
        match (&self.tls_cert, &self.tls_key, self.tls_self_signed) {
            (Some(cert), Some(key), _) => load_server_config_from_pem(cert, key)
                .context("failed to load TLS certificate/key PEM"),
            (None, None, true) => generate_self_signed_server(&[])
                .context("failed to generate self-signed TLS certificate")
                .map(|c| c.server_config),
            _ => bail!("provide either --tls-cert and --tls-key, or pass --tls-self-signed"),
        }
    }
}

/// Initializes default `tracing_subscriber` formatting (`RUST_LOG`, defaulting to `info`).
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

/// Running HTTPS `axum` server handle with graceful shutdown.
pub struct SpawnedHttpsServer {
    /// Bound socket address.
    pub local_addr: SocketAddr,
    /// Canonical HTTPS origin (`https://localhost:<port>` unless overridden).
    pub origin: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl SpawnedHttpsServer {
    /// Signals graceful shutdown and awaits listener exit.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.join_handle).await;
    }
}

/// Binds `listen_addr` and serves `make_router(origin)` over TLS (`http/1.1` + `h2`).
pub async fn spawn_https_router(
    listen_addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    public_origin_override: Option<String>,
    make_router: impl FnOnce(String) -> Router,
) -> anyhow::Result<SpawnedHttpsServer> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    let origin = match public_origin_override {
        Some(origin) => normalize_public_origin(&origin)?,
        None => format!("https://localhost:{}", local_addr.port()),
    };

    let router = make_router(origin.clone());
    let acceptor = TlsAcceptor::from(tls_config);
    let connection_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let Ok(connection_slot) = connection_slots.clone().try_acquire_owned() else {
                        // Bound open sockets and spawned connection tasks under connection floods.
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let svc = TowerToHyperService::new(router.clone());
                    tokio::spawn(async move {
                        let _connection_slot = connection_slot;
                        let Ok(Ok(tls_stream)) =
                            timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        else {
                            return;
                        };

                        let mut server = AutoServerBuilder::new(TokioExecutor::new());
                        server
                            .http1()
                            .timer(TokioTimer::new())
                            .header_read_timeout(HTTP1_HEADER_READ_TIMEOUT)
                            .max_headers(MAX_REQUEST_HEADERS)
                            .max_buf_size(MAX_HEADER_BYTES);
                        server
                            .http2()
                            .max_concurrent_streams(MAX_HTTP2_CONCURRENT_STREAMS)
                            .max_header_list_size(MAX_HEADER_BYTES as u32);
                        let _ = server
                            .serve_connection(TokioIo::new(tls_stream), svc)
                            .await;
                    });
                }
            }
        }
    });

    Ok(SpawnedHttpsServer {
        local_addr,
        origin,
        shutdown_tx: Some(shutdown_tx),
        join_handle,
    })
}

fn normalize_public_origin(origin: &str) -> anyhow::Result<String> {
    let parsed = Url::parse(origin).context("invalid --public-origin URL")?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("--public-origin must be an HTTPS origin without userinfo, path, query, or fragment");
    }
    canonical_https_origin(&parsed).context("invalid --public-origin")
}

/// Builds a `Cache-Control: no-store` JSON response with `status`.
pub fn json_no_store<T: serde::Serialize>(status: StatusCode, payload: &T) -> Response {
    (
        status,
        [(CACHE_CONTROL, "no-store")],
        Json(serde_json::to_value(payload).unwrap_or_default()),
    )
        .into_response()
}

/// Builds a `Cache-Control: no-store` JSON `{"error": message}` response.
pub fn json_error(status: StatusCode, message: &str) -> Response {
    json_no_store(status, &serde_json::json!({ "error": message }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_origin_is_canonical_and_rejects_url_components() {
        assert_eq!(
            normalize_public_origin("https://Example.COM:443/").unwrap(),
            "https://example.com",
        );
        for invalid in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com/?query",
            "https://example.com/#fragment",
        ] {
            assert!(
                normalize_public_origin(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
