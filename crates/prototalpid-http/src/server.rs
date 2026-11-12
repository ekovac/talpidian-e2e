//! Shared HTTPS `axum` server runner, CLI TLS flags, and JSON response helpers
//! used by both `prototalpid-anchor` and `prototalpid-moderator-proxy`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use axum::Json;
use axum::Router;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use crate::tls::{generate_self_signed_server, load_server_config_from_pem};

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
    let origin = public_origin_override
        .unwrap_or_else(|| format!("https://localhost:{}", local_addr.port()))
        .trim_end_matches('/')
        .to_owned();

    let router = make_router(origin.clone());
    let acceptor = TlsAcceptor::from(tls_config);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let acceptor = acceptor.clone();
                    let svc = TowerToHyperService::new(router.clone());
                    tokio::spawn(async move {
                        if let Ok(tls_stream) = acceptor.accept(tcp).await {
                            let _ = AutoServerBuilder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tls_stream), svc)
                                .await;
                        }
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
