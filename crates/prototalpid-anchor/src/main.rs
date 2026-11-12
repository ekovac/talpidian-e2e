use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use prototalpid_anchor::{AnchorRuntimeConfig, AnchorStore, ChallengeMode, spawn_anchor_server};
use prototalpid_http::server::{TlsServerArgs, init_tracing};

/// HTTPS MOLE Anchor server issuing EC-IHAT Endorsements after challenge verification.
#[derive(Debug, Parser)]
#[command(name = "prototalpid-anchor", version, about)]
struct Cli {
    /// Socket address to listen on.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,

    /// Canonical public HTTPS origin (defaults to `https://localhost:<port>`).
    #[arg(long)]
    public_origin: Option<String>,

    /// Path to SQLite database file.
    #[arg(long, default_value = "anchor.db")]
    db: PathBuf,

    /// Issuance epoch string (`ctx_iss`) if initializing a new Anchor database.
    #[arg(long, default_value = "2026-11")]
    issuance_epoch: String,

    /// Challenge mode (`pow`, `prompt`, or `both`).
    #[arg(long, value_enum, default_value_t = ChallengeMode::Both)]
    challenge_mode: ChallengeMode,

    /// Number of leading zero SHA-256 bits required for PoW challenges.
    #[arg(long, default_value_t = 16)]
    pow_bits: u8,

    /// Endorsement quota granted per solved challenge.
    #[arg(long, default_value_t = 4)]
    quota_per_challenge: u32,

    /// Maximum cumulative endorsements granted per session cookie.
    #[arg(long, default_value_t = 8)]
    max_quota_per_session: u32,

    /// Maximum batch count in a single `/mole/grant` request.
    #[arg(long, default_value_t = 16)]
    max_batch_size: u16,

    #[command(flatten)]
    tls: TlsServerArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let tls_config = cli.tls.load_server_config()?;

    let store = Arc::new(
        AnchorStore::open(Some(&cli.db), cli.issuance_epoch.as_bytes())
            .context("failed to open Anchor SQLite store")?,
    );
    let cfg = AnchorRuntimeConfig {
        challenge_mode: cli.challenge_mode,
        pow_bits: cli.pow_bits,
        quota_per_challenge: cli.quota_per_challenge,
        max_quota_per_session: cli.max_quota_per_session,
        max_batch_size: cli.max_batch_size,
        ..AnchorRuntimeConfig::default()
    };

    let server = spawn_anchor_server(cli.listen, tls_config, store, cfg, cli.public_origin).await?;
    tracing::info!(
        origin = %server.origin,
        listen = %server.local_addr,
        "prototalpid-anchor listening"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down prototalpid-anchor");
    server.shutdown().await;
    Ok(())
}
