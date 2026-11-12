use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use url::Url;

use prototalpid_http::config::{AnchorConfiguration, anchor_well_known_url};
use prototalpid_http::server::{TlsServerArgs, init_tracing};
use prototalpid_http::tls::build_http_client;
use prototalpid_moderator_proxy::{
    ModerationPolicy, ModeratorProxyConfig, ModeratorStore, TrustedAnchorSet,
    spawn_moderator_proxy,
};

/// HTTPS MOLE Moderator reverse proxy protecting an upstream web server.
#[derive(Debug, Parser)]
#[command(name = "prototalpid-moderator-proxy", version, about)]
struct Cli {
    /// Socket address to listen on.
    #[arg(long, default_value = "127.0.0.1:8444")]
    listen: SocketAddr,

    /// Canonical public HTTPS origin (defaults to `https://localhost:<port>`).
    #[arg(long)]
    public_origin: Option<String>,

    /// Upstream HTTP origin URL to forward authorized requests to.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    upstream: Url,

    /// Path to SQLite database file.
    #[arg(long, default_value = "moderator.db")]
    db: PathBuf,

    /// Trusted Anchor HTTPS origins (ordered Anchor Set; fetched at startup via `/.well-known/mole-anchor`).
    #[arg(long = "anchor", required = true)]
    anchors: Vec<Url>,

    /// Optional custom CA bundle PEM for fetching trusted Anchor `.well-known` configs.
    #[arg(long)]
    anchor_cacert: Option<PathBuf>,

    /// Accept self-signed Anchor TLS certificates when bootstrapping in local dev.
    #[arg(long)]
    anchor_insecure: bool,

    /// EC-ACT balance bit-width `L` (`1..=64`).
    #[arg(long, default_value_t = 8)]
    balance_width: u8,

    /// EC-ACT coarse credential context string.
    #[arg(long, default_value = "moderator-v1")]
    credential_context: String,

    /// Result retention duration in seconds for lost-response recovery.
    #[arg(long, default_value_t = 300)]
    result_retention_secs: u64,

    /// Initial credit balance `c` issued on endorsement redemption.
    #[arg(long, default_value_t = 60)]
    initial_credits: u64,

    /// Escrowed deposit `s` (`spend_amount`) per session presentation.
    #[arg(long, default_value_t = 20)]
    deposit_credits: u64,

    /// Duration in seconds to hold credentials (`held-for-update-0001="<secs>"`).
    #[arg(long, default_value_t = 30)]
    hold_secs: u64,

    /// Sliding rate-limit window in seconds for active `Mole-Session`s.
    #[arg(long, default_value_t = 10)]
    rate_window_secs: u64,

    /// Max allowed requests per `rate_window_secs` before invalidating `Mole-Session`.
    #[arg(long, default_value_t = 5)]
    max_requests_per_window: u32,

    /// Revoke the entire credential chain (`NoUpdate`) on a rate-limit flood instead of forfeiting `s`.
    #[arg(long)]
    revoke_chain_on_flood: bool,

    #[command(flatten)]
    tls: TlsServerArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let tls_config = cli.tls.load_server_config()?;
    let anchor_client = build_http_client(cli.anchor_insecure, cli.anchor_cacert.as_deref())?;

    let mut epoch_opt: Option<Vec<u8>> = None;
    let mut anchor_pks = Vec::with_capacity(cli.anchors.len());
    for anchor_url in &cli.anchors {
        let wk = anchor_well_known_url(anchor_url)?;
        let cfg: AnchorConfiguration = anchor_client
            .get(wk.clone())
            .send()
            .await
            .with_context(|| format!("failed to connect to {wk}"))?
            .error_for_status()
            .with_context(|| format!("HTTP error fetching {wk}"))?
            .json()
            .await
            .with_context(|| format!("invalid AnchorConfiguration JSON from {wk}"))?;
        let (_, pk) = cfg.validate_ec_ihat()?;
        if let Some(ref ep) = epoch_opt {
            if ep != &cfg.issuance_epoch {
                bail!("all Anchors in an EC-IHAT Anchor Set must share the same issuance-epoch");
            }
        } else {
            epoch_opt = Some(cfg.issuance_epoch);
        }
        anchor_pks.push(pk);
    }

    let anchor_sets = vec![TrustedAnchorSet {
        issuance_epoch: epoch_opt.unwrap_or_else(|| b"2026-11".to_vec()),
        public_keys: anchor_pks,
    }];

    let store = Arc::new(ModeratorStore::open(
        Some(&cli.db),
        cli.balance_width,
        cli.credential_context.as_bytes(),
        cli.result_retention_secs,
        anchor_sets,
    )?);

    let policy = ModerationPolicy {
        initial_credits: cli.initial_credits,
        deposit_credits: cli.deposit_credits,
        hold_duration_secs: cli.hold_secs,
        rate_window_secs: cli.rate_window_secs,
        max_requests_per_window: cli.max_requests_per_window,
        revoke_chain_on_flood: cli.revoke_chain_on_flood,
        ..ModerationPolicy::default()
    };

    let proxy_cfg = ModeratorProxyConfig {
        public_origin: String::new(),
        upstream_origin: cli.upstream,
        policy,
        maintenance_interval: Duration::from_millis(500),
    };

    let server =
        spawn_moderator_proxy(cli.listen, tls_config, store, proxy_cfg, cli.public_origin).await?;
    tracing::info!(
        origin = %server.origin,
        listen = %server.local_addr,
        "prototalpid-moderator-proxy listening"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down prototalpid-moderator-proxy");
    server.shutdown().await;
    Ok(())
}
