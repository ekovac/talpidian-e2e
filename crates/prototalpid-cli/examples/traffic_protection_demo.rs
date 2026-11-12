//! Runnable end-to-end demonstration of MOLE website traffic protection:
//!
//! ```sh
//! cargo run --release -p prototalpid-cli --example traffic_protection_demo
//! ```
//!
//! Spawns:
//! - 3 independent `prototalpid-anchor` HTTPS servers (forming a 3-Anchor anonymity set)
//! - 1 mock upstream HTTP website counting origin hits
//! - 1 `prototalpid-moderator-proxy` HTTPS reverse proxy enforcing EC-ACT session deposits
//! - 3 `prototalpid-cli` clients:
//!   1. Unendorsed bot -> blocked at the proxy (`401`, 0 origin hits)
//!   2. Polite reader (endorsed by Anchor #2) -> browses across multiple sessions with 100%
//!      deposit refunds (`c = 60 -> 40 -> 60`), never needing another endorsement
//!   3. Aggressive scraper (endorsed by Anchor #3) -> floods past rate limit, forfeits deposits
//!      (`60 -> 40 -> 20 -> 0`), gets `429` at the Anchor, and is blocked at the edge (`401`)

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{OriginalUri, State};
use bytes::Bytes;
use http::header::AUTHORIZATION;
use http::{HeaderMap, Method};
use tokio::net::TcpListener;
use url::Url;

use prototalpid_anchor::{AnchorRuntimeConfig, AnchorStore, ChallengeMode, spawn_anchor_server};
use prototalpid_cli::{MoleClient, MoleClientOptions, WalletStore};
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::MOLE_SESSION_HEADER;
use prototalpid_moderator_proxy::{
    ModerationPolicy, ModeratorProxyConfig, ModeratorStore, TrustedAnchorSet,
    spawn_moderator_proxy,
};

async fn spawn_origin_website(hits: Arc<AtomicUsize>) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .fallback(
            |State(hits): State<Arc<AtomicUsize>>, OriginalUri(uri): OriginalUri, headers: HeaderMap| async move {
                assert!(headers.get(&MOLE_SESSION_HEADER).is_none());
                assert!(headers.get(AUTHORIZATION).is_none());
                let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                format!("Origin article {uri} (upstream hit #{n})")
            },
        )
        .with_state(hits);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (Url::parse(&format!("http://{addr}")).unwrap(), handle)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== MOLE End-to-End Website Traffic Protection Demo ===\n");

    let ca = LocalCa::generate("MOLE Demo Root CA")?;
    let http_client = ca.http_client()?;
    let ctx_iss = b"2026-11-demo".to_vec();

    // 1. Start 3 independent HTTPS Anchors
    let mut anchors = Vec::new();
    let mut anchor_pks = Vec::new();
    for idx in 1..=3 {
        let leaf = ca.issue_server_cert(&[])?;
        let store = Arc::new(AnchorStore::open(None, &ctx_iss)?);
        anchor_pks.push(store.public_key().clone());
        let srv = spawn_anchor_server(
            "127.0.0.1:0".parse()?,
            leaf.server_config,
            store,
            AnchorRuntimeConfig {
                challenge_mode: ChallengeMode::Pow,
                pow_bits: 10,
                quota_per_challenge: 1,
                max_quota_per_session: 1,
                max_batch_size: 4,
                ..AnchorRuntimeConfig::default()
            },
            None,
        )
        .await?;
        println!("  [Anchor #{idx}] listening at {}", srv.origin);
        anchors.push(srv);
    }

    // 2. Start Upstream Website + Moderator Proxy
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let (upstream_url, upstream_task) = spawn_origin_website(upstream_hits.clone()).await;
    println!("  [Upstream]  origin website at {upstream_url}");

    let mod_leaf = ca.issue_server_cert(&[])?;
    let mod_store = Arc::new(ModeratorStore::open(
        None,
        8,
        b"demo-site-v1",
        300,
        vec![TrustedAnchorSet {
            public_keys: anchor_pks,
            issuance_epoch: ctx_iss,
        }],
    )?);
    let proxy = spawn_moderator_proxy(
        "127.0.0.1:0".parse()?,
        mod_leaf.server_config,
        mod_store,
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url,
            policy: ModerationPolicy {
                initial_credits: 60,
                deposit_credits: 20,
                max_top_up: 20,
                hold_duration_secs: 30,
                max_requests_per_window: 3,
                rate_window_secs: 60,
                revoke_chain_on_flood: false,
                challenge_window_secs: 60,
                allow_no_endorsement: false,
            },
            maintenance_interval: Duration::from_millis(250),
        },
        None,
    )
    .await?;
    println!(
        "  [Moderator] HTTPS proxy at {} (initial=60, deposit=20, max_req/window=3)\n",
        proxy.origin
    );

    // -------------------------------------------------------------------------
    // Phase A: Unendorsed Bot
    // -------------------------------------------------------------------------
    println!("1) Unendorsed Bot attempts to scrape {}/news:", proxy.origin);
    let bot_client = MoleClient::new(
        Arc::new(WalletStore::open(None)?),
        MoleClientOptions::new(http_client.clone()),
    );
    let bot_resp = bot_client
        .execute_request(
            Method::GET,
            Url::parse(&format!("{}/news", proxy.origin))?,
            Default::default(),
            Bytes::new(),
        )
        .await?;
    println!(
        "   -> HTTP {} (upstream hits = {})\n",
        bot_resp.status,
        upstream_hits.load(Ordering::SeqCst)
    );

    // -------------------------------------------------------------------------
    // Phase B: Polite Reader (endorsed by Anchor #2 of 3)
    // -------------------------------------------------------------------------
    println!("2) Polite Reader acquires 1 scarce EC-IHAT endorsement from Anchor #2 (1-of-3 ring):");
    let polite_store = Arc::new(WalletStore::open(None)?);
    let polite_client = MoleClient::new(
        polite_store.clone(),
        MoleClientOptions::new(http_client.clone()),
    );
    let granted = polite_client
        .acquire_endorsements(&Url::parse(&format!("{}/challenge", anchors[1].origin))?, 1)
        .await?;
    println!("   -> Stored {granted} EC-IHAT endorsement(s)");

    for session_num in 1..=2 {
        for page in 1..=3 {
            let url = Url::parse(&format!(
                "{}/articles/s{session_num}-p{page}",
                proxy.origin
            ))?;
            let resp = polite_client
                .execute_request(Method::GET, url, Default::default(), Bytes::new())
                .await?;
            println!(
                "   -> [Session {session_num}, req {page}/3] HTTP {} | {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            );
        }
        polite_client.signoff_origin(&proxy.origin).await?;
        let st = polite_store.status_summary()?;
        println!(
            "   -> [Session {session_num} signoff] refunded! Credential balance = {} credits (spends = {})",
            st.credentials[0].balance, st.credentials[0].presentations_count
        );
    }
    println!();

    // -------------------------------------------------------------------------
    // Phase C: Aggressive Scraper (endorsed by Anchor #3 of 3)
    // -------------------------------------------------------------------------
    println!("3) Aggressive Scraper acquires 1 EC-IHAT endorsement from Anchor #3 and floods 12 requests:");
    let scraper_store = Arc::new(WalletStore::open(None)?);
    let scraper_client = MoleClient::new(
        scraper_store.clone(),
        MoleClientOptions::new(http_client.clone()),
    );
    scraper_client
        .acquire_endorsements(&Url::parse(&format!("{}/challenge", anchors[2].origin))?, 1)
        .await?;

    for i in 1..=12 {
        let url = Url::parse(&format!("{}/scrape/item-{i}", proxy.origin))?;
        let resp = scraper_client
            .execute_request(Method::GET, url, Default::default(), Bytes::new())
            .await?;
        let st = scraper_store.status_summary()?;
        let bal_desc = if let Some(p) = st.pending_spends.first() {
            format!("held (remainder={})", p.remainder_balance)
        } else if let Some(c) = st.credentials.first() {
            format!("settled (balance={})", c.balance)
        } else {
            "none".to_owned()
        };
        println!(
            "   -> [Flood #{i:02}] HTTP {} | wallet: {bal_desc} | total upstream hits = {}",
            resp.status,
            upstream_hits.load(Ordering::SeqCst)
        );
    }

    match scraper_client
        .acquire_endorsements(&Url::parse(&format!("{}/challenge", anchors[2].origin))?, 1)
        .await
    {
        Ok(_) => unreachable!("Anchor quota was 1"),
        Err(e) => println!("   -> Scraper tried to get more endorsements from Anchor #3: {e}"),
    }

    println!("\n=== Demo Complete: Polite Reader retained 60/60 credits; Scraper drained to 0 and blocked! ===");

    proxy.shutdown().await;
    for a in anchors {
        a.shutdown().await;
    }
    upstream_task.abort();
    Ok(())
}
