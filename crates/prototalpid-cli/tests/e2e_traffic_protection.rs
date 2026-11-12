use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{OriginalUri, State};
use http::HeaderMap;
use http::header::AUTHORIZATION;
use tokio::net::TcpListener;
use url::Url;

use prototalpid_anchor::{AnchorRuntimeConfig, AnchorStore, ChallengeMode, spawn_anchor_server};
use prototalpid_cli::StoreStatus;
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::MOLE_SESSION_HEADER;
use prototalpid_moderator_proxy::{
    ModerationPolicy, ModeratorProxyConfig, ModeratorStore, TrustedAnchorSet,
    spawn_moderator_proxy,
};

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_prototalpid-cli")
}

async fn spawn_protected_website(hits: Arc<AtomicUsize>) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .fallback(
            |State(hits): State<Arc<AtomicUsize>>, OriginalUri(uri): OriginalUri, headers: HeaderMap| async move {
                assert!(
                    headers.get(&MOLE_SESSION_HEADER).is_none(),
                    "Mole-Session header must be stripped before upstream"
                );
                assert!(
                    headers.get(AUTHORIZATION).is_none(),
                    "Mole Authorization header must be stripped before upstream"
                );
                let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                format!("website:{uri}:hit={n}")
            },
        )
        .with_state(hits);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (Url::parse(&format!("http://{addr}")).unwrap(), handle)
}

fn run_cli(store: &Path, cacert: &Path, extra_args: &[&str]) -> Output {
    Command::new(cli_bin())
        .arg("--mole-store")
        .arg(store)
        .arg("--cacert")
        .arg(cacert)
        .args(extra_args)
        .output()
        .expect("failed to invoke prototalpid-cli")
}

fn wallet_status(store: &Path, cacert: &Path) -> StoreStatus {
    let out = run_cli(store, cacert, &["--mole-status"]);
    assert!(
        out.status.success(),
        "--mole-status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_multi_anchor_website_traffic_protection() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = LocalCa::generate("MOLE E2E Root CA").unwrap();
    let cacert_path = tmp.path().join("mole-e2e-ca.pem");
    std::fs::write(&cacert_path, ca.cert_pem()).unwrap();

    let ctx_iss = b"2026-11-epoch".to_vec();

    // -------------------------------------------------------------------------
    // 1. Spawn 3 distinct HTTPS Anchors with scarce per-session quotas (max = 1)
    // -------------------------------------------------------------------------
    let mut anchor_servers = Vec::new();
    let mut anchor_pks = Vec::new();
    for _ in 0..3 {
        let leaf = ca.issue_server_cert(&[]).unwrap();
        let store = Arc::new(AnchorStore::open(None, &ctx_iss).unwrap());
        anchor_pks.push(store.public_key().clone());
        let srv = spawn_anchor_server(
            "127.0.0.1:0".parse().unwrap(),
            leaf.server_config,
            store,
            AnchorRuntimeConfig {
                challenge_mode: ChallengeMode::Pow,
                pow_bits: 8,
                quota_per_challenge: 1,
                max_quota_per_session: 1,
                max_batch_size: 4,
                ..AnchorRuntimeConfig::default()
            },
            None,
        )
        .await
        .unwrap();
        anchor_servers.push(srv);
    }

    // -------------------------------------------------------------------------
    // 2. Spawn upstream website + Moderator Proxy #1 (progressive deposit burn)
    //    and Moderator Proxy #2 (immediate chain revocation on flood)
    // -------------------------------------------------------------------------
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let (upstream_url, upstream_task) = spawn_protected_website(upstream_hits.clone()).await;

    let mod1_leaf = ca.issue_server_cert(&[]).unwrap();
    let mod1_store = Arc::new(
        ModeratorStore::open(
            None,
            8,
            b"website-prod-v1",
            300,
            vec![TrustedAnchorSet {
                public_keys: anchor_pks.clone(),
                issuance_epoch: ctx_iss.clone(),
            }],
        )
        .unwrap(),
    );
    let mod1_srv = spawn_moderator_proxy(
        "127.0.0.1:0".parse().unwrap(),
        mod1_leaf.server_config,
        mod1_store,
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url.clone(),
            policy: ModerationPolicy {
                initial_credits: 60,
                deposit_credits: 20,
                max_top_up: 20,
                hold_duration_secs: 20,
                max_requests_per_window: 3,
                rate_window_secs: 60,
                revoke_chain_on_flood: false,
                challenge_window_secs: 60,
                allow_no_endorsement: false,
            },
            maintenance_interval: Duration::from_millis(200),
        },
        None,
    )
    .await
    .unwrap();
    let site1 = mod1_srv.origin.clone();

    let mod2_leaf = ca.issue_server_cert(&[]).unwrap();
    let mod2_store = Arc::new(
        ModeratorStore::open(
            None,
            8,
            b"website-strict-v1",
            300,
            vec![TrustedAnchorSet {
                public_keys: anchor_pks.clone(),
                issuance_epoch: ctx_iss.clone(),
            }],
        )
        .unwrap(),
    );
    let mod2_srv = spawn_moderator_proxy(
        "127.0.0.1:0".parse().unwrap(),
        mod2_leaf.server_config,
        mod2_store,
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url.clone(),
            policy: ModerationPolicy {
                initial_credits: 100,
                deposit_credits: 20,
                max_top_up: 20,
                hold_duration_secs: 20,
                max_requests_per_window: 2,
                rate_window_secs: 60,
                revoke_chain_on_flood: true,
                challenge_window_secs: 60,
                allow_no_endorsement: false,
            },
            maintenance_interval: Duration::from_millis(200),
        },
        None,
    )
    .await
    .unwrap();
    let site2 = mod2_srv.origin.clone();

    // =========================================================================
    // Scenario 1: Unendorsed clients are rejected at the edge (`401`, exit 22)
    // =========================================================================
    let unendorsed_wallet = tmp.path().join("unendorsed.db");
    let res_disabled = run_cli(
        &unendorsed_wallet,
        &cacert_path,
        &["--mole-disable", "-s", "-f", &format!("{site1}/home")],
    );
    assert_eq!(res_disabled.status.code(), Some(22));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    let res_empty = run_cli(
        &unendorsed_wallet,
        &cacert_path,
        &["-s", "-f", &format!("{site1}/home")],
    );
    assert_eq!(res_empty.status.code(), Some(22));
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "unendorsed traffic must never reach upstream origin"
    );

    // =========================================================================
    // Scenario 2: Polite endorsed client (Anchor #2 of 3) browses indefinitely
    //             on a single Endorsement via session reuse + deposit refunds
    // =========================================================================
    let polite_wallet = tmp.path().join("polite.db");
    let anchor2_challenge = format!("{}/challenge", anchor_servers[1].origin);
    let endorse_polite = run_cli(
        &polite_wallet,
        &cacert_path,
        &["--mole-endorse", "--mole-batch-count", "4", &anchor2_challenge],
    );
    assert!(endorse_polite.status.success());
    // Anchor #2 clamps batch grant to session quota = 1!
    let st_polite_init = wallet_status(&polite_wallet, &cacert_path);
    assert_eq!(
        st_polite_init.endorsements.iter().map(|e| e.count).sum::<usize>(),
        1
    );

    // Session 1: 3 polite requests (within max_requests_per_window = 3), then explicit signoff
    for page in 1..=3 {
        let out = run_cli(
            &polite_wallet,
            &cacert_path,
            &["-s", "-S", "-f", &format!("{site1}/feed?page={page}")],
        );
        assert!(out.status.success(), "polite page {page} failed");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("/feed?page={page}")),
            "unexpected body"
        );
    }
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 3);

    let signoff_out = run_cli(
        &polite_wallet,
        &cacert_path,
        &["--mole-signoff", &site1],
    );
    assert!(signoff_out.status.success());

    let st_after_s1 = wallet_status(&polite_wallet, &cacert_path);
    assert_eq!(
        st_after_s1.endorsements.iter().map(|e| e.count).sum::<usize>(),
        0
    );
    assert_eq!(st_after_s1.credentials.len(), 1);
    assert_eq!(
        st_after_s1.credentials[0].balance, 60,
        "polite session received 100% deposit refund"
    );

    // Sessions 2 & 3: continue browsing across fresh sessions without ANY new endorsements!
    for s in 2..=3 {
        let out = run_cli(
            &polite_wallet,
            &cacert_path,
            &[
                "-s",
                "-S",
                "-f",
                "--mole-signoff-on-exit",
                &format!("{site1}/session-{s}"),
            ],
        );
        assert!(out.status.success());
    }
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 5);
    let st_after_s3 = wallet_status(&polite_wallet, &cacert_path);
    assert_eq!(st_after_s3.credentials[0].balance, 60);
    assert_eq!(st_after_s3.credentials[0].presentations_count, 3);

    // =========================================================================
    // Scenario 3: Scraper / Flooder forfeits deposits (`60 -> 40 -> 20 -> 0`),
    //             gets rate-limited at Anchor (`429`), and is completely blocked!
    // =========================================================================
    let scraper_wallet = tmp.path().join("scraper.db");
    let anchor3_challenge = format!("{}/challenge", anchor_servers[2].origin);
    let endorse_scraper = run_cli(
        &scraper_wallet,
        &cacert_path,
        &["--mole-endorse", "--mole-batch-count", "1", &anchor3_challenge],
    );
    assert!(endorse_scraper.status.success());

    // Scraper tries to hoard more endorsements on the same Anchor session -> 429!
    let hoard_attempt = run_cli(
        &scraper_wallet,
        &cacert_path,
        &["--mole-endorse", "--mole-batch-count", "1", &anchor3_challenge],
    );
    assert!(
        !hoard_attempt.status.success(),
        "Anchor must reject hoarding past max_quota_per_session with 429"
    );
    assert!(String::from_utf8_lossy(&hoard_attempt.stderr).contains("429"));

    // With c = 60, s = 20, and max_requests_per_window = 3:
    // - Requests 1..=3 succeed on Session #1 (deposit 20 held, remainder 40).
    // - Request 4 breaches Session #1's rate limit -> forfeits 20 credits (balance 40) -> opens Session #2 (deposit 20 held, remainder 20) -> succeeds!
    // - Requests 5..=6 succeed on Session #2.
    // - Request 7 breaches Session #2's rate limit -> forfeits 20 credits (balance 20) -> opens Session #3 (deposit 20 held, remainder 0) -> succeeds!
    // - Requests 8..=9 succeed on Session #3.
    // - Request 10 breaches Session #3's rate limit -> forfeits final 20 credits (balance 0) -> DENIED with 401 (exit 22)!
    let hits_before_scraper = upstream_hits.load(Ordering::SeqCst);
    for i in 1..=9 {
        let out = run_cli(
            &scraper_wallet,
            &cacert_path,
            &["-s", "-S", "-f", &format!("{site1}/scrape/{i}")],
        );
        assert!(
            out.status.success(),
            "scraper request {i} expected to succeed while burning deposits: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(upstream_hits.load(Ordering::SeqCst) - hits_before_scraper, 9);

    // Request 10..=14: scraper is now completely out of credits (balance = 0) and blocked at the proxy!
    for i in 10..=14 {
        let out = run_cli(
            &scraper_wallet,
            &cacert_path,
            &["-s", "-f", &format!("{site1}/scrape/{i}")],
        );
        assert_eq!(
            out.status.code(),
            Some(22),
            "depleted scraper request {i} must be rejected with HTTP 401 (exit 22)"
        );
    }
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst) - hits_before_scraper,
        9,
        "none of the blocked flood requests (10..=14) reached upstream!"
    );

    let st_scraper_end = wallet_status(&scraper_wallet, &cacert_path);
    assert!(st_scraper_end.pending_spends.is_empty());
    assert_eq!(st_scraper_end.credentials.len(), 1);
    assert_eq!(
        st_scraper_end.credentials[0].balance, 0,
        "scraper forfeited all 60 credits across 3 rate-limited sessions"
    );

    // Verify the Polite Client is STILL completely unaffected and continues browsing `site1`!
    let polite_after_flood = run_cli(
        &polite_wallet,
        &cacert_path,
        &[
            "-s",
            "-S",
            "-f",
            "--mole-signoff-on-exit",
            &format!("{site1}/after-flood"),
        ],
    );
    assert!(polite_after_flood.status.success());
    assert_eq!(
        wallet_status(&polite_wallet, &cacert_path).credentials[0].balance,
        60
    );

    // =========================================================================
    // Scenario 4: Immediate chain revocation (`revoke_chain_on_flood = true`)
    //             wipes a 100-credit credential to Nothing on the VERY FIRST flood!
    // =========================================================================
    let strict_scraper_wallet = tmp.path().join("strict-scraper.db");
    let anchor1_challenge = format!("{}/challenge", anchor_servers[0].origin);
    assert!(
        run_cli(
            &strict_scraper_wallet,
            &cacert_path,
            &["--mole-endorse", "--mole-batch-count", "1", &anchor1_challenge],
        )
        .status
        .success()
    );

    // Requests 1 & 2 succeed (`max_requests_per_window = 2`); Request 3 floods -> immediate `update-0001=""`!
    for i in 1..=2 {
        assert!(
            run_cli(
                &strict_scraper_wallet,
                &cacert_path,
                &["-s", "-S", "-f", &format!("{site2}/strict/{i}")],
            )
            .status
            .success()
        );
    }
    let strict_r3 = run_cli(
        &strict_scraper_wallet,
        &cacert_path,
        &["-s", "-f", &format!("{site2}/strict/3")],
    );
    assert_eq!(
        strict_r3.status.code(),
        Some(22),
        "revoke_chain_on_flood must immediately terminate the 100-credit chain on first flood"
    );

    let st_strict = wallet_status(&strict_scraper_wallet, &cacert_path);
    assert!(
        st_strict.credentials.is_empty(),
        "NoUpdate (update-0001=\"\") must permanently discard the revoked credential chain"
    );
    assert!(st_strict.pending_spends.is_empty());

    mod2_srv.shutdown().await;
    mod1_srv.shutdown().await;
    for srv in anchor_servers {
        srv.shutdown().await;
    }
    upstream_task.abort();
}
