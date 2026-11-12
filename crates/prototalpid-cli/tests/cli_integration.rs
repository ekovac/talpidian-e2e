use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{OriginalUri, State};
use bytes::Bytes;
use http::header::{AUTHORIZATION, SET_COOKIE};
use http::{HeaderMap, Method, StatusCode};
use tokio::net::TcpListener;
use url::Url;

use prototalpid_anchor::{AnchorRuntimeConfig, AnchorStore, ChallengeMode, spawn_anchor_server};
use prototalpid_cli::{MoleClient, MoleClientOptions, StoreStatus, WalletStore};
use prototalpid_http::schemes::CredentialType;
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::{MOLE_SESSION_HEADER, MoleAuthorization};
use prototalpid_http::wire::{EcActChallenge, EcActPresentationAndUpdate};
use prototalpid_moderator_proxy::{
    ModerationPolicy, ModeratorProxyConfig, ModeratorStore, TrustedAnchorSet,
    spawn_moderator_proxy,
};

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_prototalpid-cli")
}

async fn spawn_test_origin(hits: Arc<AtomicUsize>) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .fallback(
            |State(hits): State<Arc<AtomicUsize>>, OriginalUri(uri): OriginalUri, headers: HeaderMap| async move {
                assert!(
                    headers.get(&MOLE_SESSION_HEADER).is_none(),
                    "Mole-Session leaked to upstream"
                );
                assert!(
                    headers.get(AUTHORIZATION).is_none(),
                    "Mole Authorization leaked to upstream"
                );
                let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                (
                    [(SET_COOKIE, "origin_pref=dark; Path=/")],
                    format!("ok:{}:hit={n}", uri.path()),
                )
            },
        )
        .with_state(hits);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (Url::parse(&format!("http://{addr}")).unwrap(), handle)
}

fn read_status_json(store_path: &Path, cacert_path: &Path) -> StoreStatus {
    let out = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(store_path)
        .arg("--cacert")
        .arg(cacert_path)
        .arg("--mole-status")
        .output()
        .expect("failed to execute prototalpid-cli --mole-status");
    assert!(
        out.status.success(),
        "prototalpid-cli --mole-status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid StoreStatus JSON")
}

fn total_endorsements(st: &StoreStatus) -> usize {
    st.endorsements.iter().map(|e| e.count).sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_permissions_cookies_session_reuse_signoff_and_expiry_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = LocalCa::generate("CLI Integration Test CA").unwrap();
    let cacert_path = tmp.path().join("ca.pem");
    std::fs::write(&cacert_path, ca.cert_pem()).unwrap();

    let ctx_iss = b"2026-11".to_vec();

    // Start Anchor #1 (PoW + Prompt enabled) and Anchor #2 (Prompt-only for interactive stdin test)
    let anchor_leaf = ca.issue_server_cert(&[]).unwrap();
    let anchor_store = Arc::new(AnchorStore::open(None, &ctx_iss).unwrap());
    let anchor_cfg = AnchorRuntimeConfig {
        challenge_mode: ChallengeMode::Both,
        pow_bits: 8,
        quota_per_challenge: 4,
        max_quota_per_session: 4,
        max_batch_size: 4,
        ..AnchorRuntimeConfig::default()
    };
    let anchor_srv = spawn_anchor_server(
        "127.0.0.1:0".parse().unwrap(),
        anchor_leaf.server_config,
        anchor_store.clone(),
        anchor_cfg,
        None,
    )
    .await
    .unwrap();
    let anchor_url = format!("https://localhost:{}/challenge", anchor_srv.local_addr.port());

    let prompt_leaf = ca.issue_server_cert(&[]).unwrap();
    let prompt_store = Arc::new(AnchorStore::open(None, &ctx_iss).unwrap());
    let prompt_srv = spawn_anchor_server(
        "127.0.0.1:0".parse().unwrap(),
        prompt_leaf.server_config,
        prompt_store.clone(),
        AnchorRuntimeConfig {
            challenge_mode: ChallengeMode::Prompt,
            quota_per_challenge: 2,
            max_quota_per_session: 2,
            max_batch_size: 2,
            ..AnchorRuntimeConfig::default()
        },
        None,
    )
    .await
    .unwrap();

    // Start Upstream + Moderator Proxy (hold_duration_secs = 3s for fast expiry testing)
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let (upstream_url, upstream_task) = spawn_test_origin(upstream_hits.clone()).await;

    let mod_leaf = ca.issue_server_cert(&[]).unwrap();
    let mod_store = Arc::new(
        ModeratorStore::open(
            None,
            8,
            b"cli-mod-ctx-v1",
            300,
            vec![TrustedAnchorSet {
                public_keys: vec![
                    anchor_store.public_key().clone(),
                    prompt_store.public_key().clone(),
                ],
                issuance_epoch: ctx_iss.clone(),
            }],
        )
        .unwrap(),
    );
    let policy = ModerationPolicy {
        initial_credits: 60,
        deposit_credits: 20,
        max_top_up: 20,
        hold_duration_secs: 3,
        max_requests_per_window: 5,
        rate_window_secs: 10,
        revoke_chain_on_flood: false,
        challenge_window_secs: 60,
        allow_no_endorsement: false,
    };
    let mod_srv = spawn_moderator_proxy(
        "127.0.0.1:0".parse().unwrap(),
        mod_leaf.server_config,
        mod_store.clone(),
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url,
            policy: policy.clone(),
            maintenance_interval: Duration::from_millis(150),
        },
        None,
    )
    .await
    .unwrap();
    let mod_origin = mod_srv.origin.clone();

    let store_path = tmp.path().join("wallet").join("state.db");
    let cookie_jar_path = tmp.path().join("cookies.txt");

    // 1. Acquire 2 EC-IHAT endorsements via CLI subprocess (automatic PoW solver) and export cookie jar
    let endorse_out = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("--mole-endorse")
        .arg("--mole-batch-count")
        .arg("2")
        .arg("-c")
        .arg(&cookie_jar_path)
        .arg(&anchor_url)
        .output()
        .unwrap();
    assert!(
        endorse_out.status.success(),
        "endorse stderr: {}",
        String::from_utf8_lossy(&endorse_out.stderr)
    );

    // Verify 0600 permissions on SQLite wallet file and 0700 on parent dir!
    let db_mode = std::fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(db_mode, 0o600, "wallet SQLite file must have 0600 permissions");
    let dir_mode = std::fs::metadata(store_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "wallet directory must have 0700 permissions");
    assert!(
        std::fs::read_to_string(&cookie_jar_path)
            .unwrap()
            .contains("anchor_session"),
        "Netscape cookie jar should export anchor_session"
    );

    // Also test cookie-jar import (`-b <file>`) into a fresh secondary wallet!
    let imported_store_path = tmp.path().join("imported").join("state.db");
    let import_out = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&imported_store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-b")
        .arg(&cookie_jar_path)
        .arg("--mole-status")
        .output()
        .unwrap();
    assert!(import_out.status.success());
    let imported_st: StoreStatus = serde_json::from_slice(&import_out.stdout).unwrap();
    assert_eq!(imported_st.cookie_count, 1);

    let st0 = read_status_json(&store_path, &cacert_path);
    assert_eq!(total_endorsements(&st0), 2);
    assert!(st0.credentials.is_empty());

    // 2. First CLI request to protected origin: redeems 1 endorsement -> c=60 -> escrows s=20 -> held!
    let r1 = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-s")
        .arg("-S")
        .arg("-w")
        .arg("\nHTTP=%{http_code}")
        .arg(format!("{mod_origin}/articles/1"))
        .output()
        .unwrap();
    assert!(r1.status.success(), "stderr: {}", String::from_utf8_lossy(&r1.stderr));
    let r1_stdout = String::from_utf8(r1.stdout).unwrap();
    assert!(r1_stdout.contains("ok:/articles/1:hit=1"));
    assert!(r1_stdout.contains("HTTP=200"));

    let st1 = read_status_json(&store_path, &cacert_path);
    assert_eq!(total_endorsements(&st1), 1, "exactly 1 endorsement burned");
    assert!(
        st1.credentials.is_empty(),
        "credential is currently held in pending_spends"
    );
    assert_eq!(st1.pending_spends.len(), 1);
    assert_eq!(st1.pending_spends[0].state, "held");
    assert_eq!(st1.pending_spends[0].remainder_balance, 40);

    // 3. Second CLI invocation immediately reuses Mole-Session without spending another credential!
    let r2 = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-s")
        .arg("-S")
        .arg(format!("{mod_origin}/articles/2"))
        .output()
        .unwrap();
    assert!(r2.status.success());
    assert_eq!(String::from_utf8(r2.stdout).unwrap(), "ok:/articles/2:hit=2");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);

    // 4. Explicit `--mole-signoff` refunds full deposit (`40 + 20 = 60` credits)!
    let so = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("--mole-signoff")
        .arg(&mod_origin)
        .output()
        .unwrap();
    assert!(so.status.success(), "stderr: {}", String::from_utf8_lossy(&so.stderr));

    let st2 = read_status_json(&store_path, &cacert_path);
    assert_eq!(total_endorsements(&st2), 1, "still 1 endorsement left");
    assert!(st2.pending_spends.is_empty());
    assert_eq!(st2.credentials.len(), 1);
    assert_eq!(st2.credentials[0].balance, 60, "polite signoff refunded full deposit");
    assert_eq!(st2.credentials[0].presentations_count, 1);

    // 5. `--mole-signoff-on-exit` opens a new session with the refunded credential and settles on exit!
    let r3 = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-s")
        .arg("-S")
        .arg("--mole-signoff-on-exit")
        .arg(format!("{mod_origin}/articles/3"))
        .output()
        .unwrap();
    assert!(r3.status.success());
    assert_eq!(String::from_utf8(r3.stdout).unwrap(), "ok:/articles/3:hit=3");

    let st3 = read_status_json(&store_path, &cacert_path);
    assert_eq!(total_endorsements(&st3), 1, "still 1 endorsement left");
    assert!(st3.pending_spends.is_empty());
    assert_eq!(st3.credentials[0].balance, 60);
    assert_eq!(st3.credentials[0].presentations_count, 2);

    // 6. Leave a session un-signed-off past `hold_duration_secs` (3s), then verify next CLI call
    //    recovers via `recovery-0001` and completes `/articles/4` + `/articles/5` without losing credits!
    let r4 = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-s")
        .arg("-S")
        .arg(format!("{mod_origin}/articles/4"))
        .output()
        .unwrap();
    assert!(r4.status.success());
    assert_eq!(String::from_utf8(r4.stdout).unwrap(), "ok:/articles/4:hit=4");

    // Wait for the 3-second hold to expire and finalize on the Moderator
    tokio::time::sleep(Duration::from_millis(3400)).await;

    let r5 = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-s")
        .arg("-S")
        .arg("--mole-signoff-on-exit")
        .arg(format!("{mod_origin}/articles/5"))
        .output()
        .unwrap();
    assert!(r5.status.success(), "stderr: {}", String::from_utf8_lossy(&r5.stderr));
    assert_eq!(String::from_utf8(r5.stdout).unwrap(), "ok:/articles/5:hit=5");

    let st4 = read_status_json(&store_path, &cacert_path);
    assert_eq!(total_endorsements(&st4), 1, "never needed a 2nd endorsement!");
    assert_eq!(st4.credentials[0].balance, 60, "expiry recovery + signoff preserved full balance");
    assert_eq!(st4.credentials[0].presentations_count, 4);

    // 7. Simulate an interrupted `in_flight` presentation (client wrote `in_flight` state and
    //    server accepted presentation, then network dropped before client saw `held-for-update`).
    {
        let wallet = WalletStore::open(Some(&store_path)).unwrap();
        let mod_cfg = wallet.load_moderator_config(&mod_origin).unwrap().unwrap();
        let (issuance_url, _, keys) = mod_cfg.parse_supported().unwrap();
        let active_key = &keys[0];
        let usable = wallet
            .find_usable_credential(
                &mod_origin,
                &active_key.key_id,
                &active_key.config.credential_context,
                active_key.config.balance_width,
                policy.deposit_credits,
                policy.max_top_up,
            )
            .unwrap()
            .unwrap();

        let probe_client = MoleClient::new(
            Arc::new(WalletStore::open(None).unwrap()),
            {
                let mut o = MoleClientOptions::new(ca.http_client().unwrap());
                o.mole_disabled = true;
                o
            },
        );
        let target_url = Url::parse(&format!("{mod_origin}/articles/crash")).unwrap();
        let resp_401 = probe_client
            .execute_request(Method::GET, target_url.clone(), Default::default(), Bytes::new())
            .await
            .unwrap();
        assert_eq!(resp_401.status, StatusCode::UNAUTHORIZED);
        let chals = prototalpid_http::transport::parse_www_authenticate_headers(&resp_401.headers);
        let raw_act = chals
            .iter()
            .find_map(|c| match c {
                prototalpid_http::transport::MoleChallenge::Credential {
                    credential_type: CredentialType::EC_ACT,
                    challenge,
                } => Some(challenge.clone()),
                _ => None,
            })
            .unwrap();
        let act_chal = EcActChallenge::from_bytes(&raw_act).unwrap();
        let params = ec_act::Params::new(active_key.config.balance_width).unwrap();
        let (spend_st, spend_msg) = ec_act::prove_spend(
            &params,
            usable.credential,
            &active_key.ctx_cred,
            act_chal.spend_amount,
            act_chal.max_top_up,
            &act_chal.ctx_spend().unwrap(),
        )
        .unwrap();
        let pres = EcActPresentationAndUpdate {
            key_id: active_key.key_id,
            spend: spend_msg,
        };
        let pres_bytes = pres.to_bytes();
        let handle = pres.recovery_handle();

        wallet
            .commit_in_flight_spend(
                usable.id,
                &mod_origin,
                issuance_url.as_str(),
                &active_key.key_id,
                &active_key.public_key,
                active_key.config.balance_width,
                &active_key.config.credential_context,
                &spend_st,
                &pres_bytes,
                &handle,
                usable.presentations_count,
                "GET",
                target_url.as_str(),
            )
            .unwrap();

        let _ = mod_store
            .process_presentation(
                &mod_origin,
                "GET",
                "/articles/crash",
                &policy,
                CredentialType::EC_ACT,
                &pres_bytes,
            )
            .unwrap();
        let _ = MoleAuthorization::Signoff {
            credential_type: CredentialType::EC_ACT,
            recovery_handle: handle.to_bytes().to_vec(),
        };
    }

    let st_crash = read_status_json(&store_path, &cacert_path);
    assert_eq!(st_crash.pending_spends.len(), 1);
    assert_eq!(st_crash.pending_spends[0].state, "in_flight");

    let r6 = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&store_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("-s")
        .arg("-S")
        .arg("--mole-signoff-on-exit")
        .arg(format!("{mod_origin}/articles/recovered"))
        .output()
        .unwrap();
    assert!(r6.status.success(), "stderr: {}", String::from_utf8_lossy(&r6.stderr));
    assert_eq!(
        String::from_utf8(r6.stdout).unwrap(),
        "ok:/articles/recovered:hit=6"
    );

    let st_final = read_status_json(&store_path, &cacert_path);
    assert_eq!(total_endorsements(&st_final), 1);
    assert!(st_final.pending_spends.is_empty());
    assert_eq!(st_final.credentials[0].balance, 60);
    assert_eq!(st_final.credentials[0].presentations_count, 6);

    // 8. Also test interactive Prompt-only Anchor challenge via subprocess stderr/stdin!
    let prompt_wallet_path = tmp.path().join("prompt-wallet").join("state.db");
    let prompt_url = format!("{}/challenge", prompt_srv.origin);
    let mut child = Command::new(cli_bin())
        .arg("--mole-store")
        .arg(&prompt_wallet_path)
        .arg("--cacert")
        .arg(&cacert_path)
        .arg("--mole-endorse")
        .arg("--mole-batch-count")
        .arg("1")
        .arg(&prompt_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Read stderr until `[Anchor Challenge] What is A + B? ` appears, compute A + B, and write to stdin!
    {
        use std::io::Read;
        let mut stderr = child.stderr.take().unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while stderr.read(&mut byte).unwrap() == 1 {
            buf.push(byte[0]);
            if buf.ends_with(b"? ") {
                break;
            }
        }
        let prompt_str = String::from_utf8(buf).unwrap();
        // Format: "[Anchor Challenge] What is 12 + 34? "
        let expr = prompt_str
            .split("What is ")
            .nth(1)
            .unwrap()
            .trim_end_matches("? ");
        let (a_s, b_s) = expr.split_once(" + ").unwrap();
        let ans = a_s.parse::<u32>().unwrap() + b_s.parse::<u32>().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{ans}").unwrap();
    }
    let prompt_res = child.wait_with_output().unwrap();
    assert!(prompt_res.status.success());
    let st_prompt = read_status_json(&prompt_wallet_path, &cacert_path);
    assert_eq!(total_endorsements(&st_prompt), 1);

    mod_srv.shutdown().await;
    prompt_srv.shutdown().await;
    anchor_srv.shutdown().await;
    upstream_task.abort();
}
