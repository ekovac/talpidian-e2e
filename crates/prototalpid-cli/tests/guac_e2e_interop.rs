//! End-to-end network and CLI interoperability tests between `talpidian-e2e`
//! (`prototalpid-anchor`, `prototalpid-moderator-proxy`, `prototalpid-cli`) and
//! [`cloudflareresearch/guac`](https://github.com/cloudflareresearch/guac)
//! (both the `guac` Rust library and the `guac` CLI binary).

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use cookie::Cookie;
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HeaderName, SET_COOKIE, WWW_AUTHENTICATE,
};
use http::{HeaderMap, HeaderValue, StatusCode};
use rusqlite::Connection;
use tokio::net::TcpListener;
use url::Url;

use prototalpid_anchor::{
    ANCHOR_GRANT_PATH, AnchorRuntimeConfig, AnchorStore, ChallengeMode, spawn_anchor_server,
};
use prototalpid_cli::{StoreStatus, WalletStore};
use prototalpid_http::challenge::{AnchorChallengeOffer, AnchorChallengeSubmission, solve_pow};
use prototalpid_http::config::{
    AnchorConfiguration, EcActKeyConfig, EcIhatEndorsementConfig, ModeratorConfiguration,
    WELL_KNOWN_MOLE_ANCHOR, WELL_KNOWN_MOLE_MODERATOR,
};
use prototalpid_http::schemes::{CIPHERSUITE_P256_SHA256, EC_IHAT_CTX_RED, EndorsementType};
use prototalpid_http::server::{json_error, json_no_store, spawn_https_router};
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::{
    MOLE_CREDENTIAL_HEADER, MOLE_SESSION_HEADER, WANT_ENDORSEMENT_HEADER,
};
use prototalpid_http::unix_now;
use prototalpid_http::wire::decode_quic_varint;
use prototalpid_moderator_proxy::{
    MODERATOR_ISSUE_PATH, ModerationPolicy, ModeratorProxyConfig, ModeratorStore, TrustedAnchorSet,
    spawn_moderator_proxy,
};

fn talpid_cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_prototalpid-cli")
}

/// Locates the `guac` repository checkout resolved by Cargo (or `GUAC_SRC_DIR`).
fn locate_guac_source_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("GUAC_SRC_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .or_else(|| {
            Command::new(&cargo)
                .args(["metadata", "--format-version", "1", "--manifest-path"])
                .arg(&manifest)
                .output()
                .ok()
        })
        .expect("cargo metadata failed");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let manifest_path = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"].as_str() == Some("guac"))
        .and_then(|p| p["manifest_path"].as_str())
        .expect("guac package present in metadata");
    PathBuf::from(manifest_path).parent().unwrap().to_path_buf()
}

/// Resolves `GUAC_BIN` or compiles `guac-cli` (`bin = "guac"`) once into `target/guac-cli-interop`.
fn guac_cli_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(explicit) = std::env::var_os("GUAC_BIN") {
            return PathBuf::from(explicit);
        }
        let guac_src = locate_guac_source_dir();
        let cli_manifest = guac_src.join("cli").join("Cargo.toml");
        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("target")
            })
            .join("guac-cli-interop");

        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let offline_status = Command::new(&cargo)
            .args([
                "build",
                "--offline",
                "--locked",
                "--bin",
                "guac",
                "--manifest-path",
            ])
            .arg(&cli_manifest)
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("failed invoking cargo build for guac-cli");

        if !offline_status.status.success() {
            let online_status = Command::new(&cargo)
                .args(["build", "--locked", "--bin", "guac", "--manifest-path"])
                .arg(&cli_manifest)
                .arg("--target-dir")
                .arg(&target_dir)
                .output()
                .expect("failed invoking online cargo build for guac-cli");
            assert!(
                online_status.status.success(),
                "failed building guac-cli:\noffline stderr: {}\nonline stderr: {}",
                String::from_utf8_lossy(&offline_status.stderr),
                String::from_utf8_lossy(&online_status.stderr)
            );
        }

        let bin = target_dir
            .join("debug")
            .join(format!("guac{}", std::env::consts::EXE_SUFFIX));
        assert!(
            bin.exists(),
            "built guac binary missing at {}",
            bin.display()
        );
        bin
    })
}

fn run_guac_cli(guac_home: &Path, cacert: &Path, args: &[&str]) -> Output {
    Command::new(guac_cli_bin())
        .env("GUAC_HOME", guac_home)
        .env("CURL_CA_BUNDLE", cacert)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("failed running guac CLI")
}

fn run_talpid_cli(store: &Path, cacert: &Path, args: &[&str]) -> Output {
    Command::new(talpid_cli_bin())
        .arg("--mole-store")
        .arg(store)
        .arg("--cacert")
        .arg(cacert)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("failed running prototalpid-cli")
}

fn unwrap_guac_secret_envelope(envelope: &[u8]) -> &[u8] {
    assert_eq!(&envelope[..5], b"GUAC\x02");
    let (len, used) = decode_quic_varint(&envelope[40..]).expect("valid GUAC envelope varint");
    let payload = &envelope[40 + used..];
    assert_eq!(payload.len(), usize::try_from(len).unwrap());
    payload
}

async fn spawn_upstream_origin(hits: Arc<AtomicUsize>) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .fallback(
            |State(hits): State<Arc<AtomicUsize>>,
             OriginalUri(uri): OriginalUri,
             headers: HeaderMap| async move {
                assert!(headers.get(&MOLE_SESSION_HEADER).is_none());
                assert!(headers.get(AUTHORIZATION).is_none());
                let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                format!("origin-ok:{uri}:hit={n}")
            },
        )
        .with_state(hits);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (Url::parse(&format!("http://{addr}")).unwrap(), task)
}

async fn solve_anchor_session_cookie(client: &reqwest::Client, anchor_origin: &str) -> String {
    let challenge_url = format!("{anchor_origin}/challenge");
    let offer: AnchorChallengeOffer = client
        .get(&challenge_url)
        .header(WANT_ENDORSEMENT_HEADER, "Mole")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pow = offer.pow.as_ref().expect("PoW challenge enabled");
    let nonce = solve_pow(&offer.challenge_id, &pow.prefix, pow.bits).unwrap();
    let resp = client
        .post(&challenge_url)
        .header(WANT_ENDORSEMENT_HEADER, "Mole")
        .json(&AnchorChallengeSubmission {
            challenge_id: offer.challenge_id,
            pow_nonce: Some(nonce),
            prompt_answer: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw_cookie = resp.headers().get(SET_COOKIE).unwrap().to_str().unwrap();
    let parsed = Cookie::parse(raw_cookie).unwrap();
    format!("{}={}", parsed.name(), parsed.value())
}

// ---------------------------------------------------------------------------
// Helper HTTPS Server 1: Wraps `guac::Anchor` and `guac::Moderator` (library)
// ---------------------------------------------------------------------------

struct GuacRoleServerState {
    origin: String,
    anchor: guac::Anchor,
    moderator: guac::Moderator,
    store: guac::storage::MemoryStore,
    last_issue_error: Arc<Mutex<Option<String>>>,
}

async fn spawn_guac_roles_https_server(
    ca: &LocalCa,
    epoch: Vec<u8>,
) -> (
    prototalpid_http::server::SpawnedHttpsServer,
    ec_ihat::PublicKey,
    Arc<Mutex<Option<String>>>,
) {
    let leaf = ca.issue_server_cert(&[]).unwrap();
    let anchor = guac::Anchor::generate(epoch).unwrap();
    let pk_bytes = anchor.configuration().public_key();
    let talpid_pk = ec_ihat::PublicKey::from_bytes(&pk_bytes).unwrap();
    let last_issue_error = Arc::new(Mutex::new(None));
    let last_err_for_router = last_issue_error.clone();

    let server = spawn_https_router(
        "127.0.0.1:0".parse().unwrap(),
        leaf.server_config,
        None,
        move |origin| {
            let issue_uri = format!("{origin}{MODERATOR_ISSUE_PATH}");
            let moderator = guac::Moderator::generate(
                &issue_uri,
                8,
                b"interop-mod-ctx".to_vec(),
                guac::EndorsementPolicy::NotRequired,
                120,
            )
            .unwrap();
            let state = Arc::new(GuacRoleServerState {
                origin,
                anchor,
                moderator,
                store: guac::storage::MemoryStore::default(),
                last_issue_error: last_err_for_router,
            });
            Router::new()
                .route(WELL_KNOWN_MOLE_ANCHOR, get(guac_anchor_well_known))
                .route("/challenge", get(guac_anchor_challenge))
                .route(ANCHOR_GRANT_PATH, post(guac_anchor_grant))
                .route(WELL_KNOWN_MOLE_MODERATOR, get(guac_moderator_well_known))
                .route(MODERATOR_ISSUE_PATH, post(guac_moderator_issue))
                .fallback(guac_protected_resource)
                .with_state(state)
        },
    )
    .await
    .unwrap();

    (server, talpid_pk, last_issue_error)
}

async fn guac_anchor_well_known(State(st): State<Arc<GuacRoleServerState>>) -> Response {
    let ac = st.anchor.configuration();
    let cfg = AnchorConfiguration {
        grant_uri: format!("{}{ANCHOR_GRANT_PATH}", st.origin),
        endorsement_type: EndorsementType::EC_IHAT.0,
        ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
        anchor_key: ac.public_key().to_vec(),
        issuance_epoch: ac.epoch().to_vec(),
    };
    json_no_store(StatusCode::OK, &cfg)
}

async fn guac_anchor_challenge() -> Response {
    let endorse_hdr = guac::http::Challenge::Endorse.to_string();
    (
        StatusCode::OK,
        [
            (CACHE_CONTROL, "no-store"),
            (WWW_AUTHENTICATE, endorse_hdr.as_str()),
        ],
        "{}",
    )
        .into_response()
}

async fn guac_anchor_grant(
    State(st): State<Arc<GuacRoleServerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if guac::http::check_content_type(ct, guac::http::ENDORSEMENT_REQUEST).is_err() {
        return json_error(StatusCode::BAD_REQUEST, "bad grant content-type");
    }
    let Ok(req) = guac::protocol::EndorsementRequest::from_bytes(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "malformed grant body");
    };
    let now = unix_now().max(0) as u64;
    match st
        .anchor
        .grant(&st.store, &req, now, now + 120, NonZeroU16::MAX)
    {
        Ok(resp) => (
            StatusCode::OK,
            [
                (CONTENT_TYPE, guac::http::ENDORSEMENT_RESPONSE),
                (CACHE_CONTROL, "no-store"),
                (HeaderName::from_static("x-guac-grant"), "guac-role-route"),
            ],
            resp.to_bytes(),
        )
            .into_response(),
        Err(_) => json_error(StatusCode::BAD_REQUEST, "guac anchor grant failed"),
    }
}

async fn guac_moderator_well_known(State(st): State<Arc<GuacRoleServerState>>) -> Response {
    let mc = st.moderator.configuration();
    let ac = st.anchor.configuration();
    let cfg = ModeratorConfiguration::from_typed(
        mc.endpoint().to_string(),
        true,
        &[EcIhatEndorsementConfig {
            endorsement_type: EndorsementType::EC_IHAT.0,
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            issuance_epoch: ac.epoch().to_vec(),
            anchor_set: vec![ac.public_key().to_vec()],
        }],
        &[EcActKeyConfig {
            credential_type: 1,
            credential_key: mc.public_key().to_vec(),
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            balance_width: mc.balance_bits(),
            credential_context: mc.credential_context().to_vec(),
            result_retention: 120,
        }],
    )
    .unwrap();
    json_no_store(StatusCode::OK, &cfg)
}

async fn guac_moderator_issue(
    State(st): State<Arc<GuacRoleServerState>>,
    headers: HeaderMap,
) -> Response {
    let now = unix_now().max(0) as u64;
    let auth_str = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let parsed = match guac::http::Authorization::parse(auth_str) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "malformed Authorization"),
    };
    let Some(auth) = parsed else {
        let chal = st.moderator.redemption_challenge(now).unwrap();
        let hdr = guac::http::Challenge::Redeem(chal).to_string();
        return (
            StatusCode::UNAUTHORIZED,
            [
                (CACHE_CONTROL, "no-store"),
                (WWW_AUTHENTICATE, hdr.as_str()),
            ],
            "",
        )
            .into_response();
    };

    match auth {
        guac::http::Authorization::Issue(req) => match st.moderator.issue(&st.store, &req, 60, now)
        {
            Ok(resp) => {
                let cred_hdr = guac::http::CredentialField::Response(resp).to_string();
                (
                    StatusCode::OK,
                    [
                        (CACHE_CONTROL, "no-store"),
                        (MOLE_CREDENTIAL_HEADER, cred_hdr.as_str()),
                    ],
                    "",
                )
                    .into_response()
            }
            Err(err) => {
                *st.last_issue_error.lock().unwrap() = Some(format!("{err:?}"));
                let chal = st.moderator.redemption_challenge(now).unwrap();
                let hdr = guac::http::Challenge::Redeem(chal).to_string();
                (
                    StatusCode::UNAUTHORIZED,
                    [
                        (CACHE_CONTROL, "no-store"),
                        (WWW_AUTHENTICATE, hdr.as_str()),
                    ],
                    "",
                )
                    .into_response()
            }
        },
        guac::http::Authorization::Recover(handle) => {
            match st.moderator.recover(&st.store, &handle, now) {
                Ok(upd) => {
                    let cred_hdr = guac::http::CredentialField::Update(upd).to_string();
                    (
                        StatusCode::OK,
                        [
                            (CACHE_CONTROL, "no-store"),
                            (MOLE_CREDENTIAL_HEADER, cred_hdr.as_str()),
                        ],
                        "",
                    )
                        .into_response()
                }
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        guac::http::Authorization::Present(_) => json_error(
            StatusCode::BAD_REQUEST,
            "unexpected presentation on issue endpoint",
        ),
    }
}

async fn guac_protected_resource(State(st): State<Arc<GuacRoleServerState>>) -> Response {
    let now = unix_now().max(0) as u64;
    let p_chal = st
        .moderator
        .presentation_challenge(10, 0, b"GET /guac-protected", now)
        .unwrap();
    let r_chal = st.moderator.redemption_challenge(now).unwrap();
    let www = format!(
        "{}, {}",
        guac::http::Challenge::Present(p_chal),
        guac::http::Challenge::Redeem(r_chal)
    );
    (
        StatusCode::UNAUTHORIZED,
        [
            (CACHE_CONTROL, "no-store"),
            (WWW_AUTHENTICATE, www.as_str()),
        ],
        "{\"error\":\"mole challenge\"}",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Helper HTTPS Server 2: Thin cookie + `X-Guac-Grant` adapter around `prototalpid-anchor`
// so `guac-cli` (`guac endorsement request`) can run its full 2-step grant over HTTPS.
// ---------------------------------------------------------------------------

struct AnchorCliBridgeState {
    bridge_origin: String,
    anchor_origin: String,
    session_cookie: String,
    client: reqwest::Client,
}

async fn spawn_guac_cli_bridge_for_talpid_anchor(
    ca: &LocalCa,
    anchor_origin: String,
    session_cookie: String,
) -> prototalpid_http::server::SpawnedHttpsServer {
    let leaf = ca.issue_server_cert(&[]).unwrap();
    let client = ca.http_client().unwrap();
    spawn_https_router(
        "127.0.0.1:0".parse().unwrap(),
        leaf.server_config,
        None,
        move |bridge_origin| {
            let st = Arc::new(AnchorCliBridgeState {
                bridge_origin,
                anchor_origin,
                session_cookie,
                client,
            });
            Router::new()
                .route(
                    WELL_KNOWN_MOLE_ANCHOR,
                    get(|State(st): State<Arc<AnchorCliBridgeState>>| async move {
                        let mut cfg: AnchorConfiguration = st
                            .client
                            .get(format!("{}{WELL_KNOWN_MOLE_ANCHOR}", st.anchor_origin))
                            .send()
                            .await
                            .unwrap()
                            .json()
                            .await
                            .unwrap();
                        cfg.grant_uri = format!("{}{ANCHOR_GRANT_PATH}", st.bridge_origin);
                        json_no_store(StatusCode::OK, &cfg)
                    }),
                )
                .route(
                    ANCHOR_GRANT_PATH,
                    post(
                        |State(st): State<Arc<AnchorCliBridgeState>>,
                         headers: HeaderMap,
                         body: Bytes| async move {
                            let mut req = st
                                .client
                                .post(format!("{}{ANCHOR_GRANT_PATH}", st.anchor_origin))
                                .header(COOKIE, &st.session_cookie);
                            if let Some(ct) = headers.get(CONTENT_TYPE) {
                                req = req.header(CONTENT_TYPE, ct);
                            }
                            let upstream = req.body(body).send().await.unwrap();
                            let status = upstream.status();
                            let mut out_headers = HeaderMap::new();
                            if let Some(ct) = upstream.headers().get(CONTENT_TYPE) {
                                out_headers.insert(CONTENT_TYPE, ct.clone());
                            }
                            out_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                            out_headers.insert(
                                "x-guac-grant",
                                HeaderValue::from_static("talpid-anchor-session"),
                            );
                            let resp_bytes = upstream.bytes().await.unwrap();
                            (status, out_headers, resp_bytes).into_response()
                        },
                    ),
                )
                .with_state(st)
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_library_and_cli_interop_between_talpidian_and_guac() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = LocalCa::generate("MOLE Guac Interop Root CA").unwrap();
    let cacert_path = tmp.path().join("ca.pem");
    std::fs::write(&cacert_path, ca.cert_pem()).unwrap();
    let http_client = ca.http_client().unwrap();

    let epoch = b"2026-11-interop-epoch".to_vec();

    // 1. Spawn a real `prototalpid-anchor` server AND a real `guac::Anchor`+`guac::Moderator` HTTPS server
    let talpid_anchor_leaf = ca.issue_server_cert(&[]).unwrap();
    let talpid_anchor_store = Arc::new(AnchorStore::open(None, &epoch).unwrap());
    let talpid_anchor = spawn_anchor_server(
        "127.0.0.1:0".parse().unwrap(),
        talpid_anchor_leaf.server_config,
        talpid_anchor_store.clone(),
        AnchorRuntimeConfig {
            challenge_mode: ChallengeMode::Pow,
            pow_bits: 8,
            quota_per_challenge: 4,
            max_quota_per_session: 8,
            max_batch_size: 8,
            ..AnchorRuntimeConfig::default()
        },
        None,
    )
    .await
    .unwrap();

    let (mut guac_srv, guac_anchor_pk, guac_mod_last_err) =
        spawn_guac_roles_https_server(&ca, epoch.clone()).await;

    // 2. Spawn upstream origin + `prototalpid-moderator-proxy` trusting BOTH `prototalpid-anchor`
    //    AND `guac::Anchor`, with `hold_duration_secs = 0` (immediate update-0001) & `allow_no_endorsement = true`
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let (upstream_url, upstream_task) = spawn_upstream_origin(upstream_hits.clone()).await;

    let mod_leaf = ca.issue_server_cert(&[]).unwrap();
    let mod_store = Arc::new(
        ModeratorStore::open(
            None,
            8,
            b"interop-mod-ctx",
            300,
            vec![TrustedAnchorSet {
                issuance_epoch: epoch.clone(),
                public_keys: vec![talpid_anchor.public_key.clone(), guac_anchor_pk.clone()],
            }],
        )
        .unwrap(),
    );
    let mod_endorsed_only_leaf = ca.issue_server_cert(&[]).unwrap();
    let mod_endorsed_store = Arc::new(
        ModeratorStore::open(
            None,
            8,
            b"interop-endorsed-only",
            300,
            vec![TrustedAnchorSet {
                issuance_epoch: epoch.clone(),
                public_keys: vec![talpid_anchor.public_key.clone(), guac_anchor_pk.clone()],
            }],
        )
        .unwrap(),
    );

    let mod_open = spawn_moderator_proxy(
        "127.0.0.1:0".parse().unwrap(),
        mod_leaf.server_config,
        mod_store,
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url.clone(),
            policy: ModerationPolicy {
                initial_credits: 60,
                deposit_credits: 20,
                max_top_up: 0,
                hold_duration_secs: 0,
                rate_window_secs: 10,
                max_requests_per_window: 5,
                revoke_chain_on_flood: false,
                challenge_window_secs: 60,
                allow_no_endorsement: true,
            },
            maintenance_interval: Duration::from_millis(200),
        },
        None,
    )
    .await
    .unwrap();

    let mod_endorsed = spawn_moderator_proxy(
        "127.0.0.1:0".parse().unwrap(),
        mod_endorsed_only_leaf.server_config,
        mod_endorsed_store,
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url,
            policy: ModerationPolicy {
                initial_credits: 60,
                deposit_credits: 20,
                max_top_up: 0,
                hold_duration_secs: 0,
                rate_window_secs: 10,
                max_requests_per_window: 5,
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

    // =========================================================================
    // Flow 1: `prototalpid-cli` subprocess -> `guac::Anchor` HTTPS server ->
    //         redeems `guac::Anchor` endorsement on `prototalpid-moderator-proxy`!
    // =========================================================================
    let talpid_wallet_1 = tmp.path().join("talpid-from-guac-anchor.db");
    let endorse_from_guac = run_talpid_cli(
        &talpid_wallet_1,
        &cacert_path,
        &[
            "--mole-endorse",
            "--mole-batch-count",
            "2",
            &format!("{}/challenge", guac_srv.origin),
        ],
    );
    assert!(
        endorse_from_guac.status.success(),
        "prototalpid-cli failed acquiring endorsements from guac::Anchor: {}",
        String::from_utf8_lossy(&endorse_from_guac.stderr)
    );

    let st1: StoreStatus = serde_json::from_slice(
        &run_talpid_cli(&talpid_wallet_1, &cacert_path, &["--mole-status"]).stdout,
    )
    .unwrap();
    assert_eq!(st1.endorsements.len(), 1);
    assert_eq!(st1.endorsements[0].count, 2);

    // Redeem one of the `guac::Anchor`-minted endorsements on `mod_endorsed` (`allow_no_endorsement: false`)!
    let fetch_1 = run_talpid_cli(
        &talpid_wallet_1,
        &cacert_path,
        &[
            "-s",
            "-S",
            "-f",
            &format!("{}/from-guac-anchor", mod_endorsed.origin),
        ],
    );
    assert!(
        fetch_1.status.success(),
        "redeeming guac::Anchor endorsement failed: {}",
        String::from_utf8_lossy(&fetch_1.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&fetch_1.stdout),
        "origin-ok:/from-guac-anchor:hit=1"
    );

    // Also verify `prototalpid-cli` redeems via updated 32-byte `WWW-Authenticate: Mole redeem-0001`
    // against `mod_open` (`allow_no_endorsement: true`, fresh unendorsed wallet)!
    let unendorsed_wallet = tmp.path().join("talpid-no-endorsement.db");
    let fetch_no_end = run_talpid_cli(
        &unendorsed_wallet,
        &cacert_path,
        &[
            "-s",
            "-S",
            "-f",
            &format!("{}/unendorsed-ok", mod_open.origin),
        ],
    );
    assert!(
        fetch_no_end.status.success(),
        "unendorsed redeem-0001 flow failed: {}",
        String::from_utf8_lossy(&fetch_no_end.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&fetch_no_end.stdout),
        "origin-ok:/unendorsed-ok:hit=2"
    );

    // =========================================================================
    // Flow 2: `guac::Client` (library) -> live `prototalpid-anchor` HTTPS server
    // =========================================================================
    let wk_anchor: AnchorConfiguration = http_client
        .get(format!("{}{WELL_KNOWN_MOLE_ANCHOR}", talpid_anchor.origin))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let guac_anchor_cfg = guac::AnchorConfig::new(
        wk_anchor.anchor_key.as_slice().try_into().unwrap(),
        wk_anchor.issuance_epoch.clone(),
    )
    .unwrap();
    let cookie = solve_anchor_session_cookie(&http_client, &talpid_anchor.origin).await;

    let (g_req1, g_pend1) = guac::Client.start_grant(&guac_anchor_cfg, NonZeroU16::new(2).unwrap());
    let g_http1 = http_client
        .post(&wk_anchor.grant_uri)
        .header(COOKIE, &cookie)
        .header(CONTENT_TYPE, guac::http::ENDORSEMENT_REQUEST)
        .body(g_req1.to_bytes())
        .send()
        .await
        .unwrap();
    assert_eq!(g_http1.status(), StatusCode::OK);
    guac::http::check_content_type(
        g_http1
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        guac::http::ENDORSEMENT_RESPONSE,
    )
    .unwrap();
    let g_resp1 =
        guac::protocol::EndorsementResponse::from_bytes(&g_http1.bytes().await.unwrap()).unwrap();
    let guac::GrantStep::Continue {
        request: g_req2,
        pending: g_pend2,
    } = g_pend1.advance(&g_resp1).unwrap()
    else {
        panic!("expected GrantStep::Continue");
    };

    let g_http2 = http_client
        .post(&wk_anchor.grant_uri)
        .header(CONTENT_TYPE, guac::http::ENDORSEMENT_REQUEST)
        .body(g_req2.to_bytes())
        .send()
        .await
        .unwrap();
    assert_eq!(g_http2.status(), StatusCode::OK);
    let g_resp2 =
        guac::protocol::EndorsementResponse::from_bytes(&g_http2.bytes().await.unwrap()).unwrap();
    let guac::GrantStep::Complete(guac_endorsements) = g_pend2.advance(&g_resp2).unwrap() else {
        panic!("expected GrantStep::Complete");
    };
    assert_eq!(guac_endorsements.len(), 2);
    for ge in &guac_endorsements {
        assert!(
            guac::Endorsement::from_storage_bytes(&ge.to_storage_bytes(), &guac_anchor_cfg).is_ok()
        );
    }

    // =========================================================================
    // Flow 3: `guac` CLI binary (`guac-cli` + `curl`) <-> `prototalpid-anchor`
    //         and `prototalpid-moderator-proxy` over HTTPS (`CURL_CA_BUNDLE`)
    // =========================================================================
    let guac_home = tmp.path().join("guac-home");

    // 3a. `guac anchor add` directly discovers `prototalpid-anchor`'s `/.well-known/mole-anchor`
    let add_direct_anchor = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--json",
            "anchor",
            "add",
            "talpid-direct",
            &format!("{}{WELL_KNOWN_MOLE_ANCHOR}", talpid_anchor.origin),
        ],
    );
    assert!(
        add_direct_anchor.status.success(),
        "guac anchor add failed: {}",
        String::from_utf8_lossy(&add_direct_anchor.stderr)
    );
    // Direct `guac endorsement request` without an `anchor_session` cookie hits HTTP 401
    let direct_grant = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--no-input",
            "endorsement",
            "request",
            "--anchor",
            "talpid-direct",
            "--no-browser",
            "--count",
            "2",
        ],
    );
    assert!(!direct_grant.status.success());
    assert!(
        String::from_utf8_lossy(&direct_grant.stderr).contains("HTTP 401"),
        "expected HTTP 401 without anchor_session cookie, got: {}",
        String::from_utf8_lossy(&direct_grant.stderr)
    );

    // 3b. With pre-solved `anchor_session` cookie + `X-Guac-Grant` route header bridged around
    //     `prototalpid-anchor`, `guac endorsement request` completes the full 2-step batch grant!
    let bridge_cookie = solve_anchor_session_cookie(&http_client, &talpid_anchor.origin).await;
    let mut bridge_srv =
        spawn_guac_cli_bridge_for_talpid_anchor(&ca, talpid_anchor.origin.clone(), bridge_cookie)
            .await;

    let add_bridged = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--json",
            "anchor",
            "add",
            "talpid-bridged",
            &format!("{}{WELL_KNOWN_MOLE_ANCHOR}", bridge_srv.origin),
        ],
    );
    assert!(add_bridged.status.success());

    let bridged_grant = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--json",
            "--no-input",
            "endorsement",
            "request",
            "--anchor",
            "talpid-bridged",
            "--no-browser",
            "--count",
            "2",
        ],
    );
    assert!(
        bridged_grant.status.success(),
        "guac endorsement request failed: {}",
        String::from_utf8_lossy(&bridged_grant.stderr)
    );
    let grant_json: serde_json::Value = serde_json::from_slice(&bridged_grant.stdout).unwrap();
    let end_ids = grant_json["ids"].as_array().unwrap();
    assert_eq!(end_ids.len(), 2);

    // Import one of the endorsements stored by `guac` CLI in `guac.sqlite3` into `prototalpid-cli`
    // and redeem it live against `mod_endorsed`!
    let guac_db = Connection::open(guac_home.join("guac.sqlite3")).unwrap();
    let stored_secret: Vec<u8> = guac_db
        .query_row(
            "SELECT secret FROM endorsements WHERE id = ?1",
            [end_ids[0].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    let raw_end = unwrap_guac_secret_envelope(&stored_secret);
    let end_tok = ec_ihat::Endorsement::from_bytes(raw_end).unwrap();
    ec_ihat::verify(&talpid_anchor.public_key, &end_tok, &epoch, EC_IHAT_CTX_RED).unwrap();

    let imported_wallet_path = tmp.path().join("imported-from-guac-cli.db");
    {
        let w = WalletStore::open(Some(&imported_wallet_path)).unwrap();
        w.save_ec_ihat_endorsements(
            &talpid_anchor.origin,
            &talpid_anchor.public_key,
            &epoch,
            &[end_tok],
        )
        .unwrap();
    }
    let fetch_imported = run_talpid_cli(
        &imported_wallet_path,
        &cacert_path,
        &[
            "-s",
            "-S",
            "-f",
            &format!("{}/from-guac-cli-endorsement", mod_endorsed.origin),
        ],
    );
    assert!(
        fetch_imported.status.success(),
        "redeeming endorsement acquired by guac CLI failed: {}",
        String::from_utf8_lossy(&fetch_imported.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&fetch_imported.stdout),
        "origin-ok:/from-guac-cli-endorsement:hit=3"
    );

    // 3c. `guac moderator add` discovers `prototalpid-moderator-proxy`'s `/.well-known/mole-moderator`,
    //     and `guac credential issue` parses the 32-byte `redeem-0001` challenge, sends `RedeemAndIssue`,
    //     and hits the strict `EC-ACTv1` vs `ACTv1` proof verification boundary (HTTP 401)!
    let add_mod = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--json",
            "moderator",
            "add",
            "talpid-mod",
            &format!("{}{WELL_KNOWN_MOLE_MODERATOR}", mod_open.origin),
        ],
    );
    assert!(
        add_mod.status.success(),
        "guac moderator add failed: {}",
        String::from_utf8_lossy(&add_mod.stderr)
    );
    let mod_json: serde_json::Value = serde_json::from_slice(&add_mod.stdout).unwrap();
    assert_eq!(mod_json["directory"]["balance_width"], 8);
    assert_eq!(
        mod_json["directory"]["issuance_uri"],
        format!("{}{MODERATOR_ISSUE_PATH}", mod_open.origin)
    );

    let guac_issue = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--no-input",
            "credential",
            "issue",
            "--moderator",
            "talpid-mod",
            "--as",
            "talpid-cred",
        ],
    );
    // Exit status 75 (EXIT_PENDING): guac accepted our 32-byte `WWW-Authenticate: Mole redeem-0001`,
    // committed its pending issuance locally, sent `Authorization: Mole redeem-0001="", credential-request-0001="..."`,
    // and `prototalpid-moderator-proxy` rejected the `ACTv1` proof under `EC-ACTv1` with HTTP 401!
    assert_eq!(
        guac_issue.status.code(),
        Some(75),
        "expected guac EXIT_PENDING (75) after sending issuance request and receiving HTTP 401: {}",
        String::from_utf8_lossy(&guac_issue.stderr)
    );
    assert!(
        String::from_utf8_lossy(&guac_issue.stderr).contains("Moderator did not issue (HTTP 401)"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&guac_issue.stderr)
    );

    // 3d. Endorsed `guac credential issue` (`redeem-0002`) using the 2nd endorsement from `prototalpid-anchor`
    //     against `mod_endorsed` (`allow_no_endorsement: false`):
    assert!(
        run_guac_cli(
            &guac_home,
            &cacert_path,
            &[
                "moderator",
                "add",
                "talpid-mod-endorsed",
                &format!("{}{WELL_KNOWN_MOLE_MODERATOR}", mod_endorsed.origin),
            ],
        )
        .status
        .success()
    );
    let guac_issue_endorsed = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "--no-input",
            "credential",
            "issue",
            "--moderator",
            "talpid-mod-endorsed",
            "--endorsement",
            end_ids[1].as_str().unwrap(),
            "--as",
            "talpid-endorsed-cred",
        ],
    );
    assert_eq!(guac_issue_endorsed.status.code(), Some(75));
    assert!(
        String::from_utf8_lossy(&guac_issue_endorsed.stderr)
            .contains("Moderator did not issue (HTTP 401)")
    );

    // 3e. `guac curl` presentation flow against `prototalpid-moderator-proxy`:
    //     Issue a usable credential from `guac_srv` (matching `interop-mod-ctx`), then run `guac curl`
    //     against `mod_open` to verify `guac curl` parses `prototalpid-moderator-proxy`'s `401`
    //     `challenge-0001`, sends `Authorization: Mole presentation-0001="..."`, and `mod_open`
    //     rejects the foreign/ACTv1 presentation with zero upstream hits!
    let hits_before_guac_curl = upstream_hits.load(Ordering::SeqCst);
    assert!(
        run_guac_cli(
            &guac_home,
            &cacert_path,
            &[
                "moderator",
                "add",
                "guac-mod",
                &format!("{}{WELL_KNOWN_MOLE_MODERATOR}", guac_srv.origin),
            ],
        )
        .status
        .success()
    );
    assert!(
        run_guac_cli(
            &guac_home,
            &cacert_path,
            &[
                "--no-input",
                "credential",
                "issue",
                "--moderator",
                "guac-mod",
                "--as",
                "gcred",
            ],
        )
        .status
        .success()
    );
    let guac_curl_res = run_guac_cli(
        &guac_home,
        &cacert_path,
        &[
            "curl",
            "--credential",
            "gcred",
            "--",
            "--cacert",
            cacert_path.to_str().unwrap(),
            "-sS",
            &format!("{}/via-guac-curl", mod_open.origin),
        ],
    );
    assert_eq!(
        guac_curl_res.status.code(),
        Some(75),
        "guac curl should parse challenge-0001, send presentation-0001, and leave pending on 401: {}",
        String::from_utf8_lossy(&guac_curl_res.stderr)
    );
    assert!(
        String::from_utf8_lossy(&guac_curl_res.stderr)
            .contains("server answered HTTP 401 without a credential update")
    );
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        hits_before_guac_curl,
        "rejected guac curl presentation must never reach upstream"
    );

    let pendings_out = run_guac_cli(&guac_home, &cacert_path, &["--json", "pending", "list"]);
    assert!(pendings_out.status.success());
    let pendings_json: serde_json::Value = serde_json::from_slice(&pendings_out.stdout).unwrap();
    let pres_op_id = pendings_json
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["kind"] == "presentation" && p["credential"] == "gcred")
        .and_then(|p| p["id"].as_str())
        .expect("pending presentation recorded by guac curl");
    assert!(
        run_guac_cli(
            &guac_home,
            &cacert_path,
            &["--no-input", "pending", "forget", "--force", pres_op_id],
        )
        .status
        .success()
    );
    assert!(
        run_guac_cli(&guac_home, &cacert_path, &["--json", "status"])
            .status
            .success()
    );

    // =========================================================================
    // Flow 4: `prototalpid-cli` subprocess -> `guac::Moderator` HTTPS server
    //         discovers config, parses 32-byte `redeem-0001`, sends `EC-ACTv1`
    //         `RedeemAndIssue`, and `guac::Moderator` reports `Error::Credential`!
    // =========================================================================
    let probe_guac_mod_wallet = tmp.path().join("probe-guac-mod.db");
    let res_against_guac_mod = run_talpid_cli(
        &probe_guac_mod_wallet,
        &cacert_path,
        &["-s", "-f", &format!("{}/guac-protected", guac_srv.origin)],
    );
    assert_eq!(res_against_guac_mod.status.code(), Some(22));
    let recorded_err = guac_mod_last_err
        .lock()
        .unwrap()
        .clone()
        .expect("guac::Moderator must have received RedeemAndIssue from prototalpid-cli");
    assert!(
        recorded_err.starts_with("Credential("),
        "expected guac::Error::Credential on EC-ACTv1 vs ACTv1 skew, got: {recorded_err}"
    );

    bridge_srv.shutdown().await;
    mod_endorsed.shutdown().await;
    mod_open.shutdown().await;
    guac_srv.shutdown().await;
    talpid_anchor.shutdown().await;
    upstream_task.abort();
}
