//! HTTPS server for `prototalpid-anchor` (`axum` + `prototalpid_http::server`).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, StatusCode};
use rustls::ServerConfig;

use prototalpid_http::challenge::{AnchorChallengeSubmission, DEFAULT_ANCHOR_CHALLENGE_PATH};
use prototalpid_http::config::{AnchorConfiguration, WELL_KNOWN_MOLE_ANCHOR};
use prototalpid_http::schemes::{CIPHERSUITE_P256_SHA256, EndorsementType};
use prototalpid_http::server::{
    SpawnedHttpsServer, json_error, json_no_store, spawn_https_router,
};
use prototalpid_http::transport::{
    MoleChallenge, apply_expose_auth_headers, format_endorsement_response_content_type,
    has_want_endorsement_mole, parse_endorsement_request_content_type,
};
use prototalpid_http::wire::EcIhatGrantPost;

use crate::store::{AnchorStore, ChallengeMode, StoreError};

/// Cookie name storing Anchor trust-session tokens.
pub const ANCHOR_SESSION_COOKIE: &str = "anchor_session";

/// Grant endpoint path served by `prototalpid-anchor`.
pub const ANCHOR_GRANT_PATH: &str = "/mole/grant";

const MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;

/// Runtime configuration for an Anchor server instance.
#[derive(Clone, Debug)]
pub struct AnchorRuntimeConfig {
    /// Canonical HTTPS origin (`https://host:port`), without trailing slash.
    pub public_origin: String,
    /// Enabled challenge mode (`pow`, `prompt`, or `both`).
    pub challenge_mode: ChallengeMode,
    /// Leading zero bits required for PoW challenges.
    pub pow_bits: u8,
    /// Endorsements added per solved challenge.
    pub quota_per_challenge: u32,
    /// Maximum cumulative endorsements granted per session token.
    pub max_quota_per_session: u32,
    /// Maximum batch size granted in a single `/mole/grant` exchange.
    pub max_batch_size: u16,
    /// Challenge validity TTL in seconds.
    pub challenge_ttl_secs: u64,
    /// Session cookie TTL in seconds.
    pub session_ttl_secs: u64,
    /// Grant commitment/challenge correlation TTL in seconds.
    pub grant_ttl_secs: u64,
}

impl Default for AnchorRuntimeConfig {
    fn default() -> Self {
        Self {
            public_origin: "https://localhost:8443".to_owned(),
            challenge_mode: ChallengeMode::Both,
            pow_bits: 12,
            quota_per_challenge: 4,
            max_quota_per_session: 8,
            max_batch_size: 16,
            challenge_ttl_secs: 300,
            session_ttl_secs: 3600,
            grant_ttl_secs: 120,
        }
    }
}

/// Shared Anchor application state.
pub struct AnchorApp {
    /// Persistent store.
    pub store: Arc<AnchorStore>,
    /// Runtime settings.
    pub config: AnchorRuntimeConfig,
}

/// Handle to a spawned HTTPS Anchor server.
pub struct RunningAnchorServer {
    /// Bound socket address.
    pub local_addr: SocketAddr,
    /// Canonical HTTPS origin (`https://localhost:<port>`).
    pub origin: String,
    /// Anchor's EC-IHAT public key.
    pub public_key: ec_ihat::PublicKey,
    /// Underlying store handle.
    pub store: Arc<AnchorStore>,
    inner: SpawnedHttpsServer,
}

impl RunningAnchorServer {
    /// Signals graceful shutdown and awaits server task exit.
    pub async fn shutdown(mut self) {
        self.inner.shutdown().await;
    }
}

/// Binds and spawns an HTTPS `prototalpid-anchor` server.
///
/// If `public_origin_override` is `None`, `config.public_origin` is set to
/// `https://localhost:<bound_port>`.
pub async fn spawn_anchor_server(
    listen_addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    store: Arc<AnchorStore>,
    mut config: AnchorRuntimeConfig,
    public_origin_override: Option<String>,
) -> anyhow::Result<RunningAnchorServer> {
    let public_key = store.public_key().clone();
    let store_for_router = store.clone();
    let inner = spawn_https_router(listen_addr, tls_config, public_origin_override, |origin| {
        config.public_origin = origin;
        let app = Arc::new(AnchorApp {
            store: store_for_router,
            config,
        });
        Router::new()
            .route(WELL_KNOWN_MOLE_ANCHOR, get(handle_well_known))
            .route("/", get(handle_root))
            .route(
                DEFAULT_ANCHOR_CHALLENGE_PATH,
                get(handle_get_challenge).post(handle_post_challenge),
            )
            .route(ANCHOR_GRANT_PATH, post(handle_post_grant))
            .fallback(|| async { json_error(StatusCode::NOT_FOUND, "not found") })
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .with_state(app)
    })
    .await?;

    Ok(RunningAnchorServer {
        local_addr: inner.local_addr,
        origin: inner.origin.clone(),
        public_key,
        store,
        inner,
    })
}

async fn handle_well_known(State(app): State<Arc<AnchorApp>>) -> Response {
    let cfg = AnchorConfiguration {
        grant_uri: format!("{}{ANCHOR_GRANT_PATH}", app.config.public_origin),
        endorsement_type: EndorsementType::EC_IHAT.0,
        ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
        anchor_key: app.store.public_key().to_bytes().to_vec(),
        issuance_epoch: app.store.issuance_epoch().to_vec(),
    };
    json_no_store(StatusCode::OK, &cfg)
}

async fn handle_root(State(app): State<Arc<AnchorApp>>, headers: HeaderMap) -> Response {
    let quota = current_session_quota(&app, &headers);
    let mut resp = json_no_store(
        StatusCode::OK,
        &serde_json::json!({
            "service": "prototalpid-anchor",
            "challenge-uri": format!("{}{DEFAULT_ANCHOR_CHALLENGE_PATH}", app.config.public_origin),
            "grant-uri": format!("{}{ANCHOR_GRANT_PATH}", app.config.public_origin),
            "remaining-quota": quota,
        }),
    );
    if has_want_endorsement_mole(&headers) && quota > 0 {
        attach_endorse_header(resp.headers_mut());
    }
    resp
}

async fn handle_get_challenge(State(app): State<Arc<AnchorApp>>, headers: HeaderMap) -> Response {
    let quota = current_session_quota(&app, &headers);
    let Ok(offer) = app.store.create_challenge(
        app.config.challenge_mode,
        app.config.pow_bits,
        app.config.challenge_ttl_secs,
    ) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "challenge creation error");
    };
    let mut resp = json_no_store(StatusCode::OK, &offer);
    if has_want_endorsement_mole(&headers) && quota > 0 {
        attach_endorse_header(resp.headers_mut());
    }
    resp
}

async fn handle_post_challenge(
    State(app): State<Arc<AnchorApp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(submission) = serde_json::from_slice::<AnchorChallengeSubmission>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "malformed challenge submission JSON");
    };
    let existing_cookie = extract_cookie(&headers, ANCHOR_SESSION_COOKIE);

    match app.store.verify_challenge_and_issue_session(
        existing_cookie.as_deref(),
        &submission,
        app.config.quota_per_challenge,
        app.config.max_quota_per_session,
        app.config.session_ttl_secs,
    ) {
        Ok(solved) => {
            let cookie = Cookie::build((ANCHOR_SESSION_COOKIE, solved.session_token))
                .path("/")
                .max_age(Duration::seconds(
                    i64::try_from(app.config.session_ttl_secs).unwrap_or(3600),
                ))
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Lax)
                .to_string();
            let mut resp = json_no_store(StatusCode::OK, &solved.accepted);
            if let Ok(hv) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(SET_COOKIE, hv);
            }
            if has_want_endorsement_mole(&headers) || solved.accepted.remaining_quota > 0 {
                attach_endorse_header(resp.headers_mut());
            }
            resp
        }
        Err(StoreError::QuotaExhausted) => {
            json_error(StatusCode::TOO_MANY_REQUESTS, "endorsement session quota exhausted")
        }
        Err(StoreError::ChallengeFailed) => {
            json_error(StatusCode::FORBIDDEN, "challenge verification failed")
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal anchor error"),
    }
}

async fn handle_post_grant(
    State(app): State<Arc<AnchorApp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(endorsement_type) = parse_endorsement_request_content_type(&headers) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid or missing application/mole-endorsement-request Content-Type",
        );
    };
    if endorsement_type != EndorsementType::EC_IHAT {
        return json_error(StatusCode::BAD_REQUEST, "unsupported endorsement type");
    }
    let Ok(post) = EcIhatGrantPost::from_bytes(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "malformed EC-IHAT grant message");
    };
    let resp_ct = format_endorsement_response_content_type(EndorsementType::EC_IHAT).unwrap();

    let encoded = match post {
        EcIhatGrantPost::Request(grant_req) => {
            let Some(tok) = extract_cookie(&headers, ANCHOR_SESSION_COOKIE) else {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "anchor_session cookie required for GrantRequest",
                );
            };
            match app.store.begin_grant_batch(
                &tok,
                grant_req.count,
                app.config.max_batch_size,
                app.config.grant_ttl_secs,
            ) {
                Ok(commitments) => commitments.to_bytes(),
                Err(StoreError::Unauthorized) => {
                    return json_error(StatusCode::UNAUTHORIZED, "invalid or expired anchor_session");
                }
                Err(StoreError::QuotaExhausted) => {
                    return json_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "endorsement quota exhausted for anchor_session",
                    );
                }
                Err(StoreError::BadGrant(msg)) => return json_error(StatusCode::BAD_REQUEST, msg),
                Err(_) => {
                    return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal grant error");
                }
            }
        }
        EcIhatGrantPost::Challenges(grant_ch) => match app.store.complete_grant_batch(&grant_ch) {
            Ok(responses) => responses.to_bytes(),
            Err(StoreError::BadGrant(msg)) => return json_error(StatusCode::BAD_REQUEST, msg),
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "grant challenge rejected"),
        },
    };

    match encoded {
        Ok(bytes) => (
            StatusCode::OK,
            [(CONTENT_TYPE, resp_ct.as_str()), (CACHE_CONTROL, "no-store")],
            bytes,
        )
            .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "encoding error"),
    }
}

fn current_session_quota(app: &AnchorApp, headers: &HeaderMap) -> u32 {
    extract_cookie(headers, ANCHOR_SESSION_COOKIE)
        .and_then(|t| app.store.check_session_quota(&t).ok().flatten())
        .unwrap_or(0)
}

fn attach_endorse_header(headers: &mut HeaderMap) {
    if let Ok(val) = (MoleChallenge::Endorse {
        endorsement_type: EndorsementType::EC_IHAT,
        context: Vec::new(),
    })
    .to_header_value()
        && let Ok(hv) = HeaderValue::from_str(&val)
    {
        headers.insert(WWW_AUTHENTICATE, hv);
        apply_expose_auth_headers(headers);
    }
}

fn extract_cookie(headers: &HeaderMap, target_name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(Cookie::split_parse)
        .filter_map(Result::ok)
        .find(|c| c.name() == target_name && !c.value().is_empty())
        .map(|c| c.value().to_owned())
}
