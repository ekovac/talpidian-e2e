//! HTTPS Moderator reverse proxy server (`axum` + `prototalpid_http::server` + `reqwest`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::StatusCode;
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName,
    HeaderValue, TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
};
use rustls::ServerConfig;
use url::Url;

use prototalpid_http::config::WELL_KNOWN_MOLE_MODERATOR;
use prototalpid_http::schemes::{CredentialType, EndorsementType};
use prototalpid_http::server::{
    SpawnedHttpsServer, json_error, json_no_store, spawn_https_router,
};
use prototalpid_http::tls::ensure_crypto_provider;
use prototalpid_http::transport::{
    MOLE_SESSION_HEADER, MoleAuthorization, MoleChallenge, MoleCredentialHeader,
    apply_expose_auth_headers, apply_mole_credential_headers, format_www_authenticate,
    parse_mole_session,
};

use crate::store::{
    ModerationPolicy, ModeratorError, ModeratorStore, PresentationVerdict, SessionVerdict,
};

/// Redeem & Issue / Signoff / Recovery endpoint path served by `prototalpid-moderator-proxy`.
pub const MODERATOR_ISSUE_PATH: &str = "/mole/issue";

const MAX_PROXY_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Runtime configuration for `prototalpid-moderator-proxy`.
#[derive(Clone, Debug)]
pub struct ModeratorProxyConfig {
    /// Canonical public HTTPS origin (`https://host:port`), without trailing slash.
    pub public_origin: String,
    /// Upstream HTTP origin URL (e.g. `http://127.0.0.1:9000`).
    pub upstream_origin: Url,
    /// Moderation & session-deposit rate-limiting policy.
    pub policy: ModerationPolicy,
    /// Background hold-expiry maintenance interval.
    pub maintenance_interval: Duration,
}

/// Shared Moderator proxy state.
pub struct ModeratorProxyApp {
    /// Persistent store & cryptographic engine.
    pub store: Arc<ModeratorStore>,
    /// Runtime configuration.
    pub config: ModeratorProxyConfig,
    /// Upstream HTTP client pool.
    http_client: reqwest::Client,
}

/// Handle to a running HTTPS `prototalpid-moderator-proxy` server.
pub struct RunningModeratorProxy {
    /// Bound socket address.
    pub local_addr: SocketAddr,
    /// Canonical HTTPS origin (`https://localhost:<port>`).
    pub origin: String,
    /// Underlying store handle.
    pub store: Arc<ModeratorStore>,
    inner: SpawnedHttpsServer,
    maint_handle: tokio::task::JoinHandle<()>,
}

impl RunningModeratorProxy {
    /// Signals graceful shutdown and awaits server + maintenance tasks.
    pub async fn shutdown(mut self) {
        self.maint_handle.abort();
        self.inner.shutdown().await;
    }
}

/// Binds and spawns an HTTPS `prototalpid-moderator-proxy` server alongside its
/// background hold-expiry finalization task.
pub async fn spawn_moderator_proxy(
    listen_addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    store: Arc<ModeratorStore>,
    mut config: ModeratorProxyConfig,
    public_origin_override: Option<String>,
) -> anyhow::Result<RunningModeratorProxy> {
    ensure_crypto_provider();
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let maint_interval = config.maintenance_interval;
    let maint_store = store.clone();
    let maint_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(maint_interval);
        loop {
            ticker.tick().await;
            let _ = maint_store.run_maintenance_tick();
        }
    });

    let store_for_router = store.clone();
    let inner = spawn_https_router(listen_addr, tls_config, public_origin_override, |origin| {
        config.public_origin = origin;
        let app = Arc::new(ModeratorProxyApp {
            store: store_for_router,
            config,
            http_client,
        });
        Router::new()
            .route(WELL_KNOWN_MOLE_MODERATOR, get(handle_well_known))
            .route(MODERATOR_ISSUE_PATH, post(handle_issue_endpoint))
            .fallback(handle_proxied_resource)
            .layer(DefaultBodyLimit::max(MAX_PROXY_BODY_BYTES))
            .with_state(app)
    })
    .await?;

    Ok(RunningModeratorProxy {
        local_addr: inner.local_addr,
        origin: inner.origin.clone(),
        store,
        inner,
        maint_handle,
    })
}

async fn handle_well_known(State(app): State<Arc<ModeratorProxyApp>>) -> Response {
    let issuance_uri = format!("{}{MODERATOR_ISSUE_PATH}", app.config.public_origin);
    match app
        .store
        .build_configuration(issuance_uri, app.config.policy.allow_no_endorsement)
    {
        Ok(cfg) => json_no_store(StatusCode::OK, &cfg),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to build moderator configuration",
        ),
    }
}

async fn handle_issue_endpoint(
    State(app): State<Arc<ModeratorProxyApp>>,
    headers: HeaderMap,
) -> Response {
    let auth = match MoleAuthorization::from_headers(&headers) {
        Ok(Some(a)) => a,
        Ok(None) => return challenge_401_response(&app, "POST", MODERATOR_ISSUE_PATH),
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "malformed Authorization header"),
    };

    match auth {
        MoleAuthorization::RedeemAndIssue {
            endorsement_type,
            redemption,
            credential_type,
            credential_request,
        } => match app.store.redeem_and_issue(
            &app.config.public_origin,
            &app.config.policy,
            endorsement_type,
            &redemption,
            credential_type,
            &credential_request,
        ) {
            Ok(cred_hdr) => empty_credential_response(StatusCode::OK, &cred_hdr),
            Err(ModeratorError::BadRequest(msg)) => json_error(StatusCode::BAD_REQUEST, msg),
            Err(ModeratorError::Forbidden(msg)) => json_error(StatusCode::FORBIDDEN, msg),
            Err(ModeratorError::Unauthorized(_)) => {
                challenge_401_response(&app, "POST", MODERATOR_ISSUE_PATH)
            }
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "issuance error"),
        },
        MoleAuthorization::Signoff {
            credential_type,
            recovery_handle,
        } => settle_response(
            app.store.process_signoff(credential_type, &recovery_handle),
            "signoff error",
        ),
        MoleAuthorization::Recovery {
            credential_type,
            recovery_handle,
        } => settle_response(
            app.store.process_recovery(credential_type, &recovery_handle),
            "recovery error",
        ),
        MoleAuthorization::Presentation { .. } => json_error(
            StatusCode::BAD_REQUEST,
            "Presentation must be sent to the protected resource, not /mole/issue",
        ),
    }
}

fn settle_response(
    result: Result<MoleCredentialHeader, ModeratorError>,
    internal_msg: &str,
) -> Response {
    match result {
        Ok(cred_hdr) => empty_credential_response(StatusCode::OK, &cred_hdr),
        Err(ModeratorError::BadRequest(msg)) => json_error(StatusCode::BAD_REQUEST, msg),
        Err(ModeratorError::NotFound) => {
            (StatusCode::NOT_FOUND, [(CACHE_CONTROL, "no-store")]).into_response()
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, internal_msg),
    }
}

fn empty_credential_response(status: StatusCode, cred_hdr: &MoleCredentialHeader) -> Response {
    let mut resp = status.into_response();
    let _ = apply_mole_credential_headers(resp.headers_mut(), cred_hdr);
    resp
}

async fn handle_proxied_resource(
    State(app): State<Arc<ModeratorProxyApp>>,
    req: Request,
) -> Response {
    let method_str = req.method().as_str().to_owned();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_owned();

    let mole_auth = match MoleAuthorization::from_headers(req.headers()) {
        Ok(a) => a,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "malformed Mole Authorization header",
            );
        }
    };
    let mole_session = match parse_mole_session(req.headers()) {
        Ok(s) => s,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "malformed Mole-Session header"),
    };

    if let Some(auth) = mole_auth {
        let MoleAuthorization::Presentation {
            credential_type,
            presentation,
        } = auth
        else {
            return json_error(
                StatusCode::BAD_REQUEST,
                "only presentation-T is allowed in Authorization on protected resources",
            );
        };

        let Ok(verdict) = app.store.process_presentation(
            &app.config.public_origin,
            &method_str,
            &path_and_query,
            &app.config.policy,
            credential_type,
            &presentation,
        ) else {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "presentation error");
        };

        return match verdict {
            PresentationVerdict::Malformed(msg) => json_error(StatusCode::BAD_REQUEST, msg),
            PresentationVerdict::RejectedUnauthorized => {
                challenge_401_response(&app, &method_str, &path_and_query)
            }
            PresentationVerdict::DuplicateRetained { mole_credential } => {
                // `draft-jms-mole-http-transport` §5.3 & §5.6: duplicate presentation returns 409
                // with the retained Mole-Credential and MUST NOT attempt the protected operation!
                empty_credential_response(StatusCode::CONFLICT, &mole_credential)
            }
            PresentationVerdict::AcceptedFresh {
                session_token,
                mole_credential,
            } => {
                let mut resp = forward_to_upstream(&app, req, true).await;
                if let Some(tok) = session_token
                    && let Ok(hv) = HeaderValue::from_str(&tok)
                {
                    resp.headers_mut().insert(MOLE_SESSION_HEADER, hv);
                }
                let _ = apply_mole_credential_headers(resp.headers_mut(), &mole_credential);
                resp
            }
        };
    }

    if let Some(tok) = mole_session {
        return match app
            .store
            .check_and_record_session_request(&tok, &app.config.policy)
        {
            Ok(SessionVerdict::Allowed) => forward_to_upstream(&app, req, false).await,
            Ok(SessionVerdict::InvalidOrExpired | SessionVerdict::RateLimited) => {
                challenge_401_response(&app, &method_str, &path_and_query)
            }
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "session check error"),
        };
    }

    challenge_401_response(&app, &method_str, &path_and_query)
}

async fn forward_to_upstream(
    app: &ModeratorProxyApp,
    req: Request,
    strip_authorization: bool,
) -> Response {
    let method = req.method().clone();
    let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let target_url = format!("{}{pq}", app.config.upstream_origin.as_str().trim_end_matches('/'));

    let mut out_headers = HeaderMap::new();
    copy_filtered_headers(req.headers(), &mut out_headers, strip_authorization, true);

    let Ok(body_bytes) = to_bytes(req.into_body(), MAX_PROXY_BODY_BYTES).await else {
        return json_error(StatusCode::BAD_REQUEST, "request body too large");
    };

    let Ok(upstream_resp) = app
        .http_client
        .request(method, target_url)
        .headers(out_headers)
        .body(body_bytes)
        .send()
        .await
    else {
        return json_error(StatusCode::BAD_GATEWAY, "upstream origin unreachable");
    };

    let status = upstream_resp.status();
    let mut resp_headers = HeaderMap::new();
    copy_filtered_headers(upstream_resp.headers(), &mut resp_headers, false, false);
    let Ok(resp_body) = upstream_resp.bytes().await else {
        return json_error(StatusCode::BAD_GATEWAY, "failed reading upstream response");
    };

    (status, resp_headers, resp_body).into_response()
}

fn copy_filtered_headers(
    src: &HeaderMap,
    dst: &mut HeaderMap,
    strip_authorization: bool,
    strip_host: bool,
) {
    const HOP_BY_HOP: [HeaderName; 5] = [
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-authenticate"),
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("te"),
        HeaderName::from_static("trailers"),
    ];

    for (name, val) in src {
        if name == MOLE_SESSION_HEADER
            || name == CONNECTION
            || name == TRANSFER_ENCODING
            || name == UPGRADE
            || HOP_BY_HOP.contains(name)
            || (strip_authorization && name == AUTHORIZATION)
            || (strip_host && name == HOST)
        {
            continue;
        }
        dst.append(name.clone(), val.clone());
    }
}

fn challenge_401_response(
    app: &ModeratorProxyApp,
    method: &str,
    path_and_query: &str,
) -> Response {
    let act_chal = app.store.issue_ec_act_challenge(
        &app.config.public_origin,
        method,
        path_and_query,
        &app.config.policy,
    );
    let red_chal = app
        .store
        .issue_redemption_challenge(&app.config.public_origin, &app.config.policy);

    let mut challenges = vec![
        MoleChallenge::Credential {
            credential_type: CredentialType::EC_ACT,
            challenge: act_chal.to_bytes().unwrap_or_default(),
        },
        MoleChallenge::Redeem {
            endorsement_type: EndorsementType::EC_IHAT,
            challenge: red_chal.to_bytes().to_vec(),
        },
    ];
    if app.config.policy.allow_no_endorsement {
        challenges.push(MoleChallenge::Redeem {
            endorsement_type: EndorsementType::NO_ENDORSEMENT,
            challenge: Vec::new(),
        });
    }

    let www_auth = format_www_authenticate(&challenges).unwrap_or_default();
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "no-store"),
            (WWW_AUTHENTICATE, www_auth.as_str()),
        ],
        "{\"error\":\"MOLE session or credential presentation required\"}",
    )
        .into_response();
    apply_expose_auth_headers(resp.headers_mut());
    resp
}
