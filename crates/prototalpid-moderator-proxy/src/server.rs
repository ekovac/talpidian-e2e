//! HTTPS Moderator reverse proxy server (`axum` + `prototalpid_http::server` + `reqwest`).

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Bytes, to_bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap,
    HeaderName, HeaderValue, TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
};
use http::request::Parts;
use http::{Method, StatusCode};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use url::Url;

use prototalpid_http::config::WELL_KNOWN_MOLE_MODERATOR;
use prototalpid_http::schemes::{CredentialType, EndorsementType};
use prototalpid_http::server::{SpawnedHttpsServer, json_error, json_no_store, spawn_https_router};
use prototalpid_http::tls::ensure_crypto_provider;
use prototalpid_http::transport::{
    MOLE_CREDENTIAL_HEADER, MOLE_SESSION_HEADER, MoleAuthorization, MoleChallenge,
    MoleCredentialHeader, apply_expose_auth_headers, apply_mole_credential_headers,
    format_www_authenticate, parse_mole_session, parse_www_authenticate_str,
};

use crate::store::{
    ModerationPolicy, ModeratorError, ModeratorStore, PresentationVerdict, SessionVerdict,
};

/// Redeem & Issue / Signoff / Recovery endpoint path served by `prototalpid-moderator-proxy`.
pub const MODERATOR_ISSUE_PATH: &str = "/mole/issue";

const MAX_PROXY_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROXY_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

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
    validate_upstream_origin(&config.upstream_origin)?;
    store.validate_policy(&config.policy)?;
    anyhow::ensure!(
        !config.maintenance_interval.is_zero(),
        "maintenance_interval must be greater than zero"
    );
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
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
    let request_binding =
        compute_request_binding(&Method::POST, MODERATOR_ISSUE_PATH, &headers, &[]);
    let auth = match MoleAuthorization::from_headers(&headers) {
        Ok(Some(a)) => a,
        Ok(None) => return challenge_401_response(&app, &request_binding),
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
            Err(ModeratorError::Unauthorized(_)) => challenge_401_response(&app, &request_binding),
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
            app.store
                .process_recovery(credential_type, &recovery_handle),
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
    let (parts, body) = req.into_parts();
    if matches!(parts.method, Method::CONNECT | Method::TRACE) {
        return json_error(StatusCode::METHOD_NOT_ALLOWED, "unsupported proxy method");
    }
    let Ok(body_bytes) = to_bytes(body, MAX_PROXY_BODY_BYTES).await else {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_owned();
    let request_binding =
        compute_request_binding(&parts.method, &path_and_query, &parts.headers, &body_bytes);

    let mole_auth = match MoleAuthorization::from_headers(&parts.headers) {
        Ok(a) => a,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "malformed Mole Authorization header",
            );
        }
    };
    let mole_session = match parse_mole_session(&parts.headers) {
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
            &request_binding,
            &app.config.policy,
            credential_type,
            &presentation,
        ) else {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "presentation error");
        };

        return match verdict {
            PresentationVerdict::Malformed(msg) => json_error(StatusCode::BAD_REQUEST, msg),
            PresentationVerdict::RejectedUnauthorized => {
                challenge_401_response(&app, &request_binding)
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
                let mut resp = forward_to_upstream(&app, parts, body_bytes, true).await;
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
            Ok(SessionVerdict::Allowed) => {
                forward_to_upstream(&app, parts, body_bytes, false).await
            }
            Ok(SessionVerdict::InvalidOrExpired | SessionVerdict::RateLimited) => {
                challenge_401_response(&app, &request_binding)
            }
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "session check error"),
        };
    }

    challenge_401_response(&app, &request_binding)
}

async fn forward_to_upstream(
    app: &ModeratorProxyApp,
    parts: Parts,
    body_bytes: Bytes,
    strip_authorization: bool,
) -> Response {
    let method = parts.method;
    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let target_url = format!(
        "{}{pq}",
        app.config.upstream_origin.as_str().trim_end_matches('/')
    );

    let mut out_headers = HeaderMap::new();
    copy_filtered_headers(&parts.headers, &mut out_headers, strip_authorization, true);

    let Ok(mut upstream_resp) = app
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
    let Ok(resp_body) =
        read_upstream_body_limited(&mut upstream_resp, MAX_PROXY_RESPONSE_BODY_BYTES).await
    else {
        return json_error(StatusCode::BAD_GATEWAY, "failed reading upstream response");
    };

    (status, resp_headers, resp_body).into_response()
}

async fn read_upstream_body_limited(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> anyhow::Result<Bytes> {
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= max_bytes as u64),
        "upstream response body too large"
    );
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(max_bytes),
    );
    while let Some(chunk) = response.chunk().await? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("upstream response body length overflow"))?;
        anyhow::ensure!(next_len <= max_bytes, "upstream response body too large");
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

fn copy_filtered_headers(
    src: &HeaderMap,
    dst: &mut HeaderMap,
    strip_authorization: bool,
    strip_host: bool,
) {
    let connection_nominated = connection_nominated_headers(src);

    for (name, val) in src {
        if name == MOLE_SESSION_HEADER
            || name == MOLE_CREDENTIAL_HEADER
            || is_hop_by_hop_header(name)
            || connection_nominated.contains(name.as_str())
            || (strip_authorization && name == AUTHORIZATION)
            || (strip_host && name == HOST)
            || (strip_host && is_untrusted_forwarding_header(name))
            || (!strip_host
                && name == WWW_AUTHENTICATE
                && val
                    .to_str()
                    .is_ok_and(|value| !parse_www_authenticate_str(value).is_empty()))
        {
            continue;
        }
        dst.append(name.clone(), val.clone());
    }
}

fn is_untrusted_forwarding_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "cf-connecting-ip"
            | "forwarded"
            | "proxy"
            | "true-client-ip"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}

fn validate_upstream_origin(origin: &Url) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(origin.scheme(), "http" | "https") && origin.has_host(),
        "upstream_origin must be an absolute HTTP(S) origin"
    );
    anyhow::ensure!(
        origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "upstream_origin must not contain userinfo, path, query, or fragment"
    );
    Ok(())
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == CONTENT_LENGTH
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || matches!(
            name.as_str(),
            "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "trailers"
        )
}

fn connection_nominated_headers(headers: &HeaderMap) -> BTreeSet<String> {
    let mut nominated = BTreeSet::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                nominated.insert(name.as_str().to_owned());
            }
        }
    }
    nominated
}

/// Computes the canonical digest bound into a protected request's EC-ACT challenge.
///
/// MOLE transport headers and hop-by-hop framing fields are excluded because they
/// necessarily differ between the unauthenticated request and its presentation retry.
/// All other end-to-end fields, including cookies, plus the complete body are bound.
pub fn compute_request_binding(
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> [u8; 32] {
    let mut excluded: BTreeSet<String> = [
        "authorization",
        "cf-connecting-ip",
        "connection",
        "content-length",
        "forwarded",
        "host",
        "keep-alive",
        "mole-credential",
        "mole-session",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "proxy",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "true-client-ip",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    excluded.extend(connection_nominated_headers(headers));

    let mut fields = Vec::new();
    let included_names: BTreeSet<&str> = headers
        .keys()
        .map(HeaderName::as_str)
        .filter(|name| !excluded.contains(*name))
        .collect();
    for name in included_names {
        for value in headers.get_all(name) {
            fields.push((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
    }

    let mut hash = Sha256::new();
    hash_request_field(&mut hash, b"MOLE-PROTECTED-REQUEST-v1");
    hash_request_field(&mut hash, method.as_str().as_bytes());
    hash_request_field(&mut hash, path_and_query.as_bytes());
    hash.update((fields.len() as u64).to_be_bytes());
    for (name, value) in fields {
        hash_request_field(&mut hash, &name);
        hash_request_field(&mut hash, &value);
    }
    hash_request_field(&mut hash, body);
    hash.finalize().into()
}

fn hash_request_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn challenge_401_response(app: &ModeratorProxyApp, request_binding: &[u8; 32]) -> Response {
    let act_chal = app.store.issue_ec_act_challenge(
        &app.config.public_origin,
        request_binding,
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::COOKIE;

    #[test]
    fn request_binding_covers_body_and_cookie() {
        let mut alice = HeaderMap::new();
        alice.insert(COOKIE, HeaderValue::from_static("account=alice"));
        let safe = compute_request_binding(&Method::POST, "/transfer", &alice, b"amount=1");

        assert_ne!(
            safe,
            compute_request_binding(&Method::POST, "/transfer", &alice, b"amount=1000")
        );

        let mut mallory = HeaderMap::new();
        mallory.insert(COOKIE, HeaderValue::from_static("account=mallory"));
        assert_ne!(
            safe,
            compute_request_binding(&Method::POST, "/transfer", &mallory, b"amount=1")
        );
    }

    #[test]
    fn request_binding_ignores_mole_retry_headers() {
        let base = compute_request_binding(&Method::GET, "/protected", &HeaderMap::new(), &[]);
        let mut retry = HeaderMap::new();
        retry.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Mole presentation-0001=\"test\""),
        );
        retry.insert(MOLE_SESSION_HEADER, HeaderValue::from_static(":dGVzdA=:"));
        assert_eq!(
            base,
            compute_request_binding(&Method::GET, "/protected", &retry, &[])
        );
    }

    #[test]
    fn connection_nominated_headers_are_neither_bound_nor_forwarded() {
        let removable = HeaderName::from_static("x-remove");
        let retained = HeaderName::from_static("x-retain");
        let mut first = HeaderMap::new();
        first.insert(CONNECTION, HeaderValue::from_static("Cookie, X-Remove"));
        first.insert(COOKIE, HeaderValue::from_static("account=alice"));
        first.insert(&removable, HeaderValue::from_static("first"));
        first.insert(&retained, HeaderValue::from_static("stable"));

        let mut second = first.clone();
        second.insert(COOKIE, HeaderValue::from_static("account=mallory"));
        second.insert(&removable, HeaderValue::from_static("second"));
        assert_eq!(
            compute_request_binding(&Method::GET, "/protected", &first, &[]),
            compute_request_binding(&Method::GET, "/protected", &second, &[]),
        );

        let mut forwarded = HeaderMap::new();
        copy_filtered_headers(&second, &mut forwarded, false, true);
        assert!(forwarded.get(CONNECTION).is_none());
        assert!(forwarded.get(COOKIE).is_none());
        assert!(forwarded.get(&removable).is_none());
        assert_eq!(forwarded.get(&retained).unwrap(), "stable");
    }

    #[test]
    fn request_binding_preserves_duplicate_value_order() {
        let repeated = HeaderName::from_static("x-repeated");
        let mut first = HeaderMap::new();
        first.append(&repeated, HeaderValue::from_static("first"));
        first.append(&repeated, HeaderValue::from_static("last"));

        let mut reversed = HeaderMap::new();
        reversed.append(&repeated, HeaderValue::from_static("last"));
        reversed.append(&repeated, HeaderValue::from_static("first"));

        assert_ne!(
            compute_request_binding(&Method::GET, "/protected", &first, &[]),
            compute_request_binding(&Method::GET, "/protected", &reversed, &[]),
        );
    }

    #[test]
    fn upstream_cannot_inject_mole_control_headers() {
        let mut upstream = HeaderMap::new();
        upstream.insert(
            MOLE_CREDENTIAL_HEADER,
            HeaderValue::from_static("update-0001=\"\""),
        );
        upstream.insert(
            MOLE_SESSION_HEADER,
            HeaderValue::from_static(":c3RvbGVuOg=:"),
        );
        upstream.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Mole challenge-0001=\"AA\""),
        );
        upstream.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"origin\""),
        );
        upstream.insert("set-cookie", HeaderValue::from_static("origin=ok; Secure"));

        let mut client_response = HeaderMap::new();
        copy_filtered_headers(&upstream, &mut client_response, false, false);
        assert!(client_response.get(MOLE_CREDENTIAL_HEADER).is_none());
        assert!(client_response.get(MOLE_SESSION_HEADER).is_none());
        assert_eq!(
            client_response
                .get_all(WWW_AUTHENTICATE)
                .iter()
                .collect::<Vec<_>>(),
            vec![&HeaderValue::from_static("Basic realm=\"origin\"")],
        );
        assert_eq!(
            client_response.get("set-cookie").unwrap(),
            "origin=ok; Secure"
        );
    }

    #[test]
    fn client_cannot_spoof_forwarding_identity_headers() {
        let mut client_request = HeaderMap::new();
        client_request.insert("forwarded", HeaderValue::from_static("for=192.0.2.1"));
        client_request.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        client_request.insert("x-real-ip", HeaderValue::from_static("192.0.2.1"));
        client_request.insert("x-application", HeaderValue::from_static("retained"));

        let mut upstream_request = HeaderMap::new();
        copy_filtered_headers(&client_request, &mut upstream_request, false, true);
        assert!(upstream_request.get("forwarded").is_none());
        assert!(upstream_request.get("x-forwarded-for").is_none());
        assert!(upstream_request.get("x-real-ip").is_none());
        assert_eq!(upstream_request.get("x-application").unwrap(), "retained");
    }

    #[test]
    fn upstream_configuration_must_be_an_origin() {
        assert!(validate_upstream_origin(&Url::parse("http://127.0.0.1:8080/").unwrap()).is_ok());
        for invalid in [
            "ftp://example.com/",
            "http://user@example.com/",
            "http://example.com/base",
            "http://example.com/?query",
        ] {
            assert!(validate_upstream_origin(&Url::parse(invalid).unwrap()).is_err());
        }
    }
}
