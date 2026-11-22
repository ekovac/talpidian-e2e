//! MOLE-aware HTTP/HTTPS client engine (`prototalpid-cli`).
//!
//! Implements:
//! - Anchor challenge solving (PoW or interactive prompt) & 2-step batched EC-IHAT grants
//! - `.well-known` Moderator discovery & Anchor Set redemption matching
//! - `Mole-Session` attachment, proactive pre-expiry `signoff-0001`, post-expiry `recovery-0001`,
//!   and automatic early-`401` signoff-then-re-present moderation settlement

use std::io::{self, Write};
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::{Bytes, BytesMut};
use http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, HeaderMap, HeaderValue, LOCATION,
    PROXY_AUTHORIZATION, SET_COOKIE, TRANSFER_ENCODING,
};
use http::{Method, StatusCode};
use url::{Position, Url};

use prototalpid_http::challenge::{
    AnchorChallengeOffer, AnchorChallengeSubmission, DEFAULT_ANCHOR_CHALLENGE_PATH, solve_pow,
};
use prototalpid_http::config::{
    AnchorConfiguration, ModeratorConfiguration, SupportedModeratorEndorsement, ValidatedEcActKey,
    anchor_well_known_url, canonical_https_origin, moderator_well_known_url,
};
use prototalpid_http::schemes::{CredentialType, EC_IHAT_CTX_RED, EndorsementType};
use prototalpid_http::transport::{
    MOLE_CREDENTIAL_HEADER, MOLE_SESSION_HEADER, MoleAuthorization, MoleChallenge,
    MoleCredentialHeader, WANT_ENDORSEMENT_HEADER, format_endorsement_request_content_type,
    parse_endorsement_response_content_type, parse_mole_session, parse_www_authenticate_headers,
};
use prototalpid_http::unix_now;
use prototalpid_http::wire::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    GrantChallenges, GrantCommitments, GrantRequest, GrantResponses, RedemptionChallenge,
};

use crate::store::{PendingSpendRecord, PendingSpendState, UsableCredential, WalletStore};

const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Options controlling a [`MoleClient`] instance.
#[derive(Clone)]
pub struct MoleClientOptions {
    /// Non-redirecting HTTP/HTTPS client (`reqwest::Client`).
    pub http_client: reqwest::Client,
    /// Disable all MOLE headers and `401` challenge handling (`--mole-disable`).
    pub mole_disabled: bool,
    /// Emit `curl -v`-style HTTP + MOLE state trace to `stderr`.
    pub verbose: bool,
    /// Follow HTTP `3xx` redirects on user requests (`-L`).
    pub follow_redirects: bool,
    /// Maximum redirects to follow when `follow_redirects` is true.
    pub max_redirects: usize,
    /// Optional literal `Cookie` override string (`-b name=val`).
    pub explicit_cookie_header: Option<String>,
    /// Optional pre-supplied prompt answer for non-TTY tests.
    pub prompt_answer_override: Option<String>,
    /// Lead time in seconds before `held_until` at which the Client proactively sends `signoff-0001`.
    pub proactive_signoff_lead_secs: i64,
}

impl MoleClientOptions {
    /// Creates default options with the provided `http_client`.
    pub fn new(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            mole_disabled: false,
            verbose: false,
            follow_redirects: false,
            max_redirects: 10,
            explicit_cookie_header: None,
            prompt_answer_override: None,
            proactive_signoff_lead_secs: 1,
        }
    }
}

/// Completed HTTP response returned by [`MoleClient`].
#[derive(Clone, Debug)]
pub struct HttpResponseData {
    /// Final HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body bytes.
    pub body: Bytes,
    /// Effective final URL (after any redirects).
    pub effective_url: Url,
}

/// Stateful MOLE HTTP/HTTPS client backed by [`WalletStore`].
pub struct MoleClient {
    store: Arc<WalletStore>,
    opts: MoleClientOptions,
}

/// Material needed to prove and durably commit one challenged EC-ACT spend.
struct SpendCredential {
    issuance_url: Url,
    active_key: ValidatedEcActKey,
    usable: UsableCredential,
}

/// End-to-end request material frozen across the unauthenticated attempt and retry.
struct FrozenRequest<'a> {
    method: &'a Method,
    url: &'a Url,
    headers: HeaderMap,
    body: &'a Bytes,
}

impl MoleClient {
    /// Creates a new `MoleClient`.
    pub fn new(store: Arc<WalletStore>, opts: MoleClientOptions) -> Self {
        Self { store, opts }
    }

    /// Accesses the underlying [`WalletStore`].
    pub fn store(&self) -> &Arc<WalletStore> {
        &self.store
    }

    fn vlog(&self, msg: impl AsRef<str>) {
        if self.opts.verbose {
            eprintln!("* {}", msg.as_ref());
        }
    }

    // -----------------------------------------------------------------------
    // 1. Anchor Endorsement Acquisition (`--mole-endorse`)
    // -----------------------------------------------------------------------

    /// Solves an Anchor trust challenge (if needed) and runs a 2-step batched EC-IHAT
    /// grant at `anchor_url`, returning the number of finalized Endorsements stored.
    pub async fn acquire_endorsements(
        &self,
        anchor_url: &Url,
        batch_count: u16,
    ) -> anyhow::Result<usize> {
        if anchor_url.scheme() != "https" {
            bail!("MOLE Anchor exchanges require https:// URLs");
        }
        if batch_count == 0 {
            bail!("batch_count must be >= 1");
        }
        let anchor_origin = canonical_https_origin(anchor_url)?;

        // 1. Fetch /.well-known/mole-anchor
        let wk_url = anchor_well_known_url(anchor_url)?;
        self.vlog(format!("MOLE: discovering Anchor config at {wk_url}"));
        let wk_resp = self
            .raw_send(&Method::GET, &wk_url, HeaderMap::new(), Bytes::new(), true)
            .await?;
        if !wk_resp.status.is_success() {
            bail!(
                "Anchor well-known discovery failed with HTTP {}",
                wk_resp.status
            );
        }
        let anchor_cfg: AnchorConfiguration =
            serde_json::from_slice(&wk_resp.body).context("invalid AnchorConfiguration JSON")?;
        let (grant_url, pk_a) = anchor_cfg.validate_ec_ihat()?;
        self.store.save_anchor_config(&anchor_origin, &anchor_cfg)?;

        // 2. Check if we already hold a valid anchor_session with endorsement quota
        let ch_path = if anchor_url.path() == "/" || anchor_url.path().is_empty() {
            DEFAULT_ANCHOR_CHALLENGE_PATH
        } else {
            anchor_url.path()
        };
        let ch_url = anchor_url.join(ch_path)?;

        let mut probe_headers = HeaderMap::new();
        probe_headers.insert(WANT_ENDORSEMENT_HEADER, HeaderValue::from_static("Mole"));
        let ch_get = self
            .raw_send(&Method::GET, &ch_url, probe_headers, Bytes::new(), true)
            .await?;
        if ch_get.status == StatusCode::TOO_MANY_REQUESTS {
            bail!("Anchor rate-limited endorsement acquisition (HTTP 429)");
        }
        if !ch_get.status.is_success() {
            bail!("Anchor challenge endpoint returned HTTP {}", ch_get.status);
        }

        let already_endorsed = parse_www_authenticate_headers(&ch_get.headers)
            .iter()
            .any(|c| {
                matches!(
                    c,
                    MoleChallenge::Endorse {
                        endorsement_type: EndorsementType::EC_IHAT,
                        ..
                    }
                )
            });

        if !already_endorsed {
            let offer: AnchorChallengeOffer = serde_json::from_slice(&ch_get.body)
                .context("expected AnchorChallengeOffer JSON from Anchor")?;
            let submission = self.solve_anchor_offer(&offer)?;
            let mut post_headers = HeaderMap::new();
            post_headers.insert(WANT_ENDORSEMENT_HEADER, HeaderValue::from_static("Mole"));
            post_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let post_body = Bytes::from(serde_json::to_vec(&submission)?);
            let ch_post = self
                .raw_send(&Method::POST, &ch_url, post_headers, post_body, true)
                .await?;
            if ch_post.status == StatusCode::TOO_MANY_REQUESTS {
                bail!("Anchor endorsement quota exhausted (HTTP 429)");
            }
            if !ch_post.status.is_success() {
                bail!(
                    "Anchor challenge verification failed with HTTP {}",
                    ch_post.status
                );
            }
        }

        // 3. Step 1 Grant POST (never follow redirects on stateful grant POSTs!)
        let req_ct = format_endorsement_request_content_type(EndorsementType::EC_IHAT)?;
        let mut g1_headers = HeaderMap::new();
        g1_headers.insert(CONTENT_TYPE, HeaderValue::from_str(&req_ct)?);
        let g1_body = Bytes::copy_from_slice(&GrantRequest { count: batch_count }.to_bytes()?);
        self.vlog(format!(
            "MOLE: sending GrantRequest(count={batch_count}) to {grant_url}"
        ));
        let g1_resp = self
            .raw_send(&Method::POST, &grant_url, g1_headers, g1_body, true)
            .await?;
        if g1_resp.status == StatusCode::TOO_MANY_REQUESTS {
            bail!("Anchor grant quota exhausted (HTTP 429)");
        }
        if g1_resp.status != StatusCode::OK {
            bail!("Anchor GrantRequest failed with HTTP {}", g1_resp.status);
        }
        if parse_endorsement_response_content_type(&g1_resp.headers)? != EndorsementType::EC_IHAT {
            bail!("Anchor returned mismatched grant media type");
        }

        let grant_commitments = GrantCommitments::from_bytes(&g1_resp.body)?;
        if grant_commitments.commitments.len() > usize::from(batch_count) {
            bail!("Anchor returned more commitments than requested");
        }

        // 4. Blind challenges + Step 2 Grant POST
        let (client_states, challenges): (Vec<_>, Vec<_>) = grant_commitments
            .commitments
            .iter()
            .map(|com| {
                ec_ihat::challenge(&pk_a, &anchor_cfg.issuance_epoch, EC_IHAT_CTX_RED, com)
                    .map_err(|e| anyhow::anyhow!("ec_ihat::challenge failed: {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .unzip();

        let g2_payload = GrantChallenges {
            session_id: grant_commitments.session_id,
            challenges,
        }
        .to_bytes()?;
        let mut g2_headers = HeaderMap::new();
        g2_headers.insert(CONTENT_TYPE, HeaderValue::from_str(&req_ct)?);
        let g2_resp = self
            .raw_send(
                &Method::POST,
                &grant_url,
                g2_headers,
                Bytes::from(g2_payload),
                true,
            )
            .await?;
        if g2_resp.status != StatusCode::OK {
            bail!("Anchor GrantChallenges failed with HTTP {}", g2_resp.status);
        }
        if parse_endorsement_response_content_type(&g2_resp.headers)? != EndorsementType::EC_IHAT {
            bail!("Anchor Step 2 returned mismatched grant media type");
        }

        let grant_responses = GrantResponses::from_bytes(&g2_resp.body)?;
        if grant_responses.responses.len() != client_states.len() {
            bail!("Anchor GrantResponses count mismatch; discarding batch");
        }

        let finalized = client_states
            .into_iter()
            .zip(&grant_responses.responses)
            .map(|(st, resp)| {
                ec_ihat::finalize(&pk_a, st, resp).map_err(|e| {
                    anyhow::anyhow!("ec_ihat::finalize failed (discarding batch): {e}")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let count = finalized.len();
        self.store.save_ec_ihat_endorsements(
            &anchor_origin,
            &pk_a,
            &anchor_cfg.issuance_epoch,
            &finalized,
        )?;
        self.vlog(format!(
            "MOLE: stored {count} EC-IHAT Endorsements from {anchor_origin}"
        ));
        Ok(count)
    }

    fn solve_anchor_offer(
        &self,
        offer: &AnchorChallengeOffer,
    ) -> anyhow::Result<AnchorChallengeSubmission> {
        if let (Some(ans), Some(_)) = (&self.opts.prompt_answer_override, &offer.prompt) {
            self.vlog("MOLE: answering Anchor prompt challenge");
            return Ok(AnchorChallengeSubmission {
                challenge_id: offer.challenge_id.clone(),
                pow_nonce: None,
                prompt_answer: Some(ans.clone()),
            });
        }

        if let Some(ref pow) = offer.pow {
            self.vlog(format!(
                "MOLE: solving {}-bit Anchor Proof-of-Work puzzle...",
                pow.bits
            ));
            let nonce = solve_pow(&offer.challenge_id, &pow.prefix, pow.bits)
                .context("failed to find PoW solution")?;
            return Ok(AnchorChallengeSubmission {
                challenge_id: offer.challenge_id.clone(),
                pow_nonce: Some(nonce),
                prompt_answer: None,
            });
        }

        if let Some(ref prompt) = offer.prompt {
            eprint!("[Anchor Challenge] {} ", prompt.question);
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            return Ok(AnchorChallengeSubmission {
                challenge_id: offer.challenge_id.clone(),
                pow_nonce: None,
                prompt_answer: Some(line.trim().to_owned()),
            });
        }

        bail!("Anchor offered no supported challenge mode")
    }

    // -----------------------------------------------------------------------
    // 2. Explicit Signoff & Recovery Helpers
    // -----------------------------------------------------------------------

    /// Explicitly sends `signoff-0001` (or `recovery-0001` if already past `held_until`)
    /// for `moderator_origin`, settling any held/pending credential.
    pub async fn signoff_origin(&self, moderator_origin: &str) -> anyhow::Result<bool> {
        let Some(pending) = self.store.get_pending_spend(moderator_origin)? else {
            return Ok(false);
        };
        if pending.state == PendingSpendState::Held
            && pending.held_until.is_some_and(|u| unix_now() >= u)
        {
            let _ = self.send_recovery(&pending).await?;
        } else {
            self.send_signoff(&pending).await?;
        }
        Ok(true)
    }

    /// Signs off all currently held/pending Moderator origins (used by `--mole-signoff-on-exit`).
    pub async fn signoff_all_held(&self) -> anyhow::Result<()> {
        for origin in self.store.list_pending_origins()? {
            let _ = self.signoff_origin(&origin).await?;
        }
        Ok(())
    }

    async fn send_signoff(&self, pending: &PendingSpendRecord) -> anyhow::Result<()> {
        let _ = self.send_handle_settlement(pending, true).await?;
        Ok(())
    }

    async fn send_recovery(&self, pending: &PendingSpendRecord) -> anyhow::Result<bool> {
        self.send_handle_settlement(pending, false).await
    }

    async fn send_handle_settlement(
        &self,
        pending: &PendingSpendRecord,
        is_signoff: bool,
    ) -> anyhow::Result<bool> {
        let issue_url = Url::parse(&pending.issuance_uri)?;
        let recovery_handle = pending.recovery_handle.to_bytes().to_vec();
        let (label, auth) = if is_signoff {
            (
                "signoff",
                MoleAuthorization::Signoff {
                    credential_type: pending.credential_type,
                    recovery_handle,
                },
            )
        } else {
            (
                "recovery",
                MoleAuthorization::Recovery {
                    credential_type: pending.credential_type,
                    recovery_handle,
                },
            )
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth.to_header_value()?)?,
        );
        self.vlog(format!(
            "MOLE: sending {label}-0001 to {}",
            pending.issuance_uri
        ));
        let resp = self
            .raw_send(&Method::POST, &issue_url, headers, Bytes::new(), false)
            .await?;

        if let Some(MoleCredentialHeader::Update { update, .. }) =
            MoleCredentialHeader::from_headers(&resp.headers)?
        {
            let new_bal = self
                .store
                .settle_pending_spend_with_update(&pending.moderator_origin, update.as_deref())?;
            self.vlog(format!(
                "MOLE: {label} settled for {} -> new balance: {:?}",
                pending.moderator_origin, new_bal
            ));
            return Ok(true);
        }
        if is_signoff && resp.status == StatusCode::NOT_FOUND {
            self.vlog(format!(
                "MOLE: signoff returned 404 for {}; discarding expired spend state",
                pending.moderator_origin
            ));
            self.store
                .discard_pending_spend(&pending.moderator_origin)?;
        }
        Ok(false)
    }

    // -----------------------------------------------------------------------
    // 3. Main Request Execution (`execute_request`)
    // -----------------------------------------------------------------------

    /// Executes an HTTP/HTTPS request with optional redirects and full MOLE session /
    /// challenge / redemption / presentation / signoff / recovery handling.
    pub async fn execute_request(
        &self,
        initial_method: Method,
        initial_url: Url,
        user_headers: HeaderMap,
        initial_body: Bytes,
    ) -> anyhow::Result<HttpResponseData> {
        let mut method = initial_method;
        let mut url = initial_url;
        let mut body = initial_body;
        let mut redirects = 0usize;
        let initial_origin = url.origin();
        let mut redirect_cleared_body = false;

        loop {
            let same_origin = url.origin() == initial_origin;
            let hop_headers = redirect_headers(&user_headers, same_origin, redirect_cleared_body);
            let resp = self
                .execute_single_hop(&method, &url, &hop_headers, &body, same_origin)
                .await?;

            if self.opts.follow_redirects
                && resp.status.is_redirection()
                && let Some(loc_val) = resp.headers.get(LOCATION)
                && let Ok(loc_str) = loc_val.to_str()
            {
                if redirects >= self.opts.max_redirects {
                    bail!("maximum redirects ({}) exceeded", self.opts.max_redirects);
                }
                let next_url = url.join(loc_str)?;
                let rewrite_to_get = (resp.status == StatusCode::SEE_OTHER
                    && method != Method::HEAD)
                    || (matches!(
                        resp.status,
                        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                    ) && method == Method::POST);
                if rewrite_to_get {
                    method = Method::GET;
                    body = Bytes::new();
                    redirect_cleared_body = true;
                }
                url = next_url;
                redirects += 1;
                continue;
            }

            return Ok(resp);
        }
    }

    async fn execute_single_hop(
        &self,
        method: &Method,
        url: &Url,
        user_headers: &HeaderMap,
        body: &Bytes,
        include_explicit_cookie: bool,
    ) -> anyhow::Result<HttpResponseData> {
        if self.opts.mole_disabled || url.scheme() != "https" {
            let headers =
                self.headers_with_cookies(url, user_headers.clone(), include_explicit_cookie)?;
            return self
                .raw_send(method, url, headers, body.clone(), false)
                .await;
        }

        let moderator_origin = canonical_https_origin(url)?;

        // Step 1: Reconcile durable spend state before attaching any active session.
        let attached_session_token = self.prepare_pending_session(&moderator_origin).await?;

        // Step 2: Freeze the end-to-end request headers for the challenge/presentation pair.
        // In particular, discovery or issuance responses between the two attempts must not
        // change the Cookie field that the Moderator bound into the challenge.
        let base_headers =
            self.headers_with_cookies(url, user_headers.clone(), include_explicit_cookie)?;
        let mut req_headers = base_headers.clone();
        if let Some(ref tok) = attached_session_token {
            self.vlog("MOLE: attaching active Mole-Session header");
            req_headers.insert(MOLE_SESSION_HEADER, HeaderValue::from_str(tok)?);
        }

        let initial_resp = self
            .raw_send(method, url, req_headers, body.clone(), false)
            .await?;

        self.process_response_mole_credential(&moderator_origin, &initial_resp.headers)?;

        if initial_resp.status != StatusCode::UNAUTHORIZED {
            return Ok(initial_resp);
        }

        // Step 3: Received 401! Check if it carries Mole challenges.
        let challenges = parse_www_authenticate_headers(&initial_resp.headers);
        if challenges.is_empty() {
            return Ok(initial_resp);
        }

        self.settle_pending_after_challenge(&moderator_origin)
            .await?;

        let Some(act_chal_raw) = challenges.iter().find_map(|c| match c {
            MoleChallenge::Credential {
                credential_type: CredentialType::EC_ACT,
                challenge,
            } => Some(challenge.clone()),
            _ => None,
        }) else {
            return Ok(initial_resp);
        };
        let act_chal = EcActChallenge::from_bytes(&act_chal_raw)?;

        let Some(spend_credential) = self
            .obtain_spend_credential(
                url,
                &moderator_origin,
                &act_chal,
                &challenges,
                include_explicit_cookie,
            )
            .await?
        else {
            return Ok(initial_resp);
        };

        // Step 4: ProveSpend, durably commit `in_flight`, and retry the frozen request.
        self.present_credential(
            FrozenRequest {
                method,
                url,
                headers: base_headers,
                body,
            },
            &moderator_origin,
            &act_chal,
            spend_credential,
        )
        .await
    }

    async fn prepare_pending_session(
        &self,
        moderator_origin: &str,
    ) -> anyhow::Result<Option<String>> {
        let Some(pending) = self.store.get_pending_spend(moderator_origin)? else {
            return Ok(None);
        };

        let now = unix_now();
        match pending.state {
            PendingSpendState::InFlight => {
                self.vlog(format!(
                    "MOLE: found interrupted in_flight spend for {moderator_origin}; recovering..."
                ));
                if !self.send_recovery(&pending).await? {
                    self.send_signoff(&pending).await?;
                }
                Ok(None)
            }
            PendingSpendState::Held => {
                let held_until = pending.held_until.unwrap_or(0);
                if now >= held_until {
                    self.vlog(format!(
                        "MOLE: hold expired for {moderator_origin}; sending recovery-0001"
                    ));
                    if !self.send_recovery(&pending).await? {
                        self.store.discard_pending_spend(moderator_origin)?;
                    }
                    Ok(None)
                } else if held_until - now <= self.opts.proactive_signoff_lead_secs {
                    self.vlog(format!(
                        "MOLE: hold near expiry for {moderator_origin}; proactively sending signoff-0001"
                    ));
                    self.send_signoff(&pending).await?;
                    Ok(None)
                } else {
                    Ok(pending.session_token)
                }
            }
        }
    }

    async fn settle_pending_after_challenge(&self, moderator_origin: &str) -> anyhow::Result<()> {
        let Some(pending) = self.store.get_pending_spend(moderator_origin)? else {
            return Ok(());
        };

        self.vlog("MOLE: active session challenged with 401; settling held credential first");
        if pending.state == PendingSpendState::Held
            && pending.held_until.is_some_and(|until| unix_now() >= until)
        {
            if !self.send_recovery(&pending).await? {
                self.store.discard_pending_spend(moderator_origin)?;
            }
        } else {
            self.send_signoff(&pending).await?;
        }
        Ok(())
    }

    async fn obtain_spend_credential(
        &self,
        target_url: &Url,
        moderator_origin: &str,
        challenge: &EcActChallenge,
        offered_challenges: &[MoleChallenge],
        include_explicit_cookie: bool,
    ) -> anyhow::Result<Option<SpendCredential>> {
        let config = self
            .ensure_moderator_config(
                target_url,
                moderator_origin,
                challenge,
                include_explicit_cookie,
            )
            .await?;
        let (issuance_url, supported_endorsements, supported_keys) = config.parse_supported()?;
        let Some(active_key) = supported_keys
            .into_iter()
            .find(|key| key.config.credential_context == challenge.credential_context)
        else {
            self.vlog(
                "MOLE: Moderator has no active EC-ACT key matching challenged credential_context",
            );
            return Ok(None);
        };

        let find_usable = || {
            self.store.find_usable_credential(
                moderator_origin,
                &active_key.key_id,
                &active_key.config.credential_context,
                active_key.config.balance_width,
                challenge.spend_amount,
                challenge.max_top_up,
            )
        };
        let mut usable = find_usable()?;
        if usable.is_none() {
            let issued = self
                .try_redeem_and_issue(
                    moderator_origin,
                    &issuance_url,
                    offered_challenges,
                    &supported_endorsements,
                    &active_key,
                )
                .await?;
            if !issued {
                self.vlog(
                    "MOLE: no usable Credential with sufficient credits and no redeemable Endorsement available",
                );
                return Ok(None);
            }
            usable = find_usable()?;
        }

        Ok(usable.map(|usable| SpendCredential {
            issuance_url,
            active_key,
            usable,
        }))
    }

    async fn present_credential(
        &self,
        request: FrozenRequest<'_>,
        moderator_origin: &str,
        challenge: &EcActChallenge,
        spend_credential: SpendCredential,
    ) -> anyhow::Result<HttpResponseData> {
        let SpendCredential {
            issuance_url,
            active_key,
            usable,
        } = spend_credential;
        let UsableCredential {
            id: credential_id,
            credential,
            presentations_count,
        } = usable;

        let params = ec_act::Params::new(active_key.config.balance_width)?;
        let ctx_spend = challenge.ctx_spend()?;
        let (spend_state, spend_message) = ec_act::prove_spend(
            &params,
            credential,
            &active_key.ctx_cred,
            challenge.spend_amount,
            challenge.max_top_up,
            &ctx_spend,
        )?;
        let presentation = EcActPresentationAndUpdate {
            key_id: active_key.key_id,
            spend: spend_message,
        };
        let presentation_bytes = presentation.to_bytes();
        let recovery_handle = presentation.recovery_handle();

        self.store.commit_in_flight_spend(
            credential_id,
            moderator_origin,
            issuance_url.as_str(),
            &active_key.key_id,
            &active_key.public_key,
            active_key.config.balance_width,
            &active_key.config.credential_context,
            &spend_state,
            &presentation_bytes,
            &recovery_handle,
            presentations_count,
            request.method.as_str(),
            request.url.as_str(),
        )?;

        let authorization = (MoleAuthorization::Presentation {
            credential_type: CredentialType::EC_ACT,
            presentation: presentation_bytes,
        })
        .to_header_value()?;
        let mut retry_headers = request.headers;
        retry_headers.insert(AUTHORIZATION, HeaderValue::from_str(&authorization)?);
        self.vlog(format!(
            "MOLE: presenting EC-ACT Credential (escrowing s={} credits)",
            challenge.spend_amount
        ));

        let response = self
            .raw_send(
                request.method,
                request.url,
                retry_headers,
                request.body.clone(),
                false,
            )
            .await?;
        self.process_response_mole_credential(moderator_origin, &response.headers)?;
        Ok(response)
    }

    fn process_response_mole_credential(
        &self,
        moderator_origin: &str,
        headers: &HeaderMap,
    ) -> anyhow::Result<()> {
        let Some(cred_hdr) = MoleCredentialHeader::from_headers(headers)? else {
            return Ok(());
        };
        match cred_hdr {
            MoleCredentialHeader::HeldForUpdate {
                credential_type: CredentialType::EC_ACT,
                duration_secs,
            } => {
                let sess_tok = parse_mole_session(headers)?;
                self.store
                    .mark_spend_held(moderator_origin, sess_tok.as_deref(), duration_secs)?;
                self.vlog(format!(
                    "MOLE: credential held-for-update for {duration_secs}s (Mole-Session received: {})",
                    sess_tok.is_some()
                ));
            }
            MoleCredentialHeader::Update {
                credential_type: CredentialType::EC_ACT,
                update,
            } => {
                let new_bal = self
                    .store
                    .settle_pending_spend_with_update(moderator_origin, update.as_deref())?;
                self.vlog(format!(
                    "MOLE: settled immediate credential update -> balance: {:?}",
                    new_bal
                ));
            }
            _ => {}
        }
        Ok(())
    }

    async fn ensure_moderator_config(
        &self,
        target_url: &Url,
        moderator_origin: &str,
        act_chal: &EcActChallenge,
        include_explicit_cookie: bool,
    ) -> anyhow::Result<ModeratorConfiguration> {
        if let Some(cached) = self.store.load_moderator_config(moderator_origin)?
            && let Ok((_, _, keys)) = cached.parse_supported()
            && keys
                .iter()
                .any(|k| k.config.credential_context == act_chal.credential_context)
        {
            return Ok(cached);
        }

        let wk_url = moderator_well_known_url(target_url)?;
        self.vlog(format!("MOLE: fetching Moderator config from {wk_url}"));
        let headers =
            self.headers_with_cookies(&wk_url, HeaderMap::new(), include_explicit_cookie)?;
        let resp = self
            .raw_send(&Method::GET, &wk_url, headers, Bytes::new(), false)
            .await?;
        if !resp.status.is_success() {
            bail!(
                "Moderator well-known discovery failed with HTTP {}",
                resp.status
            );
        }
        let cfg: ModeratorConfiguration =
            serde_json::from_slice(&resp.body).context("invalid ModeratorConfiguration JSON")?;
        self.store.save_moderator_config(moderator_origin, &cfg)?;
        Ok(cfg)
    }

    async fn try_redeem_and_issue(
        &self,
        moderator_origin: &str,
        issuance_url: &Url,
        challenges: &[MoleChallenge],
        sup_endorsements: &[SupportedModeratorEndorsement],
        active_key: &prototalpid_http::config::ValidatedEcActKey,
    ) -> anyhow::Result<bool> {
        let params = ec_act::Params::new(active_key.config.balance_width)?;

        let no_end_offered = challenges.iter().any(|c| {
            matches!(
                c,
                MoleChallenge::Redeem {
                    endorsement_type: EndorsementType::NO_ENDORSEMENT,
                    ..
                }
            )
        }) && sup_endorsements
            .iter()
            .any(|e| matches!(e, SupportedModeratorEndorsement::NoEndorsement));

        let (end_type, redemption_bytes) = if no_end_offered {
            (EndorsementType::NO_ENDORSEMENT, Vec::new())
        } else {
            let Some(red_chal_raw) = challenges.iter().find_map(|c| match c {
                MoleChallenge::Redeem {
                    endorsement_type: EndorsementType::EC_IHAT,
                    challenge,
                } => Some(challenge.clone()),
                _ => None,
            }) else {
                return Ok(false);
            };
            let digest = RedemptionChallenge::from_bytes(&red_chal_raw)?.digest();

            let mut matched_redemption: Option<Vec<u8>> = None;
            for sup in sup_endorsements {
                let SupportedModeratorEndorsement::EcIhat(ec_cfg) = sup else {
                    continue;
                };
                let anchor_pks = ec_cfg.decode_anchor_set()?;
                if let Some((idx, endorsement)) = self
                    .store
                    .take_matching_ec_ihat_endorsement(&anchor_pks, &ec_cfg.issuance_epoch)?
                {
                    let redemption = ec_ihat::redeem(
                        &anchor_pks,
                        idx,
                        endorsement,
                        &ec_cfg.issuance_epoch,
                        EC_IHAT_CTX_RED,
                        &digest,
                    )?;
                    matched_redemption = Some(redemption.to_bytes());
                    break;
                }
            }
            let Some(bytes) = matched_redemption else {
                return Ok(false);
            };
            (EndorsementType::EC_IHAT, bytes)
        };

        let (iss_state, iss_req_msg) = ec_act::issue_request(&params)?;
        let iss_req = EcActIssuanceRequest {
            truncated_key_id: active_key.truncated_key_id,
            credential_context: active_key.config.credential_context.clone(),
            request: iss_req_msg,
        };
        let auth_val = (MoleAuthorization::RedeemAndIssue {
            endorsement_type: end_type,
            redemption: redemption_bytes,
            credential_type: CredentialType::EC_ACT,
            credential_request: iss_req.to_bytes()?,
        })
        .to_header_value()?;

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val)?);
        self.vlog(format!(
            "MOLE: sending RedeemAndIssue (endorsement={end_type}) to {issuance_url}"
        ));
        let resp = self
            .raw_send(&Method::POST, issuance_url, headers, Bytes::new(), false)
            .await?;
        if resp.status != StatusCode::OK {
            self.vlog(format!(
                "MOLE: RedeemAndIssue failed with HTTP {}",
                resp.status
            ));
            return Ok(false);
        }

        let Some(MoleCredentialHeader::Response {
            credential_type: CredentialType::EC_ACT,
            response: resp_raw,
        }) = MoleCredentialHeader::from_headers(&resp.headers)?
        else {
            bail!("RedeemAndIssue 200 response missing Mole-Credential: response-0001");
        };

        let iss_resp = EcActIssuanceResponse::from_bytes(&params, &resp_raw)?;
        let cred = ec_act::finalize_issue(
            &params,
            &active_key.public_key,
            &active_key.ctx_cred,
            iss_state,
            &iss_resp.response,
        )?;
        self.vlog(format!(
            "MOLE: finalized EC-ACT Credential with initial balance c={}",
            cred.balance()
        ));
        self.store.save_issued_credential(
            moderator_origin,
            issuance_url.as_str(),
            &active_key.key_id,
            &active_key.public_key,
            active_key.config.balance_width,
            &active_key.config.credential_context,
            &cred,
        )?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // 4. Pooled HTTP/HTTPS Transport (`reqwest`) & Cookie Handling
    // -----------------------------------------------------------------------

    async fn raw_send(
        &self,
        method: &Method,
        url: &Url,
        mut headers: HeaderMap,
        body: Bytes,
        include_cookies: bool,
    ) -> anyhow::Result<HttpResponseData> {
        if include_cookies {
            headers = self.headers_with_cookies(url, headers, true)?;
        }

        if self.opts.verbose {
            let target = match &url[Position::BeforePath..] {
                "" => "/",
                s => s,
            };
            eprintln!("> {} {target} HTTP/1.1", method.as_str());
            for (k, v) in &headers {
                if is_sensitive_trace_header(k) {
                    eprintln!("> {k}: <redacted>");
                } else if let Ok(vs) = v.to_str() {
                    eprintln!("> {k}: {vs}");
                }
            }
            eprintln!(">");
        }

        let mut resp = self
            .opts
            .http_client
            .request(method.clone(), url.clone())
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        if self.opts.verbose {
            eprintln!("< {:?} {status}", resp.version());
            for (k, v) in &resp_headers {
                if is_sensitive_trace_header(k) {
                    eprintln!("< {k}: <redacted>");
                } else if let Ok(vs) = v.to_str() {
                    eprintln!("< {k}: {vs}");
                }
            }
            eprintln!("<");
        }

        let set_cookies: Vec<&str> = resp_headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if !set_cookies.is_empty() {
            self.store.store_set_cookies(url, set_cookies)?;
        }

        let resp_body = read_response_body_limited(&mut resp, MAX_RESPONSE_BODY_BYTES).await?;
        Ok(HttpResponseData {
            status,
            headers: resp_headers,
            body: resp_body,
            effective_url: url.clone(),
        })
    }

    fn headers_with_cookies(
        &self,
        url: &Url,
        mut headers: HeaderMap,
        include_explicit_cookie: bool,
    ) -> anyhow::Result<HeaderMap> {
        if !headers.contains_key(COOKIE) {
            if include_explicit_cookie && let Some(ref explicit) = self.opts.explicit_cookie_header
            {
                headers.insert(COOKIE, HeaderValue::from_str(explicit)?);
            } else if let Some(stored_cookie) = self.store.cookie_header_for_url(url)? {
                headers.insert(COOKIE, HeaderValue::from_str(&stored_cookie)?);
            }
        }
        Ok(headers)
    }
}

fn is_sensitive_trace_header(name: &http::HeaderName) -> bool {
    name == AUTHORIZATION
        || name == PROXY_AUTHORIZATION
        || name == COOKIE
        || name == SET_COOKIE
        || name == MOLE_SESSION_HEADER
        || name == MOLE_CREDENTIAL_HEADER
}

async fn read_response_body_limited(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> anyhow::Result<Bytes> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("HTTP response body exceeds {max_bytes} byte limit");
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut body = BytesMut::with_capacity(initial_capacity);
    while let Some(chunk) = response.chunk().await? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("HTTP response body length overflow"))?;
        if next_len > max_bytes {
            bail!("HTTP response body exceeds {max_bytes} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

fn redirect_headers(original: &HeaderMap, same_origin: bool, body_was_cleared: bool) -> HeaderMap {
    let mut headers = original.clone();
    if !same_origin {
        headers.remove(AUTHORIZATION);
        headers.remove(COOKIE);
        headers.remove(HOST);
        headers.remove(PROXY_AUTHORIZATION);
    }
    if body_was_cleared {
        headers.remove(CONTENT_LENGTH);
        headers.remove(CONTENT_TYPE);
        headers.remove(TRANSFER_ENCODING);
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_origin_redirect_strips_credentials_and_body_metadata() {
        let mut original = HeaderMap::new();
        original.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        original.insert(COOKIE, HeaderValue::from_static("session=secret"));
        original.insert(HOST, HeaderValue::from_static("first.example"));
        original.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic c2VjcmV0"),
        );
        original.insert(CONTENT_LENGTH, HeaderValue::from_static("7"));
        original.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        original.insert("x-retained", HeaderValue::from_static("yes"));

        let redirected = redirect_headers(&original, false, true);
        assert!(redirected.get(AUTHORIZATION).is_none());
        assert!(redirected.get(COOKIE).is_none());
        assert!(redirected.get(HOST).is_none());
        assert!(redirected.get(PROXY_AUTHORIZATION).is_none());
        assert!(redirected.get(CONTENT_LENGTH).is_none());
        assert!(redirected.get(CONTENT_TYPE).is_none());
        assert_eq!(redirected.get("x-retained").unwrap(), "yes");
    }

    #[test]
    fn explicit_cookie_is_scoped_to_initial_origin() {
        prototalpid_http::tls::ensure_crypto_provider();
        let store = Arc::new(WalletStore::open(None).unwrap());
        let mut options = MoleClientOptions::new(reqwest::Client::new());
        options.explicit_cookie_header = Some("explicit=secret".to_owned());
        let client = MoleClient::new(store, options);
        let url = Url::parse("https://redirected.example/").unwrap();

        assert_eq!(
            client
                .headers_with_cookies(&url, HeaderMap::new(), true)
                .unwrap()
                .get(COOKIE)
                .unwrap(),
            "explicit=secret",
        );
        assert!(
            client
                .headers_with_cookies(&url, HeaderMap::new(), false)
                .unwrap()
                .get(COOKIE)
                .is_none()
        );
    }

    #[test]
    fn credential_bearing_trace_headers_are_sensitive() {
        for name in [
            &AUTHORIZATION,
            &PROXY_AUTHORIZATION,
            &COOKIE,
            &SET_COOKIE,
            &MOLE_SESSION_HEADER,
            &MOLE_CREDENTIAL_HEADER,
        ] {
            assert!(is_sensitive_trace_header(name));
        }
        assert!(!is_sensitive_trace_header(&CONTENT_TYPE));
    }
}
