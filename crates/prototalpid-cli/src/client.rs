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
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderMap, HeaderValue, LOCATION, SET_COOKIE};
use http::{Method, StatusCode};
use url::{Position, Url};

use prototalpid_http::challenge::{
    AnchorChallengeOffer, AnchorChallengeSubmission, DEFAULT_ANCHOR_CHALLENGE_PATH, solve_pow,
};
use prototalpid_http::config::{
    AnchorConfiguration, ModeratorConfiguration, SupportedModeratorEndorsement,
    anchor_well_known_url, canonical_https_origin, moderator_well_known_url,
};
use prototalpid_http::schemes::{CredentialType, EC_IHAT_CTX_RED, EndorsementType};
use prototalpid_http::transport::{
    MOLE_SESSION_HEADER, MoleAuthorization, MoleChallenge, MoleCredentialHeader,
    WANT_ENDORSEMENT_HEADER, format_endorsement_request_content_type,
    parse_endorsement_response_content_type, parse_mole_session, parse_www_authenticate_headers,
};
use prototalpid_http::unix_now;
use prototalpid_http::wire::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    GrantChallenges, GrantCommitments, GrantRequest, GrantResponses, RedemptionChallenge,
};

use crate::store::{PendingSpendRecord, WalletStore};

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
        let anchor_cfg: AnchorConfiguration = serde_json::from_slice(&wk_resp.body)
            .context("invalid AnchorConfiguration JSON")?;
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
                ec_ihat::finalize(&pk_a, st, resp)
                    .map_err(|e| anyhow::anyhow!("ec_ihat::finalize failed (discarding batch): {e}"))
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
        if pending.state == "held" && pending.held_until.is_some_and(|u| unix_now() >= u) {
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
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth.to_header_value()?)?);
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
            self.store.discard_pending_spend(&pending.moderator_origin)?;
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

        loop {
            let resp = self
                .execute_single_hop(&method, &url, &user_headers, &body)
                .await?;

            if self.opts.follow_redirects
                && resp.status.is_redirection()
                && let Some(loc_val) = resp.headers.get(LOCATION)
                && let Ok(loc_str) = loc_val.to_str()
            {
                if redirects >= self.opts.max_redirects {
                    bail!("maximum redirects ({}) exceeded", self.opts.max_redirects);
                }
                url = url.join(loc_str)?;
                if matches!(
                    resp.status,
                    StatusCode::SEE_OTHER | StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                ) && method == Method::POST
                {
                    method = Method::GET;
                    body = Bytes::new();
                }
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
    ) -> anyhow::Result<HttpResponseData> {
        if self.opts.mole_disabled || url.scheme() != "https" {
            return self
                .raw_send(method, url, user_headers.clone(), body.clone(), true)
                .await;
        }

        let moderator_origin = canonical_https_origin(url)?;

        // Step 1: Pre-flight check on any pending or held spend for this Moderator origin.
        let mut attached_session_token: Option<String> = None;
        if let Some(pending) = self.store.get_pending_spend(&moderator_origin)? {
            let now = unix_now();
            match pending.state.as_str() {
                "in_flight" => {
                    self.vlog(format!(
                        "MOLE: found interrupted in_flight spend for {moderator_origin}; recovering..."
                    ));
                    if !self.send_recovery(&pending).await? {
                        self.send_signoff(&pending).await?;
                    }
                }
                "held" => {
                    let held_until = pending.held_until.unwrap_or(0);
                    if now >= held_until {
                        self.vlog(format!(
                            "MOLE: hold expired for {moderator_origin}; sending recovery-0001"
                        ));
                        if !self.send_recovery(&pending).await? {
                            self.store.discard_pending_spend(&moderator_origin)?;
                        }
                    } else if held_until - now <= self.opts.proactive_signoff_lead_secs {
                        self.vlog(format!(
                            "MOLE: hold near expiry for {moderator_origin}; proactively sending signoff-0001"
                        ));
                        self.send_signoff(&pending).await?;
                    } else if let Some(ref tok) = pending.session_token {
                        attached_session_token = Some(tok.clone());
                    }
                }
                _ => {}
            }
        }

        // Step 2: Send initial request (attaching Mole-Session if active).
        let mut req_headers = user_headers.clone();
        if let Some(ref tok) = attached_session_token {
            self.vlog("MOLE: attaching active Mole-Session header");
            req_headers.insert(MOLE_SESSION_HEADER, HeaderValue::from_str(tok)?);
        }

        let initial_resp = self
            .raw_send(method, url, req_headers, body.clone(), true)
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

        if let Some(pending) = self.store.get_pending_spend(&moderator_origin)? {
            self.vlog("MOLE: active session challenged with 401; settling held credential first");
            if pending.state == "held" && pending.held_until.is_some_and(|u| unix_now() >= u) {
                if !self.send_recovery(&pending).await? {
                    self.store.discard_pending_spend(&moderator_origin)?;
                }
            } else {
                self.send_signoff(&pending).await?;
            }
        }

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

        let mod_cfg = self
            .ensure_moderator_config(url, &moderator_origin, &act_chal)
            .await?;
        let (issuance_url, sup_endorsements, sup_keys) = mod_cfg.parse_supported()?;
        let Some(active_key) = sup_keys
            .iter()
            .find(|k| k.config.credential_context == act_chal.credential_context)
        else {
            self.vlog(
                "MOLE: Moderator has no active EC-ACT key matching challenged credential_context",
            );
            return Ok(initial_resp);
        };

        let mut usable_opt = self.store.find_usable_credential(
            &moderator_origin,
            &active_key.key_id,
            &active_key.config.credential_context,
            active_key.config.balance_width,
            act_chal.spend_amount,
            act_chal.max_top_up,
        )?;

        if usable_opt.is_none() {
            let issued = self
                .try_redeem_and_issue(
                    &moderator_origin,
                    &issuance_url,
                    &challenges,
                    &sup_endorsements,
                    active_key,
                )
                .await?;
            if !issued {
                self.vlog(
                    "MOLE: no usable Credential with sufficient credits and no redeemable Endorsement available",
                );
                return Ok(initial_resp);
            }
            usable_opt = self.store.find_usable_credential(
                &moderator_origin,
                &active_key.key_id,
                &active_key.config.credential_context,
                active_key.config.balance_width,
                act_chal.spend_amount,
                act_chal.max_top_up,
            )?;
        }

        let Some(usable) = usable_opt else {
            return Ok(initial_resp);
        };

        // Step 4: ProveSpend, durably commit `in_flight` state, and resend protected request!
        let params = ec_act::Params::new(active_key.config.balance_width)?;
        let ctx_spend = act_chal.ctx_spend()?;
        let (spend_state, spend_msg) = ec_act::prove_spend(
            &params,
            usable.credential,
            &active_key.ctx_cred,
            act_chal.spend_amount,
            act_chal.max_top_up,
            &ctx_spend,
        )?;
        let pres = EcActPresentationAndUpdate {
            key_id: active_key.key_id,
            spend: spend_msg,
        };
        let pres_bytes = pres.to_bytes();
        let recovery_handle = pres.recovery_handle();

        self.store.commit_in_flight_spend(
            usable.id,
            &moderator_origin,
            issuance_url.as_str(),
            &active_key.key_id,
            &active_key.public_key,
            active_key.config.balance_width,
            &active_key.config.credential_context,
            &spend_state,
            &pres_bytes,
            &recovery_handle,
            usable.presentations_count,
            method.as_str(),
            url.as_str(),
        )?;

        let auth_val = (MoleAuthorization::Presentation {
            credential_type: CredentialType::EC_ACT,
            presentation: pres_bytes,
        })
        .to_header_value()?;

        let mut retry_headers = user_headers.clone();
        retry_headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val)?);
        self.vlog(format!(
            "MOLE: presenting EC-ACT Credential (escrowing s={} credits)",
            act_chal.spend_amount
        ));

        let retry_resp = self
            .raw_send(method, url, retry_headers, body.clone(), true)
            .await?;

        self.process_response_mole_credential(&moderator_origin, &retry_resp.headers)?;
        Ok(retry_resp)
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
                    "MOLE: credential held-for-update for {duration_secs}s (Mole-Session: {:?})",
                    sess_tok
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
        let resp = self
            .raw_send(&Method::GET, &wk_url, HeaderMap::new(), Bytes::new(), true)
            .await?;
        if !resp.status.is_success() {
            bail!(
                "Moderator well-known discovery failed with HTTP {}",
                resp.status
            );
        }
        let cfg: ModeratorConfiguration = serde_json::from_slice(&resp.body)
            .context("invalid ModeratorConfiguration JSON")?;
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
        if include_cookies && !headers.contains_key(COOKIE) {
            if let Some(ref explicit) = self.opts.explicit_cookie_header {
                headers.insert(COOKIE, HeaderValue::from_str(explicit)?);
            } else if let Some(stored_cookie) = self.store.cookie_header_for_url(url)? {
                headers.insert(COOKIE, HeaderValue::from_str(&stored_cookie)?);
            }
        }

        if self.opts.verbose {
            let target = match &url[Position::BeforePath..] {
                "" => "/",
                s => s,
            };
            eprintln!("> {} {target} HTTP/1.1", method.as_str());
            for (k, v) in &headers {
                if let Ok(vs) = v.to_str() {
                    eprintln!("> {k}: {vs}");
                }
            }
            eprintln!(">");
        }

        let resp = self
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
                if let Ok(vs) = v.to_str() {
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

        let resp_body = resp.bytes().await?;
        Ok(HttpResponseData {
            status,
            headers: resp_headers,
            body: resp_body,
            effective_url: url.clone(),
        })
    }
}
