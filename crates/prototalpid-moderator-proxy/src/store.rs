//! SQLite store, stateless HMAC challenge derivation, multi-Anchor EC-IHAT
//! redemption verification, and deferred `held-for-update` / `signoff` / `recovery`
//! EC-ACT credential moderation for `prototalpid-moderator-proxy`.

#![allow(clippy::type_complexity)]

use std::path::Path;
use std::sync::Mutex;

use ec_act::{Backend as _, DefaultBackend as ActBackend};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use prototalpid_http::config::{
    EcActKeyConfig, EcIhatEndorsementConfig, ModeratorConfiguration,
};
use prototalpid_http::schemes::{
    CIPHERSUITE_P256_SHA256, CredentialType, EC_IHAT_CTX_RED, EndorsementType,
    compute_ec_act_key_id, derive_ec_act_ctx_cred, truncated_key_id,
};
use prototalpid_http::transport::{MoleCredentialHeader, format_mole_session};
use prototalpid_http::unix_now;
use prototalpid_http::wire::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, RecoveryHandle, RedemptionChallenge,
};

type HmacSha256 = Hmac<Sha256>;

/// Moderation & rate-limiting policy parameters for `prototalpid-moderator-proxy`.
#[derive(Clone, Debug)]
pub struct ModerationPolicy {
    /// Initial credit balance `c` issued on `RedeemAndIssue` (must be `< 2^L`).
    pub initial_credits: u64,
    /// Escrowed deposit `s` (`spend_amount`) required per session presentation.
    pub deposit_credits: u64,
    /// Maximum top-up `a` offered in challenges (`0` by default).
    pub max_top_up: u64,
    /// Duration in seconds to hold a credential update (`held-for-update-0001="<secs>"`).
    pub hold_duration_secs: u64,
    /// Sliding rate-limit window length in seconds for active `Mole-Session`s.
    pub rate_window_secs: u64,
    /// Maximum allowed requests within `rate_window_secs` before session invalidation.
    pub max_requests_per_window: u32,
    /// If `true`, breaching the rate limit records `NoUpdate` (revoking the entire
    /// credential chain); if `false`, forfeits the escrowed deposit (`t = 0`).
    pub revoke_chain_on_flood: bool,
    /// Time bucket length in seconds for stateless HMAC challenges (accepts current & previous bucket).
    pub challenge_window_secs: u64,
    /// Whether `endorsement-type = 0x0001` (`No Endorsement Required`) is accepted.
    pub allow_no_endorsement: bool,
}

impl Default for ModerationPolicy {
    fn default() -> Self {
        Self {
            initial_credits: 60,
            deposit_credits: 20,
            max_top_up: 0,
            hold_duration_secs: 30,
            rate_window_secs: 10,
            max_requests_per_window: 5,
            revoke_chain_on_flood: false,
            challenge_window_secs: 60,
            allow_no_endorsement: false,
        }
    }
}

/// Trusted Anchor Set entry loaded into the Moderator.
#[derive(Clone, Debug)]
pub struct TrustedAnchorSet {
    /// Shared `ctx_iss` (`issuance-epoch`).
    pub issuance_epoch: Vec<u8>,
    /// Ordered list of Anchor EC-IHAT public keys.
    pub public_keys: Vec<ec_ihat::PublicKey>,
}

/// Outcome of checking an active `Mole-Session` token on a proxied request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionVerdict {
    /// Session is active and within rate limits; forward request to upstream.
    Allowed,
    /// Session is unknown, expired, or already invalidated; return `401` challenge.
    InvalidOrExpired,
    /// Session exceeded `max_requests_per_window`; session invalidated & held credential
    /// penalized/revoked; return `401` challenge without hitting upstream.
    RateLimited,
}

/// Outcome of processing an `Authorization: Mole presentation-0001="..."` header.
#[derive(Clone, Debug)]
pub enum PresentationVerdict {
    /// Fresh valid presentation: forward request to upstream and attach `mole_credential`
    /// (plus `Mole-Session` if `session_token` is `Some`).
    AcceptedFresh {
        /// Newly created `Mole-Session` token (when `hold_duration_secs > 0`).
        session_token: Option<String>,
        /// `Mole-Credential` header to return (`held-for-update-0001` or immediate `update-0001`).
        mole_credential: MoleCredentialHeader,
    },
    /// Byte-identical retry of an already recorded presentation with retained result:
    /// return `409 Conflict` with `mole_credential` and DO NOT forward upstream.
    DuplicateRetained {
        /// Retained `Mole-Credential` header.
        mole_credential: MoleCredentialHeader,
    },
    /// Invalid proof, wrong challenge/key/amounts, conflicting nullifier, or expired duplicate:
    /// return `401 Unauthorized` with fresh challenge.
    RejectedUnauthorized,
    /// Syntactically malformed wire payload: return `400 Bad Request`.
    Malformed(&'static str),
}

/// Errors from Moderator store operations.
#[derive(Debug, thiserror::Error)]
pub enum ModeratorError {
    /// SQLite error.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// Malformed client payload (`400`).
    #[error("malformed request: {0}")]
    BadRequest(&'static str),
    /// Invalid or replayed authentication (`401`).
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    /// Disallowed by policy (`403`).
    #[error("forbidden by policy: {0}")]
    Forbidden(&'static str),
    /// Signoff / recovery result unavailable (`404`).
    #[error("result not found")]
    NotFound,
    /// Internal crypto/config error.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

struct StoredSpendRecord {
    presentation_sha256: Vec<u8>,
    state: String,
    outcome_type: Option<String>,
    refund_bytes: Option<Vec<u8>>,
    held_until: i64,
    result_expires_at: i64,
}

/// Persistent SQLite store and cryptographic engine for `prototalpid-moderator-proxy`.
pub struct ModeratorStore {
    conn: Mutex<Connection>,
    params: ec_act::Params,
    secret_key: ec_act::SecretKey,
    public_key: ec_act::PublicKey,
    key_id: [u8; 32],
    truncated_key_id: u8,
    credential_context: Vec<u8>,
    ctx_cred: Vec<u8>,
    result_retention_secs: u64,
    hmac_secret: Zeroizing<[u8; 32]>,
    anchor_sets: Vec<TrustedAnchorSet>,
}

impl ModeratorStore {
    /// Opens or initializes the Moderator SQLite store.
    pub fn open(
        db_path: Option<&Path>,
        default_balance_width: u8,
        default_credential_context: &[u8],
        default_result_retention_secs: u64,
        anchor_sets: Vec<TrustedAnchorSet>,
    ) -> Result<Self, ModeratorError> {
        let conn = match db_path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS moderator_keys (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 seed BLOB NOT NULL,
                 hmac_secret BLOB NOT NULL,
                 balance_width INTEGER NOT NULL,
                 credential_context BLOB NOT NULL,
                 result_retention_secs INTEGER NOT NULL,
                 created_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS redeemed_endorsements (
                 ctx_iss BLOB NOT NULL,
                 nullifier BLOB NOT NULL,
                 redeemed_at INTEGER NOT NULL,
                 PRIMARY KEY (ctx_iss, nullifier)
             );

             CREATE TABLE IF NOT EXISTS spent_credentials (
                 key_id BLOB NOT NULL,
                 ctx_cred BLOB NOT NULL,
                 nullifier BLOB NOT NULL,
                 presentation_sha256 BLOB NOT NULL,
                 state TEXT NOT NULL,
                 spend_bytes BLOB,
                 ctx_spend BLOB,
                 spend_amount INTEGER NOT NULL,
                 outcome_type TEXT,
                 refund_bytes BLOB,
                 held_until INTEGER NOT NULL,
                 result_expires_at INTEGER NOT NULL,
                 PRIMARY KEY (key_id, ctx_cred, nullifier)
             );

             CREATE TABLE IF NOT EXISTS mole_sessions (
                 session_token TEXT PRIMARY KEY,
                 key_id BLOB NOT NULL,
                 ctx_cred BLOB NOT NULL,
                 nullifier BLOB NOT NULL,
                 active INTEGER NOT NULL,
                 request_count INTEGER NOT NULL,
                 window_started_at INTEGER NOT NULL,
                 window_hits INTEGER NOT NULL,
                 penalty_credits INTEGER NOT NULL,
                 revoke_chain INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL
             );",
        )?;

        let row: Option<(Vec<u8>, Vec<u8>, u8, Vec<u8>, i64)> = conn
            .query_row(
                "SELECT seed, hmac_secret, balance_width, credential_context, result_retention_secs
                 FROM moderator_keys WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;

        let (seed, hmac_secret, balance_width, credential_context, result_retention_secs) =
            if let Some((seed_v, hmac_v, bw, cctx, ret)) = row {
                let mut s = Zeroizing::new([0u8; ec_act::SEED_LENGTH]);
                *s = seed_v
                    .as_slice()
                    .try_into()
                    .map_err(|_| ModeratorError::Internal("corrupt moderator seed"))?;
                let mut hm = Zeroizing::new([0u8; 32]);
                *hm = hmac_v
                    .as_slice()
                    .try_into()
                    .map_err(|_| ModeratorError::Internal("corrupt HMAC secret"))?;
                (s, hm, bw, cctx, ret as u64)
            } else {
                let seed = ActBackend::generate_seed()
                    .map_err(|_| ModeratorError::Internal("failed to generate EC-ACT seed"))?;
                let mut hm = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut *hm)
                    .map_err(|_| ModeratorError::Internal("entropy failure"))?;
                let now = unix_now();
                conn.execute(
                    "INSERT INTO moderator_keys
                     (id, seed, hmac_secret, balance_width, credential_context, result_retention_secs, created_at)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        seed.as_slice(),
                        hm.as_slice(),
                        default_balance_width,
                        default_credential_context,
                        default_result_retention_secs as i64,
                        now
                    ],
                )?;
                (
                    seed,
                    hm,
                    default_balance_width,
                    default_credential_context.to_vec(),
                    default_result_retention_secs,
                )
            };

        let params = ec_act::Params::new(balance_width)
            .map_err(|_| ModeratorError::Internal("invalid EC-ACT balance_width"))?;
        let secret_key = ec_act::SecretKey::from_seed(&seed)
            .map_err(|_| ModeratorError::Internal("failed to derive EC-ACT SecretKey"))?;
        let public_key = secret_key.public_key();
        let key_id = compute_ec_act_key_id(&public_key);
        let trunc = truncated_key_id(&key_id);
        let ctx_cred = derive_ec_act_ctx_cred(&credential_context, balance_width)
            .map_err(|_| ModeratorError::Internal("invalid EC-ACT credential_context"))?;

        Ok(Self {
            conn: Mutex::new(conn),
            params,
            secret_key,
            public_key,
            key_id,
            truncated_key_id: trunc,
            credential_context,
            ctx_cred,
            result_retention_secs,
            hmac_secret,
            anchor_sets,
        })
    }

    /// Builds the JSON [`ModeratorConfiguration`] published at `/.well-known/mole-moderator`.
    pub fn build_configuration(
        &self,
        issuance_uri: String,
        allow_no_endorsement: bool,
    ) -> Result<ModeratorConfiguration, ModeratorError> {
        let ec_ihat_sets: Vec<EcIhatEndorsementConfig> = self
            .anchor_sets
            .iter()
            .map(|s| EcIhatEndorsementConfig {
                endorsement_type: EndorsementType::EC_IHAT.0,
                ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
                issuance_epoch: s.issuance_epoch.clone(),
                anchor_set: s.public_keys.iter().map(|pk| pk.to_bytes().to_vec()).collect(),
            })
            .collect();

        let key_cfg = EcActKeyConfig {
            credential_type: CredentialType::EC_ACT.0,
            credential_key: self.public_key.to_bytes().to_vec(),
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            balance_width: self.params.balance_width(),
            credential_context: self.credential_context.clone(),
            result_retention: self.result_retention_secs,
        };

        ModeratorConfiguration::from_typed(
            issuance_uri,
            allow_no_endorsement,
            &ec_ihat_sets,
            &[key_cfg],
        )
        .map_err(|_| ModeratorError::Internal("failed to construct ModeratorConfiguration"))
    }

    /// Constructs a stateless time-windowed `RedemptionChallenge` for `public_origin`.
    pub fn issue_redemption_challenge(
        &self,
        public_origin: &str,
        policy: &ModerationPolicy,
    ) -> RedemptionChallenge {
        self.redemption_challenge_for_bucket(
            public_origin,
            current_bucket(policy.challenge_window_secs),
        )
    }

    fn redemption_challenge_for_bucket(
        &self,
        public_origin: &str,
        bucket: u64,
    ) -> RedemptionChallenge {
        RedemptionChallenge {
            redemption_context: hmac_sha256(
                &self.hmac_secret,
                &[
                    b"MOLE-REDEEM-v1|",
                    public_origin.as_bytes(),
                    b"|",
                    &bucket.to_be_bytes(),
                ],
            ),
        }
    }

    /// Constructs a stateless request-bound `EcActChallenge` for `(public_origin, method, path_and_query)`.
    pub fn issue_ec_act_challenge(
        &self,
        public_origin: &str,
        method: &str,
        path_and_query: &str,
        policy: &ModerationPolicy,
    ) -> EcActChallenge {
        self.ec_act_challenge_for_bucket(
            public_origin,
            method,
            path_and_query,
            policy,
            current_bucket(policy.challenge_window_secs),
        )
    }

    fn ec_act_challenge_for_bucket(
        &self,
        public_origin: &str,
        method: &str,
        path_and_query: &str,
        policy: &ModerationPolicy,
        bucket: u64,
    ) -> EcActChallenge {
        let request_context = hmac_sha256(
            &self.hmac_secret,
            &[
                b"MOLE-SPEND-v1|",
                public_origin.as_bytes(),
                b"|",
                method.as_bytes(),
                b"|",
                path_and_query.as_bytes(),
                b"|",
                &bucket.to_be_bytes(),
            ],
        )
        .to_vec();
        EcActChallenge {
            spend_amount: policy.deposit_credits,
            max_top_up: policy.max_top_up,
            credential_context: self.credential_context.clone(),
            request_context,
        }
    }

    /// Processes `RedeemAndIssue` on `/mole/issue` (`draft-jms-mole-protocols` §5.2.2).
    pub fn redeem_and_issue(
        &self,
        public_origin: &str,
        policy: &ModerationPolicy,
        endorsement_type: EndorsementType,
        redemption_bytes: &[u8],
        credential_type: CredentialType,
        credential_request_bytes: &[u8],
    ) -> Result<MoleCredentialHeader, ModeratorError> {
        if credential_type != CredentialType::EC_ACT {
            return Err(ModeratorError::Unauthorized("unsupported credential-type"));
        }

        // Step 1 & 2: Check truncated_key_id, credential_context, and IssueRequestMessage proof.
        let (trunc_id, req_cred_ctx, req_msg_bytes) =
            EcActIssuanceRequest::split_header(credential_request_bytes)
                .map_err(|_| ModeratorError::BadRequest("malformed EcActIssuanceRequest"))?;
        if trunc_id != self.truncated_key_id || req_cred_ctx != self.credential_context {
            return Err(ModeratorError::Unauthorized(
                "unknown truncated_key_id or credential_context",
            ));
        }
        let issue_req_msg = ec_act::IssueRequestMessage::from_bytes(&self.params, req_msg_bytes)
            .map_err(|_| ModeratorError::BadRequest("malformed IssueRequestMessage"))?;
        let verified_req = ec_act::verify_issue_request(&self.params, &issue_req_msg)
            .map_err(|_| ModeratorError::Unauthorized("IssueRequestMessage proof invalid"))?;

        // Step 3: FinalizeRedeem across current and previous challenge buckets.
        let replay_id: Option<(Vec<u8>, [u8; 32])> = match endorsement_type {
            EndorsementType::NO_ENDORSEMENT => {
                if !redemption_bytes.is_empty() {
                    return Err(ModeratorError::BadRequest("redeem-0001 must be empty"));
                }
                if !policy.allow_no_endorsement {
                    return Err(ModeratorError::Forbidden(
                        "NoEndorsement not permitted by policy",
                    ));
                }
                None
            }
            EndorsementType::EC_IHAT => {
                let bucket = current_bucket(policy.challenge_window_secs);
                let buckets = [bucket, bucket.saturating_sub(1)];
                let mut matched: Option<(Vec<u8>, [u8; 32])> = None;
                let mut decoded_any = false;
                for set in &self.anchor_sets {
                    let Ok(redemption) =
                        ec_ihat::Redemption::from_bytes(redemption_bytes, set.public_keys.len())
                    else {
                        continue;
                    };
                    decoded_any = true;
                    for &b in &buckets {
                        let chal = self.redemption_challenge_for_bucket(public_origin, b);
                        if let Ok(nf) = ec_ihat::verify_redemption(
                            &set.public_keys,
                            &redemption,
                            &set.issuance_epoch,
                            EC_IHAT_CTX_RED,
                            &chal.digest(),
                        ) {
                            matched = Some((set.issuance_epoch.clone(), nf));
                            break;
                        }
                    }
                    if matched.is_some() {
                        break;
                    }
                }
                if let Some(m) = matched {
                    Some(m)
                } else if !decoded_any {
                    return Err(ModeratorError::BadRequest("malformed EC-IHAT Redemption"));
                } else {
                    return Err(ModeratorError::Unauthorized(
                        "EC-IHAT Redemption verification failed",
                    ));
                }
            }
            _ => return Err(ModeratorError::Unauthorized("unsupported endorsement-type")),
        };

        // Step 4: IssueResponse + atomic replay-protection insert.
        let resp_msg = ec_act::issue_response(
            &self.secret_key,
            &self.ctx_cred,
            policy.initial_credits,
            verified_req,
        )
        .map_err(|_| ModeratorError::Internal("ec_act::issue_response failed"))?;
        let resp_bytes = (EcActIssuanceResponse { response: resp_msg }).to_bytes();

        if let Some((ctx_iss, nf)) = replay_id {
            let now = unix_now();
            let mut conn = self.conn.lock().expect("ModeratorStore mutex poisoned");
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO redeemed_endorsements (ctx_iss, nullifier, redeemed_at)
                 VALUES (?1, ?2, ?3)",
                params![ctx_iss.as_slice(), nf.as_slice(), now],
            )?;
            if inserted != 1 {
                return Err(ModeratorError::Unauthorized(
                    "endorsement nullifier already redeemed",
                ));
            }
            tx.commit()?;
        }

        Ok(MoleCredentialHeader::Response {
            credential_type: CredentialType::EC_ACT,
            response: resp_bytes,
        })
    }

    /// Checks and updates an active `Mole-Session` token on an incoming proxied request.
    pub fn check_and_record_session_request(
        &self,
        session_token: &str,
        policy: &ModerationPolicy,
    ) -> Result<SessionVerdict, ModeratorError> {
        let now = unix_now();
        let mut conn = self.conn.lock().expect("ModeratorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        self.finalize_expired_holds_in_tx(&tx, now)?;

        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, u32, i64)> = tx
            .query_row(
                "SELECT key_id, ctx_cred, nullifier, active, request_count, window_started_at, window_hits, expires_at
                 FROM mole_sessions
                 WHERE session_token = ?1",
                params![session_token],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            key_id,
            ctx_cred,
            nullifier,
            active,
            req_count_i64,
            win_start,
            win_hits,
            expires_at,
        )) = row
        else {
            tx.commit()?;
            return Ok(SessionVerdict::InvalidOrExpired);
        };

        if active == 0 || expires_at <= now {
            tx.commit()?;
            return Ok(SessionVerdict::InvalidOrExpired);
        }

        let win_len = i64::try_from(policy.rate_window_secs.max(1)).unwrap_or(10);
        let (new_win_start, new_win_hits) = if now.saturating_sub(win_start) >= win_len {
            (now, 1u32)
        } else {
            (win_start, win_hits.saturating_add(1))
        };
        let new_req_count = (req_count_i64 as u64).saturating_add(1);

        if new_win_hits > policy.max_requests_per_window {
            // Rate limit breached! Invalidate session and immediately finalize held credential.
            tx.execute(
                "UPDATE mole_sessions
                 SET active = 0,
                     request_count = ?1,
                     window_started_at = ?2,
                     window_hits = ?3,
                     penalty_credits = ?4,
                     revoke_chain = ?5
                 WHERE session_token = ?6",
                params![
                    new_req_count as i64,
                    new_win_start,
                    new_win_hits,
                    policy.deposit_credits as i64,
                    i32::from(policy.revoke_chain_on_flood),
                    session_token
                ],
            )?;
            self.finalize_single_held_spend_in_tx(
                &tx,
                &key_id,
                &ctx_cred,
                &nullifier,
                policy.deposit_credits,
                policy.revoke_chain_on_flood,
                now,
            )?;
            tx.commit()?;
            return Ok(SessionVerdict::RateLimited);
        }

        tx.execute(
            "UPDATE mole_sessions
             SET request_count = ?1, window_started_at = ?2, window_hits = ?3
             WHERE session_token = ?4",
            params![
                new_req_count as i64,
                new_win_start,
                new_win_hits,
                session_token
            ],
        )?;
        tx.commit()?;
        Ok(SessionVerdict::Allowed)
    }

    /// Processes an `Authorization: Mole presentation-0001="..."` on a protected request.
    pub fn process_presentation(
        &self,
        public_origin: &str,
        method: &str,
        path_and_query: &str,
        policy: &ModerationPolicy,
        credential_type: CredentialType,
        presentation_bytes: &[u8],
    ) -> Result<PresentationVerdict, ModeratorError> {
        if credential_type != CredentialType::EC_ACT {
            return Ok(PresentationVerdict::RejectedUnauthorized);
        }

        let Ok((recv_key_id, spend_slice)) =
            EcActPresentationAndUpdate::split_key_id(presentation_bytes)
        else {
            return Ok(PresentationVerdict::Malformed(
                "PresentationAndUpdate too short",
            ));
        };

        if !bool::from(recv_key_id.ct_eq(&self.key_id)) {
            return Ok(PresentationVerdict::RejectedUnauthorized);
        }

        let Ok(spend) = ec_act::SpendMessage::from_bytes(&self.params, spend_slice) else {
            return Ok(PresentationVerdict::Malformed("malformed SpendMessage"));
        };

        let nullifier = spend.nullifier();
        let pres_sha256 = EcActPresentationAndUpdate::sha256(presentation_bytes);
        let now = unix_now();

        {
            let mut conn = self.conn.lock().expect("ModeratorStore mutex poisoned");
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            self.finalize_expired_holds_in_tx(&tx, now)?;
            if let Some(verdict) = self.lookup_existing_nullifier_in_tx(
                &tx,
                &recv_key_id,
                &nullifier,
                &pres_sha256,
                now,
            )? {
                tx.commit()?;
                return Ok(verdict);
            }
            tx.commit()?;
        }

        if spend.amount() != policy.deposit_credits || spend.allowance() != policy.max_top_up {
            return Ok(PresentationVerdict::RejectedUnauthorized);
        }

        let bucket = current_bucket(policy.challenge_window_secs);
        let buckets = [bucket, bucket.saturating_sub(1)];
        let mut verified_ctx_spend: Option<[u8; 32]> = None;
        let mut immediate_refund_bytes: Option<Vec<u8>> = None;

        for &b in &buckets {
            let chal = self.ec_act_challenge_for_bucket(
                public_origin,
                method,
                path_and_query,
                policy,
                b,
            );
            let Ok(ctx_spend) = chal.ctx_spend() else {
                continue;
            };
            if let Ok(verified) = ec_act::verify_spend(
                &self.params,
                &self.secret_key,
                &self.ctx_cred,
                &ctx_spend,
                &spend,
            ) {
                if policy.hold_duration_secs == 0 {
                    let refund = ec_act::issue_refund(verified, policy.deposit_credits)
                        .map_err(|_| ModeratorError::Internal("issue_refund failed"))?;
                    immediate_refund_bytes = Some((EcActUpdate { refund }).to_bytes());
                }
                verified_ctx_spend = Some(ctx_spend);
                break;
            }
        }

        let Some(ctx_spend) = verified_ctx_spend else {
            return Ok(PresentationVerdict::RejectedUnauthorized);
        };

        let mut conn = self.conn.lock().expect("ModeratorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(verdict) = self.lookup_existing_nullifier_in_tx(
            &tx,
            &recv_key_id,
            &nullifier,
            &pres_sha256,
            now,
        )? {
            tx.commit()?;
            return Ok(verdict);
        }

        let retention = i64::try_from(self.result_retention_secs).unwrap_or(300);

        if policy.hold_duration_secs == 0 {
            let refund_bytes = immediate_refund_bytes.expect("set when hold_duration_secs == 0");
            let result_expires_at = now.saturating_add(retention);
            tx.execute(
                "INSERT INTO spent_credentials
                 (key_id, ctx_cred, nullifier, presentation_sha256, state, spend_bytes, ctx_spend,
                  spend_amount, outcome_type, refund_bytes, held_until, result_expires_at)
                 VALUES (?1, ?2, ?3, ?4, 'finalized', NULL, NULL, ?5, 'refund', ?6, ?7, ?8)",
                params![
                    recv_key_id.as_slice(),
                    self.ctx_cred.as_slice(),
                    nullifier.as_slice(),
                    pres_sha256.as_slice(),
                    policy.deposit_credits as i64,
                    refund_bytes.as_slice(),
                    now,
                    result_expires_at
                ],
            )?;
            tx.commit()?;
            return Ok(PresentationVerdict::AcceptedFresh {
                session_token: None,
                mole_credential: MoleCredentialHeader::Update {
                    credential_type: CredentialType::EC_ACT,
                    update: Some(refund_bytes),
                },
            });
        }

        let hold_i64 = i64::try_from(policy.hold_duration_secs).unwrap_or(30);
        let held_until = now.saturating_add(hold_i64);
        let result_expires_at = held_until.saturating_add(retention);

        let mut tok_bytes = [0u8; 24];
        getrandom::fill(&mut tok_bytes).map_err(|_| ModeratorError::Internal("entropy failure"))?;
        let session_token = format_mole_session(&tok_bytes);

        tx.execute(
            "INSERT INTO spent_credentials
             (key_id, ctx_cred, nullifier, presentation_sha256, state, spend_bytes, ctx_spend,
              spend_amount, outcome_type, refund_bytes, held_until, result_expires_at)
             VALUES (?1, ?2, ?3, ?4, 'held', ?5, ?6, ?7, NULL, NULL, ?8, ?9)",
            params![
                recv_key_id.as_slice(),
                self.ctx_cred.as_slice(),
                nullifier.as_slice(),
                pres_sha256.as_slice(),
                spend_slice,
                ctx_spend.as_slice(),
                policy.deposit_credits as i64,
                held_until,
                result_expires_at
            ],
        )?;

        tx.execute(
            "INSERT INTO mole_sessions
             (session_token, key_id, ctx_cred, nullifier, active, request_count, window_started_at,
              window_hits, penalty_credits, revoke_chain, expires_at)
             VALUES (?1, ?2, ?3, ?4, 1, 1, ?5, 1, 0, 0, ?6)",
            params![
                session_token,
                recv_key_id.as_slice(),
                self.ctx_cred.as_slice(),
                nullifier.as_slice(),
                now,
                held_until
            ],
        )?;
        tx.commit()?;

        Ok(PresentationVerdict::AcceptedFresh {
            session_token: Some(session_token),
            mole_credential: MoleCredentialHeader::HeldForUpdate {
                credential_type: CredentialType::EC_ACT,
                duration_secs: policy.hold_duration_secs,
            },
        })
    }

    /// Processes `POST /mole/issue` with `Authorization: Mole signoff-0001="<handle>"`.
    ///
    /// Invalidates any active `Mole-Session` for this spend, finalizes the behavior-based
    /// refund (if still `'held'`), and returns `Mole-Credential: update-0001="..."`.
    pub fn process_signoff(
        &self,
        credential_type: CredentialType,
        handle_bytes: &[u8],
    ) -> Result<MoleCredentialHeader, ModeratorError> {
        self.resolve_handle(credential_type, handle_bytes, true)
    }

    /// Processes `POST /mole/issue` with `Authorization: Mole recovery-0001="<handle>"`
    /// (`draft-jms-mole-http-transport` §5.4).
    ///
    /// Never verifies a client proof or runs an upstream operation. If still `'held'`
    /// (`now < held_until`), returns `NotFound` (`404`) without altering the active hold.
    pub fn process_recovery(
        &self,
        credential_type: CredentialType,
        handle_bytes: &[u8],
    ) -> Result<MoleCredentialHeader, ModeratorError> {
        self.resolve_handle(credential_type, handle_bytes, false)
    }

    fn resolve_handle(
        &self,
        credential_type: CredentialType,
        handle_bytes: &[u8],
        settle_if_held: bool,
    ) -> Result<MoleCredentialHeader, ModeratorError> {
        if credential_type != CredentialType::EC_ACT {
            return Err(ModeratorError::BadRequest("unsupported handle credential-type"));
        }
        let handle = RecoveryHandle::from_bytes(handle_bytes)
            .map_err(|_| ModeratorError::BadRequest("malformed 96-byte RecoveryHandle"))?;
        if !bool::from(handle.key_id.ct_eq(&self.key_id)) {
            return Err(ModeratorError::NotFound);
        }

        let now = unix_now();
        let mut conn = self.conn.lock().expect("ModeratorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.finalize_expired_holds_in_tx(&tx, now)?;

        let Some(rec) = self.load_stored_spend_in_tx(&tx, &handle.key_id, &handle.nullifier)?
        else {
            tx.commit()?;
            return Err(ModeratorError::NotFound);
        };

        if !sha256_matches(&rec.presentation_sha256, &handle.presentation_sha256) {
            tx.commit()?;
            return Err(ModeratorError::NotFound);
        }

        if rec.state == "held" {
            if !settle_if_held {
                // Premature recovery before hold duration elapsed: return 404 without disturbing hold!
                tx.commit()?;
                return Err(ModeratorError::NotFound);
            }
            let hdr = self.deactivate_session_and_finalize_in_tx(
                &tx,
                &handle.key_id,
                &self.ctx_cred,
                &handle.nullifier,
                now,
            )?;
            tx.commit()?;
            return Ok(hdr);
        }

        tx.commit()?;
        if rec.state != "finalized" || now >= rec.result_expires_at {
            return Err(ModeratorError::NotFound);
        }
        outcome_to_credential_header(rec.outcome_type.as_deref(), rec.refund_bytes)
            .ok_or(ModeratorError::NotFound)
    }

    /// Background maintenance tick: finalizes any held credentials whose `held_until <= now`
    /// and wipes expired recovery payloads while retaining nullifiers.
    pub fn run_maintenance_tick(&self) -> Result<(), ModeratorError> {
        let now = unix_now();
        let mut conn = self.conn.lock().expect("ModeratorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.finalize_expired_holds_in_tx(&tx, now)?;
        // Delete expired recovery payloads while keeping nullifier tombstones (`draft-jms-mole-protocols` §5.2.5).
        tx.execute(
            "UPDATE spent_credentials
             SET outcome_type = 'expired', refund_bytes = NULL
             WHERE state = 'finalized' AND result_expires_at <= ?1 AND outcome_type != 'expired'",
            params![now],
        )?;
        tx.execute(
            "DELETE FROM mole_sessions WHERE active = 0 AND expires_at <= ?1",
            params![now],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn load_stored_spend_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key_id: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Result<Option<StoredSpendRecord>, ModeratorError> {
        tx.query_row(
            "SELECT presentation_sha256, state, outcome_type, refund_bytes, held_until, result_expires_at
             FROM spent_credentials
             WHERE key_id = ?1 AND ctx_cred = ?2 AND nullifier = ?3",
            params![key_id.as_slice(), self.ctx_cred.as_slice(), nullifier.as_slice()],
            |r| {
                Ok(StoredSpendRecord {
                    presentation_sha256: r.get(0)?,
                    state: r.get(1)?,
                    outcome_type: r.get(2)?,
                    refund_bytes: r.get(3)?,
                    held_until: r.get(4)?,
                    result_expires_at: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(ModeratorError::from)
    }

    fn lookup_existing_nullifier_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key_id: &[u8; 32],
        nullifier: &[u8; 32],
        pres_sha256: &[u8; 32],
        now: i64,
    ) -> Result<Option<PresentationVerdict>, ModeratorError> {
        let Some(rec) = self.load_stored_spend_in_tx(tx, key_id, nullifier)? else {
            return Ok(None);
        };

        if !sha256_matches(&rec.presentation_sha256, pres_sha256) || now >= rec.result_expires_at {
            return Ok(Some(PresentationVerdict::RejectedUnauthorized));
        }

        if rec.state == "held" {
            let rem = u64::try_from(rec.held_until.saturating_sub(now).max(1)).unwrap_or(1);
            return Ok(Some(PresentationVerdict::DuplicateRetained {
                mole_credential: MoleCredentialHeader::HeldForUpdate {
                    credential_type: CredentialType::EC_ACT,
                    duration_secs: rem,
                },
            }));
        }

        Ok(Some(
            match outcome_to_credential_header(rec.outcome_type.as_deref(), rec.refund_bytes) {
                Some(mole_credential) => {
                    PresentationVerdict::DuplicateRetained { mole_credential }
                }
                None => PresentationVerdict::RejectedUnauthorized,
            },
        ))
    }

    fn finalize_expired_holds_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        now: i64,
    ) -> Result<(), ModeratorError> {
        let expired: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT key_id, ctx_cred, nullifier
                 FROM spent_credentials
                 WHERE state = 'held' AND held_until <= ?1",
            )?;
            let iter = stmt.query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            iter.collect::<Result<Vec<_>, _>>()?
        };

        for (kid, cctx, nf) in expired {
            let _ = self.deactivate_session_and_finalize_in_tx(tx, &kid, &cctx, &nf, now)?;
        }
        Ok(())
    }

    fn deactivate_session_and_finalize_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key_id: &[u8],
        ctx_cred: &[u8],
        nullifier: &[u8],
        now: i64,
    ) -> Result<MoleCredentialHeader, ModeratorError> {
        let (penalty_i64, revoke): (i64, i32) = tx
            .query_row(
                "SELECT penalty_credits, revoke_chain FROM mole_sessions
                 WHERE key_id = ?1 AND ctx_cred = ?2 AND nullifier = ?3",
                params![key_id, ctx_cred, nullifier],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0));
        tx.execute(
            "UPDATE mole_sessions SET active = 0
             WHERE key_id = ?1 AND ctx_cred = ?2 AND nullifier = ?3",
            params![key_id, ctx_cred, nullifier],
        )?;
        self.finalize_single_held_spend_in_tx(
            tx,
            key_id,
            ctx_cred,
            nullifier,
            penalty_i64 as u64,
            revoke != 0,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_single_held_spend_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key_id: &[u8],
        ctx_cred: &[u8],
        nullifier: &[u8],
        penalty_credits: u64,
        revoke_chain: bool,
        now: i64,
    ) -> Result<MoleCredentialHeader, ModeratorError> {
        let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>, i64)> = tx
            .query_row(
                "SELECT spend_bytes, ctx_spend, spend_amount
                 FROM spent_credentials
                 WHERE key_id = ?1 AND ctx_cred = ?2 AND nullifier = ?3 AND state = 'held'",
                params![key_id, ctx_cred, nullifier],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((spend_opt, ctx_spend_opt, spend_amount_i64)) = row else {
            return Err(ModeratorError::NotFound);
        };
        let spend_amount = spend_amount_i64 as u64;
        let retention = i64::try_from(self.result_retention_secs).unwrap_or(300);
        let result_expires_at = now.saturating_add(retention);

        if revoke_chain {
            tx.execute(
                "UPDATE spent_credentials
                 SET state = 'finalized',
                     spend_bytes = NULL,
                     ctx_spend = NULL,
                     outcome_type = 'no_update',
                     refund_bytes = NULL,
                     result_expires_at = ?1
                 WHERE key_id = ?2 AND ctx_cred = ?3 AND nullifier = ?4",
                params![result_expires_at, key_id, ctx_cred, nullifier],
            )?;
            return Ok(MoleCredentialHeader::Update {
                credential_type: CredentialType::EC_ACT,
                update: None,
            });
        }

        let spend_bytes =
            spend_opt.ok_or(ModeratorError::Internal("missing held spend_bytes"))?;
        let ctx_spend = ctx_spend_opt.ok_or(ModeratorError::Internal("missing held ctx_spend"))?;
        let spend_msg = ec_act::SpendMessage::from_bytes(&self.params, &spend_bytes)
            .map_err(|_| ModeratorError::Internal("corrupt stored spend_bytes"))?;
        let verified =
            ec_act::verify_spend(&self.params, &self.secret_key, ctx_cred, &ctx_spend, &spend_msg)
                .map_err(|_| ModeratorError::Internal("stored spend failed re-verification"))?;
        let refund_amount = spend_amount.saturating_sub(penalty_credits);
        let refund_msg = ec_act::issue_refund(verified, refund_amount)
            .map_err(|_| ModeratorError::Internal("issue_refund failed during finalization"))?;
        let refund_bytes = (EcActUpdate { refund: refund_msg }).to_bytes();

        tx.execute(
            "UPDATE spent_credentials
             SET state = 'finalized',
                 spend_bytes = NULL,
                 ctx_spend = NULL,
                 outcome_type = 'refund',
                 refund_bytes = ?1,
                 result_expires_at = ?2
             WHERE key_id = ?3 AND ctx_cred = ?4 AND nullifier = ?5",
            params![
                refund_bytes.as_slice(),
                result_expires_at,
                key_id,
                ctx_cred,
                nullifier
            ],
        )?;

        Ok(MoleCredentialHeader::Update {
            credential_type: CredentialType::EC_ACT,
            update: Some(refund_bytes),
        })
    }
}

fn sha256_matches(stored: &[u8], expected: &[u8; 32]) -> bool {
    stored.len() == 32 && bool::from(stored.ct_eq(expected))
}

fn outcome_to_credential_header(
    outcome_type: Option<&str>,
    refund_bytes: Option<Vec<u8>>,
) -> Option<MoleCredentialHeader> {
    match outcome_type {
        Some("refund") => Some(MoleCredentialHeader::Update {
            credential_type: CredentialType::EC_ACT,
            update: Some(refund_bytes?),
        }),
        Some("no_update") => Some(MoleCredentialHeader::Update {
            credential_type: CredentialType::EC_ACT,
            update: None,
        }),
        _ => None,
    }
}

fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key is always valid");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn current_bucket(window_secs: u64) -> u64 {
    (unix_now().max(0) as u64) / window_secs.max(1)
}
