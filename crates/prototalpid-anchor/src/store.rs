//! SQLite persistence, single-use challenge verification, session quotas, and
//! AEAD-protected atomic single-claim `AnchorState` management for `prototalpid-anchor`.

#![allow(clippy::type_complexity)]

use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ec_ihat::{Backend as _, DefaultBackend as IhatBackend};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use prototalpid_http::challenge::{
    AnchorChallengeAccepted, AnchorChallengeOffer, AnchorChallengeSubmission, PowChallengeParams,
    PromptChallengeParams, verify_pow,
};
use prototalpid_http::unix_now;
use prototalpid_http::wire::{GrantChallenges, GrantCommitments, GrantResponses};

/// Challenge modes supported by `prototalpid-anchor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ChallengeMode {
    /// SHA-256 leading-zero-bits Proof-of-Work puzzle.
    Pow,
    /// Single-use interactive arithmetic/text question.
    Prompt,
    /// Offer both `pow` and `prompt` options; client may solve either.
    Both,
}

/// Errors produced by [`AnchorStore`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite error.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// Missing or expired `anchor_session` cookie.
    #[error("missing or expired anchor session")]
    Unauthorized,
    /// Endorsement quota exhausted (`429 Too Many Requests`).
    #[error("anchor endorsement quota exhausted")]
    QuotaExhausted,
    /// Challenge failed verification, expired, or was already consumed.
    #[error("challenge verification failed")]
    ChallengeFailed,
    /// Malformed request or grant session state.
    #[error("invalid grant request or session: {0}")]
    BadGrant(&'static str),
    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(&'static str),
}

/// Result of solving `/challenge`.
#[derive(Clone, Debug)]
pub struct SolvedSession {
    /// Cookie value for `anchor_session`.
    pub session_token: String,
    /// Accepted response body.
    pub accepted: AnchorChallengeAccepted,
}

/// SQLite-backed Anchor state store.
pub struct AnchorStore {
    conn: Mutex<Connection>,
    secret_key: ec_ihat::SecretKey,
    public_key: ec_ihat::PublicKey,
    aead_key: Zeroizing<[u8; 32]>,
    issuance_epoch: Vec<u8>,
}

impl AnchorStore {
    /// Opens or initializes an `AnchorStore` at `db_path` (or `:memory:` if `None`).
    pub fn open(db_path: Option<&Path>, default_epoch: &[u8]) -> Result<Self, StoreError> {
        let conn = match db_path {
            Some(path) => Connection::open(path)?,
            None => Connection::open_in_memory()?,
        };
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS anchor_keys (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 seed BLOB NOT NULL,
                 aead_key BLOB NOT NULL,
                 issuance_epoch BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS challenges (
                 challenge_id TEXT PRIMARY KEY,
                 pow_prefix BLOB,
                 pow_bits INTEGER,
                 expected_answer TEXT,
                 consumed INTEGER NOT NULL DEFAULT 0,
                 expires_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS anchor_sessions (
                 session_token TEXT PRIMARY KEY,
                 remaining_quota INTEGER NOT NULL,
                 total_issued INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS grant_sessions (
                 session_id BLOB PRIMARY KEY,
                 state_nonce BLOB,
                 state_ciphertext BLOB,
                 count INTEGER NOT NULL,
                 consumed INTEGER NOT NULL DEFAULT 0,
                 expires_at INTEGER NOT NULL
             );",
        )?;

        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT seed, aead_key, issuance_epoch FROM anchor_keys WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let (seed_arr, aead_arr, issuance_epoch) = if let Some((seed_vec, aead_vec, epoch)) = row {
            let mut s = Zeroizing::new([0u8; ec_ihat::SEED_LENGTH]);
            *s = seed_vec
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Crypto("corrupt stored anchor seed length"))?;
            let mut ak = Zeroizing::new([0u8; 32]);
            *ak = aead_vec
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Crypto("corrupt stored AEAD key length"))?;
            (s, ak, epoch)
        } else {
            let seed = IhatBackend::generate_seed()
                .map_err(|_| StoreError::Crypto("failed to generate anchor seed"))?;
            let ak = Zeroizing::new(random_bytes::<32>()?);
            let now = unix_now();
            conn.execute(
                "INSERT INTO anchor_keys (id, seed, aead_key, issuance_epoch, created_at)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                params![seed.as_slice(), ak.as_slice(), default_epoch, now],
            )?;
            (seed, ak, default_epoch.to_vec())
        };

        let secret_key: ec_ihat::SecretKey = ec_ihat::SecretKey::from_seed(&seed_arr)
            .map_err(|_| StoreError::Crypto("failed to derive EC-IHAT SecretKey"))?;
        let public_key = secret_key.public_key();

        Ok(Self {
            conn: Mutex::new(conn),
            secret_key,
            public_key,
            aead_key: aead_arr,
            issuance_epoch,
        })
    }

    /// Returns the Anchor's EC-IHAT `PublicKey`.
    pub fn public_key(&self) -> &ec_ihat::PublicKey {
        &self.public_key
    }

    /// Returns the configured `ctx_iss` (`issuance-epoch`).
    pub fn issuance_epoch(&self) -> &[u8] {
        &self.issuance_epoch
    }

    /// Checks whether `session_token` names an unexpired session and returns its
    /// remaining endorsement quota (`Some(0)` if exhausted, `None` if unknown/expired).
    pub fn check_session_quota(&self, session_token: &str) -> Result<Option<u32>, StoreError> {
        let now = unix_now();
        let conn = self.conn.lock().expect("AnchorStore mutex poisoned");
        conn.query_row(
            "SELECT remaining_quota FROM anchor_sessions
             WHERE session_token = ?1 AND expires_at > ?2",
            params![session_token, now],
            |r| r.get(0),
        )
        .optional()
        .map_err(StoreError::from)
    }

    /// Creates and persists a single-use challenge offer.
    pub fn create_challenge(
        &self,
        mode: ChallengeMode,
        pow_bits: u8,
        ttl_secs: u64,
    ) -> Result<AnchorChallengeOffer, StoreError> {
        let challenge_id = URL_SAFE_NO_PAD.encode(random_bytes::<16>()?);

        let pow = if matches!(mode, ChallengeMode::Pow | ChallengeMode::Both) {
            Some(PowChallengeParams {
                prefix: random_bytes::<16>()?.to_vec(),
                bits: pow_bits,
            })
        } else {
            None
        };

        let (prompt, expected_answer) =
            if matches!(mode, ChallengeMode::Prompt | ChallengeMode::Both) {
                let nums = random_bytes::<2>()?;
                let a = u32::from(nums[0] % 40) + 5;
                let b = u32::from(nums[1] % 40) + 5;
                (
                    Some(PromptChallengeParams {
                        question: format!("What is {a} + {b}?"),
                    }),
                    Some((a + b).to_string()),
                )
            } else {
                (None, None)
            };

        let now = unix_now();
        let expires_at = now.saturating_add(i64::try_from(ttl_secs).unwrap_or(300));
        let pow_prefix = pow.as_ref().map(|p| p.prefix.as_slice());
        let pow_bits_db = pow.as_ref().map(|p| u32::from(p.bits));

        let mut conn = self.conn.lock().expect("AnchorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM challenges WHERE expires_at <= ?1",
            params![now],
        )?;
        tx.execute(
            "INSERT INTO challenges (challenge_id, pow_prefix, pow_bits, expected_answer, consumed, expires_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![challenge_id, pow_prefix, pow_bits_db, expected_answer, expires_at],
        )?;
        tx.commit()?;

        Ok(AnchorChallengeOffer {
            challenge_id,
            pow,
            prompt,
        })
    }

    /// Atomically consumes a challenge, verifies its solution, and issues or tops up
    /// an `anchor_session` up to `max_quota_per_session`.
    pub fn verify_challenge_and_issue_session(
        &self,
        existing_session_token: Option<&str>,
        submission: &AnchorChallengeSubmission,
        quota_per_challenge: u32,
        max_quota_per_session: u32,
        session_ttl_secs: u64,
    ) -> Result<SolvedSession, StoreError> {
        let now = unix_now();
        let mut conn = self.conn.lock().expect("AnchorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let row: Option<(Option<Vec<u8>>, Option<u32>, Option<String>)> = tx
            .query_row(
                "SELECT pow_prefix, pow_bits, expected_answer
                 FROM challenges
                 WHERE challenge_id = ?1 AND consumed = 0 AND expires_at > ?2",
                params![submission.challenge_id, now],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((pow_prefix, pow_bits, expected_answer)) = row else {
            return Err(StoreError::ChallengeFailed);
        };

        // Single-use claim: burn the challenge whether the answer is right or wrong.
        let claimed = tx.execute(
            "UPDATE challenges SET consumed = 1 WHERE challenge_id = ?1 AND consumed = 0",
            params![submission.challenge_id],
        )?;
        if claimed != 1 {
            return Err(StoreError::ChallengeFailed);
        }

        let valid = match (submission.pow_nonce, submission.prompt_answer.as_deref()) {
            (Some(nonce), _) => pow_prefix
                .as_deref()
                .zip(pow_bits.and_then(|b| u8::try_from(b).ok()))
                .is_some_and(|(prefix, bits)| {
                    verify_pow(&submission.challenge_id, prefix, bits, nonce)
                }),
            (None, Some(ans)) => expected_answer
                .as_deref()
                .is_some_and(|exp| ans.trim().eq_ignore_ascii_case(exp.trim())),
            (None, None) => false,
        };

        if !valid {
            // Commit the burned challenge so an attacker cannot brute-force a prompt challenge!
            tx.commit()?;
            return Err(StoreError::ChallengeFailed);
        }

        let expires_at = now.saturating_add(i64::try_from(session_ttl_secs).unwrap_or(3600));

        if let Some(tok) = existing_session_token {
            let existing: Option<(u32, u32)> = tx
                .query_row(
                    "SELECT remaining_quota, total_issued FROM anchor_sessions
                     WHERE session_token = ?1 AND expires_at > ?2",
                    params![tok, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((rem, total)) = existing {
                if total >= max_quota_per_session {
                    tx.commit()?;
                    return Err(StoreError::QuotaExhausted);
                }
                let add = quota_per_challenge.min(max_quota_per_session - total);
                let new_rem = rem.saturating_add(add);
                let new_total = total.saturating_add(add);
                tx.execute(
                    "UPDATE anchor_sessions
                     SET remaining_quota = ?1, total_issued = ?2, expires_at = ?3
                     WHERE session_token = ?4",
                    params![new_rem, new_total, expires_at, tok],
                )?;
                tx.commit()?;
                return Ok(SolvedSession {
                    session_token: tok.to_owned(),
                    accepted: AnchorChallengeAccepted {
                        remaining_quota: new_rem,
                    },
                });
            }
        }

        let initial = quota_per_challenge.min(max_quota_per_session);
        if initial == 0 {
            tx.commit()?;
            return Err(StoreError::QuotaExhausted);
        }
        let session_token = URL_SAFE_NO_PAD.encode(random_bytes::<24>()?);
        tx.execute(
            "INSERT INTO anchor_sessions (session_token, remaining_quota, total_issued, expires_at)
             VALUES (?1, ?2, ?2, ?3)",
            params![session_token, initial, expires_at],
        )?;
        tx.commit()?;

        Ok(SolvedSession {
            session_token,
            accepted: AnchorChallengeAccepted {
                remaining_quota: initial,
            },
        })
    }

    /// Step 1 of EC-IHAT batch grant (`GrantRequest` -> `GrantCommitments`).
    pub fn begin_grant_batch(
        &self,
        session_token: &str,
        requested_count: u16,
        max_batch_size: u16,
        grant_ttl_secs: u64,
    ) -> Result<GrantCommitments, StoreError> {
        if requested_count == 0 {
            return Err(StoreError::BadGrant("GrantRequest count must be >= 1"));
        }
        let now = unix_now();
        let session_id = random_bytes::<32>()?;
        let nonce_bytes = random_bytes::<12>()?;

        let mut conn = self.conn.lock().expect("AnchorStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM grant_sessions WHERE expires_at <= ?1",
            params![now],
        )?;

        let remaining_quota: u32 = tx
            .query_row(
                "SELECT remaining_quota FROM anchor_sessions
                 WHERE session_token = ?1 AND expires_at > ?2",
                params![session_token, now],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::Unauthorized)?;
        if remaining_quota == 0 {
            return Err(StoreError::QuotaExhausted);
        }

        let grant_n = u32::from(requested_count.min(max_batch_size.max(1))).min(remaining_quota);
        let grant_n_usize = usize::try_from(grant_n).unwrap_or(0);
        if grant_n_usize == 0 {
            return Err(StoreError::QuotaExhausted);
        }

        let mut commitments = Vec::with_capacity(grant_n_usize);
        let mut states = Vec::with_capacity(grant_n_usize);
        for _ in 0..grant_n_usize {
            let (st, com) = ec_ihat::commit(&self.issuance_epoch)
                .map_err(|_| StoreError::Crypto("ec_ihat::commit failed"))?;
            states.push(st);
            commitments.push(com);
        }

        let plaintext = serialize_anchor_states(&states)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.aead_key.as_slice()));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &session_id,
                },
            )
            .map_err(|_| StoreError::Crypto("AnchorState AEAD encryption failed"))?;

        tx.execute(
            "UPDATE anchor_sessions SET remaining_quota = ?1 WHERE session_token = ?2",
            params![remaining_quota - grant_n, session_token],
        )?;

        let expires_at = now.saturating_add(i64::try_from(grant_ttl_secs).unwrap_or(120));
        tx.execute(
            "INSERT INTO grant_sessions (session_id, state_nonce, state_ciphertext, count, consumed, expires_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![
                session_id.as_slice(),
                nonce_bytes.as_slice(),
                ciphertext.as_slice(),
                grant_n,
                expires_at
            ],
        )?;
        tx.commit()?;

        Ok(GrantCommitments {
            session_id,
            commitments,
        })
    }

    /// Step 2 of EC-IHAT batch grant (`GrantChallenges` -> `GrantResponses`).
    ///
    /// Atomically claims and nullifies `state_ciphertext` inside a `BEGIN IMMEDIATE`
    /// transaction (`consumed = 1`) **before** decrypting or invoking `ec_ihat::respond`,
    /// guaranteeing that `AnchorState` can never be used twice (`draft-ladd-mole-ec-ihat` §5.3).
    pub fn complete_grant_batch(
        &self,
        grant_challenges: &GrantChallenges,
    ) -> Result<GrantResponses, StoreError> {
        let now = unix_now();
        let (nonce_vec, ciphertext_vec, expected_count) = {
            let mut conn = self.conn.lock().expect("AnchorStore mutex poisoned");
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>, u32, i64, i64)> = tx
                .query_row(
                    "SELECT state_nonce, state_ciphertext, count, consumed, expires_at
                     FROM grant_sessions
                     WHERE session_id = ?1",
                    params![grant_challenges.session_id.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;

            let Some((nonce_opt, ct_opt, count, consumed, expires_at)) = row else {
                return Err(StoreError::BadGrant("unknown grant session_id"));
            };
            if consumed != 0 || expires_at <= now {
                return Err(StoreError::BadGrant("grant session already consumed or expired"));
            }
            let (Some(nonce_vec), Some(ct_vec)) = (nonce_opt, ct_opt) else {
                return Err(StoreError::BadGrant("missing AnchorState ciphertext"));
            };

            let updated = tx.execute(
                "UPDATE grant_sessions
                 SET consumed = 1, state_nonce = NULL, state_ciphertext = NULL
                 WHERE session_id = ?1 AND consumed = 0",
                params![grant_challenges.session_id.as_slice()],
            )?;
            if updated != 1 {
                return Err(StoreError::BadGrant("concurrent grant session claim lost"));
            }
            // Commit tombstone BEFORE decrypting or touching `ec_ihat::respond`!
            tx.commit()?;
            (nonce_vec, ct_vec, count as usize)
        };

        if grant_challenges.challenges.len() != expected_count {
            return Err(StoreError::BadGrant(
                "GrantChallenges count does not match batch state count",
            ));
        }

        let nonce_arr: &[u8; 12] = nonce_vec
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Crypto("invalid stored AEAD nonce length"))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.aead_key.as_slice()));
        let decrypted = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce_arr),
                    Payload {
                        msg: ciphertext_vec.as_slice(),
                        aad: &grant_challenges.session_id,
                    },
                )
                .map_err(|_| StoreError::Crypto("AnchorState AEAD authentication failed"))?,
        );

        let states = deserialize_anchor_states(&decrypted)?;
        if states.len() != expected_count {
            return Err(StoreError::Crypto("stored AnchorState count mismatch"));
        }

        let responses = states
            .into_iter()
            .zip(&grant_challenges.challenges)
            .map(|(state, challenge)| {
                ec_ihat::respond(&self.secret_key, state, challenge)
                    .map_err(|_| StoreError::BadGrant("ec_ihat::respond rejected challenge"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GrantResponses { responses })
    }

    /// Test helper returning expected prompt answer for `challenge_id`, if unconsumed.
    pub fn peek_prompt_answer_for_test(
        &self,
        challenge_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().expect("AnchorStore mutex poisoned");
        let ans: Option<Option<String>> = conn
            .query_row(
                "SELECT expected_answer FROM challenges WHERE challenge_id = ?1 AND consumed = 0",
                params![challenge_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(ans.flatten())
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| StoreError::Crypto("entropy failure"))?;
    Ok(out)
}

fn serialize_anchor_states(
    states: &[ec_ihat::AnchorState],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let count_u16 =
        u16::try_from(states.len()).map_err(|_| StoreError::BadGrant("batch too large"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(2 + states.len() * 140));
    out.extend_from_slice(&count_u16.to_be_bytes());
    for st in states {
        let encoded = st.to_bytes();
        let len_u32 =
            u32::try_from(encoded.len()).map_err(|_| StoreError::Crypto("state len overflow"))?;
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(encoded.as_slice());
    }
    Ok(out)
}

fn deserialize_anchor_states(bytes: &[u8]) -> Result<Vec<ec_ihat::AnchorState>, StoreError> {
    let (&count_bytes, mut rest) = bytes
        .split_first_chunk::<2>()
        .ok_or(StoreError::Crypto("truncated AnchorState batch"))?;
    let count = usize::from(u16::from_be_bytes(count_bytes));
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (&len_bytes, after_len) = rest
            .split_first_chunk::<4>()
            .ok_or(StoreError::Crypto("truncated state len"))?;
        let len = usize::try_from(u32::from_be_bytes(len_bytes))
            .map_err(|_| StoreError::Crypto("state len overflow"))?;
        let (slice, next_rest) = after_len
            .split_at_checked(len)
            .ok_or(StoreError::Crypto("truncated state bytes"))?;
        rest = next_rest;
        out.push(
            ec_ihat::AnchorState::from_bytes(slice)
                .map_err(|_| StoreError::Crypto("invalid stored AnchorState encoding"))?,
        );
    }
    if !rest.is_empty() {
        return Err(StoreError::Crypto("trailing bytes in stored AnchorState batch"));
    }
    Ok(out)
}
