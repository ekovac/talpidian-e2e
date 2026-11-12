//! Persistent SQLite wallet & cookie jar for `prototalpid-cli` (XDG-backed with `0600`
//! permissions on Unix).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cookie::Cookie;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use url::Url;

use prototalpid_http::config::{
    AnchorConfiguration, ModeratorConfiguration, canonical_https_origin,
};
use prototalpid_http::schemes::{CredentialType, EndorsementType, derive_ec_act_ctx_cred};
use prototalpid_http::unix_now;
use prototalpid_http::wire::{EcActUpdate, RecoveryHandle};

/// Default XDG prefix directory name (`$XDG_DATA_HOME/prototalpid/state.db`).
pub const XDG_APP_PREFIX: &str = "prototalpid";
/// Default database filename inside XDG data home.
pub const DEFAULT_DB_FILENAME: &str = "state.db";

/// Resolves the default XDG database path (`$XDG_DATA_HOME/prototalpid/state.db`).
pub fn default_store_path() -> anyhow::Result<PathBuf> {
    let xdg_dirs = xdg::BaseDirectories::with_prefix(XDG_APP_PREFIX);
    let path = xdg_dirs.place_data_file(DEFAULT_DB_FILENAME)?;
    Ok(path)
}

/// Summary snapshot of the CLI store for `--mole-status` and tests.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoreStatus {
    /// Count of unspent endorsements by Anchor origin.
    pub endorsements: Vec<EndorsementSummary>,
    /// Usable EC-ACT credentials.
    pub credentials: Vec<CredentialSummary>,
    /// In-flight or held EC-ACT spends / active `Mole-Session`s.
    pub pending_spends: Vec<PendingSpendSummary>,
    /// Stored HTTP cookies.
    pub cookie_count: usize,
}

/// Summary of endorsements per Anchor origin.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EndorsementSummary {
    /// Anchor HTTPS origin.
    pub anchor_origin: String,
    /// Endorsement type (`2` = EC-IHAT).
    pub endorsement_type: u16,
    /// Number of stored single-use endorsements.
    pub count: usize,
}

/// Summary of a usable EC-ACT credential.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CredentialSummary {
    /// Moderator HTTPS origin.
    pub moderator_origin: String,
    /// Remaining credit balance `c`.
    pub balance: u64,
    /// Number of presentations completed in this chain.
    pub presentations_count: u64,
}

/// Summary of a pending (`in_flight` or `held`) spend.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingSpendSummary {
    /// Moderator HTTPS origin.
    pub moderator_origin: String,
    /// `'in_flight'` or `'held'`.
    pub state: String,
    /// Active `Mole-Session` token, if held.
    pub session_token: Option<String>,
    /// UNIX timestamp when hold expires, if held.
    pub held_until: Option<i64>,
    /// Pre-refund remainder `c - s`.
    pub remainder_balance: u64,
}

/// Loaded pending spend record for recovery / signoff / session attachment.
#[derive(Clone, Debug)]
pub struct PendingSpendRecord {
    /// Moderator HTTPS origin.
    pub moderator_origin: String,
    /// Redeem & Issue / Signoff / Recovery endpoint URI.
    pub issuance_uri: String,
    /// Credential type (`0x0001`).
    pub credential_type: CredentialType,
    /// 32-byte `key_id`.
    pub key_id: [u8; 32],
    /// 33-byte compressed `pkM`.
    pub public_key_bytes: [u8; 33],
    /// Balance width `L`.
    pub balance_width: u8,
    /// Configured `credential_context`.
    pub credential_context: Vec<u8>,
    /// Encoded `ec_act::ClientSpendState`.
    pub spend_state_bytes: Vec<u8>,
    /// Encoded `EcActPresentationAndUpdate` octets.
    pub presentation_bytes: Vec<u8>,
    /// 96-byte `RecoveryHandle`.
    pub recovery_handle: RecoveryHandle,
    /// Presentations count prior to this spend.
    pub presentations_count: u64,
    /// `'in_flight'` or `'held'`.
    pub state: String,
    /// Active `Mole-Session` token when `state == "held"`.
    pub session_token: Option<String>,
    /// UNIX expiry timestamp when `state == "held"`.
    pub held_until: Option<i64>,
    /// Original HTTP method.
    pub original_method: String,
    /// Original target URL.
    pub original_url: String,
}

/// Loaded usable EC-ACT credential record.
pub struct UsableCredential {
    /// Row ID in `credentials`.
    pub id: i64,
    /// Decoded `ec_act::Credential`.
    pub credential: ec_act::Credential,
    /// Presentations completed so far on this chain.
    pub presentations_count: u64,
}

/// Persistent SQLite store for `prototalpid-cli`.
pub struct WalletStore {
    conn: Mutex<Connection>,
}

impl WalletStore {
    /// Opens or creates the SQLite wallet store at `path` (setting `0600` permissions on Unix).
    pub fn open(path: Option<&Path>) -> anyhow::Result<Self> {
        let conn = match path {
            Some(p) => {
                if let Some(parent) = p.parent()
                    && !parent.as_os_str().is_empty()
                {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        let mut builder = fs::DirBuilder::new();
                        builder.recursive(true).mode(0o700);
                        builder.create(parent)?;
                    }
                    #[cfg(not(unix))]
                    {
                        fs::create_dir_all(parent)?;
                    }
                }
                let c = Connection::open(p)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o600));
                }
                c
            }
            None => Connection::open_in_memory()?,
        };

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS cookies (
                 host TEXT NOT NULL,
                 path TEXT NOT NULL,
                 name TEXT NOT NULL,
                 value TEXT NOT NULL,
                 secure INTEGER NOT NULL,
                 http_only INTEGER NOT NULL,
                 expires_at INTEGER,
                 PRIMARY KEY (host, path, name)
             );

             CREATE TABLE IF NOT EXISTS anchor_configs (
                 anchor_origin TEXT PRIMARY KEY,
                 config_json TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS moderator_configs (
                 moderator_origin TEXT PRIMARY KEY,
                 config_json TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS endorsements (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 anchor_origin TEXT NOT NULL,
                 endorsement_type INTEGER NOT NULL,
                 anchor_pk BLOB NOT NULL,
                 ctx_iss BLOB NOT NULL,
                 endorsement_bytes BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS credentials (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 moderator_origin TEXT NOT NULL,
                 issuance_uri TEXT NOT NULL,
                 credential_type INTEGER NOT NULL,
                 key_id BLOB NOT NULL,
                 public_key BLOB NOT NULL,
                 balance_width INTEGER NOT NULL,
                 credential_context BLOB NOT NULL,
                 balance INTEGER NOT NULL,
                 credential_bytes BLOB NOT NULL,
                 presentations_count INTEGER NOT NULL DEFAULT 0,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS pending_spends (
                 moderator_origin TEXT PRIMARY KEY,
                 issuance_uri TEXT NOT NULL,
                 credential_type INTEGER NOT NULL,
                 key_id BLOB NOT NULL,
                 public_key BLOB NOT NULL,
                 balance_width INTEGER NOT NULL,
                 credential_context BLOB NOT NULL,
                 spend_state_bytes BLOB NOT NULL,
                 presentation_bytes BLOB NOT NULL,
                 recovery_handle BLOB NOT NULL,
                 presentations_count INTEGER NOT NULL,
                 state TEXT NOT NULL,
                 session_token TEXT,
                 held_until INTEGER,
                 original_method TEXT NOT NULL,
                 original_url TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // -----------------------------------------------------------------------
    // Cookie Jar
    // -----------------------------------------------------------------------

    /// Stores `Set-Cookie` headers received from `url`.
    pub fn store_set_cookies<'a, I>(&self, url: &Url, set_cookie_headers: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let Some(default_host) = url.host_str().map(|h| h.to_ascii_lowercase()) else {
            return Ok(());
        };
        let now = unix_now();
        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        for raw in set_cookie_headers {
            let Ok(parsed) = Cookie::parse(raw) else {
                continue;
            };
            let name = parsed.name();
            if name.is_empty() {
                continue;
            }
            let path = parsed
                .path()
                .filter(|p| p.starts_with('/'))
                .unwrap_or("/")
                .to_owned();
            let host = parsed
                .domain()
                .map(|d| d.trim_start_matches('.').to_ascii_lowercase())
                .filter(|clean| {
                    default_host == *clean || default_host.ends_with(&format!(".{clean}"))
                })
                .unwrap_or_else(|| default_host.clone());
            let expires_at = parsed
                .max_age()
                .map(|d| now.saturating_add(d.whole_seconds()));

            if expires_at.is_some_and(|exp| exp <= now) {
                tx.execute(
                    "DELETE FROM cookies WHERE host = ?1 AND path = ?2 AND name = ?3",
                    params![host, path, name],
                )?;
                continue;
            }

            tx.execute(
                "INSERT INTO cookies (host, path, name, value, secure, http_only, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(host, path, name) DO UPDATE SET
                     value = excluded.value,
                     secure = excluded.secure,
                     http_only = excluded.http_only,
                     expires_at = excluded.expires_at",
                params![
                    host,
                    path,
                    name,
                    parsed.value(),
                    i32::from(parsed.secure().unwrap_or(false)),
                    i32::from(parsed.http_only().unwrap_or(false)),
                    expires_at
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Formats the `Cookie` request header value for `url`, if matching cookies exist.
    pub fn cookie_header_for_url(&self, url: &Url) -> anyhow::Result<Option<String>> {
        let Some(req_host) = url.host_str().map(|h| h.to_ascii_lowercase()) else {
            return Ok(None);
        };
        let req_path = url.path();
        let is_https = url.scheme() == "https";
        let now = unix_now();

        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT host, path, name, value, secure, expires_at FROM cookies",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i32>(4)? != 0,
                r.get::<_, Option<i64>>(5)?,
            ))
        })?;

        let mut pairs = Vec::new();
        for row in rows {
            let (host, path, name, value, secure, expires_at) = row?;
            if let Some(exp) = expires_at
                && exp <= now
            {
                continue;
            }
            if secure && !is_https {
                continue;
            }
            let host_matches = req_host == host || req_host.ends_with(&format!(".{host}"));
            let path_matches = req_path.starts_with(&path);
            if host_matches && path_matches {
                pairs.push(format!("{name}={value}"));
            }
        }
        if pairs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(pairs.join("; ")))
        }
    }

    /// Exports cookies in Netscape / `curl -c` cookie-jar format.
    pub fn export_cookie_jar(&self, path: &Path) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT host, path, secure, expires_at, name, value FROM cookies ORDER BY host, path, name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i32>(2)? != 0,
                r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = String::from("# Netscape HTTP Cookie File\n");
        for r in rows {
            let (host, p, sec, exp, name, val) = r?;
            let sec_str = if sec { "TRUE" } else { "FALSE" };
            out.push_str(&format!("{host}\tFALSE\t{p}\t{sec_str}\t{exp}\t{name}\t{val}\n"));
        }
        fs::write(path, out)?;
        Ok(())
    }

    /// Imports cookies from a Netscape cookie-jar file (`-b <file>`).
    pub fn import_cookie_jar(&self, path: &Path) -> anyhow::Result<()> {
        let text = fs::read_to_string(path)?;
        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = trimmed.split('\t').collect();
            if cols.len() == 7 {
                let host = cols[0].trim_start_matches('.').to_ascii_lowercase();
                let cookie_path = cols[2];
                let secure = i32::from(cols[3].eq_ignore_ascii_case("TRUE"));
                let exp_raw = cols[4].parse::<i64>().unwrap_or(0);
                let expires_at = if exp_raw > 0 { Some(exp_raw) } else { None };
                let name = cols[5];
                let val = cols[6];
                tx.execute(
                    "INSERT INTO cookies (host, path, name, value, secure, http_only, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)
                     ON CONFLICT(host, path, name) DO UPDATE SET
                         value = excluded.value,
                         secure = excluded.secure,
                         expires_at = excluded.expires_at",
                    params![host, cookie_path, name, val, secure, expires_at],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Configurations
    // -----------------------------------------------------------------------

    /// Caches an `AnchorConfiguration`.
    pub fn save_anchor_config(
        &self,
        anchor_origin: &str,
        cfg: &AnchorConfiguration,
    ) -> anyhow::Result<()> {
        let json = serde_json::to_string(cfg)?;
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        conn.execute(
            "INSERT INTO anchor_configs (anchor_origin, config_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(anchor_origin) DO UPDATE SET
                 config_json = excluded.config_json,
                 updated_at = excluded.updated_at",
            params![anchor_origin, json, unix_now()],
        )?;
        Ok(())
    }

    /// Loads a cached `ModeratorConfiguration`, if present.
    pub fn load_moderator_config(
        &self,
        moderator_origin: &str,
    ) -> anyhow::Result<Option<ModeratorConfiguration>> {
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let json_opt: Option<String> = conn
            .query_row(
                "SELECT config_json FROM moderator_configs WHERE moderator_origin = ?1",
                params![moderator_origin],
                |r| r.get(0),
            )
            .optional()?;
        match json_opt {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    /// Caches a `ModeratorConfiguration` and discards any usable credentials whose
    /// `(key_id, credential_context)` is no longer accepted (`draft-jms-mole-protocols` §5.2.4).
    pub fn save_moderator_config(
        &self,
        moderator_origin: &str,
        cfg: &ModeratorConfiguration,
    ) -> anyhow::Result<()> {
        let (_, _, active_keys) = cfg.parse_supported()?;
        let json = serde_json::to_string(cfg)?;
        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO moderator_configs (moderator_origin, config_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(moderator_origin) DO UPDATE SET
                 config_json = excluded.config_json,
                 updated_at = excluded.updated_at",
            params![moderator_origin, json, unix_now()],
        )?;

        // Purge retired usable credentials for this Moderator.
        let existing_ids: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT id, key_id, credential_context FROM credentials WHERE moderator_origin = ?1",
            )?;
            let rows =
                stmt.query_map(params![moderator_origin], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (row_id, kid, cctx) in existing_ids {
            let still_active = active_keys
                .iter()
                .any(|k| k.key_id.as_slice() == kid.as_slice() && k.config.credential_context == cctx);
            if !still_active {
                tx.execute("DELETE FROM credentials WHERE id = ?1", params![row_id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Endorsements
    // -----------------------------------------------------------------------

    /// Saves a batch of newly finalized EC-IHAT Endorsements.
    pub fn save_ec_ihat_endorsements(
        &self,
        anchor_origin: &str,
        anchor_pk: &ec_ihat::PublicKey,
        ctx_iss: &[u8],
        endorsements: &[ec_ihat::Endorsement],
    ) -> anyhow::Result<()> {
        let pk_bytes = anchor_pk.to_bytes();
        let now = unix_now();
        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for end in endorsements {
            let encoded = end.to_bytes();
            tx.execute(
                "INSERT INTO endorsements
                 (anchor_origin, endorsement_type, anchor_pk, ctx_iss, endorsement_bytes, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    anchor_origin,
                    EndorsementType::EC_IHAT.0,
                    pk_bytes.as_slice(),
                    ctx_iss,
                    encoded.as_slice(),
                    now
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Atomically selects and **burns** one stored EC-IHAT Endorsement matching
    /// `(anchor_set, ctx_iss)`, returning `(anchor_index, Endorsement)`.
    pub fn take_matching_ec_ihat_endorsement(
        &self,
        anchor_set: &[ec_ihat::PublicKey],
        ctx_iss: &[u8],
    ) -> anyhow::Result<Option<(usize, ec_ihat::Endorsement)>> {
        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let candidates: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT id, anchor_pk, endorsement_bytes
                 FROM endorsements
                 WHERE endorsement_type = ?1 AND ctx_iss = ?2
                 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![EndorsementType::EC_IHAT.0, ctx_iss], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        for (row_id, pk_vec, end_bytes) in candidates {
            if let Some(index) = anchor_set
                .iter()
                .position(|pk| pk.to_bytes().as_slice() == pk_vec.as_slice())
            {
                let deleted = tx.execute("DELETE FROM endorsements WHERE id = ?1", params![row_id])?;
                if deleted == 1 {
                    let endorsement = ec_ihat::Endorsement::from_bytes(&end_bytes)
                        .map_err(|e| anyhow::anyhow!("corrupt stored endorsement: {e}"))?;
                    tx.commit()?;
                    return Ok(Some((index, endorsement)));
                }
            }
        }

        tx.commit()?;
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Credentials & Pending Spends
    // -----------------------------------------------------------------------

    /// Saves a newly issued EC-ACT Credential.
    #[allow(clippy::too_many_arguments)]
    pub fn save_issued_credential(
        &self,
        moderator_origin: &str,
        issuance_uri: &str,
        key_id: &[u8; 32],
        public_key: &ec_act::PublicKey,
        balance_width: u8,
        credential_context: &[u8],
        credential: &ec_act::Credential,
    ) -> anyhow::Result<()> {
        let cred_bytes = credential.to_bytes();
        let pk_bytes = public_key.to_bytes();
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        conn.execute(
            "INSERT INTO credentials
             (moderator_origin, issuance_uri, credential_type, key_id, public_key,
              balance_width, credential_context, balance, credential_bytes, presentations_count, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10)",
            params![
                moderator_origin,
                issuance_uri,
                CredentialType::EC_ACT.0,
                key_id.as_slice(),
                pk_bytes.as_slice(),
                balance_width,
                credential_context,
                credential.balance() as i64,
                cred_bytes.as_slice(),
                unix_now()
            ],
        )?;
        Ok(())
    }

    /// Finds a usable EC-ACT Credential for `(moderator_origin, key_id, credential_context)`
    /// covering `spend_amount` and allowing `max_top_up` without overflowing `2^L`.
    pub fn find_usable_credential(
        &self,
        moderator_origin: &str,
        key_id: &[u8; 32],
        credential_context: &[u8],
        balance_width: u8,
        spend_amount: u64,
        max_top_up: u64,
    ) -> anyhow::Result<Option<UsableCredential>> {
        let params = ec_act::Params::new(balance_width)?;
        let max_val = params.max_amount();

        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, balance, credential_bytes, presentations_count
             FROM credentials
             WHERE moderator_origin = ?1
               AND credential_type = ?2
               AND key_id = ?3
               AND credential_context = ?4
             ORDER BY balance DESC, id ASC",
        )?;
        let rows = stmt.query_map(
            params![
                moderator_origin,
                CredentialType::EC_ACT.0,
                key_id.as_slice(),
                credential_context
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)? as u64,
                ))
            },
        )?;

        for row in rows {
            let (id, bal, cred_bytes, pres_count) = row?;
            if bal < spend_amount {
                continue;
            }
            if bal.checked_add(max_top_up).is_none_or(|sum| sum > max_val) {
                continue;
            }
            let credential = ec_act::Credential::from_bytes(&params, &cred_bytes)?;
            return Ok(Some(UsableCredential {
                id,
                credential,
                presentations_count: pres_count,
            }));
        }
        Ok(None)
    }

    /// Atomically consumes a usable Credential row and persists `pending_spends`
    /// (`state = 'in_flight'`) **before** the presentation leaves the Client
    /// (`draft-jms-mole-protocols` §5.2.4).
    #[allow(clippy::too_many_arguments)]
    pub fn commit_in_flight_spend(
        &self,
        consumed_credential_id: i64,
        moderator_origin: &str,
        issuance_uri: &str,
        key_id: &[u8; 32],
        public_key: &ec_act::PublicKey,
        balance_width: u8,
        credential_context: &[u8],
        spend_state: &ec_act::ClientSpendState,
        presentation_bytes: &[u8],
        recovery_handle: &RecoveryHandle,
        presentations_count: u64,
        original_method: &str,
        original_url: &str,
    ) -> anyhow::Result<()> {
        let state_bytes = spend_state.to_bytes();
        let pk_bytes = public_key.to_bytes();
        let handle_bytes = recovery_handle.to_bytes();
        let now = unix_now();

        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted = tx.execute(
            "DELETE FROM credentials WHERE id = ?1",
            params![consumed_credential_id],
        )?;
        if deleted != 1 {
            anyhow::bail!("usable credential row vanished before spend commit");
        }
        tx.execute(
            "INSERT INTO pending_spends
             (moderator_origin, issuance_uri, credential_type, key_id, public_key,
              balance_width, credential_context, spend_state_bytes, presentation_bytes,
              recovery_handle, presentations_count, state, session_token, held_until,
              original_method, original_url, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'in_flight', NULL, NULL, ?12, ?13, ?14)",
            params![
                moderator_origin,
                issuance_uri,
                CredentialType::EC_ACT.0,
                key_id.as_slice(),
                pk_bytes.as_slice(),
                balance_width,
                credential_context,
                state_bytes.as_slice(),
                presentation_bytes,
                handle_bytes.as_slice(),
                presentations_count as i64,
                original_method,
                original_url,
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Transitions an `in_flight` spend to `'held'` with `Mole-Session` and `held_until`.
    pub fn mark_spend_held(
        &self,
        moderator_origin: &str,
        session_token: Option<&str>,
        duration_secs: u64,
    ) -> anyhow::Result<()> {
        let now = unix_now();
        let held_until = now.saturating_add(i64::try_from(duration_secs).unwrap_or(0));
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        conn.execute(
            "UPDATE pending_spends
             SET state = 'held', session_token = ?1, held_until = ?2
             WHERE moderator_origin = ?3",
            params![session_token, held_until, moderator_origin],
        )?;
        Ok(())
    }

    /// Loads the `PendingSpendRecord` for `moderator_origin`, if one exists.
    pub fn get_pending_spend(
        &self,
        moderator_origin: &str,
    ) -> anyhow::Result<Option<PendingSpendRecord>> {
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let row = conn
            .query_row(
                "SELECT issuance_uri, credential_type, key_id, public_key, balance_width,
                        credential_context, spend_state_bytes, presentation_bytes, recovery_handle,
                        presentations_count, state, session_token, held_until, original_method, original_url
                 FROM pending_spends
                 WHERE moderator_origin = ?1",
                params![moderator_origin],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, u16>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, u8>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, Vec<u8>>(7)?,
                        r.get::<_, Vec<u8>>(8)?,
                        r.get::<_, i64>(9)? as u64,
                        r.get::<_, String>(10)?,
                        r.get::<_, Option<String>>(11)?,
                        r.get::<_, Option<i64>>(12)?,
                        r.get::<_, String>(13)?,
                        r.get::<_, String>(14)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            issuance_uri,
            ct,
            kid_vec,
            pk_vec,
            bw,
            cctx,
            spend_state_bytes,
            presentation_bytes,
            handle_vec,
            presentations_count,
            state,
            session_token,
            held_until,
            original_method,
            original_url,
        )) = row
        else {
            return Ok(None);
        };

        let key_id: [u8; 32] = kid_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt pending key_id"))?;
        let public_key_bytes: [u8; 33] = pk_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt pending public_key"))?;
        let recovery_handle = RecoveryHandle::from_bytes(&handle_vec)?;

        Ok(Some(PendingSpendRecord {
            moderator_origin: moderator_origin.to_owned(),
            issuance_uri,
            credential_type: CredentialType(ct),
            key_id,
            public_key_bytes,
            balance_width: bw,
            credential_context: cctx,
            spend_state_bytes,
            presentation_bytes,
            recovery_handle,
            presentations_count,
            state,
            session_token,
            held_until,
            original_method,
            original_url,
        }))
    }

    /// Lists all Moderator origins currently having a `'held'` or `'in_flight'` spend.
    pub fn list_pending_origins(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT moderator_origin FROM pending_spends ORDER BY moderator_origin")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Finalizes a pending spend with `update_opt` (`Some(bytes)` -> `FinalizeRefund`,
    /// `None` -> `NoUpdate` chain termination), atomically updating SQLite.
    ///
    /// Returns `Ok(Some(new_balance))` if replaced, or `Ok(None)` on `NoUpdate`.
    pub fn settle_pending_spend_with_update(
        &self,
        moderator_origin: &str,
        update_opt: Option<&[u8]>,
    ) -> anyhow::Result<Option<u64>> {
        let Some(rec) = self.get_pending_spend(moderator_origin)? else {
            return Ok(None);
        };

        let replacement: Option<(u64, zeroize::Zeroizing<Vec<u8>>)> = match update_opt {
            None => None,
            Some(upd_bytes) => {
                let params = ec_act::Params::new(rec.balance_width)?;
                let pk_m = ec_act::PublicKey::from_bytes(&rec.public_key_bytes)?;
                let ctx_cred =
                    derive_ec_act_ctx_cred(&rec.credential_context, rec.balance_width)?;
                let spend_state =
                    ec_act::ClientSpendState::from_bytes(&params, &rec.spend_state_bytes)?;
                let upd = EcActUpdate::from_bytes(&params, upd_bytes)?;
                let new_cred =
                    ec_act::finalize_refund(&params, &pk_m, &ctx_cred, spend_state, &upd.refund)?;
                let bal = new_cred.balance();
                Some((bal, new_cred.to_bytes()))
            }
        };

        let mut conn = self.conn.lock().expect("WalletStore mutex poisoned");
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM pending_spends WHERE moderator_origin = ?1",
            params![moderator_origin],
        )?;
        if let Some((bal, ref cred_bytes)) = replacement {
            tx.execute(
                "INSERT INTO credentials
                 (moderator_origin, issuance_uri, credential_type, key_id, public_key,
                  balance_width, credential_context, balance, credential_bytes, presentations_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    moderator_origin,
                    rec.issuance_uri,
                    rec.credential_type.0,
                    rec.key_id.as_slice(),
                    rec.public_key_bytes.as_slice(),
                    rec.balance_width,
                    rec.credential_context.as_slice(),
                    bal as i64,
                    cred_bytes.as_slice(),
                    (rec.presentations_count + 1) as i64,
                    unix_now()
                ],
            )?;
            tx.commit()?;
            Ok(Some(bal))
        } else {
            tx.commit()?;
            Ok(None)
        }
    }

    /// Discards an unrecoverable pending spend (`404` after retention expiry).
    pub fn discard_pending_spend(&self, moderator_origin: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");
        conn.execute(
            "DELETE FROM pending_spends WHERE moderator_origin = ?1",
            params![moderator_origin],
        )?;
        Ok(())
    }

    /// Produces a structured summary of wallet state for `--mole-status` and tests.
    pub fn status_summary(&self) -> anyhow::Result<StoreStatus> {
        let conn = self.conn.lock().expect("WalletStore mutex poisoned");

        let endorsements = {
            let mut stmt = conn.prepare(
                "SELECT anchor_origin, endorsement_type, COUNT(*)
                 FROM endorsements
                 GROUP BY anchor_origin, endorsement_type
                 ORDER BY anchor_origin",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(EndorsementSummary {
                    anchor_origin: r.get(0)?,
                    endorsement_type: r.get(1)?,
                    count: r.get::<_, i64>(2)? as usize,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let credentials = {
            let mut stmt = conn.prepare(
                "SELECT moderator_origin, balance, presentations_count
                 FROM credentials
                 ORDER BY moderator_origin, id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(CredentialSummary {
                    moderator_origin: r.get(0)?,
                    balance: r.get::<_, i64>(1)? as u64,
                    presentations_count: r.get::<_, i64>(2)? as u64,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let pending_spends = {
            let mut stmt = conn.prepare(
                "SELECT moderator_origin, balance_width, spend_state_bytes, state, session_token, held_until
                 FROM pending_spends
                 ORDER BY moderator_origin",
            )?;
            let rows = stmt.query_map([], |r| {
                let origin: String = r.get(0)?;
                let bw: u8 = r.get(1)?;
                let st_bytes: Vec<u8> = r.get(2)?;
                let state: String = r.get(3)?;
                let tok: Option<String> = r.get(4)?;
                let until: Option<i64> = r.get(5)?;
                let rem = <ec_act::Params>::new(bw)
                    .ok()
                    .and_then(|p| ec_act::ClientSpendState::from_bytes(&p, &st_bytes).ok())
                    .map(|s| s.remainder())
                    .unwrap_or(0);
                Ok(PendingSpendSummary {
                    moderator_origin: origin,
                    state,
                    session_token: tok,
                    held_until: until,
                    remainder_balance: rem,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let cookie_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM cookies", [], |r| r.get(0))?;

        Ok(StoreStatus {
            endorsements,
            credentials,
            pending_spends,
            cookie_count: cookie_count as usize,
        })
    }
}

/// Normalizes an origin or full HTTPS URL to `https://host[:port]`.
pub fn normalize_origin_input(input: &str) -> anyhow::Result<String> {
    let url = Url::parse(input)?;
    Ok(canonical_https_origin(&url)?)
}
