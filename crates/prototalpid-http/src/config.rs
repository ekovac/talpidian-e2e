//! JSON configuration schemas and well-known endpoint helpers per
//! `draft-jms-mole-protocols` §6.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use url::Url;

use crate::Error;
use crate::schemes::{
    CIPHERSUITE_P256_SHA256, CredentialType, EndorsementType, MAX_CREDENTIAL_CONTEXT_LEN,
    compute_ec_act_key_id, derive_ec_act_ctx_cred, truncated_key_id,
};

/// Well-known discovery path for an Anchor (`/.well-known/mole-anchor`).
pub const WELL_KNOWN_MOLE_ANCHOR: &str = "/.well-known/mole-anchor";

/// Well-known discovery path for a Moderator (`/.well-known/mole-moderator`).
pub const WELL_KNOWN_MOLE_MODERATOR: &str = "/.well-known/mole-moderator";

/// Validates an absolute `https://` URI with no userinfo and no fragment
/// (`draft-jms-mole-protocols` §6).
pub fn validate_https_endpoint_uri(uri: &str) -> Result<Url, Error> {
    let parsed = Url::parse(uri).map_err(|_| Error::InvalidConfig("invalid endpoint URI"))?;
    if parsed.scheme() != "https" {
        return Err(Error::InvalidConfig("MOLE endpoint URI must use https"));
    }
    if parsed.host_str().is_none() {
        return Err(Error::InvalidConfig("MOLE endpoint URI missing host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::InvalidConfig(
            "MOLE endpoint URI must not contain userinfo",
        ));
    }
    if parsed.fragment().is_some() {
        return Err(Error::InvalidConfig(
            "MOLE endpoint URI must not contain a fragment",
        ));
    }
    Ok(parsed)
}

/// Returns the canonical origin string (`https://host[:port]`) for an HTTPS URL.
pub fn canonical_https_origin(url: &Url) -> Result<String, Error> {
    if url.scheme() != "https" || !url.has_host() {
        return Err(Error::InvalidConfig("URL must be an https origin with a host"));
    }
    Ok(url.origin().ascii_serialization())
}

/// Builds `https://<origin>/.well-known/mole-anchor`.
pub fn anchor_well_known_url(base: &Url) -> Result<Url, Error> {
    let _ = canonical_https_origin(base)?;
    base.join(WELL_KNOWN_MOLE_ANCHOR)
        .map_err(|_| Error::InvalidConfig("invalid well-known anchor URL"))
}

/// Builds `https://<origin>/.well-known/mole-moderator`.
pub fn moderator_well_known_url(base: &Url) -> Result<Url, Error> {
    let _ = canonical_https_origin(base)?;
    base.join(WELL_KNOWN_MOLE_MODERATOR)
        .map_err(|_| Error::InvalidConfig("invalid well-known moderator URL"))
}

/// Anchor JSON configuration (`draft-jms-mole-protocols` §6):
/// ```json
/// {
///   "grant-uri": "https://anchor.example/mole/grant",
///   "endorsement-type": 2,
///   "ciphersuite": "P256-SHA256",
///   "anchor-key": "...",
///   "issuance-epoch": "..."
/// }
/// ```
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorConfiguration {
    /// Absolute HTTPS grant endpoint URI.
    #[serde(rename = "grant-uri")]
    pub grant_uri: String,
    /// Endorsement type (`2` for EC-IHAT).
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
    /// Ciphersuite identifier (`"P256-SHA256"`).
    pub ciphersuite: String,
    /// `SerializeElement(pkA)` as unpadded base64url.
    #[serde(rename = "anchor-key")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub anchor_key: Vec<u8>,
    /// Issuance context `ctx_iss` as unpadded base64url.
    #[serde(rename = "issuance-epoch")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub issuance_epoch: Vec<u8>,
}

impl AnchorConfiguration {
    /// Validates URI rules and decodes the EC-IHAT `PublicKey` when type is EC-IHAT.
    pub fn validate_ec_ihat(&self) -> Result<(Url, ec_ihat::PublicKey), Error> {
        let grant_url = validate_https_endpoint_uri(&self.grant_uri)?;
        if EndorsementType(self.endorsement_type) != EndorsementType::EC_IHAT {
            return Err(Error::InvalidConfig("unsupported anchor endorsement-type"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(Error::InvalidConfig("unsupported EC-IHAT ciphersuite"));
        }
        if self.issuance_epoch.len() > u16::MAX as usize {
            return Err(Error::InvalidConfig("issuance-epoch exceeds 65535 bytes"));
        }
        let key_arr: &[u8; 33] = self
            .anchor_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidConfig("invalid EC-IHAT anchor-key length"))?;
        let pk = ec_ihat::PublicKey::from_bytes(key_arr)
            .map_err(|_| Error::InvalidConfig("invalid EC-IHAT anchor-key point"))?;
        Ok((grant_url, pk))
    }
}

/// Raw Moderator JSON configuration (`draft-jms-mole-protocols` §6).
///
/// Entries in `endorsements` and `credential-keys` are stored as `serde_json::Value`
/// on the wire so Clients cleanly skip unknown endorsement/credential types while
/// validating known entries (`draft-jms-mole-protocols` §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeratorConfiguration {
    /// Absolute HTTPS Redeem & Issue endpoint URI.
    #[serde(rename = "issuance-uri")]
    pub issuance_uri: String,
    /// Accepted endorsement entries (`[+ $endorsement]`).
    pub endorsements: Vec<serde_json::Value>,
    /// Active credential-key entries (`[+ $credential-key]`).
    #[serde(rename = "credential-keys")]
    pub credential_keys: Vec<serde_json::Value>,
}

/// Typed EC-IHAT endorsement configuration entry inside `ModeratorConfiguration`.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcIhatEndorsementConfig {
    /// Must be `2`.
    #[serde(rename = "endorsement-type")]
    pub endorsement_type: u16,
    /// Ciphersuite (`"P256-SHA256"`).
    pub ciphersuite: String,
    /// Shared issuance epoch `ctx_iss`.
    #[serde(rename = "issuance-epoch")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub issuance_epoch: Vec<u8>,
    /// Ordered list of accepted Anchor public keys (`SerializeElement(pkA)`).
    #[serde(rename = "anchor-set")]
    #[serde_as(as = "Vec<Base64<UrlSafe, Unpadded>>")]
    pub anchor_set: Vec<Vec<u8>>,
}

impl EcIhatEndorsementConfig {
    /// Validates and decodes the ordered Anchor Set public keys.
    pub fn decode_anchor_set(&self) -> Result<Vec<ec_ihat::PublicKey>, Error> {
        if self.endorsement_type != EndorsementType::EC_IHAT.0 {
            return Err(Error::InvalidConfig("expected endorsement-type 2"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(Error::InvalidConfig("unsupported EC-IHAT ciphersuite"));
        }
        if self.anchor_set.is_empty() {
            return Err(Error::InvalidConfig("anchor-set must not be empty"));
        }
        if self.issuance_epoch.len() > u16::MAX as usize {
            return Err(Error::InvalidConfig("issuance-epoch exceeds 65535 bytes"));
        }
        self.anchor_set
            .iter()
            .map(|raw| {
                let arr: &[u8; 33] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidConfig("invalid key length in anchor-set"))?;
                ec_ihat::PublicKey::from_bytes(arr)
                    .map_err(|_| Error::InvalidConfig("invalid P-256 point in anchor-set"))
            })
            .collect()
    }
}

/// Supported endorsement configuration variants extracted from `ModeratorConfiguration`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupportedModeratorEndorsement {
    /// `endorsement-type = 1` (No Endorsement Required).
    NoEndorsement,
    /// `endorsement-type = 2` (EC-IHAT).
    EcIhat(EcIhatEndorsementConfig),
}

/// Typed EC-ACT credential-key entry inside `ModeratorConfiguration`.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcActKeyConfig {
    /// Must be `1`.
    #[serde(rename = "credential-type")]
    pub credential_type: u16,
    /// `SerializeElement(pkM)` as unpadded base64url.
    #[serde(rename = "credential-key")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub credential_key: Vec<u8>,
    /// Ciphersuite (`"P256-SHA256"`).
    pub ciphersuite: String,
    /// Balance width `L` (`1..=64`).
    #[serde(rename = "balance-width")]
    pub balance_width: u8,
    /// Coarse credential context (`<= 65534` bytes).
    #[serde(rename = "credential-context")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub credential_context: Vec<u8>,
    /// Result retention window in seconds.
    #[serde(rename = "result-retention")]
    pub result_retention: u64,
}

/// Validated EC-ACT key entry with pre-derived `PublicKey`, `key_id`, and `ctx_cred`.
#[derive(Clone, Debug)]
pub struct ValidatedEcActKey {
    /// Raw config entry.
    pub config: EcActKeyConfig,
    /// Decoded `pkM`.
    pub public_key: ec_act::PublicKey,
    /// `SHA-256(SerializeElement(pkM))`.
    pub key_id: [u8; 32],
    /// `key_id[31]`.
    pub truncated_key_id: u8,
    /// `credential_context || I2OSP(L, 1)`.
    pub ctx_cred: Vec<u8>,
}

impl EcActKeyConfig {
    /// Validates all EC-ACT fields and derives `key_id`, `truncated_key_id`, and `ctx_cred`.
    pub fn validate(&self) -> Result<ValidatedEcActKey, Error> {
        if self.credential_type != CredentialType::EC_ACT.0 {
            return Err(Error::InvalidConfig("expected credential-type 1"));
        }
        if self.ciphersuite != CIPHERSUITE_P256_SHA256 {
            return Err(Error::InvalidConfig("unsupported EC-ACT ciphersuite"));
        }
        if self.balance_width == 0 || self.balance_width > ec_act::MAX_BALANCE_WIDTH {
            return Err(Error::InvalidConfig("balance-width must be in 1..=64"));
        }
        if self.credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(Error::InvalidConfig(
                "credential-context exceeds 65534 bytes",
            ));
        }
        let arr: &[u8; 33] = self
            .credential_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidConfig("invalid EC-ACT credential-key length"))?;
        let public_key = ec_act::PublicKey::from_bytes(arr)
            .map_err(|_| Error::InvalidConfig("invalid EC-ACT credential-key point"))?;
        let key_id = compute_ec_act_key_id(&public_key);
        let trunc = truncated_key_id(&key_id);
        let ctx_cred = derive_ec_act_ctx_cred(&self.credential_context, self.balance_width)?;
        Ok(ValidatedEcActKey {
            config: self.clone(),
            public_key,
            key_id,
            truncated_key_id: trunc,
            ctx_cred,
        })
    }
}

impl ModeratorConfiguration {
    /// Constructs a `ModeratorConfiguration` from typed endorsement and EC-ACT key configs.
    pub fn from_typed(
        issuance_uri: String,
        no_endorsement: bool,
        ec_ihat_sets: &[EcIhatEndorsementConfig],
        ec_act_keys: &[EcActKeyConfig],
    ) -> Result<Self, Error> {
        let _ = validate_https_endpoint_uri(&issuance_uri)?;
        let mut endorsements = Vec::new();
        if no_endorsement {
            endorsements.push(serde_json::json!({ "endorsement-type": 1 }));
        }
        for set in ec_ihat_sets {
            let _ = set.decode_anchor_set()?;
            endorsements.push(
                serde_json::to_value(set)
                    .map_err(|_| Error::InvalidConfig("failed to serialize endorsement entry"))?,
            );
        }
        if endorsements.is_empty() {
            return Err(Error::InvalidConfig("endorsements list must not be empty"));
        }

        let mut trunc_ids = HashSet::new();
        let mut credential_keys = Vec::new();
        for key in ec_act_keys {
            let validated = key.validate()?;
            if !trunc_ids.insert(validated.truncated_key_id) {
                return Err(Error::InvalidConfig(
                    "active EC-ACT keys share truncated_key_id",
                ));
            }
            credential_keys.push(
                serde_json::to_value(key)
                    .map_err(|_| Error::InvalidConfig("failed to serialize credential-key"))?,
            );
        }
        if credential_keys.is_empty() {
            return Err(Error::InvalidConfig(
                "credential-keys list must not be empty",
            ));
        }

        Ok(Self {
            issuance_uri,
            endorsements,
            credential_keys,
        })
    }

    /// Validates `issuance-uri`, ensures non-empty arrays, parses supported endorsement
    /// entries (`1` and `2`, skipping unknown types), and parses supported EC-ACT keys
    /// (`1`, skipping unknown types while checking distinct `truncated_key_id`).
    pub fn parse_supported(
        &self,
    ) -> Result<
        (
            Url,
            Vec<SupportedModeratorEndorsement>,
            Vec<ValidatedEcActKey>,
        ),
        Error,
    > {
        let issuance_url = validate_https_endpoint_uri(&self.issuance_uri)?;
        if self.endorsements.is_empty() {
            return Err(Error::InvalidConfig("endorsements list must not be empty"));
        }
        if self.credential_keys.is_empty() {
            return Err(Error::InvalidConfig(
                "credential-keys list must not be empty",
            ));
        }

        let mut endorsements = Vec::new();
        for entry in &self.endorsements {
            let et = entry
                .get("endorsement-type")
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::InvalidConfig(
                    "endorsement entry missing integer endorsement-type",
                ))?;
            if et == 0 || et > u64::from(u16::MAX) {
                return Err(Error::InvalidConfig("invalid endorsement-type in config"));
            }
            match et as u16 {
                1 => endorsements.push(SupportedModeratorEndorsement::NoEndorsement),
                2 => {
                    let cfg: EcIhatEndorsementConfig = serde_json::from_value(entry.clone())
                        .map_err(|_| Error::InvalidConfig("malformed EC-IHAT endorsement entry"))?;
                    let _ = cfg.decode_anchor_set()?;
                    endorsements.push(SupportedModeratorEndorsement::EcIhat(cfg));
                }
                _ => {
                    // Unknown endorsement types (e.g. Longfellow 3) are skipped cleanly.
                }
            }
        }

        let mut keys = Vec::new();
        let mut trunc_ids = HashSet::new();
        for entry in &self.credential_keys {
            let ct = entry
                .get("credential-type")
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::InvalidConfig(
                    "credential-key entry missing integer credential-type",
                ))?;
            if ct == 0 || ct > u64::from(u16::MAX) {
                return Err(Error::InvalidConfig("invalid credential-type in config"));
            }
            if ct as u16 == CredentialType::EC_ACT.0 {
                let cfg: EcActKeyConfig = serde_json::from_value(entry.clone())
                    .map_err(|_| Error::InvalidConfig("malformed EC-ACT credential-key entry"))?;
                let validated = cfg.validate()?;
                if !trunc_ids.insert(validated.truncated_key_id) {
                    return Err(Error::InvalidConfig(
                        "duplicate truncated_key_id across active EC-ACT keys",
                    ));
                }
                keys.push(validated);
            }
        }

        Ok((issuance_url, endorsements, keys))
    }
}
