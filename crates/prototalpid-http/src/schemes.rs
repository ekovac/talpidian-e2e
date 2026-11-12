//! MOLE protocol type registries, greasing helpers, and cryptographic context
//! derivations per `draft-jms-mole-protocols`.

use core::fmt;
use sha2::{Digest, Sha256};

use crate::Error;

/// Fixed cryptographic redemption context for EC-IHAT (`draft-jms-mole-protocols` §4.4.1).
pub const EC_IHAT_CTX_RED: &[u8] = b"MOLE-EC-IHAT-ctx_red-v1";

/// Ciphersuite identifier shared by EC-IHAT and EC-ACT over P-256.
pub const CIPHERSUITE_P256_SHA256: &str = "P256-SHA256";

/// Maximum byte length of an EC-ACT `credential_context` (`2^16 - 2`), so that
/// `ctx_cred = credential_context || I2OSP(L, 1)` fits in `2^16 - 1` bytes.
pub const MAX_CREDENTIAL_CONTEXT_LEN: usize = 65_534;

/// Reserved greased 16-bit protocol type values (`0x0A0A, 0x1A1A, ..., 0xFAFA`).
pub const GREASED_TYPES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

macro_rules! define_protocol_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u16);

        impl $name {
            /// Invalid reserved type `0x0000`.
            pub const RESERVED: Self = Self(0x0000);

            /// Parses a 4-hex-digit suffix, rejecting `0000` and non-4-hex inputs.
            pub fn from_hex4(s: &str) -> Result<Self, Error> {
                parse_hex4_nonzero(s).map(Self)
            }

            /// Formats as 4 lowercase hex digits.
            pub fn to_hex4(self) -> String {
                format!("{:04x}", self.0)
            }

            /// Returns whether this value is non-zero and valid to appear on the wire.
            pub fn is_valid_wire(self) -> bool {
                self.0 != 0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:04x}", self.0)
            }
        }
    };
}

define_protocol_type!(
    /// Candidate MOLE Endorsement Type (`draft-jms-mole-protocols` §8.1).
    EndorsementType
);

impl EndorsementType {
    /// No Endorsement Required (`0x0001`).
    pub const NO_ENDORSEMENT: Self = Self(0x0001);
    /// EC-IHAT (`0x0002`).
    pub const EC_IHAT: Self = Self(0x0002);
    /// Longfellow (`0x0003`).
    pub const LONGFELLOW: Self = Self(0x0003);
}

define_protocol_type!(
    /// Candidate MOLE Credential Type (`draft-jms-mole-protocols` §8.2).
    CredentialType
);

impl CredentialType {
    /// EC-ACT (`0x0001`).
    pub const EC_ACT: Self = Self(0x0001);
    /// Privacy Pass with a Reverse Flow (`0x0002`).
    pub const PRIVACY_PASS_REVERSE: Self = Self(0x0002);

    /// Returns whether this value matches the greased pattern `0x?A?A`.
    ///
    /// Note: Moderators MUST NOT special-case greased values; this helper is
    /// provided for Client greasing generation and diagnostics.
    pub fn is_greased(self) -> bool {
        (self.0 & 0x0f0f) == 0x0a0a
    }
}

/// Parses an exact 4-character hexadecimal type suffix, rejecting `0000`.
pub fn parse_hex4_nonzero(s: &str) -> Result<u16, Error> {
    if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidTypeSuffix);
    }
    match u16::from_str_radix(s, 16) {
        Ok(val) if val != 0 => Ok(val),
        _ => Err(Error::InvalidTypeSuffix),
    }
}

/// Selects a random greased credential type (`0x0A0A..=0xFAFA`) and random payload
/// for Client greasing (`draft-jms-mole-protocols` §3.2).
pub fn generate_greased_presentation() -> Result<(CredentialType, Vec<u8>), Error> {
    let mut rand_hdr = [0u8; 2];
    getrandom::fill(&mut rand_hdr).map_err(|_| Error::Entropy)?;
    let idx = usize::from(rand_hdr[0] & 0x0f);
    let len = 16 + usize::from(rand_hdr[1] & 0x3f);
    let mut body = vec![0u8; len];
    getrandom::fill(&mut body).map_err(|_| Error::Entropy)?;
    Ok((CredentialType(GREASED_TYPES[idx]), body))
}

/// Computes `key_id = SHA-256(SerializeElement(pkM))` (`draft-jms-mole-protocols` §5.2.1).
pub fn compute_ec_act_key_id(pk_m: &ec_act::PublicKey) -> [u8; 32] {
    Sha256::digest(pk_m.to_bytes()).into()
}

/// Computes `key_id = SHA-256(pk_m_bytes)` from raw 33-byte compressed SEC1 key bytes.
pub fn compute_key_id_from_bytes(pk_m_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(pk_m_bytes).into()
}

/// Returns `truncated_key_id`, the final byte of `key_id` (`draft-jms-mole-protocols` §5.2.1).
pub fn truncated_key_id(key_id: &[u8; 32]) -> u8 {
    key_id[31]
}

/// Derives `ctx_cred = credential_context || I2OSP(L, 1)` (`draft-jms-mole-protocols` §5.2.1).
pub fn derive_ec_act_ctx_cred(
    credential_context: &[u8],
    balance_width: u8,
) -> Result<Vec<u8>, Error> {
    if credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
        return Err(Error::InvalidPayload("credential_context exceeds 65534 bytes"));
    }
    if balance_width == 0 || balance_width > ec_act::MAX_BALANCE_WIDTH {
        return Err(Error::InvalidPayload("balance_width must be in 1..=64"));
    }
    let mut out = Vec::with_capacity(credential_context.len() + 1);
    out.extend_from_slice(credential_context);
    out.push(balance_width);
    Ok(out)
}

/// Computes `challenge_digest = SHA-256(moderator_challenge)` over raw decoded
/// `RedemptionChallenge` octets (`draft-jms-mole-protocols` §4.1).
pub fn derive_redemption_challenge_digest(raw_challenge: &[u8]) -> [u8; 32] {
    Sha256::digest(raw_challenge).into()
}

/// Computes `ctx_spend = SHA-256(credential_challenge)` over raw decoded EC-ACT
/// `Challenge` octets (`draft-jms-mole-protocols` §5.2.3.1).
pub fn derive_ec_act_ctx_spend(raw_credential_challenge: &[u8]) -> [u8; 32] {
    Sha256::digest(raw_credential_challenge).into()
}

/// Computes the 96-byte EC-ACT recovery handle:
/// `key_id || SerializeScalar(spend.k) || SHA-256(PresentationAndUpdate)`
/// (`draft-jms-mole-protocols` §5.2.5).
pub fn compute_ec_act_recovery_handle(
    key_id: &[u8; 32],
    nullifier_k: &[u8; 32],
    presentation_and_update_bytes: &[u8],
) -> [u8; 96] {
    let digest: [u8; 32] = Sha256::digest(presentation_and_update_bytes).into();
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(key_id);
    out[32..64].copy_from_slice(nullifier_k);
    out[64..96].copy_from_slice(&digest);
    out
}
