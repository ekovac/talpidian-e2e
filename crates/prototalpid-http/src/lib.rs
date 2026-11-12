//! `prototalpid-http`: MOLE HTTP transport (`draft-jms-mole-http-transport`),
//! binary wire formats & JSON configurations (`draft-jms-mole-protocols`),
//! protocol registries & context derivations, and shared HTTPS server/TLS helpers.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod challenge;
pub mod config;
pub mod schemes;
pub mod server;
pub mod tls;
pub mod transport;
pub mod wire;

/// Returns the current UNIX timestamp in seconds.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Errors returned by `prototalpid-http` parsing, encoding, and validation routines.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Input was not canonical unpadded base64url.
    #[error("invalid canonical unpadded base64url")]
    InvalidBase64Url,
    /// Protocol type suffix was not 4 hex digits or was reserved `0000`.
    #[error("invalid 4-hex-digit protocol type suffix")]
    InvalidTypeSuffix,
    /// Malformed QUIC variable-length integer (`<V>`).
    #[error("invalid or non-minimal QUIC variable-length integer")]
    InvalidVarint,
    /// Unexpected trailing bytes after wire payload.
    #[error("trailing bytes in binary payload")]
    TrailingBytes,
    /// Invalid binary payload content or bounds.
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    /// Cryptographic decoding or verification error.
    #[error("cryptographic error: {0}")]
    Crypto(&'static str),
    /// Malformed HTTP authentication or `Mole-Credential` / `Mole-Session` header.
    #[error("invalid HTTP header: {0}")]
    InvalidHeader(&'static str),
    /// Invalid or mismatched MOLE endorsement grant media type.
    #[error("invalid MOLE media type: {0}")]
    InvalidMediaType(&'static str),
    /// Invalid Anchor or Moderator JSON configuration.
    #[error("invalid MOLE configuration: {0}")]
    InvalidConfig(&'static str),
    /// TLS configuration or certificate error.
    #[error("TLS error: {0}")]
    Tls(&'static str),
    /// System random number generator error.
    #[error("entropy failure")]
    Entropy,
}
