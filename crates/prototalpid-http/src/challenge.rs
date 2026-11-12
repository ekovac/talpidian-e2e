//! Concept-phase Anchor trust-establishment challenge types (Proof-of-Work and
//! single-use interactive prompt) shared between `prototalpid-anchor` and `prototalpid-cli`.

use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use sha2::{Digest, Sha256};

/// Default Anchor challenge endpoint path.
pub const DEFAULT_ANCHOR_CHALLENGE_PATH: &str = "/challenge";

/// Domain-separation prefix for local Anchor Proof-of-Work puzzles.
pub const POW_DOMAIN_TAG: &[u8] = b"MOLE-ANCHOR-POW-v1:";

/// Proof-of-work parameters in an [`AnchorChallengeOffer`].
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowChallengeParams {
    /// Random 16-byte puzzle prefix (unpadded base64url).
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub prefix: Vec<u8>,
    /// Required number of leading zero bits in the SHA-256 digest (`0..=32`).
    pub bits: u8,
}

/// Interactive prompt parameters in an [`AnchorChallengeOffer`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptChallengeParams {
    /// Human-readable question to display on a TTY.
    pub question: String,
}

/// JSON response returned by `GET /challenge` on `prototalpid-anchor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorChallengeOffer {
    /// Single-use challenge identifier.
    #[serde(rename = "challenge-id")]
    pub challenge_id: String,
    /// Optional PoW puzzle option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow: Option<PowChallengeParams>,
    /// Optional interactive prompt option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<PromptChallengeParams>,
}

/// JSON request body sent to `POST /challenge` on `prototalpid-anchor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorChallengeSubmission {
    /// Single-use challenge identifier from [`AnchorChallengeOffer`].
    #[serde(rename = "challenge-id")]
    pub challenge_id: String,
    /// Solved 64-bit PoW nonce (if answering `pow`).
    #[serde(rename = "pow-nonce", skip_serializing_if = "Option::is_none")]
    pub pow_nonce: Option<u64>,
    /// User-entered text answer (if answering `prompt`).
    #[serde(rename = "prompt-answer", skip_serializing_if = "Option::is_none")]
    pub prompt_answer: Option<String>,
}

/// JSON response returned by `POST /challenge` upon valid verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorChallengeAccepted {
    /// Remaining endorsement grant quota in the issued `anchor_session`.
    #[serde(rename = "remaining-quota")]
    pub remaining_quota: u32,
}

/// Computes the SHA-256 digest for an Anchor PoW candidate nonce.
pub fn compute_pow_digest(challenge_id: &str, prefix: &[u8], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POW_DOMAIN_TAG);
    hasher.update(challenge_id.as_bytes());
    hasher.update(b":");
    hasher.update(prefix);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

/// Counts leading zero bits in a 32-byte digest.
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    digest
        .iter()
        .position(|&b| b != 0)
        .map_or(256, |i| (i as u32) * 8 + digest[i].leading_zeros())
}

/// Verifies whether `nonce` satisfies `bits` leading zero bits.
pub fn verify_pow(challenge_id: &str, prefix: &[u8], bits: u8, nonce: u64) -> bool {
    if bits > 32 {
        return false;
    }
    let digest = compute_pow_digest(challenge_id, prefix, nonce);
    leading_zero_bits(&digest) >= u32::from(bits)
}

/// Searches for a `nonce` satisfying `bits` leading zero bits for local Anchor PoW challenges.
pub fn solve_pow(challenge_id: &str, prefix: &[u8], bits: u8) -> Option<u64> {
    if bits > 32 {
        return None;
    }
    (0..=u64::MAX).find(|&nonce| verify_pow(challenge_id, prefix, bits, nonce))
}
