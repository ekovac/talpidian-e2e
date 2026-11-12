//! Binary wire codecs for `draft-jms-mole-protocols` (QUIC `<V>` variable-length
//! vectors, EC-IHAT batch grant messages, `RedemptionChallenge`, and EC-ACT
//! issuance, challenge, presentation, update, and recovery-handle payloads).

use sha2::{Digest, Sha256};

use crate::Error;
use crate::schemes::{
    MAX_CREDENTIAL_CONTEXT_LEN, compute_ec_act_recovery_handle, derive_ec_act_ctx_spend,
    derive_redemption_challenge_digest,
};

/// Maximum value representable in a QUIC variable-length integer (`2^62 - 1`).
pub const MAX_QUIC_VARINT: u64 = (1u64 << 62) - 1;

/// Encodes `value` as a minimal-length RFC 9000 §16 QUIC variable-length integer.
pub fn encode_quic_varint(value: u64) -> Result<Vec<u8>, Error> {
    if value > MAX_QUIC_VARINT {
        return Err(Error::InvalidVarint);
    }
    if value < (1 << 6) {
        Ok(vec![value as u8])
    } else if value < (1 << 14) {
        Ok(((value as u16) | 0x4000).to_be_bytes().to_vec())
    } else if value < (1 << 30) {
        Ok(((value as u32) | 0x8000_0000).to_be_bytes().to_vec())
    } else {
        Ok((value | 0xc000_0000_0000_0000).to_be_bytes().to_vec())
    }
}

/// Decodes a minimal-length RFC 9000 §16 QUIC variable-length integer from the
/// start of `input`, returning `(value, bytes_consumed)`.
///
/// Rejects empty inputs and non-shortest encodings (`draft-jms-mole-protocols` §2).
pub fn decode_quic_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    let first = *input.first().ok_or(Error::InvalidVarint)?;
    let size = 1usize << (first >> 6);
    if input.len() < size {
        return Err(Error::InvalidVarint);
    }
    let mut value = u64::from(first & 0x3f);
    for &byte in &input[1..size] {
        value = (value << 8) | u64::from(byte);
    }
    let min_for_size = match size {
        1 => 0,
        2 => 1u64 << 6,
        4 => 1u64 << 14,
        8 => 1u64 << 30,
        _ => return Err(Error::InvalidVarint),
    };
    if value < min_for_size {
        return Err(Error::InvalidVarint);
    }
    Ok((value, size))
}

fn append_vector(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), Error> {
    let len = u64::try_from(payload.len()).map_err(|_| Error::InvalidVarint)?;
    out.extend_from_slice(&encode_quic_varint(len)?);
    out.extend_from_slice(payload);
    Ok(())
}

fn take_vector(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (len_u64, consumed) = decode_quic_varint(input)?;
    let len = usize::try_from(len_u64).map_err(|_| Error::InvalidVarint)?;
    input[consumed..]
        .split_at_checked(len)
        .ok_or(Error::InvalidPayload("unexpected EOF"))
}

fn encode_fixed_batch<const N: usize, T>(
    prefix_session_id: Option<&[u8; 32]>,
    items: &[T],
    empty_err: &'static str,
    to_bytes: impl Fn(&T) -> [u8; N],
) -> Result<Vec<u8>, Error> {
    if items.is_empty() {
        return Err(Error::InvalidPayload(empty_err));
    }
    let mut raw = Vec::with_capacity(items.len() * N);
    for item in items {
        raw.extend_from_slice(&to_bytes(item));
    }
    let mut out = Vec::with_capacity(prefix_session_id.map_or(0, |s| s.len()) + 8 + raw.len());
    if let Some(sid) = prefix_session_id {
        out.extend_from_slice(sid);
    }
    append_vector(&mut out, &raw)?;
    Ok(out)
}

fn decode_fixed_batch<const N: usize, T, E>(
    bytes: &[u8],
    len_err: &'static str,
    crypto_err: &'static str,
    from_slice: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<Vec<T>, Error> {
    let (raw, rest) = take_vector(bytes)?;
    if !rest.is_empty() {
        return Err(Error::TrailingBytes);
    }
    if raw.is_empty() || raw.len() % N != 0 {
        return Err(Error::InvalidPayload(len_err));
    }
    raw.as_chunks::<N>()
        .0
        .iter()
        .map(|chunk| from_slice(chunk.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Crypto(crypto_err))
}

// ---------------------------------------------------------------------------
// EC-IHAT Batch Grant Messages (`draft-jms-mole-protocols` §4.4.2)
// ---------------------------------------------------------------------------

/// Step 1 client message on `/mole/grant`: `struct { uint16 count; } GrantRequest;`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    /// Requested number of Endorsements (`count >= 1`).
    pub count: u16,
}

impl GrantRequest {
    /// Encoded byte length of `GrantRequest` (always 2 bytes).
    pub const LENGTH: usize = 2;

    /// Encodes `GrantRequest`, rejecting `count == 0`.
    pub fn to_bytes(&self) -> Result<[u8; Self::LENGTH], Error> {
        if self.count == 0 {
            return Err(Error::InvalidPayload("GrantRequest count must be >= 1"));
        }
        Ok(self.count.to_be_bytes())
    }

    /// Decodes `GrantRequest`, rejecting `count == 0` and non-2-byte slices.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| Error::InvalidPayload("GrantRequest must be 2 bytes"))?;
        let count = u16::from_be_bytes(arr);
        if count == 0 {
            return Err(Error::InvalidPayload("GrantRequest count must be >= 1"));
        }
        Ok(Self { count })
    }
}

/// Step 1 anchor response on `/mole/grant`:
/// `struct { opaque session_id[32]; CommitMessage commitments<V>; } GrantCommitments;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantCommitments {
    /// Fresh 32-byte batch session identifier.
    pub session_id: [u8; 32],
    /// Ordered commitments (`1 <= commitments.len() <= count`).
    pub commitments: Vec<ec_ihat::CommitMessage>,
}

impl GrantCommitments {
    /// Encodes `GrantCommitments`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        encode_fixed_batch(
            Some(&self.session_id),
            &self.commitments,
            "GrantCommitments must contain at least 1 commitment",
            ec_ihat::CommitMessage::to_bytes,
        )
    }

    /// Decodes `GrantCommitments`, rejecting empty batches or malformed points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&session_id, rest) = bytes
            .split_first_chunk::<32>()
            .ok_or(Error::InvalidPayload("unexpected EOF"))?;
        let commitments = decode_fixed_batch::<{ <ec_ihat::CommitMessage>::LENGTH }, _, _>(
            rest,
            "GrantCommitments vector has invalid length",
            "invalid EC-IHAT CommitMessage",
            ec_ihat::CommitMessage::from_bytes,
        )?;
        Ok(Self {
            session_id,
            commitments,
        })
    }
}

/// Step 2 client request on `/mole/grant`:
/// `struct { opaque session_id[32]; ChallengeMessage challenges<V>; } GrantChallenges;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantChallenges {
    /// Correlating 32-byte batch session identifier.
    pub session_id: [u8; 32],
    /// Ordered blind issuance challenges.
    pub challenges: Vec<ec_ihat::ChallengeMessage>,
}

impl GrantChallenges {
    /// Encodes `GrantChallenges`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        encode_fixed_batch(
            Some(&self.session_id),
            &self.challenges,
            "GrantChallenges must contain at least 1 challenge",
            ec_ihat::ChallengeMessage::to_bytes,
        )
    }

    /// Decodes `GrantChallenges`, rejecting empty batches or non-canonical scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&session_id, rest) = bytes
            .split_first_chunk::<32>()
            .ok_or(Error::InvalidPayload("unexpected EOF"))?;
        let challenges = decode_fixed_batch::<{ <ec_ihat::ChallengeMessage>::LENGTH }, _, _>(
            rest,
            "GrantChallenges vector has invalid length",
            "invalid EC-IHAT ChallengeMessage",
            ec_ihat::ChallengeMessage::from_bytes,
        )?;
        Ok(Self {
            session_id,
            challenges,
        })
    }
}

/// Step 2 anchor response on `/mole/grant`:
/// `struct { ResponseMessage responses<V>; } GrantResponses;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantResponses {
    /// Ordered issuance responses matching `GrantChallenges`.
    pub responses: Vec<ec_ihat::ResponseMessage>,
}

impl GrantResponses {
    /// Encodes `GrantResponses`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        encode_fixed_batch(
            None,
            &self.responses,
            "GrantResponses must contain at least 1 response",
            ec_ihat::ResponseMessage::to_bytes,
        )
    }

    /// Decodes `GrantResponses`, rejecting empty batches or non-canonical scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let responses = decode_fixed_batch::<{ <ec_ihat::ResponseMessage>::LENGTH }, _, _>(
            bytes,
            "GrantResponses vector has invalid length",
            "invalid EC-IHAT ResponseMessage",
            ec_ihat::ResponseMessage::from_bytes,
        )?;
        Ok(Self { responses })
    }
}

/// Disambiguates an incoming EC-IHAT grant POST body at `grant-uri`:
/// Step 1 (`GrantRequest`) is always 2 bytes, whereas Step 2 (`GrantChallenges`)
/// is at least 65 bytes (`32 + 1 + 32`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcIhatGrantPost {
    /// Step 1: initial batch request.
    Request(GrantRequest),
    /// Step 2: blinded challenge submission.
    Challenges(GrantChallenges),
}

impl EcIhatGrantPost {
    /// Parses an `application/mole-endorsement-request; type=0002` body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == GrantRequest::LENGTH {
            Ok(Self::Request(GrantRequest::from_bytes(bytes)?))
        } else {
            Ok(Self::Challenges(GrantChallenges::from_bytes(bytes)?))
        }
    }
}

// ---------------------------------------------------------------------------
// Redemption Challenge (`draft-jms-mole-protocols` §4.1)
// ---------------------------------------------------------------------------

/// Moderator Challenge for endorsement redemption:
/// `struct { opaque redemption_context[32]; } RedemptionChallenge;`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedemptionChallenge {
    /// Moderator-constructed 32-byte redemption context.
    pub redemption_context: [u8; 32],
}

impl RedemptionChallenge {
    /// Exact encoded byte length.
    pub const LENGTH: usize = 32;

    /// Encodes `RedemptionChallenge`.
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.redemption_context
    }

    /// Decodes `RedemptionChallenge`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let redemption_context = bytes
            .try_into()
            .map_err(|_| Error::InvalidPayload("RedemptionChallenge must be 32 bytes"))?;
        Ok(Self { redemption_context })
    }

    /// Computes `challenge_digest = SHA-256(moderator_challenge)`.
    pub fn digest(&self) -> [u8; 32] {
        derive_redemption_challenge_digest(&self.redemption_context)
    }
}

// ---------------------------------------------------------------------------
// EC-ACT Payloads (`draft-jms-mole-protocols` §5.2)
// ---------------------------------------------------------------------------

/// EC-ACT `IssuanceRequest` (`draft-jms-mole-protocols` §5.2.2):
/// `struct { uint8 truncated_key_id; opaque credential_context<V>; IssueRequestMessage request; }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActIssuanceRequest {
    /// Last byte of `key_id = SHA-256(SerializeElement(pkM))`.
    pub truncated_key_id: u8,
    /// Configured `credential_context` (`<= 65534` bytes).
    pub credential_context: Vec<u8>,
    /// Underlying EC-ACT `IssueRequestMessage`.
    pub request: ec_act::IssueRequestMessage,
}

impl EcActIssuanceRequest {
    /// Encodes `EcActIssuanceRequest`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(Error::InvalidPayload(
                "credential_context exceeds 65534 bytes",
            ));
        }
        let req_bytes = self.request.to_bytes();
        let mut out = Vec::with_capacity(1 + 4 + self.credential_context.len() + req_bytes.len());
        out.push(self.truncated_key_id);
        append_vector(&mut out, &self.credential_context)?;
        out.extend_from_slice(&req_bytes);
        Ok(out)
    }

    /// Decodes the header (`truncated_key_id` + `credential_context<V>`) and raw
    /// `IssueRequestMessage` slice before `Params` selection, enabling key lookup first
    /// per `draft-jms-mole-protocols` §5.2.2 step 1.
    pub fn split_header(bytes: &[u8]) -> Result<(u8, Vec<u8>, &[u8]), Error> {
        let (&truncated_key_id, rest) = bytes
            .split_first()
            .ok_or(Error::InvalidPayload("unexpected EOF"))?;
        let (credential_context, rest) = take_vector(rest)?;
        if credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(Error::InvalidPayload(
                "credential_context exceeds 65534 bytes",
            ));
        }
        let (req_slice, trailing) = rest
            .split_at_checked(<ec_act::IssueRequestMessage>::LENGTH)
            .ok_or(Error::InvalidPayload("unexpected EOF"))?;
        if !trailing.is_empty() {
            return Err(Error::TrailingBytes);
        }
        Ok((truncated_key_id, credential_context.to_vec(), req_slice))
    }

    /// Decodes `EcActIssuanceRequest` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, Error> {
        let (truncated_key_id, credential_context, req_slice) = Self::split_header(bytes)?;
        let request = ec_act::IssueRequestMessage::from_bytes(params, req_slice)
            .map_err(|_| Error::Crypto("invalid EC-ACT IssueRequestMessage"))?;
        Ok(Self {
            truncated_key_id,
            credential_context,
            request,
        })
    }
}

/// EC-ACT `IssuanceResponse` (`draft-jms-mole-protocols` §5.2.2):
/// `struct { IssueResponseMessage response; }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActIssuanceResponse {
    /// Underlying EC-ACT `IssueResponseMessage`.
    pub response: ec_act::IssueResponseMessage,
}

impl EcActIssuanceResponse {
    /// Encodes `EcActIssuanceResponse`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.response.to_bytes()
    }

    /// Decodes `EcActIssuanceResponse` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, Error> {
        let response = ec_act::IssueResponseMessage::from_bytes(params, bytes)
            .map_err(|_| Error::Crypto("invalid EC-ACT IssueResponseMessage"))?;
        Ok(Self { response })
    }
}

/// EC-ACT `Challenge` (`draft-jms-mole-protocols` §5.2.3):
/// `struct { uint64 spend_amount; uint64 max_top_up; opaque credential_context<V>; opaque request_context<V>; }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActChallenge {
    /// Required public spend amount `s`.
    pub spend_amount: u64,
    /// Offered maximum top-up `a`.
    pub max_top_up: u64,
    /// Credential context (`<= 65534` bytes).
    pub credential_context: Vec<u8>,
    /// Policy-scoped (empty) or request-bound context bytes.
    pub request_context: Vec<u8>,
}

impl EcActChallenge {
    /// Encodes `EcActChallenge`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(Error::InvalidPayload(
                "credential_context exceeds 65534 bytes",
            ));
        }
        let mut out = Vec::with_capacity(
            16 + 8 + self.credential_context.len() + self.request_context.len(),
        );
        out.extend_from_slice(&self.spend_amount.to_be_bytes());
        out.extend_from_slice(&self.max_top_up.to_be_bytes());
        append_vector(&mut out, &self.credential_context)?;
        append_vector(&mut out, &self.request_context)?;
        Ok(out)
    }

    /// Decodes `EcActChallenge`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&spend_bytes, rest) = bytes
            .split_first_chunk::<8>()
            .ok_or(Error::InvalidPayload("unexpected EOF"))?;
        let (&top_up_bytes, rest) = rest
            .split_first_chunk::<8>()
            .ok_or(Error::InvalidPayload("unexpected EOF"))?;
        let (credential_context, rest) = take_vector(rest)?;
        if credential_context.len() > MAX_CREDENTIAL_CONTEXT_LEN {
            return Err(Error::InvalidPayload(
                "credential_context exceeds 65534 bytes",
            ));
        }
        let (request_context, rest) = take_vector(rest)?;
        if !rest.is_empty() {
            return Err(Error::TrailingBytes);
        }
        Ok(Self {
            spend_amount: u64::from_be_bytes(spend_bytes),
            max_top_up: u64::from_be_bytes(top_up_bytes),
            credential_context: credential_context.to_vec(),
            request_context: request_context.to_vec(),
        })
    }

    /// Computes `ctx_spend = SHA-256(encoded_challenge)`.
    pub fn ctx_spend(&self) -> Result<[u8; 32], Error> {
        Ok(derive_ec_act_ctx_spend(&self.to_bytes()?))
    }
}

/// EC-ACT `PresentationAndUpdate` (`draft-jms-mole-protocols` §5.2.3.2):
/// `struct { opaque key_id[32]; SpendMessage spend; }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActPresentationAndUpdate {
    /// Full 32-byte `SHA-256(SerializeElement(pkM))`.
    pub key_id: [u8; 32],
    /// Underlying EC-ACT `SpendMessage`.
    pub spend: ec_act::SpendMessage,
}

impl EcActPresentationAndUpdate {
    /// Encodes `EcActPresentationAndUpdate`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let spend_bytes = self.spend.to_bytes();
        let mut out = Vec::with_capacity(32 + spend_bytes.len());
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&spend_bytes);
        out
    }

    /// Extracts `(key_id, spend_slice)` so the Moderator can look up `key_id`
    /// and its `Params` before decoding `SpendMessage` (`draft-jms-mole-protocols` §5.2.3.2 step 1).
    pub fn split_key_id(bytes: &[u8]) -> Result<([u8; 32], &[u8]), Error> {
        match bytes.split_first_chunk::<32>() {
            Some((&key_id, spend_slice)) if !spend_slice.is_empty() => Ok((key_id, spend_slice)),
            _ => Err(Error::InvalidPayload(
                "PresentationAndUpdate shorter than key_id + SpendMessage",
            )),
        }
    }

    /// Decodes `EcActPresentationAndUpdate` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, Error> {
        let (key_id, spend_slice) = Self::split_key_id(bytes)?;
        let spend = ec_act::SpendMessage::from_bytes(params, spend_slice)
            .map_err(|_| Error::Crypto("invalid EC-ACT SpendMessage"))?;
        Ok(Self { key_id, spend })
    }

    /// Computes the 96-byte `RecoveryHandle` for this presentation.
    pub fn recovery_handle(&self) -> RecoveryHandle {
        let raw = self.to_bytes();
        let nullifier = self.spend.nullifier();
        RecoveryHandle::from_array(compute_ec_act_recovery_handle(&self.key_id, &nullifier, &raw))
    }

    /// Computes `SHA-256(PresentationAndUpdate)`.
    pub fn sha256(raw_bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(raw_bytes).into()
    }
}

/// EC-ACT `Update` (`draft-jms-mole-protocols` §5.2.3.2):
/// `struct { RefundMessage refund; }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcActUpdate {
    /// Underlying EC-ACT `RefundMessage`.
    pub refund: ec_act::RefundMessage,
}

impl EcActUpdate {
    /// Encodes `EcActUpdate` (non-empty).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.refund.to_bytes()
    }

    /// Decodes `EcActUpdate` against `params`.
    pub fn from_bytes(params: &ec_act::Params, bytes: &[u8]) -> Result<Self, Error> {
        let refund = ec_act::RefundMessage::from_bytes(params, bytes)
            .map_err(|_| Error::Crypto("invalid EC-ACT RefundMessage"))?;
        Ok(Self { refund })
    }
}

/// 96-byte EC-ACT recovery / signoff handle (`draft-jms-mole-protocols` §5.2.5):
/// `key_id[32] || SerializeScalar(spend.k)[32] || SHA-256(PresentationAndUpdate)[32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecoveryHandle {
    /// 32-byte `key_id`.
    pub key_id: [u8; 32],
    /// 32-byte big-endian scalar encoding of `spend.k`.
    pub nullifier: [u8; 32],
    /// 32-byte SHA-256 digest of the `PresentationAndUpdate` octets.
    pub presentation_sha256: [u8; 32],
}

impl RecoveryHandle {
    /// Exact encoded byte length.
    pub const LENGTH: usize = 96;

    /// Constructs from a 96-byte array.
    pub fn from_array(bytes: [u8; Self::LENGTH]) -> Self {
        let ([key_id, nullifier, presentation_sha256], _) = bytes.as_chunks::<32>() else {
            unreachable!()
        };
        Self {
            key_id: *key_id,
            nullifier: *nullifier,
            presentation_sha256: *presentation_sha256,
        }
    }

    /// Decodes a 96-byte slice, rejecting any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr = bytes
            .try_into()
            .map_err(|_| Error::InvalidPayload("RecoveryHandle must be 96 bytes"))?;
        Ok(Self::from_array(arr))
    }

    /// Encodes into a 96-byte array.
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        let mut out = [0u8; Self::LENGTH];
        out[..32].copy_from_slice(&self.key_id);
        out[32..64].copy_from_slice(&self.nullifier);
        out[64..96].copy_from_slice(&self.presentation_sha256);
        out
    }
}
