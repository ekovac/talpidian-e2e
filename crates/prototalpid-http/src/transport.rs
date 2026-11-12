//! HTTP transport implementation for `draft-jms-mole-http-transport`:
//! - `Mole` HTTP authentication scheme (`WWW-Authenticate` and `Authorization`)
//! - `Mole-Credential` response header (`response-T`, `update-T`, `held-for-update-T`)
//! - `Mole-Session` active session header and `Want-Endorsement: Mole`
//! - `application/mole-endorsement-{request,response}; type=XXXX` media types

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{
    ACCESS_CONTROL_EXPOSE_HEADERS, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderMap,
    HeaderName, HeaderValue, WWW_AUTHENTICATE,
};
use http_auth::{ChallengeParser, ChallengeRef, ParamValue, parse_challenges};
use sfv::{
    Item as SfvItem, ItemSerializer, List as SfvList, ListEntry as SfvListEntry,
    Parser as SfvParser,
};

use crate::Error;
use crate::schemes::{CredentialType, EndorsementType, parse_hex4_nonzero};

fn decode_b64(input: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| Error::InvalidBase64Url)
}

fn format_param(prefix: &str, type_id: u16, payload: &[u8]) -> Result<String, Error> {
    if type_id == 0 {
        return Err(Error::InvalidTypeSuffix);
    }
    Ok(format!(
        "{prefix}{type_id:04x}=\"{}\"",
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

fn single_header_str<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
    dup_err: Error,
    ascii_err: Error,
) -> Result<Option<&'a str>, Error> {
    let mut iter = headers.get_all(name).iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(dup_err);
    }
    first.to_str().map(Some).map_err(|_| ascii_err)
}

/// Authentication scheme token `Mole`.
pub const MOLE_AUTH_SCHEME: &str = "Mole";

/// `Mole-Credential` HTTP header name (`draft-jms-mole-http-transport` §4).
pub const MOLE_CREDENTIAL_HEADER: HeaderName = HeaderName::from_static("mole-credential");

/// Custom `Mole-Session` HTTP header name carrying an active session clearance token.
pub const MOLE_SESSION_HEADER: HeaderName = HeaderName::from_static("mole-session");

/// `Want-Endorsement` HTTP request header name (`web-drafts/explainer.md`).
pub const WANT_ENDORSEMENT_HEADER: HeaderName = HeaderName::from_static("want-endorsement");

/// Media type base for grant requests.
pub const MEDIA_ENDORSEMENT_REQUEST: &str = "application/mole-endorsement-request";

/// Media type base for grant responses.
pub const MEDIA_ENDORSEMENT_RESPONSE: &str = "application/mole-endorsement-response";

/// Parsed `Mole` challenge from `WWW-Authenticate` (`draft-jms-mole-http-transport` §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleChallenge {
    /// `endorse-T="<context>"`
    Endorse {
        /// Endorsement protocol type.
        endorsement_type: EndorsementType,
        /// Decoded anchor context (empty for currently defined protocols).
        context: Vec<u8>,
    },
    /// `redeem-T="<redemption-challenge>"`
    Redeem {
        /// Endorsement protocol type.
        endorsement_type: EndorsementType,
        /// Raw decoded `RedemptionChallenge` bytes (empty for `0001`).
        challenge: Vec<u8>,
    },
    /// `challenge-T="<credential-challenge>"`
    Credential {
        /// Credential protocol type.
        credential_type: CredentialType,
        /// Raw decoded type-specific `Challenge` bytes.
        challenge: Vec<u8>,
    },
}

impl MoleChallenge {
    /// Formats a single `WWW-Authenticate` header value (`Mole <param>="<value>"`).
    pub fn to_header_value(&self) -> Result<String, Error> {
        let param = match self {
            Self::Endorse {
                endorsement_type,
                context,
            } => format_param("endorse-", endorsement_type.0, context)?,
            Self::Redeem {
                endorsement_type,
                challenge,
            } => {
                if *endorsement_type == EndorsementType::NO_ENDORSEMENT && !challenge.is_empty() {
                    return Err(Error::InvalidPayload(
                        "NoEndorsement redeem-0001 challenge must be empty",
                    ));
                }
                format_param("redeem-", endorsement_type.0, challenge)?
            }
            Self::Credential {
                credential_type,
                challenge,
            } => format_param("challenge-", credential_type.0, challenge)?,
        };
        Ok(format!("{MOLE_AUTH_SCHEME} {param}"))
    }
}

/// Formats multiple `MoleChallenge` entries into a single comma-joined
/// `WWW-Authenticate` field value per RFC 9110 §11.6.1.
pub fn format_www_authenticate(challenges: &[MoleChallenge]) -> Result<String, Error> {
    if challenges.is_empty() {
        return Err(Error::InvalidHeader("empty challenge list"));
    }
    challenges
        .iter()
        .map(MoleChallenge::to_header_value)
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join(", "))
}

/// Parsed `Authorization: Mole ...` request credential (`draft-jms-mole-http-transport` §3 & §5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleAuthorization {
    /// `redeem-E="<redemption>", credential-request-C="<issuance-request>"`
    RedeemAndIssue {
        /// Selected endorsement type `E`.
        endorsement_type: EndorsementType,
        /// Decoded `Redemption` payload (empty iff `E == 0001`).
        redemption: Vec<u8>,
        /// Selected credential type `C`.
        credential_type: CredentialType,
        /// Decoded `IssuanceRequest` payload.
        credential_request: Vec<u8>,
    },
    /// `presentation-T="<presentation-and-update>"`
    Presentation {
        /// Credential protocol type `T`.
        credential_type: CredentialType,
        /// Decoded `PresentationAndUpdate` payload.
        presentation: Vec<u8>,
    },
    /// `recovery-T="<recovery-handle>"`
    Recovery {
        /// Credential protocol type `T`.
        credential_type: CredentialType,
        /// Decoded recovery handle bytes.
        recovery_handle: Vec<u8>,
    },
    /// `signoff-T="<recovery-handle>"`
    Signoff {
        /// Credential protocol type `T`.
        credential_type: CredentialType,
        /// Decoded recovery handle bytes.
        recovery_handle: Vec<u8>,
    },
}

impl MoleAuthorization {
    /// Formats as an `Authorization` header value (`Mole ...`).
    pub fn to_header_value(&self) -> Result<String, Error> {
        let body = match self {
            Self::RedeemAndIssue {
                endorsement_type,
                redemption,
                credential_type,
                credential_request,
            } => {
                if *endorsement_type == EndorsementType::NO_ENDORSEMENT && !redemption.is_empty() {
                    return Err(Error::InvalidPayload("redeem-0001 payload must be empty"));
                }
                format!(
                    "{}, {}",
                    format_param("redeem-", endorsement_type.0, redemption)?,
                    format_param("credential-request-", credential_type.0, credential_request)?
                )
            }
            Self::Presentation {
                credential_type,
                presentation,
            } => format_param("presentation-", credential_type.0, presentation)?,
            Self::Recovery {
                credential_type,
                recovery_handle,
            } => format_param("recovery-", credential_type.0, recovery_handle)?,
            Self::Signoff {
                credential_type,
                recovery_handle,
            } => format_param("signoff-", credential_type.0, recovery_handle)?,
        };
        Ok(format!("{MOLE_AUTH_SCHEME} {body}"))
    }

    /// Parses `Authorization` from an HTTP `HeaderMap`.
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, Error> {
        let Some(s) = single_header_str(
            headers,
            &AUTHORIZATION,
            Error::InvalidHeader("multiple Authorization headers"),
            Error::InvalidHeader("non-ASCII Authorization header"),
        )?
        else {
            return Ok(None);
        };
        Self::parse_header_str(s)
    }

    /// Parses a single `Authorization` header string. Returns `Ok(None)` if the
    /// scheme is a valid RFC 9110 auth-scheme other than `Mole`, or `Err` if a
    /// `Mole` credential (or the header syntax) is malformed.
    pub fn parse_header_str(input: &str) -> Result<Option<Self>, Error> {
        let trimmed = input.trim_matches([' ', '\t']);
        let scheme = trimmed.split([' ', '\t']).next().unwrap_or("");
        if !scheme.eq_ignore_ascii_case(MOLE_AUTH_SCHEME) {
            return match parse_challenges(scheme).as_deref() {
                Ok([ch]) if ch.scheme == scheme && ch.params.is_empty() => Ok(None),
                _ => Err(Error::InvalidHeader("expected RFC 9110 auth-scheme")),
            };
        }
        let challenges = parse_challenges(trimmed)
            .map_err(|_| Error::InvalidHeader("malformed Mole Authorization syntax"))?;
        let [ch] = challenges.as_slice() else {
            return Err(Error::InvalidHeader("expected single Mole Authorization credential"));
        };
        if ch.params.is_empty() {
            return Err(Error::InvalidHeader("empty auth-param list"));
        }
        Self::from_params(&ch.params).map(Some)
    }

    fn from_params(params: &[(&str, ParamValue<'_>)]) -> Result<Self, Error> {
        ensure_no_duplicate_param_names(params)?;

        let mut redeem: Option<(EndorsementType, Vec<u8>)> = None;
        let mut cred_req: Option<(CredentialType, Vec<u8>)> = None;
        let mut presentation: Option<(CredentialType, Vec<u8>)> = None;
        let mut recovery: Option<(CredentialType, Vec<u8>)> = None;
        let mut signoff: Option<(CredentialType, Vec<u8>)> = None;

        for (raw_name, raw_val) in params {
            let name = raw_name.to_ascii_lowercase();
            let val = raw_val.to_unescaped();
            match classify_operation_param(&name)? {
                None => {}
                Some((OpKind::Redeem, type_id)) => {
                    if redeem.is_some() {
                        return Err(Error::InvalidHeader("duplicate redeem parameter"));
                    }
                    let decoded = decode_b64(&val)?;
                    let et = EndorsementType(type_id);
                    if et == EndorsementType::NO_ENDORSEMENT && !decoded.is_empty() {
                        return Err(Error::InvalidPayload("redeem-0001 must be empty"));
                    }
                    if et != EndorsementType::NO_ENDORSEMENT && decoded.is_empty() {
                        return Err(Error::InvalidPayload("redeem payload must not be empty"));
                    }
                    redeem = Some((et, decoded));
                }
                Some((OpKind::CredentialRequest, type_id)) => {
                    if cred_req.is_some() {
                        return Err(Error::InvalidHeader("duplicate credential-request parameter"));
                    }
                    let decoded = decode_b64(&val)?;
                    if decoded.is_empty() {
                        return Err(Error::InvalidPayload(
                            "credential-request payload must not be empty",
                        ));
                    }
                    cred_req = Some((CredentialType(type_id), decoded));
                }
                Some((OpKind::Presentation, type_id)) => {
                    if presentation.is_some() {
                        return Err(Error::InvalidHeader("duplicate presentation parameter"));
                    }
                    presentation = Some((CredentialType(type_id), decode_b64(&val)?));
                }
                Some((OpKind::Recovery, type_id)) => {
                    if recovery.is_some() {
                        return Err(Error::InvalidHeader("duplicate recovery parameter"));
                    }
                    let decoded = decode_b64(&val)?;
                    if decoded.is_empty() {
                        return Err(Error::InvalidPayload("recovery handle must not be empty"));
                    }
                    recovery = Some((CredentialType(type_id), decoded));
                }
                Some((OpKind::Signoff, type_id)) => {
                    if signoff.is_some() {
                        return Err(Error::InvalidHeader("duplicate signoff parameter"));
                    }
                    let decoded = decode_b64(&val)?;
                    if decoded.is_empty() {
                        return Err(Error::InvalidPayload("signoff handle must not be empty"));
                    }
                    signoff = Some((CredentialType(type_id), decoded));
                }
                Some(_) => {
                    return Err(Error::InvalidHeader(
                        "disallowed operation parameter in Authorization",
                    ));
                }
            }
        }

        let has_redeem_pair = redeem.is_some() || cred_req.is_some();
        let active_ops = usize::from(has_redeem_pair)
            + usize::from(presentation.is_some())
            + usize::from(recovery.is_some())
            + usize::from(signoff.is_some());
        if active_ops != 1 {
            return Err(Error::InvalidHeader(
                "Authorization must select exactly one Mole operation",
            ));
        }

        if has_redeem_pair {
            let (Some((endorsement_type, redemption)), Some((credential_type, credential_request))) =
                (redeem, cred_req)
            else {
                return Err(Error::InvalidHeader(
                    "Redeem & Issue requires both redeem-E and credential-request-C",
                ));
            };
            Ok(Self::RedeemAndIssue {
                endorsement_type,
                redemption,
                credential_type,
                credential_request,
            })
        } else if let Some((credential_type, presentation)) = presentation {
            Ok(Self::Presentation {
                credential_type,
                presentation,
            })
        } else if let Some((credential_type, recovery_handle)) = recovery {
            Ok(Self::Recovery {
                credential_type,
                recovery_handle,
            })
        } else if let Some((credential_type, recovery_handle)) = signoff {
            Ok(Self::Signoff {
                credential_type,
                recovery_handle,
            })
        } else {
            Err(Error::InvalidHeader("missing Mole operation"))
        }
    }
}

/// Parsed `Mole-Credential` response header (`draft-jms-mole-http-transport` §4 & §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleCredentialHeader {
    /// `response-T="<issuance-response>"`
    Response {
        /// Credential protocol type `T`.
        credential_type: CredentialType,
        /// Decoded `IssuanceResponse` bytes.
        response: Vec<u8>,
    },
    /// `update-T="<update>"` or `update-T=""` (`None` = recorded `NoUpdate`).
    Update {
        /// Credential protocol type `T`.
        credential_type: CredentialType,
        /// `Some(bytes)` for a replacement `Update`, or `None` for `NoUpdate`.
        update: Option<Vec<u8>>,
    },
    /// `held-for-update-T="<duration_secs>"`
    HeldForUpdate {
        /// Credential protocol type `T`.
        credential_type: CredentialType,
        /// Hold duration in seconds.
        duration_secs: u64,
    },
}

impl MoleCredentialHeader {
    /// Formats as the `Mole-Credential` field value (`<param>="<value>"`).
    pub fn to_header_value(&self) -> Result<String, Error> {
        match self {
            Self::Response {
                credential_type,
                response,
            } => {
                if response.is_empty() {
                    return Err(Error::InvalidPayload(
                        "Mole-Credential response-T must not be empty",
                    ));
                }
                format_param("response-", credential_type.0, response)
            }
            Self::Update {
                credential_type,
                update: Some(bytes),
            } => {
                if bytes.is_empty() {
                    return Err(Error::InvalidPayload(
                        "non-NoUpdate update-T payload must be non-empty",
                    ));
                }
                format_param("update-", credential_type.0, bytes)
            }
            Self::Update {
                credential_type,
                update: None,
            } => {
                if !credential_type.is_valid_wire() {
                    return Err(Error::InvalidTypeSuffix);
                }
                Ok(format!("update-{credential_type}=\"\""))
            }
            Self::HeldForUpdate {
                credential_type,
                duration_secs,
            } => {
                if !credential_type.is_valid_wire() {
                    return Err(Error::InvalidTypeSuffix);
                }
                Ok(format!("held-for-update-{credential_type}=\"{duration_secs}\""))
            }
        }
    }

    /// Parses `Mole-Credential` from an HTTP response `HeaderMap`.
    /// Rejects repeated `Mole-Credential` fields per `draft-jms-mole-http-transport` §4.
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, Error> {
        single_header_str(
            headers,
            &MOLE_CREDENTIAL_HEADER,
            Error::InvalidHeader("Mole-Credential header MUST NOT be repeated"),
            Error::InvalidHeader("non-ASCII Mole-Credential header"),
        )?
        .map(Self::parse_header_str)
        .transpose()
    }

    /// Parses a single `Mole-Credential` header value string.
    pub fn parse_header_str(input: &str) -> Result<Self, Error> {
        let trimmed = input.trim_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with(',') || trimmed.ends_with(',') {
            return Err(Error::InvalidHeader(
                "Mole-Credential must contain exactly one parameter",
            ));
        }
        let synthetic = format!("{MOLE_AUTH_SCHEME} {trimmed}");
        let challenges = parse_challenges(&synthetic)
            .map_err(|_| Error::InvalidHeader("malformed Mole-Credential header"))?;
        let [ch] = challenges.as_slice() else {
            return Err(Error::InvalidHeader(
                "Mole-Credential must contain exactly one parameter",
            ));
        };
        let [(raw_name, raw_val)] = ch.params.as_slice() else {
            return Err(Error::InvalidHeader(
                "Mole-Credential must contain exactly one parameter",
            ));
        };
        let name = raw_name.to_ascii_lowercase();
        let val = raw_val.to_unescaped();
        match classify_operation_param(&name)? {
            Some((OpKind::Response, type_id)) => {
                let decoded = decode_b64(&val)?;
                if decoded.is_empty() {
                    return Err(Error::InvalidPayload("response-T must not be empty"));
                }
                Ok(Self::Response {
                    credential_type: CredentialType(type_id),
                    response: decoded,
                })
            }
            Some((OpKind::Update, type_id)) => {
                let update = if val.is_empty() {
                    None
                } else {
                    Some(decode_b64(&val)?)
                };
                Ok(Self::Update {
                    credential_type: CredentialType(type_id),
                    update,
                })
            }
            Some((OpKind::HeldForUpdate, type_id)) => Ok(Self::HeldForUpdate {
                credential_type: CredentialType(type_id),
                duration_secs: parse_ascii_u64_seconds(&val)?,
            }),
            _ => Err(Error::InvalidHeader(
                "invalid parameter in Mole-Credential header",
            )),
        }
    }
}

fn parse_ascii_u64_seconds(s: &str) -> Result<u64, Error> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidHeader(
            "held-for-update duration must be ASCII decimal seconds",
        ));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(Error::InvalidHeader(
            "held-for-update duration must not have leading zeros",
        ));
    }
    s.parse::<u64>()
        .map_err(|_| Error::InvalidHeader("held-for-update duration overflow"))
}

/// Parses all valid `Mole` challenges across all `WWW-Authenticate` header fields,
/// ignoring non-`Mole` schemes and skipping malformed individual `Mole` challenges
/// per `draft-jms-mole-http-transport` §3.
pub fn parse_www_authenticate_headers(headers: &HeaderMap) -> Vec<MoleChallenge> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|val| val.to_str().ok())
        .flat_map(parse_www_authenticate_str)
        .collect()
}

/// Parses all valid `Mole` challenges from a single `WWW-Authenticate` field value.
pub fn parse_www_authenticate_str(input: &str) -> Vec<MoleChallenge> {
    ChallengeParser::new(input)
        .map_while(Result::ok)
        .filter(|raw| raw.scheme.eq_ignore_ascii_case(MOLE_AUTH_SCHEME))
        .filter_map(|raw| parse_mole_challenge_from_ref(&raw).ok())
        .collect()
}

/// Strictly parses a single `Mole` challenge string (`Mole <param>="<val>"`),
/// returning `Err` if malformed. Useful for server self-tests and conformance tests.
pub fn parse_single_mole_challenge_strict(input: &str) -> Result<MoleChallenge, Error> {
    let challenges =
        parse_challenges(input).map_err(|_| Error::InvalidHeader("malformed challenge syntax"))?;
    let [raw] = challenges.as_slice() else {
        return Err(Error::InvalidHeader("expected exactly one challenge"));
    };
    if !raw.scheme.eq_ignore_ascii_case(MOLE_AUTH_SCHEME) {
        return Err(Error::InvalidHeader("expected Mole scheme"));
    }
    parse_mole_challenge_from_ref(raw)
}

fn parse_mole_challenge_from_ref(raw: &ChallengeRef<'_>) -> Result<MoleChallenge, Error> {
    ensure_no_duplicate_param_names(&raw.params)?;
    let mut parsed: Option<MoleChallenge> = None;
    for (raw_name, raw_val) in &raw.params {
        let name = raw_name.to_ascii_lowercase();
        let val = raw_val.to_unescaped();
        match classify_operation_param(&name)? {
            None => {}
            Some((OpKind::Endorse, type_id)) => {
                if parsed.is_some() {
                    return Err(Error::InvalidHeader(
                        "Mole challenge must have exactly one payload parameter",
                    ));
                }
                parsed = Some(MoleChallenge::Endorse {
                    endorsement_type: EndorsementType(type_id),
                    context: decode_b64(&val)?,
                });
            }
            Some((OpKind::Redeem, type_id)) => {
                if parsed.is_some() {
                    return Err(Error::InvalidHeader(
                        "Mole challenge must have exactly one payload parameter",
                    ));
                }
                let challenge = decode_b64(&val)?;
                let et = EndorsementType(type_id);
                if et == EndorsementType::NO_ENDORSEMENT && !challenge.is_empty() {
                    return Err(Error::InvalidPayload("redeem-0001 challenge must be empty"));
                }
                parsed = Some(MoleChallenge::Redeem {
                    endorsement_type: et,
                    challenge,
                });
            }
            Some((OpKind::Challenge, type_id)) => {
                if parsed.is_some() {
                    return Err(Error::InvalidHeader(
                        "Mole challenge must have exactly one payload parameter",
                    ));
                }
                parsed = Some(MoleChallenge::Credential {
                    credential_type: CredentialType(type_id),
                    challenge: decode_b64(&val)?,
                });
            }
            Some(_) => {
                return Err(Error::InvalidHeader(
                    "disallowed operation parameter in WWW-Authenticate",
                ));
            }
        }
    }
    parsed.ok_or(Error::InvalidHeader(
        "Mole challenge missing payload parameter",
    ))
}

/// Applies `Mole-Credential` along with the mandatory `Cache-Control: no-store`
/// and `Access-Control-Expose-Headers` headers (`draft-jms-mole-http-transport` §4).
pub fn apply_mole_credential_headers(
    headers: &mut HeaderMap,
    cred: &MoleCredentialHeader,
) -> Result<(), Error> {
    let hv = HeaderValue::from_str(&cred.to_header_value()?)
        .map_err(|_| Error::InvalidHeader("invalid Mole-Credential header value"))?;
    headers.insert(MOLE_CREDENTIAL_HEADER, hv);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    apply_expose_auth_headers(headers);
    Ok(())
}

/// Applies `Access-Control-Expose-Headers` for `WWW-Authenticate` responses.
pub fn apply_expose_auth_headers(headers: &mut HeaderMap) {
    headers.insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("WWW-Authenticate, Mole-Credential, Mole-Session"),
    );
}

/// Returns whether the request carries `Want-Endorsement: Mole` (RFC 9651 Token List).
pub fn has_want_endorsement_mole(headers: &HeaderMap) -> bool {
    headers
        .get_all(&WANT_ENDORSEMENT_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|s| SfvParser::new(s).parse::<SfvList>().ok())
        .flatten()
        .any(|entry| {
            matches!(
                entry,
                SfvListEntry::Item(item)
                    if item
                        .bare_item
                        .as_token()
                        .is_some_and(|t| t.as_str().eq_ignore_ascii_case(MOLE_AUTH_SCHEME))
            )
        })
}

/// Formats a binary session clearance token as an RFC 9651 Structured Field
/// Byte Sequence (`:...:` item) for the `Mole-Session` header.
pub fn format_mole_session(token_bytes: &[u8]) -> String {
    ItemSerializer::new().bare_item(token_bytes).finish()
}

/// Parses a single `Mole-Session` header as an RFC 9651 Structured Field Byte
/// Sequence (`:...:` item), returning its canonical serialized form.
/// Rejects duplicate, empty, parameterized, or non-byte-sequence headers.
pub fn parse_mole_session(headers: &HeaderMap) -> Result<Option<String>, Error> {
    let Some(raw) = single_header_str(
        headers,
        &MOLE_SESSION_HEADER,
        Error::InvalidHeader("duplicate Mole-Session header"),
        Error::InvalidHeader("non-ASCII Mole-Session header"),
    )?
    else {
        return Ok(None);
    };
    let item: SfvItem = SfvParser::new(raw)
        .parse()
        .map_err(|_| Error::InvalidHeader("invalid Mole-Session structured field"))?;
    let Some(bytes) = item.bare_item.as_byte_sequence() else {
        return Err(Error::InvalidHeader(
            "Mole-Session must be an RFC 9651 byte sequence",
        ));
    };
    if bytes.is_empty() || !item.params.is_empty() {
        return Err(Error::InvalidHeader("invalid Mole-Session structured field"));
    }
    Ok(Some(format_mole_session(bytes)))
}

/// Formats `Content-Type: application/mole-endorsement-request; type=XXXX`.
pub fn format_endorsement_request_content_type(t: EndorsementType) -> Result<String, Error> {
    if !t.is_valid_wire() {
        return Err(Error::InvalidTypeSuffix);
    }
    Ok(format!("{MEDIA_ENDORSEMENT_REQUEST}; type={t}"))
}

/// Formats `Content-Type: application/mole-endorsement-response; type=XXXX`.
pub fn format_endorsement_response_content_type(t: EndorsementType) -> Result<String, Error> {
    if !t.is_valid_wire() {
        return Err(Error::InvalidTypeSuffix);
    }
    Ok(format!("{MEDIA_ENDORSEMENT_RESPONSE}; type={t}"))
}

/// Parses `Content-Type` for `application/mole-endorsement-request; type=XXXX`
/// (`draft-jms-mole-protocols` §8.3).
pub fn parse_endorsement_request_content_type(headers: &HeaderMap) -> Result<EndorsementType, Error> {
    let ct = single_header_str(
        headers,
        &CONTENT_TYPE,
        Error::InvalidMediaType("duplicate Content-Type"),
        Error::InvalidMediaType("non-ASCII Content-Type"),
    )?
    .ok_or(Error::InvalidMediaType("missing Content-Type"))?;
    parse_mole_media_type(ct, MEDIA_ENDORSEMENT_REQUEST)
}

/// Parses `Content-Type` for `application/mole-endorsement-response; type=XXXX`
/// (`draft-jms-mole-protocols` §8.3).
pub fn parse_endorsement_response_content_type(
    headers: &HeaderMap,
) -> Result<EndorsementType, Error> {
    let ct = single_header_str(
        headers,
        &CONTENT_TYPE,
        Error::InvalidMediaType("duplicate Content-Type"),
        Error::InvalidMediaType("non-ASCII Content-Type"),
    )?
    .ok_or(Error::InvalidMediaType("missing Content-Type"))?;
    parse_mole_media_type(ct, MEDIA_ENDORSEMENT_RESPONSE)
}

/// Parses `<expected_essence>; type=XXXX` via `mime::Mime`, rejecting missing/duplicate
/// `type` parameters, non-4-hex values, `0000`, and unknown extra media-type parameters
/// (`draft-jms-mole-protocols` §8.3).
pub fn parse_mole_media_type(input: &str, expected_essence: &str) -> Result<EndorsementType, Error> {
    let parsed: mime::Mime = input
        .parse()
        .map_err(|_| Error::InvalidMediaType("malformed Content-Type"))?;
    if !parsed.essence_str().eq_ignore_ascii_case(expected_essence) {
        return Err(Error::InvalidMediaType("unexpected media type essence"));
    }
    let mut params = parsed.params();
    let Some((name, val)) = params.next() else {
        return Err(Error::InvalidMediaType("missing required 'type' parameter"));
    };
    if params.next().is_some() || name != "type" {
        return Err(Error::InvalidMediaType("expected single 'type' parameter"));
    }
    EndorsementType::from_hex4(val.as_str())
        .map_err(|_| Error::InvalidMediaType("invalid endorsement type value"))
}

// ---------------------------------------------------------------------------
// Internal Operation Prefix Classification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpKind {
    Endorse,
    Redeem,
    Challenge,
    CredentialRequest,
    Presentation,
    Recovery,
    Signoff,
    Response,
    Update,
    HeldForUpdate,
}

const OPERATIONS: &[(&str, OpKind)] = &[
    ("endorse-", OpKind::Endorse),
    ("redeem-", OpKind::Redeem),
    ("challenge-", OpKind::Challenge),
    ("credential-request-", OpKind::CredentialRequest),
    ("presentation-", OpKind::Presentation),
    ("recovery-", OpKind::Recovery),
    ("signoff-", OpKind::Signoff),
    ("response-", OpKind::Response),
    ("update-", OpKind::Update),
    ("held-for-update-", OpKind::HeldForUpdate),
];

fn classify_operation_param(lowercase_name: &str) -> Result<Option<(OpKind, u16)>, Error> {
    for &(prefix, kind) in OPERATIONS {
        if let Some(suffix) = lowercase_name.strip_prefix(prefix) {
            return Ok(Some((kind, parse_hex4_nonzero(suffix)?)));
        }
    }
    Ok(None)
}

fn ensure_no_duplicate_param_names(params: &[(&str, ParamValue<'_>)]) -> Result<(), Error> {
    let mut seen = HashSet::with_capacity(params.len());
    for (name, _) in params {
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(Error::InvalidHeader("duplicate auth-param name"));
        }
    }
    Ok(())
}
