//! Canonical request binding and proxy header filtering.
//!
//! Binding and forwarding deliberately share one classification policy so that a
//! header cannot accidentally be authenticated under one set of rules and sent
//! under another.

use std::collections::BTreeSet;

use http::Method;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, TRANSFER_ENCODING,
    UPGRADE, WWW_AUTHENTICATE,
};
use sha2::{Digest, Sha256};

use prototalpid_http::transport::{
    MOLE_CREDENTIAL_HEADER, MOLE_SESSION_HEADER, parse_www_authenticate_str,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum HeaderDirection {
    ToUpstream { strip_authorization: bool },
    ToClient,
}

/// Per-message view of the proxy's header policy.
///
/// `Connection` can nominate arbitrary additional hop-by-hop fields, so the
/// policy is derived from the complete source map rather than from a name alone.
struct ProxyHeaderPolicy {
    connection_nominated: BTreeSet<String>,
}

impl ProxyHeaderPolicy {
    fn new(headers: &HeaderMap) -> Self {
        Self {
            connection_nominated: connection_nominated_headers(headers),
        }
    }

    fn is_proxy_control(&self, name: &HeaderName) -> bool {
        name == MOLE_SESSION_HEADER
            || name == MOLE_CREDENTIAL_HEADER
            || is_hop_by_hop_header(name)
            || self.connection_nominated.contains(name.as_str())
    }

    fn should_bind(&self, name: &HeaderName) -> bool {
        !self.is_proxy_control(name)
            && name != AUTHORIZATION
            && name != HOST
            && !is_untrusted_forwarding_header(name)
    }

    fn should_forward(
        &self,
        name: &HeaderName,
        value: &http::HeaderValue,
        direction: HeaderDirection,
    ) -> bool {
        if self.is_proxy_control(name) {
            return false;
        }

        match direction {
            HeaderDirection::ToUpstream {
                strip_authorization,
            } => {
                name != HOST
                    && !is_untrusted_forwarding_header(name)
                    && !(strip_authorization && name == AUTHORIZATION)
            }
            HeaderDirection::ToClient => {
                name != WWW_AUTHENTICATE
                    || value
                        .to_str()
                        .is_ok_and(|raw| parse_www_authenticate_str(raw).is_empty())
            }
        }
    }
}

pub(crate) fn copy_filtered_headers(
    src: &HeaderMap,
    dst: &mut HeaderMap,
    direction: HeaderDirection,
) {
    let policy = ProxyHeaderPolicy::new(src);
    for (name, value) in src {
        if policy.should_forward(name, value, direction) {
            dst.append(name.clone(), value.clone());
        }
    }
}

/// Computes the canonical digest bound into a protected request's EC-ACT challenge.
///
/// MOLE transport headers and hop-by-hop framing fields are excluded because they
/// necessarily differ between the unauthenticated request and its presentation retry.
/// All other end-to-end fields, including cookies, plus the complete body are bound.
pub fn compute_request_binding(
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> [u8; 32] {
    let policy = ProxyHeaderPolicy::new(headers);
    let included_names: BTreeSet<&str> = headers
        .keys()
        .filter(|name| policy.should_bind(name))
        .map(HeaderName::as_str)
        .collect();
    let field_count = included_names
        .iter()
        .map(|name| headers.get_all(*name).iter().count())
        .sum::<usize>();

    let mut hash = Sha256::new();
    hash_request_field(&mut hash, b"MOLE-PROTECTED-REQUEST-v1");
    hash_request_field(&mut hash, method.as_str().as_bytes());
    hash_request_field(&mut hash, path_and_query.as_bytes());
    hash.update((field_count as u64).to_be_bytes());
    for name in included_names {
        for value in headers.get_all(name) {
            hash_request_field(&mut hash, name.as_bytes());
            hash_request_field(&mut hash, value.as_bytes());
        }
    }
    hash_request_field(&mut hash, body);
    hash.finalize().into()
}

fn is_untrusted_forwarding_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "cf-connecting-ip"
            | "forwarded"
            | "proxy"
            | "true-client-ip"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == CONTENT_LENGTH
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || matches!(
            name.as_str(),
            "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "trailers"
        )
}

fn connection_nominated_headers(headers: &HeaderMap) -> BTreeSet<String> {
    let mut nominated = BTreeSet::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                nominated.insert(name.as_str().to_owned());
            }
        }
    }
    nominated
}

fn hash_request_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}
