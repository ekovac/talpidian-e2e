//! Shared TLS / PKI helpers (`rcgen` + `rustls` + `reqwest`) for `prototalpid-anchor`,
//! `prototalpid-moderator-proxy`, `prototalpid-cli`, and local HTTPS tests.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Once};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::Error;

/// Installs the process-wide `ring` default `CryptoProvider` once for `rustls` / `reqwest`.
pub fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = default_provider().install_default();
    });
}

/// Ephemeral local Certificate Authority for issuing trusted leaf certificates
/// across Anchors, Moderators, and Clients in tests or local demos.
pub struct LocalCa {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
}

/// Leaf certificate + private key issued by [`LocalCa`] or self-signed.
pub struct CertifiedServer {
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key.
    pub key_pem: String,
    /// Ready-to-use `rustls::ServerConfig` with ALPN `h2` and `http/1.1`.
    pub server_config: Arc<ServerConfig>,
}

impl LocalCa {
    /// Generates a new local Root CA.
    pub fn generate(common_name: &str) -> Result<Self, Error> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let ca_key = KeyPair::generate().map_err(|_| Error::Tls("CA keygen failed"))?;
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|_| Error::Tls("CA self-sign failed"))?;
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = ca_cert.der().clone();

        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem,
            ca_cert_der,
        })
    }

    /// Returns the Root CA certificate as PEM (suitable for `--cacert`).
    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns the Root CA certificate as DER.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Issues a leaf server certificate for the given DNS/IP SANs (defaulting to
    /// `localhost` and `127.0.0.1` if empty).
    pub fn issue_server_cert(&self, sans: &[String]) -> Result<CertifiedServer, Error> {
        let mut params = build_leaf_params(sans)?;
        params.is_ca = IsCa::NoCa;
        let leaf_key = KeyPair::generate().map_err(|_| Error::Tls("leaf keygen failed"))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|_| Error::Tls("leaf signing failed"))?;

        let cert_pem = format!("{}{}", leaf_cert.pem(), self.ca_cert_pem);
        let key_pem = leaf_key.serialize_pem();
        let certs = vec![leaf_cert.der().clone(), self.ca_cert_der.clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let server_config = build_server_config_from_der(certs, key_der)?;

        Ok(CertifiedServer {
            cert_pem,
            key_pem,
            server_config,
        })
    }

    /// Builds a `rustls::ClientConfig` trusting this Root CA.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, Error> {
        ensure_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots
            .add(self.ca_cert_der.clone())
            .map_err(|_| Error::Tls("failed to add CA to RootCertStore"))?;
        build_client_config_with_roots(roots)
    }

    /// Builds a non-redirecting `reqwest::Client` trusting this Root CA.
    pub fn http_client(&self) -> Result<reqwest::Client, Error> {
        ensure_crypto_provider();
        let cert = reqwest::Certificate::from_pem(self.ca_cert_pem.as_bytes())
            .map_err(|_| Error::Tls("invalid CA PEM"))?;
        reqwest::Client::builder()
            .tls_certs_only([cert])
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Tls("failed to build reqwest client"))
    }
}

/// Generates a standalone self-signed server certificate + `ServerConfig`.
pub fn generate_self_signed_server(sans: &[String]) -> Result<CertifiedServer, Error> {
    let params = build_leaf_params(sans)?;
    let key = KeyPair::generate().map_err(|_| Error::Tls("self-signed keygen failed"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|_| Error::Tls("self-signed cert generation failed"))?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let certs = vec![cert.der().clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let server_config = build_server_config_from_der(certs, key_der)?;
    Ok(CertifiedServer {
        cert_pem,
        key_pem,
        server_config,
    })
}

/// Loads a `rustls::ServerConfig` from PEM certificate chain and private key files.
pub fn load_server_config_from_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, Error> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|_| Error::Tls("failed to open certificate PEM file"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Tls("failed to parse certificate PEM chain"))?;
    if certs.is_empty() {
        return Err(Error::Tls("certificate PEM file contained no certificates"));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|_| Error::Tls("failed to load private key PEM file"))?;
    build_server_config_from_der(certs, key)
}

/// Builds a `reqwest::Client` configured for optional `-k` (`insecure`) or `--cacert`
/// PEM bundle, with redirects disabled so callers control redirect / MOLE handling.
pub fn build_http_client(
    insecure: bool,
    cacert_pem_file: Option<&Path>,
) -> Result<reqwest::Client, Error> {
    ensure_crypto_provider();
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("prototalpid-cli/0.1.0");
    if insecure {
        builder = builder.tls_danger_accept_invalid_certs(true);
    } else if let Some(path) = cacert_pem_file {
        let pem = fs::read(path).map_err(|_| Error::Tls("failed to read --cacert PEM file"))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| Error::Tls("failed to parse --cacert PEM file"))?;
        if certs.is_empty() {
            return Err(Error::Tls("--cacert PEM file contained no certificates"));
        }
        builder = builder.tls_certs_only(certs);
    } else {
        // Load native platform roots via `rustls-native-certs` when no custom bundle is passed.
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let tls_cfg = build_client_config_with_roots(roots)?;
        builder = builder.tls_backend_preconfigured((*tls_cfg).clone());
    }
    builder
        .build()
        .map_err(|_| Error::Tls("failed to build HTTP client"))
}

fn build_client_config_with_roots(roots: RootCertStore) -> Result<Arc<ClientConfig>, Error> {
    ensure_crypto_provider();
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls("invalid TLS protocol versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn build_server_config_from_der(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    ensure_crypto_provider();
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls("invalid TLS protocol versions"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| Error::Tls("invalid TLS server certificate or key"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn build_leaf_params(sans: &[String]) -> Result<CertificateParams, Error> {
    let mut params = CertificateParams::default();
    let default_sans = ["localhost", "127.0.0.1", "::1"];
    let iter: Box<dyn Iterator<Item = &str>> = if sans.is_empty() {
        Box::new(default_sans.into_iter())
    } else {
        Box::new(sans.iter().map(String::as_str))
    };
    params.subject_alt_names = iter
        .map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => s
                .to_owned()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|_| Error::Tls("invalid DNS SAN string")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(params)
}
