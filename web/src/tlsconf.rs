//! The certificate files: the gateway serves HTTPS with the same certificate as the RDP daemon (`/etc/waydesk/cert.pem` and `key.pem`, which
//! `waydesk-admin cert` writes), re-read when they change; and it checks that the daemon it connects to presents exactly that certificate.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use anyhow::{Context as _, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};
use tracing::{info, warn};

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

struct Loaded {
    stamp: (Option<SystemTime>, Option<SystemTime>),
    key: Arc<CertifiedKey>,
    leaf: Vec<u8>,
}

/// The certificate and key files, loaded again when either changes (the daemon's renewal timer replaces them).
pub struct CertFiles {
    cert: PathBuf,
    key: PathBuf,
    state: RwLock<Loaded>,
}

fn stamp(cert: &Path, key: &Path) -> (Option<SystemTime>, Option<SystemTime>) {
    let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (m(cert), m(key))
}

fn load(cert: &Path, key: &Path) -> Result<(Arc<CertifiedKey>, Vec<u8>)> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("cannot read {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("{} is not a PEM certificate", cert.display()))?;
    let leaf = chain.first().with_context(|| format!("{} holds no certificate", cert.display()))?.as_ref().to_vec();
    let private = PrivateKeyDer::from_pem_file(key).with_context(|| format!("cannot read the key {}", key.display()))?;
    let certified = CertifiedKey::from_der(chain, private, &provider()).context("the key does not fit the certificate, or is of a kind this build cannot use")?;
    Ok((Arc::new(certified), leaf))
}

impl CertFiles {
    pub fn open(cert: &Path, key: &Path) -> Result<Arc<Self>> {
        let (certified, leaf) = load(cert, key)?;
        Ok(Arc::new(Self {
            cert: cert.to_owned(),
            key: key.to_owned(),
            state: RwLock::new(Loaded { stamp: stamp(cert, key), key: certified, leaf }),
        }))
    }

    /// Loads the files again if they changed. A pair that cannot be read (half written, say) leaves the old one in use and is tried again at the next change.
    fn refresh(&self) {
        let now = stamp(&self.cert, &self.key);
        if self.state.read().unwrap_or_else(|e| e.into_inner()).stamp == now {
            return;
        }
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        if state.stamp == now {
            return;
        }
        state.stamp = now;
        match load(&self.cert, &self.key) {
            Ok((key, leaf)) => {
                state.key = key;
                state.leaf = leaf;
                info!("the certificate changed: loaded again");
            }
            Err(e) => warn!("the certificate changed but cannot be loaded, the old one stays in use: {e:#}"),
        }
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.refresh();
        Arc::clone(&self.state.read().unwrap_or_else(|e| e.into_inner()).key)
    }

    fn leaf(&self) -> Vec<u8> {
        self.refresh();
        self.state.read().unwrap_or_else(|e| e.into_inner()).leaf.clone()
    }
}

impl std::fmt::Debug for CertFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertFiles({})", self.cert.display())
    }
}

impl ResolvesServerCert for CertFiles {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Accepts the daemon's certificate if it is the one in the file, and checks the daemon's signature with it (which proves that the daemon holds
/// the key). Names, dates and authorities do not matter here: the file is the daemon's own, on this machine.
#[derive(Debug)]
pub struct PinnedToFile {
    pub files: Arc<CertFiles>,
}

impl ServerCertVerifier for PinnedToFile {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.files.leaf().as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("the daemon presents another certificate than the file".into()))
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS settings for the gateway's own HTTPS (HTTP/1.1 only).
pub fn server_config(files: Arc<CertFiles>) -> Result<Arc<rustls::ServerConfig>> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(files);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// The TLS settings for the connection to the daemon.
pub fn daemon_client_config(files: Arc<CertFiles>) -> Result<Arc<rustls::ClientConfig>> {
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedToFile { files }))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}
