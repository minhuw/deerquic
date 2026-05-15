//! QUIC packet protection keys (RFC 9001 §5).
//!
//! Wraps rustls `quic::Keys` for Initial packet protection. rustls handles all
//! HKDF key derivation internally — we just provide the Destination Connection ID.

use rustls::crypto::ring;
use rustls::quic::{self, Keys};
use rustls::Side;
use rustls::SupportedCipherSuite;

/// Errors from key initialization.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("no QUIC-capable TLS 1.3 cipher suite found")]
    NoQuicSuite,
    #[error("failed to install ring crypto provider")]
    ProviderInstall,
}

/// Install the ring crypto provider as the default.
/// Must be called once before any TLS operations.
pub fn install_provider() -> Result<(), CryptoError> {
    ring::default_provider()
        .install_default()
        .map_err(|_| CryptoError::ProviderInstall)
}

/// Extract the first TLS 1.3 cipher suite with QUIC support from the ring provider.
fn default_quic_suite() -> Result<&'static rustls::Tls13CipherSuite, CryptoError> {
    for cs in ring::DEFAULT_CIPHER_SUITES {
        let SupportedCipherSuite::Tls13(tls13) = cs;
        if tls13.quic.is_some() {
            return Ok(tls13);
        }
    }
    Err(CryptoError::NoQuicSuite)
}

/// Generate Initial packet keys for a client.
///
/// `dst_cid` is the Destination Connection ID the client chose for its
/// first Initial packet (RFC 9001 §5.2).
pub fn client_initial_keys(dst_cid: &[u8]) -> Result<Keys, CryptoError> {
    let suite = default_quic_suite()?;
    let quic_alg = suite.quic.ok_or(CryptoError::NoQuicSuite)?;
    Ok(Keys::initial(
        quic::Version::V1,
        suite,
        quic_alg,
        dst_cid,
        Side::Client,
    ))
}

/// Generate Initial packet keys for a server (for testing/decoding).
pub fn server_initial_keys(dst_cid: &[u8]) -> Result<Keys, CryptoError> {
    let suite = default_quic_suite()?;
    let quic_alg = suite.quic.ok_or(CryptoError::NoQuicSuite)?;
    Ok(Keys::initial(
        quic::Version::V1,
        suite,
        quic_alg,
        dst_cid,
        Side::Server,
    ))
}
