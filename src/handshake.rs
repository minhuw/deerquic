//! QUIC handshake — client Initial packet generation (RFC 9000 §7, §17.2.2).

use crate::frame::{self, Frame};
use crate::varint::{self, VarInt};
use bytes::Bytes;
use rustls::quic;

/// Minimum size of the first client Initial packet (RFC 9000 §14.1).
const MIN_INITIAL_SIZE: usize = 1200;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("varint error: {0}")]
    VarInt(#[from] varint::VarIntError),
    #[error("frame error: {0}")]
    Frame(#[from] frame::FrameError),
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
    #[error("{0}")]
    Internal(String),
}

/// Generate the first client Initial packet.
///
/// Returns the fully encrypted and header-protected Initial packet
/// ready to send via UDP.
pub fn client_initial(server_name: &str) -> Result<Vec<u8>, HandshakeError> {
    // 1. Install crypto provider
    let _ = crate::crypto::install_provider();

    // 2. Create TLS client connection (skip cert verification for now)
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| HandshakeError::InvalidServerName(server_name.into()))?;

    let mut tls = quic::ClientConnection::new(
        std::sync::Arc::new(config),
        quic::Version::V1,
        name,
        vec![], // transport params — empty for now
    )?;

    // 3. Extract TLS ClientHello bytes
    let mut client_hello = Vec::new();
    let _key_change = tls.write_hs(&mut client_hello);
    if client_hello.is_empty() {
        return Err(HandshakeError::Internal(
            "TLS produced no ClientHello".into(),
        ));
    }

    // 4. Generate connection IDs
    let dst_cid = random_bytes(8);
    let src_cid = random_bytes(8);

    // 5. Derive Initial keys from the destination CID
    let keys = crate::crypto::client_initial_keys(&dst_cid)?;

    // 6. Build and protect the packet
    let protected = build_and_protect_initial(&keys, &dst_cid, &src_cid, &client_hello)?;

    Ok(protected)
}

/// Build the unprotected Initial packet header + payload, then encrypt.
fn build_and_protect_initial(
    keys: &quic::Keys,
    dst_cid: &[u8],
    src_cid: &[u8],
    client_hello: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let pn: u64 = 0;
    let pn_len: usize = 1;
    let tag_len = keys.local.packet.tag_len();

    // ── Build frames (plaintext payload) ────────────────────────
    let crypto_frame = Frame::Crypto {
        offset: 0,
        data: Bytes::copy_from_slice(client_hello),
    };
    let mut frames_buf = Vec::new();
    frame::write_frame(&crypto_frame, &mut frames_buf)?;

    // ── Calculate header layout ─────────────────────────────────
    let hdr_prefix_len = 1 + 4 + 1 + dst_cid.len() + 1 + src_cid.len();
    let token_len_varint_size = 1; // token_len=0 encoded as 1 byte
    let length_field_size = 2; // estimated
    let pn_offset = hdr_prefix_len + token_len_varint_size + length_field_size;
    let header_total = pn_offset + pn_len;

    // ── Pad to minimum Initial size ─────────────────────────────
    // packet = header + ciphertext + tag → min 1200
    // plaintext_min = 1200 - header - tag
    let plaintext_min = MIN_INITIAL_SIZE.saturating_sub(header_total + tag_len);
    let plaintext_len = frames_buf.len().max(plaintext_min);

    // Plaintext-only payload (no tag space — encrypt_in_place returns tag separately)
    let mut payload = vec![0u8; plaintext_len];
    payload[..frames_buf.len()].copy_from_slice(&frames_buf);
    // Pad remainder with PADDING frames (0x00)
    for b in payload.iter_mut().skip(frames_buf.len()) {
        *b = 0x00;
    }

    // Length = PN + ciphertext + tag = pn_len + plaintext_len + tag_len
    let length_value = (pn_len + plaintext_len + tag_len) as VarInt;

    // ── Build unprotected header ────────────────────────────────
    let mut header = vec![0u8; header_total];
    header[0] = 0b1100_0000 | ((pn_len - 1) as u8);
    header[1..5].copy_from_slice(&crate::packet::VERSION_1.to_be_bytes());
    header[5] = dst_cid.len() as u8;
    header[6..6 + dst_cid.len()].copy_from_slice(dst_cid);
    let scid_pos = 6 + dst_cid.len();
    header[scid_pos] = src_cid.len() as u8;
    header[scid_pos + 1..scid_pos + 1 + src_cid.len()].copy_from_slice(src_cid);
    let token_pos = scid_pos + 1 + src_cid.len();
    varint::encode(0, &mut header[token_pos..])?;
    let length_pos = token_pos + token_len_varint_size;
    varint::encode(length_value, &mut header[length_pos..])?;
    header[pn_offset] = 0x00; // PN = 0

    // ── AEAD encrypt ────────────────────────────────────────────
    let tag = keys
        .local
        .packet
        .encrypt_in_place(pn, &header, &mut payload)
        .map_err(|e| HandshakeError::Internal(format!("AEAD encrypt: {e}")))?;

    // Append tag → payload = ciphertext || tag
    payload.extend_from_slice(tag.as_ref());

    // ── Header protection ───────────────────────────────────────
    // Sample starts 4 bytes after the PN field (RFC 9001 §5.4.2).
    // PN is at pn_offset from packet start. The protected payload starts right
    // after the PN. So sample starts at offset (4 - pn_len) within the payload.
    let sample_start = 4 - pn_len;
    let sample_len = keys.local.header.sample_len();
    let sample = &payload[sample_start..sample_start + sample_len];

    let mut first_byte = header[0];
    let mut pn_bytes = [header[pn_offset]];
    keys.local
        .header
        .encrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|e| HandshakeError::Internal(format!("header protection: {e}")))?;

    header[0] = first_byte;
    header[pn_offset] = pn_bytes[0];

    // ── Assemble packet ─────────────────────────────────────────
    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&payload);
    Ok(packet)
}

/// Generate cryptographically random bytes.
fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).expect("getrandom");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    #[test]
    fn client_initial_encrypt_decrypt_roundtrip() {
        let packet = client_initial("localhost").expect("generate initial packet");

        // Verify minimum size
        assert!(packet.len() >= MIN_INITIAL_SIZE, "packet too small");

        // Verify long header form
        assert_eq!(packet[0] & 0x80, 0x80, "must be long header");

        // Verify version = 1
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        assert_eq!(version, crate::packet::VERSION_1);

        // Extract DCID
        let dcid_len = packet[5] as usize;
        assert!(dcid_len > 0 && dcid_len <= 20);
        let dcid = &packet[6..6 + dcid_len];

        // Extract SCID
        let scid_pos = 6 + dcid_len;
        let scid_len = packet[scid_pos] as usize;
        let _scid = &packet[scid_pos + 1..scid_pos + 1 + scid_len];

        // Get server keys for decryption
        let server_keys = crate::crypto::server_initial_keys(dcid).expect("server keys");

        // Calculate pn_offset
        // For Initial packet: header prefix + token_length(1) + length(assume 2 bytes)
        let hdr_prefix = 1 + 4 + 1 + dcid_len + 1 + scid_len;
        let token_len_size = 1;
        let length_field_size = 2;
        let pn_offset = hdr_prefix + token_len_size + length_field_size;

        // Read the PN length from the first byte (before header protection)
        // After HP, the first byte is masked. We need to remove HP first.
        let sample_len = server_keys.local.header.sample_len();
        let sample_offset = pn_offset + 4;
        assert!(packet.len() > sample_offset + sample_len);

        // Remove header protection
        let sample = &packet[sample_offset..sample_offset + sample_len];
        let mut first_byte = packet[0];
        let mut pn_encrypted = [packet[pn_offset]];
        server_keys
            .remote
            .header
            .decrypt_in_place(sample, &mut first_byte, &mut pn_encrypted)
            .expect("header protection decrypt");

        let pn_len = ((first_byte & 0x03) + 1) as usize;
        assert_eq!(pn_len, 1, "first packet has 1-byte PN");

        let pn_full: u64 = pn_encrypted[0] as u64;

        // Rebuild the unprotected header for AEAD AAD
        let header_total = pn_offset + pn_len;
        let mut aad = Vec::from(&packet[..header_total]);
        aad[0] = first_byte;
        aad[pn_offset] = pn_encrypted[0];

        // AEAD decrypt the payload
        let payload_start = header_total;
        let mut encrypted_payload = Vec::from(&packet[payload_start..]);
        let plaintext = server_keys
            .remote
            .packet
            .decrypt_in_place(pn_full, &aad, &mut encrypted_payload)
            .expect("AEAD decrypt");

        // Verify the plaintext contains at least one frame
        assert!(!plaintext.is_empty(), "plaintext must contain frames");

        // Parse the first frame — should be a CRYPTO frame
        let (frame, n) = frame::parse_frame(plaintext).expect("parse frame");
        assert!(n > 0);

        match frame {
            Frame::Crypto { offset, data } => {
                assert_eq!(offset, 0, "CRYPTO frame offset must be 0");
                // Verify we got a TLS ClientHello (starts with 0x01 = client_hello type)
                assert!(
                    data.starts_with(&[0x01]),
                    "CRYPTO data should start with TLS ClientHello type byte, got {:02x?}",
                    &data[..4]
                );
            }
            _ => panic!("expected CRYPTO frame, got {frame:?}"),
        }
    }
}
