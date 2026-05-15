//! QUIC connection state machine (sans-IO).
//!
//! The [`Connection`] struct is the core of deerquic. It exposes a pure
//! state machine API with no I/O, no async, no timers. The caller is
//! responsible for UDP sockets, event loops, and timer management.
//!
//! ```text
//!    caller                     Connection
//!    ──────                     ──────────
//!    connect() ───────────────→ creates state + first Initial packet
//!    ingest(&[u8]) ───────────→ processes incoming QUIC packet
//!    egest(&mut [u8]) ←──────── produces outgoing QUIC packet
//!    next_timeout() ←────────── when to fire a timer
//!    on_timeout() ────────────→ timer fired
//! ```

use crate::error::ConnectionError;
use crate::frame;
use crate::packet::{self, PacketNumberSpace};
use crate::space::Space;
use crate::varint::{self, VarInt};
use rustls::quic;
use std::time::Instant;

// ── Connection State ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum State {
    Connecting,
    Handshaking,
    Established,
    Closed,
}

// ── Connection ──────────────────────────────────────────────────

#[allow(dead_code)]
pub struct Connection {
    state: State,
    server_name: String,
    tls: quic::Connection,
    /// QUIC version in use.
    version: u32,
    /// Destination Connection ID (chosen by us as client).
    dst_cid: Vec<u8>,
    /// Source Connection ID (chosen by us as client).
    src_cid: Vec<u8>,
    /// The three packet number spaces (Initial, Handshake, ApplicationData).
    /// ApplicationData space is also used for 0-RTT.
    initial_space: Space,
    handshake_space: Space,
    appdata_space: Space,
    /// Reason for closing (set when entering State::Closed).
    close_reason: Option<ConnectionError>,
}

impl Connection {
    /// Create a new client connection and produce the first Initial packet.
    ///
    /// The caller should send the returned packet via UDP to the server.
    pub fn connect(server_name: &str) -> Result<(Self, Vec<u8>), ConnectionError> {
        let _ = crate::crypto::install_provider();

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;

        let mut tls_client = quic::ClientConnection::new(
            std::sync::Arc::new(config),
            quic::Version::V1,
            name,
            vec![], // transport params
        )?;

        // Extract ClientHello
        let mut client_hello = Vec::new();
        let _ = tls_client.write_hs(&mut client_hello);
        if client_hello.is_empty() {
            return Err(ConnectionError::Transport(
                crate::error::TransportError::InternalError,
            ));
        }

        let tls = quic::Connection::Client(tls_client);

        let dst_cid = random_bytes(8);
        let src_cid = random_bytes(8);

        let keys = crate::crypto::client_initial_keys(&dst_cid)?;

        // Build Initial packet
        let packet = build_initial_packet(&keys, &dst_cid, &src_cid, &client_hello)?;

        let mut initial_space = Space::new(PacketNumberSpace::Initial);
        initial_space.set_keys(keys);
        // consume PN 0 for the first packet
        let _ = initial_space.next_send_pn();

        Ok((
            Self {
                state: State::Connecting,
                tls,
                server_name: server_name.to_string(),
                version: packet::VERSION_1,
                dst_cid,
                src_cid,
                initial_space,
                handshake_space: Space::new(PacketNumberSpace::Handshake),
                appdata_space: Space::new(PacketNumberSpace::ApplicationData),
                close_reason: None,
            },
            packet,
        ))
    }

    /// Feed a raw QUIC packet (UDP payload) into the connection.
    ///
    /// Returns the number of bytes consumed from `buf`. The caller may
    /// have coalesced multiple packets into one datagram — in that case,
    /// call `ingest` again with the remaining bytes.
    pub fn ingest(&mut self, buf: &[u8]) -> Result<usize, ConnectionError> {
        if self.state == State::Closed {
            return Err(ConnectionError::Closed);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let is_long = (buf[0] & 0x80) != 0;

        if !is_long {
            let (hdr, consumed) = packet::parse_short_header(buf, self.dst_cid.len())?;
            let keys = &self.appdata_space;
            decrypt_and_process(keys, &hdr, buf, consumed)
        } else {
            let (hdr, consumed) = packet::parse_long_header(buf)?;
            let space = match hdr.ty {
                packet::LongType::Initial => &self.initial_space,
                packet::LongType::Handshake => &self.handshake_space,
                packet::LongType::ZeroRtt => &self.appdata_space,
                packet::LongType::Retry => {
                    return Err(ConnectionError::Transport(
                        crate::error::TransportError::ProtocolViolation,
                    ));
                }
                packet::LongType::VersionNegotiation => {
                    return Err(ConnectionError::Transport(
                        crate::error::TransportError::ProtocolViolation,
                    ));
                }
            };
            decrypt_and_process(space, &hdr, buf, consumed)
        }
    }

    /// Produce the next outgoing packet. Returns bytes written to `buf`.
    /// Returns 0 if no packet needs to be sent right now.
    pub fn egest(&mut self, _buf: &mut [u8]) -> Result<usize, ConnectionError> {
        if self.state == State::Closed {
            return Err(ConnectionError::Closed);
        }
        // TODO: assemble outgoing packet from pending frames
        Ok(0)
    }

    /// Absolute time of the next timer event, if any.
    pub fn next_timeout(&self) -> Option<Instant> {
        // TODO: compute from loss detection, idle timeout, etc.
        None
    }

    /// A timer has fired. Advance state accordingly (e.g., retransmit).
    pub fn on_timeout(&mut self) {
        // TODO: handle loss detection, TLP, PTO, idle timeout
    }

    // ── Queries ─────────────────────────────────────────────────

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    pub fn close_reason(&self) -> Option<&ConnectionError> {
        self.close_reason.as_ref()
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}

// ── Free function: decrypt + parse ─────────────────────────────

/// Remove header protection, AEAD decrypt, then parse frames from a packet.
fn decrypt_and_process<H>(
    space: &Space,
    hdr: &H,
    packet: &[u8],
    _header_len: usize,
) -> Result<usize, ConnectionError>
where
    H: PacketHeader,
{
    let remote_keys = space
        .remote_keys()
        .ok_or_else(|| ConnectionError::Transport(crate::error::TransportError::InternalError))?;

    let pn_offset = hdr.pn_offset();

    // The PN length is HP-protected. Sample assuming 4-byte PN (maximum).
    let sample_start = pn_offset + 4;
    let sample_len = remote_keys.header.sample_len();
    if packet.len() < sample_start + sample_len {
        return Err(ConnectionError::Packet(
            packet::PacketError::BufferTooShort {
                needed: sample_start + sample_len,
                actual: packet.len(),
            },
        ));
    }
    let sample = &packet[sample_start..sample_start + sample_len];

    // Assume 4-byte PN for HP removal; we'll find the real length after unmasking
    let max_pn_len = 4;
    let pn_end = (pn_offset + max_pn_len).min(packet.len());
    let mut first_byte = packet[0];
    let mut pn_bytes = (packet[pn_offset..pn_end]).to_vec();
    // Pad to at least 4 bytes (expected by HP mask for long headers)
    pn_bytes.resize(max_pn_len, 0);

    remote_keys
        .header
        .decrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::ProtocolViolation))?;

    // After HP removal: extract the real PN length from first byte
    let pn_len = match packet[0] & 0x80 {
        0x80 => ((first_byte & 0x03) + 1) as usize, // long header: bits 0-1
        _ => (first_byte & 0x03) as usize,          // short header: no +1
    };
    let pn_len = if pn_len == 0 { 4 } else { pn_len }; // short header: 0 means 4

    let pn_bytes = &pn_bytes[..pn_len];

    // Decode full packet number
    let truncated_pn = read_pn(pn_bytes);
    let full_pn =
        packet::decode_packet_number(space.largest_recv_pn(), truncated_pn as u64, pn_len as u8);

    // Rebuild unprotected header for AEAD AAD
    let aad_len = pn_offset + pn_len;
    if packet.len() < aad_len {
        return Err(ConnectionError::Packet(
            packet::PacketError::BufferTooShort {
                needed: aad_len,
                actual: packet.len(),
            },
        ));
    }
    let mut aad = Vec::from(&packet[..aad_len]);
    aad[0] = first_byte;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(pn_bytes);

    // AEAD decrypt the payload
    let mut encrypted_payload = Vec::from(&packet[aad_len..]);
    let plaintext = remote_keys
        .packet
        .decrypt_in_place(full_pn, &aad, &mut encrypted_payload)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::ProtocolViolation))?;

    // Parse frames
    let mut remaining = plaintext;
    while !remaining.is_empty() {
        let (frame, consumed) = frame::parse_frame(remaining)?;
        remaining = &remaining[consumed..];
        let _ = frame;
    }

    Ok(packet.len())
}

// ── Packet header abstraction ───────────────────────────────────

/// Trait over long and short headers for decrypt_and_process.
trait PacketHeader {
    fn pn_offset(&self) -> usize;
}

impl PacketHeader for packet::LongHeader {
    fn pn_offset(&self) -> usize {
        let prefix = 1 + 4 + 1 + self.dst_cid.0.len() + 1 + self.src_cid.0.len();
        let token_len_size = if self.token.is_some() {
            let token_bytes = self.token.as_ref().map_or(0, |t| t.len());
            varint::encoded_len(token_bytes as VarInt)
        } else {
            1
        };
        let length_field_size = self.length.map_or(0, varint::encoded_len);
        prefix + token_len_size + length_field_size
    }
}

impl PacketHeader for packet::ShortHeader {
    fn pn_offset(&self) -> usize {
        1 + self.dst_cid.0.len()
    }
}

// ── Initial packet builder ──────────────────────────────────────

fn build_initial_packet(
    keys: &rustls::quic::Keys,
    dst_cid: &[u8],
    src_cid: &[u8],
    client_hello: &[u8],
) -> Result<Vec<u8>, ConnectionError> {
    use crate::frame::{self, Frame};
    use crate::varint;
    use bytes::Bytes;

    let pn: u64 = 0;
    let pn_len: usize = 1;
    let tag_len = keys.local.packet.tag_len();

    // Build CRYPTO frame
    let crypto_frame = Frame::Crypto {
        offset: 0,
        data: Bytes::copy_from_slice(client_hello),
    };
    let mut frames_buf = Vec::new();
    frame::write_frame(&crypto_frame, &mut frames_buf)?;

    // Calculate header layout
    let hdr_prefix = 1 + 4 + 1 + dst_cid.len() + 1 + src_cid.len();
    let token_len_varint_size = 1;
    let length_field_size = 2;
    let pn_offset = hdr_prefix + token_len_varint_size + length_field_size;

    // Pad to 1200 bytes
    let header_total = pn_offset + pn_len;
    let plaintext_min = 1200usize.saturating_sub(header_total + tag_len);
    let plaintext_len = frames_buf.len().max(plaintext_min);
    let length_value = (pn_len + plaintext_len + tag_len) as VarInt;

    // Plaintext-only payload
    let mut payload = vec![0u8; plaintext_len];
    payload[..frames_buf.len()].copy_from_slice(&frames_buf);
    for b in payload.iter_mut().skip(frames_buf.len()) {
        *b = 0x00; // PADDING
    }

    // Build header
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
    header[pn_offset] = 0x00;

    // AEAD encrypt
    let tag = keys
        .local
        .packet
        .encrypt_in_place(pn, &header, &mut payload)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    payload.extend_from_slice(tag.as_ref());

    // Header protection
    let sample_start = 4 - pn_len;
    let sample_len = keys.local.header.sample_len();
    let sample = &payload[sample_start..sample_start + sample_len];
    let mut first_byte = header[0];
    let mut pn_bytes = [header[pn_offset]];
    keys.local
        .header
        .encrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    header[0] = first_byte;
    header[pn_offset] = pn_bytes[0];

    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&payload);
    Ok(packet)
}

// ── Helpers ─────────────────────────────────────────────────────

fn read_pn(bytes: &[u8]) -> u32 {
    match bytes.len() {
        1 => bytes[0] as u32,
        2 => u16::from_be_bytes([bytes[0], bytes[1]]) as u32,
        3 => u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        _ => 0,
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).expect("getrandom");
    buf
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_produces_valid_initial() {
        let (_conn, packet) = Connection::connect("localhost").expect("connect");
        assert!(packet.len() >= 1200, "Initial packet must be >= 1200 bytes");
        assert_eq!(packet[0] & 0x80, 0x80, "must be long header");
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        assert_eq!(version, packet::VERSION_1);
    }

    #[test]
    fn connect_then_reingest() {
        let (mut conn, packet) = Connection::connect("localhost").expect("connect");

        // Extract DCID for server key derivation
        let dcid_len = packet[5] as usize;
        let dcid = &packet[6..6 + dcid_len];

        // Re-ingest: decrypt and parse the packet we just generated
        let server_keys = crate::crypto::server_initial_keys(dcid).unwrap();

        // Manually set server keys in the connection's initial space
        // so the decrypt_and_parse works from the server perspective
        conn.initial_space = {
            let mut space = Space::new(PacketNumberSpace::Initial);
            space.set_keys(server_keys);
            space
        };

        let result = conn.ingest(&packet);
        assert!(result.is_ok(), "ingest our own Initial: {result:?}");
        assert_eq!(result.unwrap(), packet.len());
    }
}
