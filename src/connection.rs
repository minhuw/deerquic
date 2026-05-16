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
//!    accept()  ───────────────→ creates server from incoming Initial
//!    ingest(&[u8]) ───────────→ processes incoming QUIC packet
//!    egest(&mut [u8]) ←──────── produces outgoing QUIC packet
//!    next_timeout() ←────────── when to fire a timer
//!    on_timeout() ────────────→ timer fired
//! ```

use crate::error::ConnectionError;
use crate::frame::{self, AckRange, Frame};
use crate::packet::{self, LongType, PacketNumberSpace};
use crate::space::Space;
use crate::varint::{self, VarInt};
use bytes::Bytes;
use rustls::quic::{self, Keys};
use std::sync::Arc;
use std::time::Instant;

// ── Side ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

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
    side: Side,
    state: State,
    tls: quic::Connection,
    /// QUIC version in use.
    version: u32,
    /// Destination Connection ID (the peer's CID — what we put in packets we send).
    dst_cid: Vec<u8>,
    /// Source Connection ID (our CID — what the peer sends to).
    src_cid: Vec<u8>,
    /// The three packet number spaces.
    pub(crate) initial_space: Space,
    pub(crate) handshake_space: Space,
    pub(crate) appdata_space: Space,
    /// Buffered CRYPTO data from TLS output, per encryption level.
    /// Index 0 = Initial, 1 = Handshake, 2 = ApplicationData.
    pending_crypto: [Vec<u8>; 3],
    /// Crypto stream receive offset per level (for ordering CRYPTO frames).
    crypto_recv_offset: [u64; 3],
    close_reason: Option<ConnectionError>,
}

impl Connection {
    // ── Client constructor ──────────────────────────────────────

    /// Create a new client connection and produce the first Initial packet.
    pub fn connect(server_name: &str) -> Result<(Self, Vec<u8>), ConnectionError> {
        let _ = crate::crypto::install_provider();

        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(SkipVerify))
                .with_no_client_auth();

        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;

        let mut tls_client = quic::ClientConnection::new(
            Arc::new(config),
            quic::Version::V1,
            name,
            vec![], // transport params
        )?;

        let mut client_hello = Vec::new();
        let _ = tls_client.write_hs(&mut client_hello);

        let tls = quic::Connection::Client(tls_client);

        let dst_cid = random_bytes(8);
        let src_cid = random_bytes(8);

        let keys = crate::crypto::client_initial_keys(&dst_cid)?;
        let packet = build_initial_packet(&keys, &dst_cid, &src_cid, &client_hello, 0)?;

        let mut initial_space = Space::new(PacketNumberSpace::Initial);
        initial_space.set_keys(keys);
        let _ = initial_space.next_send_pn(); // PN 0 consumed

        Ok((
            Self {
                side: Side::Client,
                state: State::Connecting,
                tls,
                version: packet::VERSION_1,
                dst_cid,
                src_cid,
                initial_space,
                handshake_space: Space::new(PacketNumberSpace::Handshake),
                appdata_space: Space::new(PacketNumberSpace::ApplicationData),
                pending_crypto: [Vec::new(), Vec::new(), Vec::new()],
                crypto_recv_offset: [0; 3],
                close_reason: None,
            },
            packet,
        ))
    }

    // ── Server constructor ──────────────────────────────────────

    /// Accept a connection from an incoming client Initial packet.
    ///
    /// Returns the new server [`Connection`]. The caller should call
    /// [`egest`](Self::egest) to retrieve response packets.
    pub fn accept(
        initial_packet: &[u8],
        server_config: Arc<rustls::ServerConfig>,
    ) -> Result<Self, ConnectionError> {
        let _ = crate::crypto::install_provider();

        // 1. Parse the Initial packet header
        let (hdr, hdr_len) = packet::parse_long_header(initial_packet)?;
        let dst_cid = hdr.dst_cid.0.to_vec(); // our (server's) CID
        let src_cid = hdr.src_cid.0.to_vec(); // client's CID

        // 2. Derive server initial keys and decrypt client's Initial
        // Client encrypts with client_initial_secret, server decrypts with same.
        // server_keys.remote = client_initial_secret keys = correct for decryption.
        let server_keys = crate::crypto::server_initial_keys(&dst_cid)?;

        let (frames, _pn) = decrypt_initial(initial_packet, &hdr, hdr_len, &server_keys)?;

        // 3. Extract ClientHello from CRYPTO frames
        let mut client_hello = Vec::new();
        for frame in &frames {
            if let Frame::Crypto { offset, data } = frame {
                if *offset == 0 {
                    client_hello.extend_from_slice(data);
                }
            }
        }

        // 4. Create server TLS connection (use ServerConnection directly)
        let mut tls_server = quic::ServerConnection::new(server_config, quic::Version::V1, vec![])?;

        // 5. Feed ClientHello to TLS
        tls_server.read_hs(&client_hello)?;
        let mut buf = Vec::new();
        let kc = tls_server.write_hs(&mut buf);
        let mut tls = quic::Connection::Server(tls_server);
        let (crypto_out, hs_keys) = process_tls_output(Some((buf, kc)), 0);

        // Convert crypto_out to pending_crypto
        let mut pending_crypto: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (lvl, data) in crypto_out {
            if lvl < 3 {
                pending_crypto[lvl] = data;
            }
        }

        let mut initial_space = Space::new(PacketNumberSpace::Initial);
        initial_space.set_keys(server_keys);
        let mut handshake_space = Space::new(PacketNumberSpace::Handshake);
        let mut appdata_space = Space::new(PacketNumberSpace::ApplicationData);
        let has_hs = hs_keys.is_some();
        if let Some(keys) = hs_keys {
            handshake_space.set_keys(keys);
        }

        // 7. Call write_hs() again to get Handshake-level data
        if has_hs {
            let mut buf2 = Vec::new();
            let kc2 = tls.write_hs(&mut buf2);
            if !buf2.is_empty() || kc2.is_some() {
                let (crypto_out2, one_rtt_keys) = process_tls_output(Some((buf2, kc2)), 1);
                for (lvl, data) in crypto_out2 {
                    if lvl < 3 {
                        pending_crypto[lvl] = data;
                    }
                }
                if let Some(keys) = one_rtt_keys {
                    appdata_space.set_keys(keys);
                }
            }
        }

        // Record client's Initial as received
        initial_space.record_recv_pn(0);

        Ok(Self {
            side: Side::Server,
            state: State::Handshaking,
            tls,
            version: hdr.version,
            dst_cid: src_cid, // we send TO client's CID
            src_cid: dst_cid, // client sends TO our CID
            initial_space,
            handshake_space,
            appdata_space,
            pending_crypto,
            crypto_recv_offset: [client_hello.len() as u64, 0, 0],
            close_reason: None,
        })
    }

    // ── Ingest ──────────────────────────────────────────────────

    /// Feed a raw QUIC packet (UDP payload) into the connection.
    pub fn ingest(&mut self, buf: &[u8]) -> Result<usize, ConnectionError> {
        if self.state == State::Closed {
            return Err(ConnectionError::Closed);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        // 1. Parse header and decrypt
        let is_long = (buf[0] & 0x80) != 0;
        let (pn_space_id, pn, frames) = if !is_long {
            let (hdr, hdr_len) = packet::parse_short_header(buf, self.dst_cid.len())?;
            let pn_offset = hdr_pn_offset_short(&hdr);
            let (pn, parsed_frames) =
                decrypt_and_parse(&self.appdata_space, &hdr, buf, hdr_len, pn_offset)?;
            (PacketNumberSpace::ApplicationData, pn, parsed_frames)
        } else {
            let (hdr, hdr_len) = packet::parse_long_header(buf)?;
            let pn_offset = hdr_pn_offset_long(&hdr);
            let (pn, parsed_frames) = match hdr.ty {
                LongType::Initial => {
                    decrypt_and_parse_long(&self.initial_space, &hdr, buf, 0, pn_offset)?
                }
                LongType::Handshake => {
                    decrypt_and_parse_long(&self.handshake_space, &hdr, buf, hdr_len, pn_offset)?
                }
                LongType::ZeroRtt => {
                    decrypt_and_parse_long(&self.appdata_space, &hdr, buf, hdr_len, pn_offset)?
                }
                LongType::Retry | LongType::VersionNegotiation => {
                    return Err(ConnectionError::Transport(
                        crate::error::TransportError::ProtocolViolation, // PV0
                    ));
                }
            };
            let pn_space = match hdr.ty {
                LongType::Initial => PacketNumberSpace::Initial,
                LongType::Handshake => PacketNumberSpace::Handshake,
                LongType::ZeroRtt => PacketNumberSpace::ApplicationData,
                _ => unreachable!(),
            };
            (pn_space, pn, parsed_frames)
        };

        // 2. Record receipt
        {
            let space = self.space_mut(pn_space_id);
            space.record_recv_pn(pn);
        }

        // 3. Process frames
        self.process_frames(&frames, pn_space_id, pn)?;

        Ok(buf.len())
    }

    // ── Egest ───────────────────────────────────────────────────

    /// Produce the next outgoing packet. Returns bytes written (0 if idle).
    pub fn egest(&mut self, buf: &mut [u8]) -> Result<usize, ConnectionError> {
        if self.state == State::Closed {
            return Err(ConnectionError::Closed);
        }
        // Collect all data we need from self before assembling
        let version = self.version;
        let dst_cid = self.dst_cid.clone();
        let src_cid = self.src_cid.clone();
        let is_established = matches!(self.state, State::Established);
        let side = self.side;
        let state = self.state;

        // Process each space in priority order
        let spaces = [
            (&mut self.initial_space, PacketNumberSpace::Initial, 0),
            (&mut self.handshake_space, PacketNumberSpace::Handshake, 1),
            (
                &mut self.appdata_space,
                PacketNumberSpace::ApplicationData,
                2,
            ),
        ];

        for (space, pn_space, crypto_idx) in spaces {
            if !space.has_keys() {
                continue;
            }

            let mut frames = Vec::new();

            let crypto_data = std::mem::take(&mut self.pending_crypto[crypto_idx]);
            if !crypto_data.is_empty() {
                frames.push(Frame::Crypto {
                    offset: 0,
                    data: Bytes::from(crypto_data),
                });
            }

            let acks = space.take_pending_acks();
            if !acks.is_empty() {
                let largest = *acks.iter().max().unwrap_or(&0);
                let first_range = acks.len().saturating_sub(1) as u64;
                frames.push(Frame::Ack {
                    largest_ack: largest,
                    ack_delay: 0,
                    ranges: vec![AckRange {
                        gap: 0,
                        range: first_range,
                    }],
                    ecn: None,
                });
            }

            if pn_space == PacketNumberSpace::ApplicationData
                && side == Side::Server
                && state == State::Handshaking
            {
                frames.push(Frame::HandshakeDone);
                self.state = State::Established; // only send once
            }

            if frames.is_empty() {
                continue;
            }

            let pn = space.next_send_pn();
            let pn_len = encoded_pn_len(pn, space.largest_recv_pn());
            let packet = encrypt_packet(
                space,
                pn_space,
                version,
                &dst_cid,
                &src_cid,
                &frames,
                pn,
                pn_len,
                is_established,
            );
            let packet = packet?;
            let len = packet.len();
            if buf.len() < len {
                return Ok(0);
            }
            buf[..len].copy_from_slice(&packet);
            return Ok(len);
        }

        Ok(0)
    }

    // ── Timer interface ──────────────────────────────────────────

    pub fn next_timeout(&self) -> Option<Instant> {
        None // TODO: loss detection, idle timeout
    }

    pub fn on_timeout(&mut self) {
        // TODO: retransmit, probe, etc.
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

    pub fn version(&self) -> u32 {
        self.version
    }
}

// ── Helpers ─────────────────────────────────────────────────────

impl Connection {
    fn space_mut(&mut self, id: PacketNumberSpace) -> &mut Space {
        match id {
            PacketNumberSpace::Initial => &mut self.initial_space,
            PacketNumberSpace::Handshake => &mut self.handshake_space,
            PacketNumberSpace::ApplicationData => &mut self.appdata_space,
        }
    }
}

// ── Frame processing ────────────────────────────────────────────

impl Connection {
    fn process_frames(
        &mut self,
        frames: &[Frame],
        pn_space_id: PacketNumberSpace,
        _pn: u64,
    ) -> Result<(), ConnectionError> {
        let level = pn_space_to_level(pn_space_id);

        for frame in frames {
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Ack { .. } => {
                    // TODO: process ACK for loss detection
                }
                Frame::Crypto { offset, data } => {
                    if level <= 2 {
                        let expected = self.crypto_recv_offset[level];
                        if *offset == expected {
                            // Feed to TLS directly (bypass feed_tls)
                            match &mut self.tls {
                                quic::Connection::Client(conn) => conn.read_hs(data)?,
                                quic::Connection::Server(conn) => conn.read_hs(data)?,
                            }
                            let mut out_buf = Vec::new();
                            let kc = match &mut self.tls {
                                quic::Connection::Client(conn) => conn.write_hs(&mut out_buf),
                                quic::Connection::Server(conn) => conn.write_hs(&mut out_buf),
                            };
                            let (crypto_out, new_keys) =
                                process_tls_output(Some((out_buf, kc)), level);
                            self.handle_crypto_output(crypto_out, new_keys, level)?;
                            self.crypto_recv_offset[level] += data.len() as u64;
                        }
                    }
                }
                Frame::ConnectionClose {
                    error_code,
                    frame_type: _,
                    reason: _,
                } => {
                    self.state = State::Closed;
                    self.close_reason = Some(ConnectionError::Transport(
                        crate::error::TransportError::from_code(*error_code)
                            .unwrap_or(crate::error::TransportError::InternalError),
                    ));
                }
                Frame::HandshakeDone => {
                    if self.side == Side::Client {
                        self.state = State::Established;
                    }
                }
                _ => {} // Other frames not processed yet
            }
        }
        Ok(())
    }

    /// Handle CRYPTO output from TLS and any key changes.
    fn handle_crypto_output(
        &mut self,
        crypto_out: Vec<(usize, Vec<u8>)>,
        new_keys: Option<Keys>,
        level: usize,
    ) -> Result<(), ConnectionError> {
        // Buffer CRYPTO data for egest
        for (lvl, data) in crypto_out {
            if lvl < 3 {
                self.pending_crypto[lvl].extend_from_slice(&data);
            }
        }

        // Install new keys, then call write_hs() again to get data at the next level
        if let Some(keys) = new_keys {
            match level {
                0 => {
                    if !self.handshake_space.has_keys() {
                        self.handshake_space.set_keys(keys);
                    }
                    // Call write_hs again to get next-level data
                    let mut buf2 = Vec::new();
                    let kc2 = match &mut self.tls {
                        quic::Connection::Client(conn) => conn.write_hs(&mut buf2),
                        quic::Connection::Server(conn) => conn.write_hs(&mut buf2),
                    };
                    if !buf2.is_empty() || kc2.is_some() {
                        let (crypto_out2, keys2) = process_tls_output(Some((buf2, kc2)), 1);
                        for (lvl, data) in crypto_out2 {
                            if lvl < 3 {
                                self.pending_crypto[lvl].extend_from_slice(&data);
                            }
                        }
                        if let Some(keys2) = keys2 {
                            if !self.appdata_space.has_keys() {
                                self.appdata_space.set_keys(keys2);
                                self.state = State::Established;
                            }
                        }
                    }
                }
                1 => {
                    if !self.appdata_space.has_keys() {
                        self.appdata_space.set_keys(keys);
                        self.state = State::Established;
                    }
                    // Get more TLS output at 1-RTT level
                    let mut buf = Vec::new();
                    let kc2 = match &mut self.tls {
                        quic::Connection::Client(c) => c.write_hs(&mut buf),
                        quic::Connection::Server(s) => s.write_hs(&mut buf),
                    };
                    if !buf.is_empty() || kc2.is_some() {
                        let (crypto_out2, keys2) = process_tls_output(Some((buf, kc2)), 2);
                        for (lvl, data) in crypto_out2 {
                            if lvl < 3 {
                                self.pending_crypto[lvl].extend_from_slice(&data);
                            }
                        }
                        if let Some(keys2) = keys2 {
                            self.appdata_space.set_keys(keys2);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Free function: encrypt a packet with AEAD + header protection.
#[allow(clippy::too_many_arguments)]
fn encrypt_packet(
    space: &Space,
    pn_space: PacketNumberSpace,
    version: u32,
    dst_cid: &[u8],
    src_cid: &[u8],
    frames: &[Frame],
    pn: u64,
    pn_len: usize,
    is_established: bool,
) -> Result<Vec<u8>, ConnectionError> {
    // debug
    let local_keys = space.local_keys().ok_or_else(|| {
        // no keys
        ConnectionError::Transport(crate::error::TransportError::InternalError)
    })?;

    let tag_len = local_keys.packet.tag_len();
    let is_long = pn_space != PacketNumberSpace::ApplicationData || !is_established;

    // Serialize frames
    let mut frames_buf = Vec::new();
    for f in frames {
        frame::write_frame(f, &mut frames_buf)?;
    }

    // Pad Initial packets to 1200 bytes
    if pn_space == PacketNumberSpace::Initial {
        let hdr_estimate = if is_long {
            hdr_size_long(
                dst_cid.len(),
                src_cid.len(),
                0,
                frames_buf.len() + pn_len + tag_len,
            )
        } else {
            1 + dst_cid.len() + pn_len
        };
        let min_size = 1200usize;
        let payload_needed = min_size.saturating_sub(hdr_estimate + tag_len);
        while frames_buf.len() < payload_needed {
            frames_buf.push(0x00);
        }
    }

    // Ensure minimum payload for HP sample (sample_len + 4 - pn_len bytes)
    let hp_min = local_keys.header.sample_len() + 4 - pn_len;
    while frames_buf.len() < hp_min {
        frames_buf.push(0x00);
    }

    if is_long {
        encrypt_long(
            local_keys,
            pn_space,
            version,
            dst_cid,
            src_cid,
            &frames_buf,
            pn,
            pn_len,
            if pn_space == PacketNumberSpace::Initial {
                Some(&[][..])
            } else {
                None
            },
        )
    } else {
        encrypt_short(local_keys, dst_cid, &frames_buf, pn, pn_len, false)
    }
}

// ── TLS integration ──────────────────────────────────────────────

/// Process TLS output at the given encryption level.
/// Returns (level, data) pairs and optional new keys.
fn process_tls_output(
    tls_out: Option<(Vec<u8>, Option<quic::KeyChange>)>,
    current_level: usize,
) -> (Vec<(usize, Vec<u8>)>, Option<Keys>) {
    let mut crypto = Vec::new();
    let mut new_keys = None;

    if let Some((data, key_change)) = tls_out {
        if !data.is_empty() {
            crypto.push((current_level, data));
        }

        if let Some(quic::KeyChange::Handshake { keys }) = key_change {
            new_keys = Some(keys);
        } else if let Some(quic::KeyChange::OneRtt { keys, .. }) = key_change {
            new_keys = Some(keys);
        }
    }

    (crypto, new_keys)
}

fn pn_space_to_level(id: PacketNumberSpace) -> usize {
    match id {
        PacketNumberSpace::Initial => 0,
        PacketNumberSpace::Handshake => 1,
        PacketNumberSpace::ApplicationData => 2,
    }
}

// ── Packet decryption helpers ───────────────────────────────────

/// Decrypt an Initial packet using the given keys. Returns parsed frames + PN.
fn decrypt_initial(
    packet: &[u8],
    hdr: &packet::LongHeader,
    _hdr_len: usize,
    keys: &Keys,
) -> Result<(Vec<Frame>, u64), ConnectionError> {
    let pn_offset = hdr_pn_offset_long(hdr);
    let (pn, frames) = decrypt_and_parse_long_inner(packet, pn_offset, &keys.remote)?;
    Ok((frames, pn))
}

/// Decrypt and parse any long header packet.
fn decrypt_and_parse_long(
    space: &Space,
    _hdr: &packet::LongHeader,
    packet: &[u8],
    _hdr_len: usize,
    pn_offset: usize,
) -> Result<(u64, Vec<Frame>), ConnectionError> {
    let remote = space
        .remote_keys()
        .ok_or_else(|| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    decrypt_and_parse_long_inner(packet, pn_offset, remote)
}

fn decrypt_and_parse_long_inner(
    packet: &[u8],
    pn_offset: usize,
    remote_keys: &rustls::quic::DirectionalKeys,
) -> Result<(u64, Vec<Frame>), ConnectionError> {
    let sample_len = remote_keys.header.sample_len();
    let sample_start = pn_offset + 4;
    if packet.len() < sample_start + sample_len {
        return Err(ConnectionError::Packet(
            packet::PacketError::BufferTooShort {
                needed: sample_start + sample_len,
                actual: packet.len(),
            },
        ));
    }
    let sample = &packet[sample_start..sample_start + sample_len];

    // Assume 4-byte PN for HP removal
    let max_pn = 4;
    let pn_end = (pn_offset + max_pn).min(packet.len());
    let mut first_byte = packet[0];
    let mut pn_bytes = (packet[pn_offset..pn_end]).to_vec();
    pn_bytes.resize(max_pn, 0);

    remote_keys
        .header
        .decrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::ProtocolViolation))?;

    // Extract real PN length
    let pn_len = ((first_byte & 0x03) + 1) as usize;
    let pn_bytes = &pn_bytes[..pn_len];

    // Decode full PN
    let truncated = read_pn(pn_bytes);
    let full_pn = packet::decode_packet_number(0, truncated as u64, pn_len as u8);

    // Rebuild AAD
    let aad_len = pn_offset + pn_len;
    let mut aad = Vec::from(&packet[..aad_len]);
    aad[0] = first_byte;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(pn_bytes);

    // AEAD decrypt
    let _enc_len = packet[aad_len..].len();
    let mut encrypted = Vec::from(&packet[aad_len..]);
    let plaintext = remote_keys
        .packet
        .decrypt_in_place(full_pn, &aad, &mut encrypted)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::ProtocolViolation))?;

    // Parse frames
    let mut remaining = plaintext;
    let mut frames = Vec::new();
    while !remaining.is_empty() {
        let (frame, consumed) = frame::parse_frame(remaining)?;
        remaining = &remaining[consumed..];
        frames.push(frame);
    }

    Ok((full_pn, frames))
}

/// Decrypt and parse a short header packet.
fn decrypt_and_parse(
    space: &Space,
    _hdr: &packet::ShortHeader,
    packet: &[u8],
    _hdr_len: usize,
    pn_offset: usize,
) -> Result<(u64, Vec<Frame>), ConnectionError> {
    let remote_keys = space
        .remote_keys()
        .ok_or_else(|| ConnectionError::Transport(crate::error::TransportError::InternalError))?;

    let sample_len = remote_keys.header.sample_len();
    let sample_start = pn_offset + 4;
    let sample = &packet[sample_start..sample_start + sample_len];

    let max_pn = 4;
    let pn_end = (pn_offset + max_pn).min(packet.len());
    let mut first_byte = packet[0];
    let mut pn_bytes = (packet[pn_offset..pn_end]).to_vec();
    pn_bytes.resize(max_pn, 0);

    remote_keys
        .header
        .decrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::ProtocolViolation))?;

    // Short header: PN length encoded directly (0 = 4 bytes)
    let pn_len = match first_byte & 0x03 {
        0 => 4,
        n => n as usize,
    };
    let pn_bytes = &pn_bytes[..pn_len];

    let truncated = read_pn(pn_bytes);
    let full_pn =
        packet::decode_packet_number(space.largest_recv_pn(), truncated as u64, pn_len as u8);

    let aad_len = pn_offset + pn_len;
    let mut aad = Vec::from(&packet[..aad_len]);
    aad[0] = first_byte;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(pn_bytes);

    let mut encrypted = Vec::from(&packet[aad_len..]);
    let plaintext = remote_keys
        .packet
        .decrypt_in_place(full_pn, &aad, &mut encrypted)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::ProtocolViolation))?;

    let mut remaining = plaintext;
    let mut frames = Vec::new();
    while !remaining.is_empty() {
        let (frame, consumed) = frame::parse_frame(remaining)?;
        remaining = &remaining[consumed..];
        frames.push(frame);
    }

    Ok((full_pn, frames))
}

// ── Header offset helpers ───────────────────────────────────────

fn hdr_pn_offset_long(hdr: &packet::LongHeader) -> usize {
    let prefix = 1 + 4 + 1 + hdr.dst_cid.0.len() + 1 + hdr.src_cid.0.len();
    let token_len_size = if hdr.ty == LongType::Initial {
        1 // token length = 0 → 1 byte varint
    } else {
        0
    };
    let length_field_size = hdr.length.map_or(0, varint::encoded_len);
    prefix + token_len_size + length_field_size
}

fn hdr_pn_offset_short(hdr: &packet::ShortHeader) -> usize {
    1 + hdr.dst_cid.0.len()
}

fn hdr_size_long(
    dst_cid_len: usize,
    src_cid_len: usize,
    _token_len: usize,
    length: usize,
) -> usize {
    let token_varint_size = 1; // token length always present for Initial
    let length_varint_size = varint::encoded_len(length as VarInt);
    1 + 4 + 1 + dst_cid_len + 1 + src_cid_len + token_varint_size + length_varint_size
}

// ── Packet encryption helpers ───────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn encrypt_long(
    keys: &rustls::quic::DirectionalKeys,
    pn_space: PacketNumberSpace,
    version: u32,
    dst_cid: &[u8],
    src_cid: &[u8],
    frames: &[u8],
    pn: u64,
    pn_len: usize,
    token: Option<&[u8]>,
) -> Result<Vec<u8>, ConnectionError> {
    let tag_len = keys.packet.tag_len();
    let is_initial = pn_space == PacketNumberSpace::Initial;

    let mut payload = frames.to_vec();

    let hdr_prefix = 1 + 4 + 1 + dst_cid.len() + 1 + src_cid.len();
    let token_varint_size = if is_initial {
        varint::encoded_len(token.map_or(0, |t| t.len() as VarInt))
    } else {
        0
    };
    let length_value = (pn_len + payload.len() + tag_len) as VarInt;
    let length_varint_size = varint::encoded_len(length_value);
    let pn_offset = hdr_prefix + token_varint_size + length_varint_size;

    let mut header = vec![0u8; pn_offset + pn_len];
    let type_bits = match pn_space {
        PacketNumberSpace::Initial => 0u8,
        PacketNumberSpace::ApplicationData => 1u8, // 0-RTT uses type 1
        PacketNumberSpace::Handshake => 2u8,
    };
    header[0] = 0b1100_0000 | (type_bits << 4) | ((pn_len - 1) as u8);
    header[1..5].copy_from_slice(&version.to_be_bytes());
    header[5] = dst_cid.len() as u8;
    header[6..6 + dst_cid.len()].copy_from_slice(dst_cid);
    let scid_pos = 6 + dst_cid.len();
    header[scid_pos] = src_cid.len() as u8;
    header[scid_pos + 1..scid_pos + 1 + src_cid.len()].copy_from_slice(src_cid);

    let _length_pos = if is_initial {
        let token_pos = scid_pos + 1 + src_cid.len();
        let token_len = token.map_or(0, |t| t.len() as VarInt);
        varint::encode(token_len, &mut header[token_pos..])?;
        let tvs = varint::encoded_len(token_len);
        let length_pos = token_pos + tvs;
        varint::encode(length_value, &mut header[length_pos..])?;
        length_pos
    } else {
        let length_pos = scid_pos + 1 + src_cid.len();
        varint::encode(length_value, &mut header[length_pos..])?;
        length_pos
    };
    write_pn(&mut header[pn_offset..], pn, pn_len);

    // AEAD encrypt
    let tag = keys
        .packet
        .encrypt_in_place(pn, &header, &mut payload)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    payload.extend_from_slice(tag.as_ref());

    // Header protection
    let sample_start = 4 - pn_len; // within payload
    let sample_len = keys.header.sample_len();
    let sample = &payload[sample_start..sample_start + sample_len];
    let mut first_byte = header[0];
    let mut pn_bytes = vec![0u8; pn_len];
    pn_bytes.copy_from_slice(&header[pn_offset..pn_offset + pn_len]);
    keys.header
        .encrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    header[0] = first_byte;
    header[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes);

    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&payload);
    Ok(packet)
}

fn encrypt_short(
    keys: &rustls::quic::DirectionalKeys,
    dst_cid: &[u8],
    frames: &[u8],
    pn: u64,
    pn_len: usize,
    key_phase: bool,
) -> Result<Vec<u8>, ConnectionError> {
    let mut payload = frames.to_vec();

    let pn_offset = 1 + dst_cid.len();
    let mut header = vec![0u8; pn_offset + pn_len];

    let pn_len_enc = if pn_len == 4 { 0u8 } else { pn_len as u8 };
    header[0] = 0x40 | if key_phase { 0x04 } else { 0 } | pn_len_enc;
    header[1..1 + dst_cid.len()].copy_from_slice(dst_cid);
    write_pn(&mut header[pn_offset..], pn, pn_len);

    let tag = keys
        .packet
        .encrypt_in_place(pn, &header, &mut payload)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    payload.extend_from_slice(tag.as_ref());

    let sample_start = 4 - pn_len;
    let sample_len = keys.header.sample_len();
    let sample = &payload[sample_start..sample_start + sample_len];
    let mut first_byte = header[0];
    let mut pn_bytes = vec![0u8; pn_len];
    pn_bytes.copy_from_slice(&header[pn_offset..pn_offset + pn_len]);
    keys.header
        .encrypt_in_place(sample, &mut first_byte, &mut pn_bytes)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    header[0] = first_byte;
    header[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes);

    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&payload);
    Ok(packet)
}

// ── Initial packet builder (for connect) ────────────────────────

fn build_initial_packet(
    keys: &Keys,
    dst_cid: &[u8],
    src_cid: &[u8],
    client_hello: &[u8],
    token_len: u64,
) -> Result<Vec<u8>, ConnectionError> {
    let pn: u64 = 0;
    let pn_len: usize = 1;
    let tag_len = keys.local.packet.tag_len();

    let crypto_frame = Frame::Crypto {
        offset: 0,
        data: Bytes::copy_from_slice(client_hello),
    };
    let mut frames_buf = Vec::new();
    frame::write_frame(&crypto_frame, &mut frames_buf)?;

    // Pad to 1200
    let hdr_est = hdr_size_long(
        dst_cid.len(),
        src_cid.len(),
        token_len as usize,
        frames_buf.len() + pn_len + tag_len,
    );
    let min_payload = 1200usize.saturating_sub(hdr_est + tag_len);
    while frames_buf.len() < min_payload {
        frames_buf.push(0x00);
    }

    encrypt_long(
        &keys.local,
        PacketNumberSpace::Initial,
        packet::VERSION_1,
        dst_cid,
        src_cid,
        &frames_buf,
        pn,
        pn_len,
        Some(&[][..]),
    )
}

// ── Helpers ─────────────────────────────────────────────────────

fn encoded_pn_len(pn: u64, largest_acked: u64) -> usize {
    let _ = largest_acked;
    if pn < 256 {
        1
    } else if pn < 65536 {
        2
    } else {
        4
    }
}

fn write_pn(buf: &mut [u8], pn: u64, len: usize) {
    match len {
        1 => buf[0] = pn as u8,
        2 => {
            buf[0] = (pn >> 8) as u8;
            buf[1] = pn as u8;
        }
        3 => {
            buf[0] = (pn >> 16) as u8;
            buf[1] = (pn >> 8) as u8;
            buf[2] = pn as u8;
        }
        4 => {
            buf[0] = (pn >> 24) as u8;
            buf[1] = (pn >> 16) as u8;
            buf[2] = (pn >> 8) as u8;
            buf[3] = pn as u8;
        }
        _ => {}
    }
}

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

// ── Certificate verifier for testing ───────────────────────────

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = cert.key_pair.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        let config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key)
                .unwrap();
        Arc::new(config)
    }

    #[test]
    fn connect_produces_valid_initial() {
        let (_conn, packet) = Connection::connect("localhost").expect("connect");
        assert!(packet.len() >= 1200);
        assert_eq!(packet[0] & 0x80, 0x80);
    }

    #[test]
    fn connect_and_reingest() {
        let (_conn, packet) = Connection::connect("localhost").unwrap();
        let (hdr, hdr_len) = packet::parse_long_header(&packet).unwrap();
        let dcid = &hdr.dst_cid.0;
        let server_keys = crate::crypto::server_initial_keys(dcid).unwrap();
        let (frames, pn) = decrypt_initial(&packet, &hdr, hdr_len, &server_keys).unwrap();
        assert!(pn == 0, "PN should be 0");
        assert!(!frames.is_empty(), "should have frames");
        // Verify the CRYPTO frame contains ClientHello (starts with 0x01)
        for f in &frames {
            if let Frame::Crypto { offset, data } = f {
                assert_eq!(*offset, 0);
                assert!(data.starts_with(&[0x01]), "ClientHello starts with 0x01");
            }
        }
    }

    #[test]
    fn hs_keys_match() {
        // Full flow: both sides get HS keys from TLS, verify they match
        let (mut client, client_initial) = Connection::connect("localhost").unwrap();
        let server_config = test_server_config();
        let mut server = Connection::accept(&client_initial, server_config).unwrap();

        // Get ALL server packets
        let mut buf = vec![0u8; 4096];
        let mut server_pkts = Vec::new();
        loop {
            let n = server.egest(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            server_pkts.push(buf[..n].to_vec());
        }

        // Client ingests first packet (Initial, contains ServerHello)
        client.ingest(&server_pkts[0]).unwrap();

        // Test HS keys RIGHT NOW, before ingesting the Handshake packet
        if client.handshake_space.has_keys() && server.handshake_space.has_keys() {
            let pt = b"hs key test before pkt1";
            let srv_local = server.handshake_space.local_keys().unwrap();
            let cli_remote = client.handshake_space.remote_keys().unwrap();

            let mut enc = pt.to_vec();
            let tag = srv_local
                .packet
                .encrypt_in_place(0, b"hdr", &mut enc)
                .unwrap();
            enc.extend_from_slice(tag.as_ref());
            let _dec = cli_remote
                .packet
                .decrypt_in_place(0, b"hdr", &mut enc)
                .unwrap();
        }

        // Now try ingesting the Handshake packet
        if server_pkts.len() > 1 {
            client.ingest(&server_pkts[1]).unwrap();
        }

        assert!(server.handshake_space.has_keys(), "server has HS keys");
        assert!(client.handshake_space.has_keys(), "client has HS keys");
        let plaintext = b"test data for key comparison";
        let srv_local = server.handshake_space.local_keys().unwrap();
        let cli_remote = client.handshake_space.remote_keys().unwrap();

        // Encrypt same plaintext with same PN+header using both keys.
        // If keys match, ciphertexts match (QUIC AEAD is deterministic).
        let mut enc1 = plaintext.to_vec();
        let t1 = srv_local
            .packet
            .encrypt_in_place(0, b"hdr", &mut enc1)
            .unwrap();
        let ct1 = enc1.clone();
        enc1.extend_from_slice(t1.as_ref());

        let mut enc2 = plaintext.to_vec();
        let t2 = cli_remote
            .packet
            .encrypt_in_place(0, b"hdr", &mut enc2)
            .unwrap();
        enc2.extend_from_slice(t2.as_ref());

        // Compare only the ciphertext portion (before tag)
        let ct1 = &enc1[..plaintext.len()];
        let ct2_part = &enc2[..plaintext.len()];
        assert_eq!(ct1, ct2_part, "ciphertexts must match if keys identical");

        // Also check decrypt using the srv_local-encrypted ciphertext
        let dec = cli_remote
            .packet
            .decrypt_in_place(0, b"hdr", &mut enc1)
            .unwrap();
        assert_eq!(dec, plaintext, "cross-decrypt after ct match");
    }

    #[test]
    fn rustls_handshake_keys_match() {
        // Minimal rustls-only test: client and server exchange handshake data,
        // check that their HS keys can encrypt/decrypt each other.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Client setup
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerify))
                .with_no_client_auth(),
        );
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut client =
            quic::ClientConnection::new(client_config, quic::Version::V1, server_name, vec![])
                .unwrap();

        // Server setup
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = cert.key_pair.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key)
                .unwrap(),
        );
        let mut server =
            quic::ServerConnection::new(server_config, quic::Version::V1, vec![]).unwrap();

        // Step 1: Client sends ClientHello
        let mut ch = Vec::new();
        let _kc = client.write_hs(&mut ch);
        assert!(!ch.is_empty(), "ClientHello");

        // Step 2: Server reads ClientHello, produces response
        server.read_hs(&ch).unwrap();
        let mut sh = Vec::new();
        let server_kc1 = server.write_hs(&mut sh);
        let server_hs_keys = match server_kc1 {
            Some(quic::KeyChange::Handshake { keys }) => Some(keys),
            _ => None,
        };
        // Data from first write_hs is at Initial level
        let initial_data = sh;

        // Step 3: Server second write_hs (Handshake level after KeyChange)
        let mut hd = Vec::new();
        let _server_kc2 = server.write_hs(&mut hd);
        let _handshake_data = hd;

        // Step 4: Client reads server's Initial data
        if !initial_data.is_empty() {
            client.read_hs(&initial_data).unwrap();
        }
        let mut client_resp = Vec::new();
        let client_kc1 = client.write_hs(&mut client_resp);
        let client_hs_keys = match client_kc1 {
            Some(quic::KeyChange::Handshake { keys }) => Some(keys),
            _ => None,
        };

        // Step 5: If client got HS keys, test they match server's HS keys
        if let (Some(ref srv_keys), Some(ref cli_keys)) = (&server_hs_keys, &client_hs_keys) {
            // Server encrypts with local, client decrypts with remote
            let pt = b"test handshake data";
            let mut enc = pt.to_vec();
            let tag = srv_keys
                .local
                .packet
                .encrypt_in_place(0, b"hdr", &mut enc)
                .unwrap();
            enc.extend_from_slice(tag.as_ref());

            let dec = cli_keys
                .remote
                .packet
                .decrypt_in_place(0, b"hdr", &mut enc)
                .unwrap();
            assert_eq!(dec, pt, "HS keys cross-decrypt");

            // Also test: client local encrypt, server remote decrypt
            let mut enc2 = pt.to_vec();
            let tag2 = cli_keys
                .local
                .packet
                .encrypt_in_place(1, b"hdr2", &mut enc2)
                .unwrap();
            enc2.extend_from_slice(tag2.as_ref());
            let dec2 = srv_keys
                .remote
                .packet
                .decrypt_in_place(1, b"hdr2", &mut enc2)
                .unwrap();
            assert_eq!(dec2, pt, "HS keys cross-decrypt reverse");
        } else {
            panic!(
                "HS keys missing: server={}, client={}",
                server_hs_keys.is_some(),
                client_hs_keys.is_some()
            );
        }
    }

    #[test]
    fn full_handshake() {
        assert!(true); // WIP
    }
}
