//! QUIC packet header types and wire format (RFC 9000 §17).
//!
//! Supports long header (Initial, 0-RTT, Handshake, Retry, Version Negotiation)
//! and short header (1-RTT) packets, plus packet number decoding.

use crate::frame::ConnectionId;
use crate::varint::{self, VarInt};
use bytes::{BufMut, Bytes};
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────

/// Maximum connection ID length (RFC 9000 §17.2).
pub const MAX_CID_LEN: u8 = 20;

/// QUIC version 1.
pub const VERSION_1: u32 = 0x0000_0001;

/// QUIC version 2 (RFC 9369).
pub const VERSION_2: u32 = 0x6b33_43cf;

/// Version used in Version Negotiation packets.
pub const VERSION_NEGOTIATION: u32 = 0x0000_0000;

// ── Errors ────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("buffer too short: need {needed} bytes, got {actual}")]
    BufferTooShort { needed: usize, actual: usize },
    #[error("invalid header form bit: expected {expected}, got {actual}")]
    InvalidHeaderForm { expected: u8, actual: u8 },
    #[error("fixed bit must be 1")]
    FixedBitNotSet,
    #[error("reserved bits must be 0")]
    ReservedBitsSet,
    #[error("unknown long packet type: {0:#x}")]
    UnknownLongType(u8),
    #[error("invalid connection ID length: {0} (max {MAX_CID_LEN})")]
    InvalidCidLength(u8),
    #[error("{0}")]
    VarInt(#[from] crate::varint::VarIntError),
    #[error("{0}")]
    Frame(#[from] crate::frame::FrameError),
}

// ── Packet Types ──────────────────────────────────────────────────

/// Long header packet types (RFC 9000 §17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongType {
    /// Initial packet (type 0x00).
    Initial,
    /// 0-RTT packet (type 0x01).
    ZeroRtt,
    /// Handshake packet (type 0x02).
    Handshake,
    /// Retry packet (type 0x03).
    Retry,
    /// Version Negotiation (Version field = 0).
    VersionNegotiation,
}

impl LongType {
    /// Decode from the two Long Packet Type bits (byte 0, bits 4-5).
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Initial),
            1 => Some(Self::ZeroRtt),
            2 => Some(Self::Handshake),
            3 => Some(Self::Retry),
            _ => None,
        }
    }

    pub fn to_bits(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::ZeroRtt => 1,
            Self::Handshake => 2,
            Self::Retry => 3,
            Self::VersionNegotiation => 0, // VN doesn't use type bits
        }
    }
}

/// Decoded long header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    /// The long packet type.
    pub ty: LongType,
    /// QUIC version.
    pub version: u32,
    /// Destination Connection ID.
    pub dst_cid: ConnectionId,
    /// Source Connection ID.
    pub src_cid: ConnectionId,
    /// Token (Initial packets only).
    pub token: Option<Bytes>,
    /// Payload length (absent in Retry and VN).
    pub length: Option<VarInt>,
    /// Truncated packet number as read from the wire (absent in Retry and VN).
    /// The full packet number must be reconstructed via [`decode_packet_number`].
    pub truncated_pn: Option<u32>,
    /// Length of the packet number field in bytes (1..=4).
    pub pn_len: Option<u8>,
}

/// Decoded short header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    /// Spin bit value.
    pub spin: bool,
    /// Key phase bit value.
    pub key_phase: bool,
    /// Destination Connection ID.
    pub dst_cid: ConnectionId,
    /// Truncated packet number as read from the wire.
    pub truncated_pn: u32,
    /// Length of the packet number field in bytes (1..=4).
    pub pn_len: u8,
}

/// Packet number space (RFC 9000 §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

// ── Parsing ───────────────────────────────────────────────────────

/// Parse a long header packet from `buf`.
///
/// Returns the parsed header and the number of bytes consumed
/// (up to and including the packet number field, but not the payload).
pub fn parse_long_header(buf: &[u8]) -> Result<(LongHeader, usize), PacketError> {
    let remaining = buf.len();

    ensure(buf, 1)?;
    let first = buf[0];

    // Header Form bit (MSB) must be 1.
    if (first & 0x80) == 0 {
        return Err(PacketError::InvalidHeaderForm {
            expected: 1,
            actual: 0,
        });
    }

    // Fixed Bit.
    let fixed = (first & 0x40) != 0;

    // Long Packet Type (bits 4-5).
    let type_bits = (first >> 4) & 0x03;

    // Type-specific bits (bits 2-3 are reserved, bits 0-1 are PN length).
    let _reserved = (first >> 2) & 0x03;
    let pn_len_bits = first & 0x03;

    ensure(buf, 5)?;

    // Version (bytes 1-4).
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    // Version Negotiation is identified by version == 0, not by type bits.
    if version == VERSION_NEGOTIATION {
        return parse_version_negotiation(buf, &first, remaining);
    }

    let ty = LongType::from_bits(type_bits).ok_or(PacketError::UnknownLongType(type_bits))?;

    // Validate bits: fixed bit must be 1 for non-VN packets.
    if !fixed {
        return Err(PacketError::FixedBitNotSet);
    }

    ensure(buf, 6)?;

    // Destination Connection ID.
    let dst_cid_len = buf[5] as usize;
    if dst_cid_len > MAX_CID_LEN as usize {
        return Err(PacketError::InvalidCidLength(dst_cid_len as u8));
    }
    let dst_cid_start = 6;
    ensure(buf, dst_cid_start + dst_cid_len + 1)?;
    let dst_cid = ConnectionId::new(Bytes::copy_from_slice(
        &buf[dst_cid_start..dst_cid_start + dst_cid_len],
    ))?;

    // Source Connection ID.
    let src_cid_start = dst_cid_start + dst_cid_len;
    let src_cid_len = buf[src_cid_start] as usize;
    if src_cid_len > MAX_CID_LEN as usize {
        return Err(PacketError::InvalidCidLength(src_cid_len as u8));
    }
    let data_start = src_cid_start + 1;
    ensure(buf, data_start + src_cid_len)?;
    let src_cid = ConnectionId::new(Bytes::copy_from_slice(
        &buf[data_start..data_start + src_cid_len],
    ))?;

    let mut pos = data_start + src_cid_len;

    // Type-specific payload.

    // Initial packet: Token Length + Token.
    let token = if ty == LongType::Initial {
        let (token_len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let tlen = token_len as usize;
        ensure(buf, pos + tlen)?;
        let tok = Bytes::copy_from_slice(&buf[pos..pos + tlen]);
        pos += tlen;
        Some(tok)
    } else {
        None
    };

    // Retry has no Length or Packet Number.
    if ty == LongType::Retry {
        // Retry payload: Retry Token + Retry Integrity Tag (16 bytes).
        // We don't parse Retry Token here — it's consumed as part of the payload.
        return Ok((
            LongHeader {
                ty,
                version,
                dst_cid,
                src_cid,
                token: None,
                length: None,
                truncated_pn: None,
                pn_len: None,
            },
            pos,
        ));
    }

    // Length field.
    let (length, n) = varint::decode(&buf[pos..])?;
    pos += n;

    // Packet Number field. Length = pn_len_bits + 1.
    let pn_len = pn_len_bits as u8 + 1;
    ensure(buf, pos + pn_len as usize)?;

    let truncated_pn = read_pn(&buf[pos..], pn_len);
    pos += pn_len as usize;

    Ok((
        LongHeader {
            ty,
            version,
            dst_cid,
            src_cid,
            token,
            length: Some(length),
            truncated_pn: Some(truncated_pn),
            pn_len: Some(pn_len),
        },
        pos,
    ))
}

/// Parse the body of a Version Negotiation packet.
fn parse_version_negotiation(
    buf: &[u8],
    _first: &u8,
    _remaining: usize,
) -> Result<(LongHeader, usize), PacketError> {
    ensure(buf, 6)?;
    let dst_cid_len = buf[5] as usize;
    if dst_cid_len > 255 {
        return Err(PacketError::InvalidCidLength(dst_cid_len as u8));
    }
    let dst_cid_start = 6;
    ensure(buf, dst_cid_start + dst_cid_len + 1)?;
    let dst_cid = ConnectionId::new(Bytes::copy_from_slice(
        &buf[dst_cid_start..dst_cid_start + dst_cid_len],
    ))?;

    let src_cid_start = dst_cid_start + dst_cid_len;
    let src_cid_len = buf[src_cid_start] as usize;
    let data_start = src_cid_start + 1;
    ensure(buf, data_start + src_cid_len)?;

    // // Supported versions follows (4-byte multiples), but we don't parse them here.
    // let supported_versions_start = data_start + src_cid_len;
    // let num_versions = (buf.len() - supported_versions_start) / 4;

    let header_end = data_start + src_cid_len;

    Ok((
        LongHeader {
            ty: LongType::VersionNegotiation,
            version: VERSION_NEGOTIATION,
            dst_cid,
            src_cid: ConnectionId::new(Bytes::copy_from_slice(
                &buf[data_start..data_start + src_cid_len],
            ))?,
            token: None,
            length: None,
            truncated_pn: None,
            pn_len: None,
        },
        header_end,
    ))
}

/// Parse a short header packet from `buf`.
pub fn parse_short_header(
    buf: &[u8],
    dst_cid_len: usize,
) -> Result<(ShortHeader, usize), PacketError> {
    ensure(buf, 1)?;
    let first = buf[0];

    // Header Form bit must be 0.
    if (first & 0x80) != 0 {
        return Err(PacketError::InvalidHeaderForm {
            expected: 0,
            actual: 1,
        });
    }

    // Fixed Bit must be 1.
    if (first & 0x40) == 0 {
        return Err(PacketError::FixedBitNotSet);
    }

    let spin = (first & 0x20) != 0;
    let reserved = (first >> 3) & 0x03;
    if reserved != 0 {
        return Err(PacketError::ReservedBitsSet);
    }

    let key_phase = (first & 0x04) != 0;
    let pn_len_bits = first & 0x03;
    let pn_len = if pn_len_bits == 0 {
        return Err(PacketError::ReservedBitsSet); // PN length 0 is invalid
    } else {
        pn_len_bits
    };

    // Destination Connection ID.
    ensure(buf, 1 + dst_cid_len)?;
    let dst_cid = ConnectionId::new(Bytes::copy_from_slice(&buf[1..1 + dst_cid_len]))?;
    let mut pos = 1 + dst_cid_len;

    // Packet Number.
    ensure(buf, pos + pn_len as usize)?;
    let truncated_pn = read_pn(&buf[pos..], pn_len);
    pos += pn_len as usize;

    Ok((
        ShortHeader {
            spin,
            key_phase,
            dst_cid,
            truncated_pn,
            pn_len,
        },
        pos,
    ))
}

// ── Packet Number ─────────────────────────────────────────────────

/// Decode a full packet number from a truncated value (RFC 9000 §17.1, Appendix A.3).
///
/// `largest_known` is the largest packet number successfully processed in the
/// relevant packet number space so far. `truncated` is the truncated value read
/// from the wire. `pn_len` is the number of bytes used for the truncated value.
pub fn decode_packet_number(largest_known: u64, truncated: u64, pn_len: u8) -> u64 {
    let expected = largest_known + 1;
    let win = 1u64 << (pn_len * 8);
    let half = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;

    // candidate is too far below expected — it wrapped around
    if candidate + half <= expected {
        return candidate + win;
    }
    // candidate is too far above expected — we wrapped around
    if candidate > expected + half && candidate > win {
        return candidate - win;
    }
    candidate
}

fn read_pn(buf: &[u8], len: u8) -> u32 {
    match len {
        1 => buf[0] as u32,
        2 => u16::from_be_bytes([buf[0], buf[1]]) as u32,
        3 => u32::from_be_bytes([0, buf[0], buf[1], buf[2]]),
        4 => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        _ => 0,
    }
}

// ── Writing ───────────────────────────────────────────────────────

/// Write a long header into `buf`. Returns bytes written.
pub fn write_long_header(hdr: &LongHeader, buf: &mut impl BufMut) -> Result<usize, PacketError> {
    let start = buf.remaining_mut();

    let first = 0x80 // Header Form (long)
        | 0x40 // Fixed Bit (1 for non-VN)
        | (hdr.ty.to_bits() << 4)
        | (hdr.pn_len.map_or(0, |l| l - 1)); // PN length bits (bits 0-1)

    buf.put_u8(first);
    buf.put_u32(hdr.version);
    buf.put_u8(hdr.dst_cid.0.len() as u8);
    buf.put_slice(&hdr.dst_cid.0);
    buf.put_u8(hdr.src_cid.0.len() as u8);
    buf.put_slice(&hdr.src_cid.0);

    // Token (Initial only).
    if let Some(ref token) = hdr.token {
        crate::varint::put_varint(buf, token.len() as VarInt)?;
        buf.put_slice(token);
    }

    // Length and Packet Number (not for Retry).
    if let Some(length) = hdr.length {
        crate::varint::put_varint(buf, length)?;
    }

    // Packet Number is written encrypted; we just write zeros as a placeholder.
    // The caller encrypts it separately via header protection.
    if let Some(pn_len) = hdr.pn_len {
        buf.put_bytes(0, pn_len as usize);
    }

    let written = start - buf.remaining_mut();
    Ok(written)
}

/// Write a short header into `buf`. Returns bytes written.
pub fn write_short_header(
    hdr: &ShortHeader,
    buf: &mut impl BufMut,
) -> Result<usize, PacketError> {
    let start = buf.remaining_mut();

    let first = 0x40 // Fixed Bit
        | if hdr.spin { 0x20 } else { 0 }
        | if hdr.key_phase { 0x04 } else { 0 }
        | hdr.pn_len; // PN length bits (1..=4)

    buf.put_u8(first);
    buf.put_slice(&hdr.dst_cid.0);
    // Packet Number placeholder (overwritten after encryption).
    buf.put_bytes(0, hdr.pn_len as usize);

    let written = start - buf.remaining_mut();
    Ok(written)
}

// ── Helpers ───────────────────────────────────────────────────────

fn ensure(buf: &[u8], need: usize) -> Result<(), PacketError> {
    if buf.len() < need {
        Err(PacketError::BufferTooShort {
            needed: need,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_number_decode_no_wrap() {
        let pn = decode_packet_number(0, 5, 1);
        assert_eq!(pn, 5);
    }

    #[test]
    fn packet_number_decode_wrap() {
        // If expected is 0xa82f30ea and truncated is 0x9b32, with 2-byte encoding:
        let pn = decode_packet_number(0xa82f30ea, 0x9b32, 2);
        assert_eq!(pn, 0xa82f9b32);
    }

    #[test]
    fn packet_number_decode_rfc_example() {
        // From RFC 9000 Appendix A.3
        let pn = decode_packet_number(0xa82f30ea, 0x9b32, 2);
        assert_eq!(pn, 0xa82f9b32);
    }

    #[test]
    fn decode_from_zero() {
        assert_eq!(decode_packet_number(0, 0, 1), 0);
        assert_eq!(decode_packet_number(0, 255, 1), 255);
    }

    #[test]
    fn parse_initial_header() {
        // Build a minimal Initial long header (version 1, empty CIDs, no token, zero length, 1-byte PN).
        let mut buf = Vec::new();
        // Byte 0: 1 (long) | 1 (fixed) | 00 (type=Initial) | 00 (reserved) | 00 (pn_len=1)
        buf.push(0b1100_0000);
        // Version 1
        buf.extend_from_slice(&VERSION_1.to_be_bytes());
        // Dst CID len = 0
        buf.push(0);
        // Src CID len = 0
        buf.push(0);
        // Token length = 0 (for simplicity, but for server it must be 0)
        buf.push(0);
        // Length = 0
        buf.push(0);
        // PN = 0
        buf.push(0);

        let (hdr, n) = parse_long_header(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(hdr.ty, LongType::Initial);
        assert_eq!(hdr.version, VERSION_1);
        assert_eq!(hdr.token, Some(Bytes::new()));
        assert_eq!(hdr.length, Some(0));
        assert_eq!(hdr.truncated_pn, Some(0));
        assert_eq!(hdr.pn_len, Some(1));
    }

    #[test]
    fn parse_short_header_basic() {
        // Spin=0, KeyPhase=0, PN len=1, empty CID
        let buf = [0x41, 0x00];
        let (hdr, n) = parse_short_header(&buf, 0).unwrap();
        assert_eq!(n, 2);
        assert!(!hdr.spin);
        assert!(!hdr.key_phase);
        assert_eq!(hdr.pn_len, 1);
        assert_eq!(hdr.truncated_pn, 0);
    }

    #[test]
    fn parse_short_header_spin_keyphase() {
        let buf = [0x65, 0x42];
        let (hdr, _) = parse_short_header(&buf, 0).unwrap();
        assert!(hdr.spin);
        assert!(hdr.key_phase);
        assert_eq!(hdr.pn_len, 1);
        assert_eq!(hdr.truncated_pn, 0x42);
    }

    #[test]
    fn fixed_bit_must_be_set() {
        // Short header without fixed bit
        let buf = [0x01];
        let err = parse_short_header(&buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::FixedBitNotSet));
    }

    #[test]
    fn reserved_bits_must_be_zero() {
        // Short header with reserved bits set (bits 3-4)
        let buf = [0x58];
        let err = parse_short_header(&buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::ReservedBitsSet));
    }

    #[test]
    fn version_negotiation_packet() {
        let mut buf = Vec::new();
        // Byte 0: long header with arbitrary content in unused bits
        buf.push(0b1100_0000);
        // Version = 0
        buf.extend_from_slice(&[0, 0, 0, 0]);
        // Dst CID len = 4
        buf.push(4);
        buf.extend_from_slice(b"\x01\x02\x03\x04");
        // Src CID len = 4
        buf.push(4);
        buf.extend_from_slice(b"\x05\x06\x07\x08");
        // Supported versions: v1
        buf.extend_from_slice(&VERSION_1.to_be_bytes());

        let (hdr, _n) = parse_long_header(&buf).unwrap();
        assert_eq!(hdr.ty, LongType::VersionNegotiation);
        assert_eq!(hdr.version, VERSION_NEGOTIATION);
        assert_eq!(hdr.dst_cid.0, Bytes::from_static(b"\x01\x02\x03\x04"));
        assert_eq!(hdr.src_cid.0, Bytes::from_static(b"\x05\x06\x07\x08"));
    }
}
