//! QUIC frame types and wire format (RFC 9000 §19).
//!
//! All 20 standard frame types. Each frame encodes its type as a
//! minimal varint (single byte for all defined types).

use crate::varint::{self, VarInt};
use bytes::{BufMut, Bytes};
use thiserror::Error;

// ── Frame Type Constants ─────────────────────────────────────────

const FRAME_PADDING: u8 = 0x00;
const FRAME_PING: u8 = 0x01;
const FRAME_ACK_BASE: u8 = 0x02; // ..0x03 (LSB = ECN)
const FRAME_RESET_STREAM: u8 = 0x04;
const FRAME_STOP_SENDING: u8 = 0x05;
const FRAME_CRYPTO: u8 = 0x06;
const FRAME_NEW_TOKEN: u8 = 0x07;
const FRAME_STREAM_BASE: u8 = 0x08; // 0x08..0x0f
const FRAME_MAX_DATA: u8 = 0x10;
const FRAME_MAX_STREAM_DATA: u8 = 0x11;
const FRAME_MAX_STREAMS_BIDI: u8 = 0x12;
const FRAME_MAX_STREAMS_UNI: u8 = 0x13;
const FRAME_DATA_BLOCKED: u8 = 0x14;
const FRAME_STREAM_DATA_BLOCKED: u8 = 0x15;
const FRAME_STREAMS_BLOCKED_BIDI: u8 = 0x16;
const FRAME_STREAMS_BLOCKED_UNI: u8 = 0x17;
const FRAME_NEW_CONNECTION_ID: u8 = 0x18;
const FRAME_RETIRE_CONNECTION_ID: u8 = 0x19;
const FRAME_PATH_CHALLENGE: u8 = 0x1a;
const FRAME_PATH_RESPONSE: u8 = 0x1b;
const FRAME_CONNECTION_CLOSE_QUIC: u8 = 0x1c;
const FRAME_CONNECTION_CLOSE_APP: u8 = 0x1d;
const FRAME_HANDSHAKE_DONE: u8 = 0x1e;

const STREAM_OFF_BIT: u8 = 0x04;
const STREAM_LEN_BIT: u8 = 0x02;
const STREAM_FIN_BIT: u8 = 0x01;

// ── Errors ────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("unknown frame type: {0:#x}")]
    UnknownType(u64),
    #[error("invalid frame type encoding: type {0:#x} must use minimal varint")]
    NonMinimalType(u64),
    #[error("{0}")]
    VarInt(#[from] varint::VarIntError),
    #[error("buffer underflow reading frame type {frame_type:#x}: expected {expected} bytes")]
    Underflow { frame_type: u64, expected: usize },
    #[error("invalid STREAM frame: must have data when LEN bit is set or absent")]
    InvalidStream,
    #[error("path challenge/response data must be 8 bytes")]
    InvalidPathData,
    #[error("connection ID length {0} out of range (1..=20)")]
    InvalidCidLength(u8),
}

// ── Sub-types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// Number of contiguous unacknowledged packets preceding the acked range.
    pub gap: VarInt,
    /// Number of contiguous acknowledged packets in this range.
    pub range: VarInt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: VarInt,
    pub ect1: VarInt,
    pub ecn_ce: VarInt,
}

/// A connection ID (0 to 20 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub Bytes);

impl ConnectionId {
    /// Validate that length is within 0..=20.
    pub fn new(bytes: Bytes) -> Result<Self, FrameError> {
        if bytes.len() > 20 {
            return Err(FrameError::InvalidCidLength(bytes.len() as u8));
        }
        Ok(Self(bytes))
    }
}

// ── Frame Enum ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ping,
    Ack {
        largest_ack: VarInt,
        ack_delay: VarInt,
        ranges: Vec<AckRange>,
        ecn: Option<EcnCounts>,
    },
    ResetStream {
        stream_id: VarInt,
        error_code: VarInt,
        final_size: VarInt,
    },
    StopSending {
        stream_id: VarInt,
        error_code: VarInt,
    },
    Crypto {
        offset: VarInt,
        data: Bytes,
    },
    NewToken {
        token: Bytes,
    },
    Stream {
        stream_id: VarInt,
        offset: VarInt,
        data: Bytes,
        fin: bool,
    },
    MaxData {
        maximum: VarInt,
    },
    MaxStreamData {
        stream_id: VarInt,
        maximum: VarInt,
    },
    MaxStreams {
        bidi: bool,
        maximum: VarInt,
    },
    DataBlocked {
        limit: VarInt,
    },
    StreamDataBlocked {
        stream_id: VarInt,
        limit: VarInt,
    },
    StreamsBlocked {
        bidi: bool,
        limit: VarInt,
    },
    NewConnectionId {
        sequence: VarInt,
        retire_prior_to: VarInt,
        id: ConnectionId,
        reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence: VarInt,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    ConnectionClose {
        error_code: VarInt,
        frame_type: Option<VarInt>,
        reason: Bytes,
    },
    HandshakeDone,
}

// ── Parsing ───────────────────────────────────────────────────────

/// Parse a single frame from `buf`. Returns the frame and bytes consumed.
pub fn parse_frame(mut buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let remaining = buf.len();
    let (frame_type, _) = varint::decode(buf)?;

    // Frame type MUST use minimal varint encoding (RFC 9000 §12.4).
    // All standard types fit in 1 byte.
    if frame_type <= 63 && varint::encoded_len(frame_type) != 1 {
        return Err(FrameError::NonMinimalType(frame_type));
    }

    // Advance past the type byte (standard frames all fit in 1 byte).
    buf = &buf[1..];
    let ft = frame_type as u8;

    let frame = match ft {
        FRAME_PADDING => Frame::Padding,

        FRAME_PING => Frame::Ping,

        // ACK (0x02 without ECN, 0x03 with ECN)
        0x02 | 0x03 => {
            let ecn = (frame_type & 0x01) != 0;
            let largest_ack = read_varint(&mut buf)?;
            let ack_delay = read_varint(&mut buf)?;
            let range_count = read_varint(&mut buf)?;
            let first_range = read_varint(&mut buf)?;

            let mut ranges = Vec::with_capacity(range_count as usize + 1);
            ranges.push(AckRange {
                gap: 0,
                range: first_range,
            });
            for _ in 0..range_count {
                let gap = read_varint(&mut buf)?;
                let range = read_varint(&mut buf)?;
                ranges.push(AckRange { gap, range });
            }

            let ecn_counts = if ecn {
                Some(EcnCounts {
                    ect0: read_varint(&mut buf)?,
                    ect1: read_varint(&mut buf)?,
                    ecn_ce: read_varint(&mut buf)?,
                })
            } else {
                None
            };

            Frame::Ack {
                largest_ack,
                ack_delay,
                ranges,
                ecn: ecn_counts,
            }
        }

        FRAME_RESET_STREAM => Frame::ResetStream {
            stream_id: read_varint(&mut buf)?,
            error_code: read_varint(&mut buf)?,
            final_size: read_varint(&mut buf)?,
        },

        FRAME_STOP_SENDING => Frame::StopSending {
            stream_id: read_varint(&mut buf)?,
            error_code: read_varint(&mut buf)?,
        },

        FRAME_CRYPTO => Frame::Crypto {
            offset: read_varint(&mut buf)?,
            data: read_varint_bytes(&mut buf)?,
        },

        FRAME_NEW_TOKEN => Frame::NewToken {
            token: read_varint_bytes(&mut buf)?,
        },

        // STREAM 0x08..0x0f
        t @ 0x08..=0x0f => {
            let off = (t & STREAM_OFF_BIT) != 0;
            let len = (t & STREAM_LEN_BIT) != 0;
            let fin = (t & STREAM_FIN_BIT) != 0;

            let stream_id = read_varint(&mut buf)?;
            let offset = if off { read_varint(&mut buf)? } else { 0 };

            let data = if len {
                read_varint_bytes(&mut buf)?
            } else {
                // Consume remaining bytes
                let d = Bytes::copy_from_slice(buf);
                buf = &buf[buf.len()..];
                d
            };

            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
            }
        }

        FRAME_MAX_DATA => Frame::MaxData {
            maximum: read_varint(&mut buf)?,
        },

        FRAME_MAX_STREAM_DATA => Frame::MaxStreamData {
            stream_id: read_varint(&mut buf)?,
            maximum: read_varint(&mut buf)?,
        },

        FRAME_MAX_STREAMS_BIDI | FRAME_MAX_STREAMS_UNI => Frame::MaxStreams {
            bidi: ft == FRAME_MAX_STREAMS_BIDI,
            maximum: read_varint(&mut buf)?,
        },

        FRAME_DATA_BLOCKED => Frame::DataBlocked {
            limit: read_varint(&mut buf)?,
        },

        FRAME_STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
            stream_id: read_varint(&mut buf)?,
            limit: read_varint(&mut buf)?,
        },

        FRAME_STREAMS_BLOCKED_BIDI | FRAME_STREAMS_BLOCKED_UNI => Frame::StreamsBlocked {
            bidi: ft == FRAME_STREAMS_BLOCKED_BIDI,
            limit: read_varint(&mut buf)?,
        },

        FRAME_NEW_CONNECTION_ID => {
            let sequence = read_varint(&mut buf)?;
            let retire_prior_to = read_varint(&mut buf)?;
            let cid_len = read_u8(&mut buf)?;
            if !(1..=20).contains(&cid_len) {
                return Err(FrameError::InvalidCidLength(cid_len));
            }
            let cid_bytes = read_bytes(&mut buf, cid_len as usize)?;
            let id = ConnectionId::new(cid_bytes)?;
            let mut reset_token = [0u8; 16];
            read_exact(&mut buf, &mut reset_token)?;
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            }
        }

        FRAME_RETIRE_CONNECTION_ID => Frame::RetireConnectionId {
            sequence: read_varint(&mut buf)?,
        },

        FRAME_PATH_CHALLENGE => {
            let mut data = [0u8; 8];
            read_exact(&mut buf, &mut data)?;
            Frame::PathChallenge { data }
        }

        FRAME_PATH_RESPONSE => {
            let mut data = [0u8; 8];
            read_exact(&mut buf, &mut data)?;
            Frame::PathResponse { data }
        }

        // CONNECTION_CLOSE: 0x1c (QUIC) has frame_type field, 0x1d (app) does not
        0x1c | 0x1d => {
            let is_app = ft == FRAME_CONNECTION_CLOSE_APP;
            let error_code = read_varint(&mut buf)?;
            let frame_type = if !is_app {
                Some(read_varint(&mut buf)?)
            } else {
                None
            };
            let reason = read_varint_bytes(&mut buf)?;
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            }
        }

        FRAME_HANDSHAKE_DONE => Frame::HandshakeDone,

        _ => return Err(FrameError::UnknownType(frame_type)),
    };

    let consumed = remaining - buf.len();
    Ok((frame, consumed))
}

// ── Writing ───────────────────────────────────────────────────────

/// Write `frame` into `buf`. Returns bytes written.
pub fn write_frame(frame: &Frame, buf: &mut impl BufMut) -> Result<usize, FrameError> {
    let start = buf.remaining_mut();
    match frame {
        Frame::Padding => {
            buf.put_u8(FRAME_PADDING);
        }
        Frame::Ping => {
            buf.put_u8(FRAME_PING);
        }
        Frame::Ack {
            largest_ack,
            ack_delay,
            ranges,
            ecn,
        } => {
            let ft = if ecn.is_some() {
                FRAME_ACK_BASE | 0x01
            } else {
                FRAME_ACK_BASE
            };
            buf.put_u8(ft);
            put_varint(buf, *largest_ack)?;
            put_varint(buf, *ack_delay)?;
            // ACK Range Count = total ranges - 1 (first range is separate)
            let range_count = ranges.len().saturating_sub(1);
            put_varint(buf, range_count as VarInt)?;
            // First ACK Range
            put_varint(buf, ranges.first().map(|r| r.range).unwrap_or(0))?;
            // Remaining Gap+Range pairs
            for r in &ranges[1..] {
                put_varint(buf, r.gap)?;
                put_varint(buf, r.range)?;
            }

            if let Some(ecn) = ecn {
                put_varint(buf, ecn.ect0)?;
                put_varint(buf, ecn.ect1)?;
                put_varint(buf, ecn.ecn_ce)?;
            }
        }
        Frame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            buf.put_u8(FRAME_RESET_STREAM);
            put_varint(buf, *stream_id)?;
            put_varint(buf, *error_code)?;
            put_varint(buf, *final_size)?;
        }
        Frame::StopSending {
            stream_id,
            error_code,
        } => {
            buf.put_u8(FRAME_STOP_SENDING);
            put_varint(buf, *stream_id)?;
            put_varint(buf, *error_code)?;
        }
        Frame::Crypto { offset, data } => {
            buf.put_u8(FRAME_CRYPTO);
            put_varint(buf, *offset)?;
            put_varint_bytes(buf, data)?;
        }
        Frame::NewToken { token } => {
            buf.put_u8(FRAME_NEW_TOKEN);
            put_varint_bytes(buf, token)?;
        }
        Frame::Stream {
            stream_id,
            offset,
            data,
            fin,
        } => {
            let mut ft = FRAME_STREAM_BASE;
            if *fin {
                ft |= STREAM_FIN_BIT;
            }
            if *offset > 0 {
                ft |= STREAM_OFF_BIT;
            }
            // We always include length if there's more data in the packet.
            // For now, just check if data is present — LEN is set when
            // we know the data doesn't go to packet end (always true for
            // standalone encoding).
            if !data.is_empty() {
                ft |= STREAM_LEN_BIT;
            }
            buf.put_u8(ft);
            put_varint(buf, *stream_id)?;
            if *offset > 0 {
                put_varint(buf, *offset)?;
            }
            if !data.is_empty() {
                put_varint(buf, data.len() as VarInt)?;
            }
            buf.put_slice(data);
        }
        Frame::MaxData { maximum } => {
            buf.put_u8(FRAME_MAX_DATA);
            put_varint(buf, *maximum)?;
        }
        Frame::MaxStreamData { stream_id, maximum } => {
            buf.put_u8(FRAME_MAX_STREAM_DATA);
            put_varint(buf, *stream_id)?;
            put_varint(buf, *maximum)?;
        }
        Frame::MaxStreams { bidi, maximum } => {
            let ft = if *bidi {
                FRAME_MAX_STREAMS_BIDI
            } else {
                FRAME_MAX_STREAMS_UNI
            };
            buf.put_u8(ft);
            put_varint(buf, *maximum)?;
        }
        Frame::DataBlocked { limit } => {
            buf.put_u8(FRAME_DATA_BLOCKED);
            put_varint(buf, *limit)?;
        }
        Frame::StreamDataBlocked { stream_id, limit } => {
            buf.put_u8(FRAME_STREAM_DATA_BLOCKED);
            put_varint(buf, *stream_id)?;
            put_varint(buf, *limit)?;
        }
        Frame::StreamsBlocked { bidi, limit } => {
            let ft = if *bidi {
                FRAME_STREAMS_BLOCKED_BIDI
            } else {
                FRAME_STREAMS_BLOCKED_UNI
            };
            buf.put_u8(ft);
            put_varint(buf, *limit)?;
        }
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            id,
            reset_token,
        } => {
            buf.put_u8(FRAME_NEW_CONNECTION_ID);
            put_varint(buf, *sequence)?;
            put_varint(buf, *retire_prior_to)?;
            buf.put_u8(id.0.len() as u8);
            buf.put_slice(&id.0);
            buf.put_slice(reset_token);
        }
        Frame::RetireConnectionId { sequence } => {
            buf.put_u8(FRAME_RETIRE_CONNECTION_ID);
            put_varint(buf, *sequence)?;
        }
        Frame::PathChallenge { data } => {
            buf.put_u8(FRAME_PATH_CHALLENGE);
            buf.put_slice(data);
        }
        Frame::PathResponse { data } => {
            buf.put_u8(FRAME_PATH_RESPONSE);
            buf.put_slice(data);
        }
        Frame::ConnectionClose {
            error_code,
            frame_type,
            reason,
        } => {
            let ft = if frame_type.is_some() {
                FRAME_CONNECTION_CLOSE_QUIC
            } else {
                FRAME_CONNECTION_CLOSE_APP
            };
            buf.put_u8(ft);
            put_varint(buf, *error_code)?;
            if let Some(ft) = frame_type {
                put_varint(buf, *ft)?;
            }
            put_varint_bytes(buf, reason)?;
        }
        Frame::HandshakeDone => {
            buf.put_u8(FRAME_HANDSHAKE_DONE);
        }
    }
    let written = start - buf.remaining_mut();
    Ok(written)
}

// ── Helpers ───────────────────────────────────────────────────────

fn read_u8(buf: &mut &[u8]) -> Result<u8, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::Underflow {
            frame_type: 0,
            expected: 1,
        });
    }
    let v = buf[0];
    *buf = &buf[1..];
    Ok(v)
}

fn read_varint(buf: &mut &[u8]) -> Result<VarInt, FrameError> {
    let (v, n) = varint::decode(buf)?;
    *buf = &buf[n..];
    Ok(v)
}

fn read_bytes(buf: &mut &[u8], len: usize) -> Result<Bytes, FrameError> {
    if buf.len() < len {
        return Err(FrameError::Underflow {
            frame_type: 0,
            expected: len,
        });
    }
    let b = Bytes::copy_from_slice(&buf[..len]);
    *buf = &buf[len..];
    Ok(b)
}

fn read_exact(buf: &mut &[u8], dst: &mut [u8]) -> Result<(), FrameError> {
    if buf.len() < dst.len() {
        return Err(FrameError::Underflow {
            frame_type: 0,
            expected: dst.len(),
        });
    }
    dst.copy_from_slice(&buf[..dst.len()]);
    *buf = &buf[dst.len()..];
    Ok(())
}

fn read_varint_bytes(buf: &mut &[u8]) -> Result<Bytes, FrameError> {
    let len = read_varint(buf)? as usize;
    read_bytes(buf, len)
}

fn put_varint(buf: &mut impl BufMut, v: VarInt) -> Result<(), FrameError> {
    varint::put_varint(buf, v).map_err(FrameError::VarInt)
}

fn put_varint_bytes(buf: &mut impl BufMut, data: &Bytes) -> Result<(), FrameError> {
    put_varint(buf, data.len() as VarInt)?;
    buf.put_slice(data);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: Frame) {
        let mut buf = Vec::new();
        write_frame(&frame, &mut buf).unwrap();
        let (decoded, n) = parse_frame(&buf).unwrap();
        assert_eq!(n, buf.len(), "consumed all bytes");
        assert_eq!(decoded, frame, "round-trip match for {frame:?}");
    }

    #[test]
    fn round_trip_padding() {
        round_trip(Frame::Padding);
    }

    #[test]
    fn round_trip_ping() {
        round_trip(Frame::Ping);
    }

    #[test]
    fn round_trip_ack() {
        round_trip(Frame::Ack {
            largest_ack: 1000,
            ack_delay: 42,
            ranges: vec![AckRange { gap: 0, range: 5 }],
            ecn: None,
        });
    }

    #[test]
    fn round_trip_ack_with_ecn() {
        round_trip(Frame::Ack {
            largest_ack: 200,
            ack_delay: 10,
            ranges: vec![AckRange { gap: 0, range: 3 }, AckRange { gap: 2, range: 4 }],
            ecn: Some(EcnCounts {
                ect0: 1,
                ect1: 2,
                ecn_ce: 0,
            }),
        });
    }

    #[test]
    fn round_trip_reset_stream() {
        round_trip(Frame::ResetStream {
            stream_id: 4,
            error_code: 123,
            final_size: 4096,
        });
    }

    #[test]
    fn round_trip_stop_sending() {
        round_trip(Frame::StopSending {
            stream_id: 2,
            error_code: 99,
        });
    }

    #[test]
    fn round_trip_crypto() {
        round_trip(Frame::Crypto {
            offset: 0,
            data: Bytes::from_static(b"hello"),
        });
    }

    #[test]
    fn round_trip_new_token() {
        round_trip(Frame::NewToken {
            token: Bytes::from_static(b"abc123"),
        });
    }

    #[test]
    fn round_trip_stream() {
        round_trip(Frame::Stream {
            stream_id: 0,
            offset: 0,
            data: Bytes::from_static(b"payload"),
            fin: false,
        });
    }

    #[test]
    fn round_trip_stream_with_offset_and_fin() {
        round_trip(Frame::Stream {
            stream_id: 10,
            offset: 2048,
            data: Bytes::from_static(b"end"),
            fin: true,
        });
    }

    #[test]
    fn round_trip_max_data() {
        round_trip(Frame::MaxData { maximum: 1_000_000 });
    }

    #[test]
    fn round_trip_max_stream_data() {
        round_trip(Frame::MaxStreamData {
            stream_id: 4,
            maximum: 65536,
        });
    }

    #[test]
    fn round_trip_max_streams() {
        round_trip(Frame::MaxStreams {
            bidi: true,
            maximum: 100,
        });
        round_trip(Frame::MaxStreams {
            bidi: false,
            maximum: 50,
        });
    }

    #[test]
    fn round_trip_data_blocked() {
        round_trip(Frame::DataBlocked { limit: 2000 });
    }

    #[test]
    fn round_trip_stream_data_blocked() {
        round_trip(Frame::StreamDataBlocked {
            stream_id: 2,
            limit: 4096,
        });
    }

    #[test]
    fn round_trip_streams_blocked() {
        round_trip(Frame::StreamsBlocked {
            bidi: true,
            limit: 100,
        });
        round_trip(Frame::StreamsBlocked {
            bidi: false,
            limit: 50,
        });
    }

    #[test]
    fn round_trip_new_connection_id() {
        round_trip(Frame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            id: ConnectionId::new(Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8])).unwrap(),
            reset_token: [0xab; 16],
        });
    }

    #[test]
    fn round_trip_retire_connection_id() {
        round_trip(Frame::RetireConnectionId { sequence: 2 });
    }

    #[test]
    fn round_trip_path_challenge() {
        round_trip(Frame::PathChallenge { data: *b"abcdefgh" });
    }

    #[test]
    fn round_trip_path_response() {
        round_trip(Frame::PathResponse { data: *b"12345678" });
    }

    #[test]
    fn round_trip_connection_close_quic() {
        round_trip(Frame::ConnectionClose {
            error_code: 0x0a,       // PROTOCOL_VIOLATION
            frame_type: Some(0x06), // triggered by a CRYPTO frame
            reason: Bytes::from_static(b"bad crypto frame"),
        });
    }

    #[test]
    fn round_trip_connection_close_app() {
        round_trip(Frame::ConnectionClose {
            error_code: 0,
            frame_type: None,
            reason: Bytes::new(),
        });
    }

    #[test]
    fn round_trip_handshake_done() {
        round_trip(Frame::HandshakeDone);
    }

    #[test]
    fn all_frames_round_trip() {
        // Ensure every frame variant round-trips at least once
        let frames = vec![
            Frame::Padding,
            Frame::Ping,
            Frame::Ack {
                largest_ack: 10,
                ack_delay: 1,
                ranges: vec![AckRange { gap: 0, range: 10 }],
                ecn: None,
            },
            Frame::ResetStream {
                stream_id: 0,
                error_code: 1,
                final_size: 2,
            },
            Frame::StopSending {
                stream_id: 0,
                error_code: 1,
            },
            Frame::Crypto {
                offset: 0,
                data: Bytes::from_static(b"a"),
            },
            Frame::NewToken {
                token: Bytes::from_static(b"t"),
            },
            Frame::Stream {
                stream_id: 0,
                offset: 0,
                data: Bytes::from_static(b"x"),
                fin: false,
            },
            Frame::MaxData { maximum: 1 },
            Frame::MaxStreamData {
                stream_id: 0,
                maximum: 1,
            },
            Frame::MaxStreams {
                bidi: true,
                maximum: 1,
            },
            Frame::DataBlocked { limit: 1 },
            Frame::StreamDataBlocked {
                stream_id: 0,
                limit: 1,
            },
            Frame::StreamsBlocked {
                bidi: true,
                limit: 1,
            },
            Frame::NewConnectionId {
                sequence: 0,
                retire_prior_to: 0,
                id: ConnectionId::new(Bytes::from_static(b"\x01\x02\x03\x04")).unwrap(),
                reset_token: [0; 16],
            },
            Frame::RetireConnectionId { sequence: 0 },
            Frame::PathChallenge { data: [0; 8] },
            Frame::PathResponse { data: [0; 8] },
            Frame::ConnectionClose {
                error_code: 0,
                frame_type: None,
                reason: Bytes::new(),
            },
            Frame::HandshakeDone,
        ];
        for f in frames {
            round_trip(f);
        }
    }

    #[test]
    fn unknown_frame_type() {
        let buf = [0x3fu8]; // 0x3f = 63, not a defined frame
        let err = parse_frame(&buf).unwrap_err();
        assert!(matches!(err, FrameError::UnknownType(0x3f)));
    }

    #[test]
    fn rfc_ping_example() {
        let buf = [0x01u8];
        let (frame, n) = parse_frame(&buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(frame, Frame::Ping);
    }

    #[test]
    fn rfc_padding_example() {
        let buf = [0x00u8, 0x00, 0x00];
        let (frame, n) = parse_frame(&buf).unwrap();
        assert_eq!(n, 1); // PADDING consumes 1 byte
        assert_eq!(frame, Frame::Padding);
        // Remaining PADDING frames can be parsed one by one
        let (frame2, n2) = parse_frame(&buf[1..]).unwrap();
        assert_eq!(n2, 1);
        assert_eq!(frame2, Frame::Padding);
    }
}
