//! QUIC variable-length integer encoding (RFC 9000 §16).
//!
//! The two most significant bits of the first byte encode the integer length:
//!
//! | 2 MSB | Length | Usable bits | Max value               |
//! |-------|--------|-------------|-------------------------|
//! | 00    | 1      | 6           | 63                      |
//! | 01    | 2      | 14          | 16383                   |
//! | 10    | 4      | 30          | 1073741823              |
//! | 11    | 8      | 62          | 4611686018427387903     |

use thiserror::Error;

/// The QUIC variable-length integer type (u64 with max 2^62 - 1).
pub type VarInt = u64;

/// Maximum value representable by a QUIC varint (2^62 - 1).
pub const VARINT_MAX: VarInt = (1 << 62) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VarIntError {
    #[error("buffer too short: need {needed} bytes, got {actual}")]
    BufferTooShort { needed: usize, actual: usize },
    #[error("value {value} exceeds maximum varint value {VARINT_MAX}")]
    ValueTooLarge { value: u64 },
}

/// Return the number of bytes needed to encode `v` as a QUIC varint.
pub fn encoded_len(v: VarInt) -> usize {
    match v {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1073741823 => 4,
        _ => 8,
    }
}

/// Write `v` to `buf` as a QUIC varint. Returns bytes written.
pub fn encode(v: VarInt, buf: &mut [u8]) -> Result<usize, VarIntError> {
    if v > VARINT_MAX {
        return Err(VarIntError::ValueTooLarge { value: v });
    }
    let len = encoded_len(v);
    if buf.len() < len {
        return Err(VarIntError::BufferTooShort {
            needed: len,
            actual: buf.len(),
        });
    }
    match len {
        1 => buf[0] = v as u8,
        2 => {
            buf[0] = 0x40 | ((v >> 8) as u8);
            buf[1] = (v & 0xff) as u8;
        }
        4 => {
            buf[0] = 0x80 | ((v >> 24) as u8);
            buf[1] = ((v >> 16) & 0xff) as u8;
            buf[2] = ((v >> 8) & 0xff) as u8;
            buf[3] = (v & 0xff) as u8;
        }
        8 => {
            buf[0] = 0xc0 | ((v >> 56) as u8);
            buf[1] = ((v >> 48) & 0xff) as u8;
            buf[2] = ((v >> 40) & 0xff) as u8;
            buf[3] = ((v >> 32) & 0xff) as u8;
            buf[4] = ((v >> 24) & 0xff) as u8;
            buf[5] = ((v >> 16) & 0xff) as u8;
            buf[6] = ((v >> 8) & 0xff) as u8;
            buf[7] = (v & 0xff) as u8;
        }
        _ => unreachable!(),
    }
    Ok(len)
}

/// Read a varint from `buf`. Returns the value and number of bytes consumed.
pub fn decode(buf: &[u8]) -> Result<(VarInt, usize), VarIntError> {
    if buf.is_empty() {
        return Err(VarIntError::BufferTooShort {
            needed: 1,
            actual: 0,
        });
    }
    let first = buf[0];
    let (len, val) = match first >> 6 {
        0 => {
            // 00xxxxxx — 1 byte
            (1, first as u64)
        }
        1 => {
            // 01xxxxxx — 2 bytes
            if buf.len() < 2 {
                return Err(VarIntError::BufferTooShort {
                    needed: 2,
                    actual: buf.len(),
                });
            }
            let v = ((first as u64 & 0x3f) << 8) | (buf[1] as u64);
            (2, v)
        }
        2 => {
            // 10xxxxxx — 4 bytes
            if buf.len() < 4 {
                return Err(VarIntError::BufferTooShort {
                    needed: 4,
                    actual: buf.len(),
                });
            }
            let v = ((first as u64 & 0x3f) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | (buf[3] as u64);
            (4, v)
        }
        3 => {
            // 11xxxxxx — 8 bytes
            if buf.len() < 8 {
                return Err(VarIntError::BufferTooShort {
                    needed: 8,
                    actual: buf.len(),
                });
            }
            let v = ((first as u64 & 0x3f) << 56)
                | ((buf[1] as u64) << 48)
                | ((buf[2] as u64) << 40)
                | ((buf[3] as u64) << 32)
                | ((buf[4] as u64) << 24)
                | ((buf[5] as u64) << 16)
                | ((buf[6] as u64) << 8)
                | (buf[7] as u64);
            (8, v)
        }
        _ => unreachable!(),
    };
    Ok((val, len))
}

/// Write a varint into a [`bytes::BufMut`].
pub fn put_varint(buf: &mut impl bytes::BufMut, v: VarInt) -> Result<(), VarIntError> {
    if v > VARINT_MAX {
        return Err(VarIntError::ValueTooLarge { value: v });
    }
    let len = encoded_len(v);
    let mut tmp = [0u8; 8];
    encode(v, &mut tmp)?;
    buf.put_slice(&tmp[..len]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_boundaries() {
        let cases = &[
            0, 1, 63, 64, 255, 16383, 16384, 65535, 1073741823, 1073741824, VARINT_MAX,
        ];
        for &v in cases {
            let mut buf = [0u8; 8];
            let n = encode(v, &mut buf).unwrap();
            let (decoded, consumed) = decode(&buf).unwrap();
            assert_eq!(consumed, n, "varint {v}");
            assert_eq!(decoded, v, "varint {v}");
        }
    }

    #[test]
    fn encoded_lengths() {
        assert_eq!(encoded_len(0), 1);
        assert_eq!(encoded_len(63), 1);
        assert_eq!(encoded_len(64), 2);
        assert_eq!(encoded_len(16383), 2);
        assert_eq!(encoded_len(16384), 4);
        assert_eq!(encoded_len(1073741823), 4);
        assert_eq!(encoded_len(1073741824), 8);
    }

    #[test]
    fn rfc_a1_examples() {
        // From RFC 9000 Appendix A.1
        let examples: &[(&[u8], u64)] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151288809941952652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494878333),
            (&[0x7b, 0xbd], 15293),
            (&[0x25], 37),
            (&[0x40, 0x25], 37), // non-minimal encoding: 37 in 2 bytes (allowed)
        ];
        for (bytes, expected) in examples {
            let (v, n) = decode(bytes).unwrap();
            assert_eq!(v, *expected, "decode {bytes:02x?}");
            assert_eq!(n, bytes.len());
        }
    }

    #[test]
    fn value_too_large() {
        let err = encode(VARINT_MAX + 1, &mut [0u8; 16]);
        assert!(matches!(err, Err(VarIntError::ValueTooLarge { value: _ })));
    }

    #[test]
    fn buffer_too_short() {
        let v = 0x4000u64; // needs 4 bytes
        let err = encode(v, &mut [0u8; 2]);
        assert!(matches!(err, Err(VarIntError::BufferTooShort { .. })));
    }

    #[test]
    fn decode_truncated() {
        // 2-byte varint truncated to 1 byte
        let buf = [0x40u8]; // 01xxxxxx says 2 bytes
        let err = decode(&buf).unwrap_err();
        assert!(matches!(err, VarIntError::BufferTooShort { .. }));
    }

    #[test]
    fn decode_empty() {
        let err = decode(&[]).unwrap_err();
        assert!(matches!(err, VarIntError::BufferTooShort { .. }));
    }
}
