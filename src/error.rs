//! QUIC error codes and connection errors (RFC 9000 §20).

use crate::varint::VarInt;

/// QUIC transport-level error codes (RFC 9000 §20.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransportError {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    VersionNegotiationError = 0x11,
    /// Cryptographic error (0x0100–0x01ff). The enclosed value is the
    /// TLS alert code offset from 0x0100.
    CryptoError(u8),
}

impl TransportError {
    /// Decode from a QUIC varint error code.
    pub fn from_code(code: VarInt) -> Option<Self> {
        match code {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::InternalError),
            0x02 => Some(Self::ConnectionRefused),
            0x03 => Some(Self::FlowControlError),
            0x04 => Some(Self::StreamLimitError),
            0x05 => Some(Self::StreamStateError),
            0x06 => Some(Self::FinalSizeError),
            0x07 => Some(Self::FrameEncodingError),
            0x08 => Some(Self::TransportParameterError),
            0x09 => Some(Self::ConnectionIdLimitError),
            0x0a => Some(Self::ProtocolViolation),
            0x0b => Some(Self::InvalidToken),
            0x0c => Some(Self::ApplicationError),
            0x0d => Some(Self::CryptoBufferExceeded),
            0x0e => Some(Self::KeyUpdateError),
            0x0f => Some(Self::AeadLimitReached),
            0x10 => Some(Self::NoViablePath),
            0x11 => Some(Self::VersionNegotiationError),
            0x0100..=0x01ff => Some(Self::CryptoError((code - 0x0100) as u8)),
            _ => None,
        }
    }

    /// Encode to a QUIC varint.
    pub fn to_code(self) -> VarInt {
        match self {
            Self::NoError => 0x00,
            Self::InternalError => 0x01,
            Self::ConnectionRefused => 0x02,
            Self::FlowControlError => 0x03,
            Self::StreamLimitError => 0x04,
            Self::StreamStateError => 0x05,
            Self::FinalSizeError => 0x06,
            Self::FrameEncodingError => 0x07,
            Self::TransportParameterError => 0x08,
            Self::ConnectionIdLimitError => 0x09,
            Self::ProtocolViolation => 0x0a,
            Self::InvalidToken => 0x0b,
            Self::ApplicationError => 0x0c,
            Self::CryptoBufferExceeded => 0x0d,
            Self::KeyUpdateError => 0x0e,
            Self::AeadLimitReached => 0x0f,
            Self::NoViablePath => 0x10,
            Self::VersionNegotiationError => 0x11,
            Self::CryptoError(alert) => 0x0100 + alert as VarInt,
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoError => write!(f, "no error"),
            Self::InternalError => write!(f, "internal error"),
            Self::ConnectionRefused => write!(f, "connection refused"),
            Self::FlowControlError => write!(f, "flow control error"),
            Self::StreamLimitError => write!(f, "stream limit error"),
            Self::StreamStateError => write!(f, "stream state error"),
            Self::FinalSizeError => write!(f, "final size error"),
            Self::FrameEncodingError => write!(f, "frame encoding error"),
            Self::TransportParameterError => write!(f, "transport parameter error"),
            Self::ConnectionIdLimitError => write!(f, "connection ID limit error"),
            Self::ProtocolViolation => write!(f, "protocol violation"),
            Self::InvalidToken => write!(f, "invalid token"),
            Self::ApplicationError => write!(f, "application error"),
            Self::CryptoBufferExceeded => write!(f, "crypto buffer exceeded"),
            Self::KeyUpdateError => write!(f, "key update error"),
            Self::AeadLimitReached => write!(f, "AEAD limit reached"),
            Self::NoViablePath => write!(f, "no viable path"),
            Self::VersionNegotiationError => write!(f, "version negotiation error"),
            Self::CryptoError(alert) => write!(f, "crypto error (alert {alert})"),
        }
    }
}

/// Top-level connection error.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("transport error: {0}")]
    Transport(TransportError),
    #[error("application error: code={code}")]
    Application { code: VarInt, reason: String },
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("handshake error: {0}")]
    Handshake(#[from] crate::handshake::HandshakeError),
    #[error("frame error: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("packet error: {0}")]
    Packet(#[from] crate::packet::PacketError),
    #[error("timer expired: {0}")]
    Timeout(String),
    #[error("connection closed")]
    Closed,
}

impl From<crate::crypto::CryptoError> for ConnectionError {
    fn from(_e: crate::crypto::CryptoError) -> Self {
        Self::Transport(TransportError::InternalError)
    }
}

impl From<crate::varint::VarIntError> for ConnectionError {
    fn from(_e: crate::varint::VarIntError) -> Self {
        Self::Transport(TransportError::InternalError)
    }
}

impl ConnectionError {
    /// Whether this error should cause a CONNECTION_CLOSE frame to be sent.
    pub fn should_send_close(&self) -> bool {
        !matches!(self, Self::Closed)
    }
}
