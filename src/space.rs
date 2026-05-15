//! Per-packet-number-space state (RFC 9000 §12.3).
//!
//! Each encryption level (Initial, Handshake, ApplicationData) maintains
//! independent packet number counters and key material.

use crate::packet::PacketNumberSpace;
use rustls::quic::{DirectionalKeys, Keys};
use std::time::Instant;

/// Key material and packet number state for one encryption level.
pub struct Space {
    /// Which space this is (Initial / Handshake / ApplicationData).
    pub id: PacketNumberSpace,

    /// Key material for this encryption level.
    /// `keys.local` encrypts outgoing packets; `keys.remote` decrypts incoming.
    keys: Option<Keys>,

    /// Next packet number to use for sending.
    next_send_pn: u64,

    /// Largest received packet number that has been authenticated.
    largest_recv_pn: u64,

    /// Time of the last received packet in this space.
    last_recv_time: Option<Instant>,
}

impl Space {
    /// Create a new, empty space (no keys yet).
    pub fn new(id: PacketNumberSpace) -> Self {
        Self {
            id,
            keys: None,
            next_send_pn: 0,
            largest_recv_pn: 0,
            last_recv_time: None,
        }
    }

    /// Install keys for this space.
    pub fn set_keys(&mut self, keys: Keys) {
        self.keys = Some(keys);
    }

    /// Borrow the local (send) keys.
    pub fn local_keys(&self) -> Option<&DirectionalKeys> {
        self.keys.as_ref().map(|k| &k.local)
    }

    /// Borrow the remote (recv) keys.
    pub fn remote_keys(&self) -> Option<&DirectionalKeys> {
        self.keys.as_ref().map(|k| &k.remote)
    }

    /// Whether keys have been installed.
    pub fn has_keys(&self) -> bool {
        self.keys.is_some()
    }

    /// Take the next send packet number and advance the counter.
    pub fn next_send_pn(&mut self) -> u64 {
        let pn = self.next_send_pn;
        self.next_send_pn += 1;
        pn
    }

    /// Peek at the next send packet number without advancing.
    pub fn peek_send_pn(&self) -> u64 {
        self.next_send_pn
    }

    /// Largest received authenticated packet number so far.
    pub fn largest_recv_pn(&self) -> u64 {
        self.largest_recv_pn
    }

    /// Record a received packet number.
    pub fn record_recv_pn(&mut self, pn: u64) {
        if pn > self.largest_recv_pn {
            self.largest_recv_pn = pn;
        }
        self.last_recv_time = Some(Instant::now());
    }

    /// Time since the last received packet (None if never received).
    pub fn time_since_last_recv(&self) -> Option<std::time::Duration> {
        self.last_recv_time.map(|t| t.elapsed())
    }
}
