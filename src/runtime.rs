//! I/O runtime for deerquic connections.
//!
//! Provides a [`Backend`] trait abstracting the I/O layer and an
//! [`Endpoint`] that pairs a [`Connection`] with a backend.
//!
//! The default [`EpollBackend`] uses raw `epoll` (Linux only) with
//! a non-blocking UDP socket. To use a different I/O mechanism,
//! implement the [`Backend`] trait.

use crate::connection::Connection;
use crate::error::ConnectionError;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

// ── Backend trait ──────────────────────────────────────────────

/// Abstract I/O backend for exchanging QUIC packets with a peer.
///
/// Implementations provide a non-blocking UDP socket and a polling
/// mechanism for readiness notification.
pub trait Backend {
    /// Send bytes to the peer. Returns number of bytes sent.
    fn send(&mut self, data: &[u8]) -> io::Result<usize>;

    /// Receive bytes from the peer. Returns (num_bytes, sender_addr).
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Wait for data to become available on the socket, with a
    /// timeout in milliseconds. Returns `true` if data is ready.
    fn poll(&mut self, timeout_ms: i32) -> io::Result<bool>;

    /// The peer address (if known).
    fn peer_addr(&self) -> Option<SocketAddr>;
}

// ── Epoll backend ──────────────────────────────────────────────

/// Epoll-based UDP backend (Linux only).
pub struct EpollBackend {
    /// The underlying UDP socket.
    pub socket: UdpSocket,
    epoll_fd: RawFd,
    peer: Option<SocketAddr>,
}

impl EpollBackend {
    /// Create a new epoll backend bound to `local_addr`, sending to `peer`.
    pub fn new(local_addr: SocketAddr, peer: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_nonblocking(true)?;
        if peer.port() != 0 {
            socket.connect(peer)?;
        }
        let epoll_fd = unsafe { libc::epoll_create1(0) };
        if epoll_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock_fd = socket.as_raw_fd();
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN as u32),
            u64: 0,
        };
        let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, sock_fd, &mut ev) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(epoll_fd) };
            return Err(err);
        }
        Ok(Self {
            socket,
            epoll_fd,
            peer: Some(peer),
        })
    }

    /// Create an epoll backend that listens on `local_addr` (server mode).
    /// Peer address is learned from the first received packet.
    pub fn bind(local_addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_nonblocking(true)?;
        let epoll_fd = unsafe { libc::epoll_create1(0) };
        if epoll_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock_fd = socket.as_raw_fd();
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN as u32),
            u64: 0,
        };
        let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, sock_fd, &mut ev) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(epoll_fd) };
            return Err(err);
        }
        Ok(Self {
            socket,
            epoll_fd,
            peer: None,
        })
    }
}

impl Backend for EpollBackend {
    fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        match self.peer {
            Some(addr) => self.socket.send_to(data, addr),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "peer address not known",
            )),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf)?;
        if self.peer.is_none() {
            self.peer = Some(addr);
            // Connect so send() works without specifying addr
            let _ = self.socket.connect(addr);
        }
        Ok((n, addr))
    }

    fn poll(&mut self, timeout_ms: i32) -> io::Result<bool> {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let n = unsafe { libc::epoll_wait(self.epoll_fd, events.as_mut_ptr(), 1, timeout_ms) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(n > 0)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }
}

impl Drop for EpollBackend {
    fn drop(&mut self) {
        unsafe { libc::close(self.epoll_fd) };
    }
}

// ── Endpoint ───────────────────────────────────────────────────

/// A QUIC endpoint pairing a [`Connection`] with a [`Backend`].
pub struct Endpoint<B: Backend> {
    conn: Connection,
    backend: B,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl<B: Backend> Endpoint<B> {
    /// Max datagram size (QUIC requires at least 1200).
    const MAX_DGRAM: usize = 2048;

    /// Create a new endpoint.
    pub fn new(conn: Connection, backend: B) -> Self {
        Self {
            conn,
            backend,
            send_buf: vec![0u8; Self::MAX_DGRAM],
            recv_buf: vec![0u8; Self::MAX_DGRAM],
        }
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// One event loop iteration:
    /// 1. Poll for incoming data
    /// 2. If data available, receive and ingest
    /// 3. Egest and send any outgoing packets
    pub fn step(&mut self, timeout_ms: i32) -> Result<bool, ConnectionError> {
        let mut worked = false;

        match self.backend.poll(timeout_ms) {
            Ok(true) => {
                worked = true;
            }
            Ok(false) => {}
            Err(_) => {
                return Err(ConnectionError::Transport(
                    crate::error::TransportError::InternalError,
                ));
            }
        }
        if worked {
            loop {
                match self.backend.recv(&mut self.recv_buf) {
                    Ok((0, _)) => break, // no more data
                    Ok((n, _addr)) => {
                        self.conn.ingest(&self.recv_buf[..n])?;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        self.flush_egress()?;
        Ok(worked)
    }

    /// Drain egress: send all pending outgoing packets.
    fn flush_egress(&mut self) -> Result<(), ConnectionError> {
        loop {
            let n = self.conn.egest(&mut self.send_buf)?;
            if n == 0 {
                break;
            }
            self.backend.send(&self.send_buf[..n]).map_err(|_| {
                ConnectionError::Transport(crate::error::TransportError::InternalError)
            })?;
        }
        Ok(())
    }

    /// Run the handshake until established or error.
    pub fn handshake(&mut self) -> Result<(), ConnectionError> {
        let mut iterations = 0;
        while !self.conn.is_established() {
            self.step(100)?;
            iterations += 1;
            if iterations > 1000 {
                return Err(ConnectionError::Transport(
                    crate::error::TransportError::InternalError,
                ));
            }
        }
        Ok(())
    }

    /// Send application data (after handshake).
    /// This puts data into a STREAM frame for the next egest.
    pub fn send_app_data(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        self.conn.send_data(data);
        self.flush_egress()
    }

    /// Try to receive application data. Returns bytes copied.
    pub fn recv_app_data(&mut self, buf: &mut [u8]) -> Result<usize, ConnectionError> {
        // Step to receive any pending packets
        let _ = self.step(0);
        Ok(self.conn.recv_data(buf))
    }

    pub fn is_established(&self) -> bool {
        self.conn.is_established()
    }
}

// ── Epoll endpoint constructors ───────────────────────────────

/// Concrete endpoint type using [`EpollBackend`].
pub type EpEndpoint = Endpoint<EpollBackend>;

/// Create a client endpoint using epoll.
pub fn ep_client(
    server_addr: SocketAddr,
    server_name: &str,
) -> Result<EpEndpoint, ConnectionError> {
    let (conn, initial) = Connection::connect(server_name)?;
    let local_addr = SocketAddr::new(server_addr.ip(), 0);
    let mut backend = EpollBackend::new(local_addr, server_addr)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    backend
        .send(&initial)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    Ok(Endpoint::new(conn, backend))
}

/// Create a server endpoint using an existing epoll backend.
/// The backend should already be bound and have received the client's
/// Initial packet (which must be passed as `initial_packet`).
pub fn ep_server(
    initial_packet: &[u8],
    backend: EpollBackend,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<EpEndpoint, ConnectionError> {
    let conn = Connection::accept(initial_packet, server_config)?;
    let mut ep = Endpoint::new(conn, backend);
    ep.conn_mut()
        .ingest(initial_packet)
        .map_err(|_| ConnectionError::Transport(crate::error::TransportError::InternalError))?;
    ep.flush_egress()?;
    Ok(ep)
}

// ── Drive handshake helper ─────────────────────────────────────

/// Drive a handshake between two endpoints (for testing).
/// Exchanges packets until both sides are established.
pub fn drive_handshake<A: Backend, B: Backend>(
    client: &mut Endpoint<A>,
    server: &mut Endpoint<B>,
) -> Result<(), ConnectionError> {
    let mut iterations = 0;
    loop {
        if client.is_established() && server.is_established() {
            return Ok(());
        }
        if iterations > 1000 {
            return Err(ConnectionError::Transport(
                crate::error::TransportError::InternalError,
            ));
        }

        // Ignore step errors during handshake — stray/delayed packets may
        // cause parse failures on the other side.
        let _ = client.step(10);
        let _ = server.step(10);
        iterations += 1;
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
        Arc::new(
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key)
                .unwrap(),
        )
    }

    #[test]
    fn handshake_via_endpoints() {
        // Bind server socket
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server_be = EpollBackend::bind(server_addr).unwrap();
        let server_local = server_be.socket.local_addr().unwrap();

        // Create client endpoint, send Initial
        let mut client_ep = ep_client(server_local, "localhost").unwrap();

        // Server waits for and accepts the Initial
        let mut buf = [0u8; 2048];
        server_be.poll(5000).expect("poll");
        let (n, _caddr) = server_be.recv(&mut buf).expect("recv");
        let mut server_ep =
            ep_server(&buf[..n], server_be, test_server_config()).expect("ep_server");

        // Drive handshake
        drive_handshake(&mut client_ep, &mut server_ep).expect("handshake");

        assert!(client_ep.is_established());
        assert!(server_ep.is_established());
    }
}
