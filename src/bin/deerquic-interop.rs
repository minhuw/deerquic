//! deerquic interop endpoint for quic-interop-runner.
//!
//! ## Server
//! ```bash
//! deerquic-interop server [--cert /certs/cert.pem] [--key /certs/priv.key]
//! ```
//! Listens on `[::]:443`, reads TLS cert + key from files.
//! Testcase is read from `$TESTCASE` environment variable.
//!
//! ## Client
//! ```bash
//! deerquic-interop client [--host server] [--port 443]
//! ```
//! Testcase is read from `$TESTCASE` environment variable.

use deerquic::runtime::{ep_client, ep_server, Backend, EpollBackend};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn testcase() -> String {
    env::var("TESTCASE").unwrap_or_else(|_| "handshake".into())
}

fn is_supported(tc: &str) -> bool {
    matches!(tc, "handshake" | "transfer")
}

fn load_server_config(cert_path: &str, key_path: &str) -> io::Result<Arc<rustls::ServerConfig>> {
    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key"))?;

    Ok(Arc::new(
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    ))
}

fn run_server(cert_path: &str, key_path: &str) -> io::Result<()> {
    let tc = testcase();
    if !is_supported(&tc) {
        eprintln!("unsupported TESTCASE={}", tc);
        std::process::exit(127);
    }

    let config = load_server_config(cert_path, key_path)?;

    let bind_addr: SocketAddr = "[::]:443".parse().unwrap();
    let mut backend = EpollBackend::bind(bind_addr).map_err(|e| {
        eprintln!("bind failed: {e}");
        e
    })?;

    let log_path = format!("/logs/{tc}_server.log");
    let mut log = fs::File::create(&log_path)
        .unwrap_or_else(|_| fs::File::create("/tmp/deerquic_server.log").unwrap());

    writeln!(log, "deerquic server starting, testcase={tc}")?;

    // Wait for client Initial
    let mut buf = [0u8; 2048];
    let (n, _client_addr) = loop {
        backend.poll(5000).expect("poll");
        match backend.recv(&mut buf) {
            Ok((0, _)) => continue,
            Ok((n, addr)) => break (n, addr),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                writeln!(log, "recv error: {e}")?;
                return Err(e);
            }
        }
    };

    let mut server = ep_server(&buf[..n], backend, config)
        .map_err(|e| {
            writeln!(log, "ep_server failed: {e}").ok();
            e
        })
        .map_err(|e| io::Error::other(format!("{e}")))?;

    writeln!(log, "accepted connection")?;

    // Handshake
    loop {
        let _ = server.step(100);
        if server.is_established() {
            break;
        }
    }

    writeln!(log, "handshake complete")?;

    if tc == "transfer" {
        // Receive data from client
        let mut recv_buf = [0u8; 4096];
        for _retry in 0..100 {
            let _ = server.step(100);
            let n = server.conn_mut().recv_data(&mut recv_buf);
            if n > 0 {
                let msg = std::str::from_utf8(&recv_buf[..n]).unwrap_or("?");
                writeln!(log, "received: {msg}")?;
                // Echo back
                server.conn_mut().send_data(msg.as_bytes());
                loop {
                    let out_n = server.conn_mut().egest(&mut buf).unwrap_or(0);
                    if out_n == 0 {
                        break;
                    }
                    let be = server.backend_mut();
                    let _ = be.send(&buf[..out_n]);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    writeln!(log, "done")?;
    Ok(())
}

fn run_client(host: &str, port: u16) -> io::Result<()> {
    let tc = testcase();
    if !is_supported(&tc) {
        eprintln!("unsupported TESTCASE={}", tc);
        std::process::exit(127);
    }

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let log_path = format!("/logs/{tc}_client.log");
    let mut log = fs::File::create(&log_path)
        .unwrap_or_else(|_| fs::File::create("/tmp/deerquic_client.log").unwrap());

    writeln!(
        log,
        "deerquic client starting, testcase={tc}, server={addr}"
    )?;

    let mut client = ep_client(addr, host)
        .map_err(|e| {
            writeln!(log, "ep_client failed: {e}").ok();
            e
        })
        .map_err(|e| io::Error::other(format!("{e}")))?;

    // Handshake
    loop {
        let _ = client.step(100);
        if client.is_established() {
            break;
        }
    }

    writeln!(log, "handshake complete")?;

    if tc == "transfer" {
        let msg = b"hello deerquic\n";
        writeln!(log, "sending: {}", std::str::from_utf8(msg).unwrap())?;
        client.conn_mut().send_data(msg);

        // Flush egress
        let mut sbuf = [0u8; 2048];
        loop {
            let n = client.conn_mut().egest(&mut sbuf).unwrap_or(0);
            if n == 0 {
                break;
            }
            let be = client.backend_mut();
            let _ = be.send(&sbuf[..n]);
        }

        // Wait for echo
        let mut recv_buf = [0u8; 4096];
        for _retry in 0..100 {
            let _ = client.step(100);
            let n = client.conn_mut().recv_data(&mut recv_buf);
            if n > 0 {
                let echo = std::str::from_utf8(&recv_buf[..n]).unwrap_or("?");
                writeln!(log, "received echo: {echo}")?;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    writeln!(log, "done")?;
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <server|client> [options]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => {
            let cert_path = args
                .iter()
                .position(|a| a == "--cert")
                .and_then(|i| args.get(i + 1))
                .map(|s| s.as_str())
                .unwrap_or("/certs/cert.pem");
            let key_path = args
                .iter()
                .position(|a| a == "--key")
                .and_then(|i| args.get(i + 1))
                .map(|s| s.as_str())
                .unwrap_or("/certs/priv.key");
            run_server(cert_path, key_path)
        }
        "client" => {
            let host = args
                .iter()
                .position(|a| a == "--host")
                .and_then(|i| args.get(i + 1))
                .map(|s| s.as_str())
                .unwrap_or("server");
            let port: u16 = args
                .iter()
                .position(|a| a == "--port")
                .and_then(|i| args.get(i + 1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(443);
            run_client(host, port)
        }
        _ => {
            eprintln!("expected 'server' or 'client', got '{}'", args[1]);
            std::process::exit(1);
        }
    }
}
