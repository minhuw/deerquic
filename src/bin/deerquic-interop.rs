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
    use rustls::pki_types::pem::PemObject;

    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let key = rustls::pki_types::PrivateKeyDer::pem_slice_iter(&key_pem)
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

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

    // Both handshake and transfer serve files via HTTP/0.9
    {
        let docroot = env::var("DOCUMENT_ROOT").unwrap_or_else(|_| "/www".into());
        let mut idle = 0u32;
        loop {
            let mut req_buf = [0u8; 2048];
            let mut req = None;
            loop {
                let _ = server.step(100);
                let n = server.conn_mut().recv_data(&mut req_buf);
                if n > 0 {
                    req = Some(
                        std::str::from_utf8(&req_buf[..n])
                            .unwrap_or("")
                            .trim()
                            .to_string(),
                    );
                    break;
                }
                idle += 1;
                if idle > 50 {
                    writeln!(log, "timeout waiting for request")?;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if idle > 50 {
                break;
            }
            idle = 0;
            let req = req.unwrap_or_default();

            if req.is_empty() {
                writeln!(log, "empty request, done")?;
                break;
            }

            // HTTP/0.9: "GET /path\r\n"
            let path = req
                .strip_prefix("GET /")
                .unwrap_or(&req)
                .trim_end_matches('\r')
                .trim_end_matches('\n')
                .to_string();

            let file_path = format!("{docroot}/{path}");
            writeln!(log, "request: {req:?} -> serving {file_path}")?;

            match fs::read(&file_path) {
                Ok(data) => {
                    writeln!(log, "  serving {} bytes", data.len())?;
                    const CHUNK: usize = 1024;
                    for chunk in data.chunks(CHUNK) {
                        server.conn_mut().send_data(chunk);
                        loop {
                            let out_n = server.conn_mut().egest(&mut buf).unwrap_or(0);
                            if out_n == 0 {
                                break;
                            }
                            let be = server.backend_mut();
                            let _ = be.send(&buf[..out_n]);
                        }
                    }
                }
                Err(e) => {
                    writeln!(log, "  file not found: {e}")?;
                }
            }
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

    // Both handshake and transfer download files via HTTP/0.9
    {
        let dl_root = env::var("DOWNLOAD_ROOT").unwrap_or_else(|_| "/downloads".into());
        let requests = env::var("REQUESTS").unwrap_or_default();

        writeln!(log, "REQUESTS={requests}")?;

        for req_url in requests.split_whitespace() {
            // e.g. "https://server/file1"
            let path = req_url.splitn(4, '/').nth(3).unwrap_or("index.html");

            let req_line = format!("GET /{path}\r\n");
            writeln!(log, "requesting: {req_line:?}")?;
            client.conn_mut().send_data(req_line.as_bytes());

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

            // Receive response (wait for data with timeout)
            let mut data = Vec::new();
            let mut silence = 0u32;
            let mut rbuf = [0u8; 16384];
            loop {
                let _ = client.step(100);
                let n = client.conn_mut().recv_data(&mut rbuf);
                if n > 0 {
                    data.extend_from_slice(&rbuf[..n]);
                    silence = 0;
                } else {
                    silence += 1;
                    if silence > 30 {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            // Save to download directory
            let save_path = format!("{dl_root}/{path}");
            if let Some(parent) = std::path::Path::new(&save_path).parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(&save_path, &data)?;
            writeln!(log, "saved {} bytes to {save_path}", data.len())?;
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
