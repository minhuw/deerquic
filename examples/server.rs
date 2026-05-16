//! deerquic server example.
//!
//! Usage: cargo run --example server -- <bind_addr>
//! Example: cargo run --example server -- 127.0.0.1:4433

use deerquic::runtime::{ep_server, Backend, EpollBackend};
use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;

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

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <bind_addr>", args[0]);
        std::process::exit(1);
    }
    let bind_addr: SocketAddr = args[1]
        .parse()
        .expect("invalid bind address (e.g. 127.0.0.1:4433)");

    println!("deerquic server listening on {}", bind_addr);

    // Create server socket and wait for client Initial
    let mut backend = EpollBackend::bind(bind_addr).expect("bind");
    println!("  bound to {}", bind_addr);

    // Wait for client's Initial packet
    println!("  waiting for client...");
    let mut buf = [0u8; 2048];
    let (n, client_addr) = loop {
        backend.poll(1000).expect("poll");
        match backend.recv(&mut buf) {
            Ok((0, _)) => continue,
            Ok((n, addr)) => break (n, addr),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                eprintln!("  recv error: {e}");
                std::process::exit(1);
            }
        }
    };
    println!("  received Initial from {}", client_addr);

    // Create server endpoint (reuse the existing backend)
    let config = test_server_config();
    let mut server = match ep_server(&buf[..n], backend, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create server: {e}");
            std::process::exit(1);
        }
    };

    // Drive handshake
    println!("  running handshake...");
    match server.handshake() {
        Ok(()) => println!("  handshake complete!"),
        Err(e) => {
            eprintln!("  handshake failed: {e}");
            std::process::exit(1);
        }
    }

    println!("Connection established with {}", client_addr);
    io::stdout().flush().ok();
    Ok(())
}
