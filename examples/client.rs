//! deerquic client example.
//!
//! Usage: cargo run --example client -- <server_addr>
//! Example: cargo run --example client -- 127.0.0.1:4433

use deerquic::runtime::ep_client;
use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <server_addr>", args[0]);
        std::process::exit(1);
    }
    let server_addr: SocketAddr = args[1]
        .parse()
        .expect("invalid server address (e.g. 127.0.0.1:4433)");

    println!("deerquic client connecting to {}", server_addr);

    // Create client endpoint (binds local port, sends Initial packet)
    let mut client = match ep_client(server_addr, "localhost") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {e}");
            std::process::exit(1);
        }
    };

    // Drive the QUIC handshake
    println!("  Running handshake...");
    match client.handshake() {
        Ok(()) => println!("  Handshake complete!"),
        Err(e) => {
            eprintln!("  Handshake failed: {e}");
            std::process::exit(1);
        }
    }

    println!("Connection established with {}", server_addr);
    io::stdout().flush().ok();
    Ok(())
}
