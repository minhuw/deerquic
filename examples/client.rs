//! deerquic client example.
//!
//! Usage: cargo run --example client -- <server_addr>
//! Example: cargo run --example client -- 127.0.0.1:4433

use deerquic::runtime::ep_client;
use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

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

    let mut client = match ep_client(server_addr, "localhost") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {e}");
            std::process::exit(1);
        }
    };

    println!("  Running handshake...");
    match client.handshake() {
        Ok(()) => println!("  Handshake complete!"),
        Err(e) => {
            eprintln!("  Handshake failed: {e}");
            std::process::exit(1);
        }
    }

    // Ping-pong loop
    let mut buf = [0u8; 2048];
    for i in 1..=5 {
        let msg = format!("ping {}", i);
        print!("  -> {}", msg);
        io::stdout().flush().ok();

        client.send_app_data(msg.as_bytes()).unwrap();

        // Wait for response
        loop {
            let n = client.recv_app_data(&mut buf).unwrap();
            if n > 0 {
                let response = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                println!("  <- {}", response);
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    println!("Done.");
    Ok(())
}
