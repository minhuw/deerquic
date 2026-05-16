# Build stage: compile deerquic-interop for the target platform
FROM rust:1.95-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --bin deerquic-interop

# Runtime stage: quic-network-simulator endpoint
FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=builder /build/target/release/deerquic-interop /usr/local/bin/deerquic-interop
COPY interop/run_endpoint.sh /run_endpoint.sh

RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
