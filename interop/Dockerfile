FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && apt-get install -y --no-install-recommends libc6 && rm -rf /var/lib/apt/lists/*

COPY target/release/deerquic-interop /usr/local/bin/deerquic-interop
COPY interop/run_endpoint.sh /run_endpoint.sh

RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
