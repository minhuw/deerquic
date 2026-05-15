# QUIC Protocol RFCs

## Core QUIC Transport (essential)

| RFC | Title | Date | Size |
|-----|-------|------|------|
| [8999](rfc8999.txt) | Version-Independent Properties of QUIC | May 2021 | 17 KB |
| [9000](rfc9000.txt) | QUIC: A UDP-Based Multiplexed and Secure Transport | May 2021 | 403 KB |
| [9001](rfc9001.txt) | Using TLS to Secure QUIC | May 2021 | 126 KB |
| [9002](rfc9002.txt) | QUIC Loss Detection and Congestion Control | May 2021 | 89 KB |

## QUIC Extensions & Version Negotiation

| RFC | Title | Date | Size |
|-----|-------|------|------|
| [9221](rfc9221.txt) | An Unreliable Datagram Extension to QUIC | Mar 2022 | 19 KB |
| [9287](rfc9287.txt) | Greasing the QUIC Bit | Aug 2022 | 11 KB |
| [9368](rfc9368.txt) | Compatible Version Negotiation for QUIC | May 2023 | 40 KB |
| [9369](rfc9369.txt) | QUIC Version 2 | May 2023 | 27 KB |
| [9443](rfc9443.txt) | Multiplexing Scheme Updates for QUIC | Jul 2023 | 16 KB |

## Informational / Applicability

| RFC | Title | Date | Size |
|-----|-------|------|------|
| [9308](rfc9308.txt) | Applicability of the QUIC Transport Protocol | Sep 2022 | 61 KB |
| [9312](rfc9312.txt) | Manageability of the QUIC Transport Protocol | Sep 2022 | 81 KB |
| [9250](rfc9250.txt) | DNS over Dedicated QUIC Connections | May 2022 | 66 KB |

## HTTP/3 & QPACK (QUIC-adjacent)

| RFC | Title | Date | Size |
|-----|-------|------|------|
| [9114](rfc9114.txt) | HTTP/3 | Jun 2022 | 155 KB |
| [9204](rfc9204.txt) | QPACK: Field Compression for HTTP/3 | Jun 2022 | 99 KB |

## Implementation Order

For a feature-complete QUIC implementation in Rust, read in this order:

1. **RFC 8999** — Start here: invariants every QUIC implementation must uphold
2. **RFC 9000** — Core transport: frames, streams, connections, packet formats
3. **RFC 9001** — TLS 1.3 integration: handshake, key derivation, header protection
4. **RFC 9002** — Loss detection timers, congestion control
5. **RFC 9221** — Unreliable datagram extension
6. **RFC 9287** — Greasing (compatibility testing)
7. **RFC 9368** — Version negotiation compatibility
8. **RFC 9369** — QUIC v2 specifics
9. **RFC 9443** — Multiplexing updates
10. **RFC 9114** — HTTP/3 mapping (if building above transport)
