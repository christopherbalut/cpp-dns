# cpp-dns

A C++ DNS project focused on learning packet parsing, protocol design, and eventually building toward a DNS resolver / filtering server.

## Current Status

The project currently implements the DNS packet-parsing foundation. At this stage, it can decode raw DNS packet bytes into structured C++ objects.

Implemented so far:
- `PacketBuffer`
- `DnsHeader` decoding
- `DnsQuestion` decoding
- `DnsRecord` decoding for `A` and unknown records
- `DnsPacket` top-level decoding
- qname parsing, including compressed names
- unit tests for buffer, header, question, record, packet, and result-code decoding

## Project Structure

- `include/dns/` — public headers
- `src/dns/` — implementations
- `tests/` — GoogleTest test suite
- `docs/` — project notes and parsing documentation
- `apps/` — small executable entry points

## Running the project

This project uses helper scripts.

Configure the build:

```bash
./scripts/configure.sh
