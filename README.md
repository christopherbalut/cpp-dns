cpp-dns

A modern C++ DNS server built to explore DNS protocol parsing, UDP networking, concurrency, caching, filtering, and server design.

Features

DNS packet encoding and decoding

compressed domain-name parsing

support for common DNS record types

UDP DNS server and upstream stub resolver

thread pool for concurrent query handling

thread-safe DNS cache

blocklist and allowlist filtering

server statistics

configuration file support

graceful shutdown

PostgreSQL integration

RAII-based socket management

GoogleTest test suite

Architecture

Client
  │
  ▼
DnsServer
  │
  ▼
ThreadPool
  │
  ▼
DnsPacket
  │
  ├── Filtering
  ├── Cache
  │
  └── StubResolver ──► Upstream DNS
  │
  ▼
Response

DNS Support

The project implements DNS packet handling directly in C++, including:

headers

questions

records

packet serialization

compressed domain names

Supported record types include:

A

AAAA

NS

CNAME

MX

unknown record types

Project Structure

cpp-dns/
├── apps/          # Executables
├── docs/          # Notes and documentation
├── include/dns/   # Public headers
├── scripts/       # Build helpers
├── src/dns/       # Implementations
├── tests/         # GoogleTest suite
└── CMakeLists.txt

Requirements

C++20

CMake 3.20+

GoogleTest

PostgreSQL

libpqxx

Build

./scripts/configure.sh
./scripts/build.sh

Or directly with CMake:

cmake -S . -B build
cmake --build build

Run

Start the server, then query it using dig:

dig @127.0.0.1 -p 2053 example.com

For a specific record type:

dig @127.0.0.1 -p 2053 example.com AAAA

Testing

ctest --test-dir build --output-on-failure

Tests cover DNS parsing, packet handling, caching, filtering, and server utilities.

Motivation

cpp-dns began as a packet-parsing project and evolved into a larger systems programming project focused on:

networking

binary protocols

modern C++

concurrency

caching

server architecture

testing and deployment

Future Work

TTL-aware cache expiration

performance benchmarks

additional DNS record types

improved observability

more advanced filtering

resolver timeout and retry policies
