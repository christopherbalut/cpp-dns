# cpp-dns

A C++20 DNS server built to explore DNS packet parsing, UDP networking, concurrency, caching, filtering, and server design.

![C++](https://img.shields.io/badge/C%2B%2B-20-blue)
![CMake](https://img.shields.io/badge/build-CMake-blue)
![Tests](https://img.shields.io/badge/tests-GoogleTest-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

## Features

- DNS packet encoding and decoding
- compressed domain-name parsing
- support for `A`, `AAAA`, `NS`, `CNAME`, and `MX` records
- UDP DNS server
- upstream DNS resolution
- concurrent request handling with a thread pool
- thread-safe DNS cache
- domain blocklist and allowlist
- runtime server statistics
- configuration file support
- graceful shutdown
- PostgreSQL integration
- GoogleTest test suite

## Architecture

```text
Client
  │
  ▼
DnsServer
  │
  ▼
ThreadPool
  │
  ▼
DNS Packet Parsing
  │
  ├── Blocklist / Allowlist
  ├── Cache
  └── StubResolver ──────► Upstream DNS
  │
  ▼
Response
```

## Project Structure

```text
cpp-dns/
├── apps/          # Executables
├── docs/          # Documentation and notes
├── include/dns/   # Public headers
├── scripts/       # Build scripts
├── src/dns/       # Implementation
├── tests/         # GoogleTest suite
└── CMakeLists.txt
```

## Build

### Requirements

- C++20 compatible compiler
- CMake 3.20+
- PostgreSQL
- libpqxx
- GoogleTest

Configure and build:

```bash
./scripts/configure.sh
./scripts/build.sh
```

Or with CMake directly:

```bash
cmake -S . -B build
cmake --build build
```

## Usage

Start the DNS server and query it using `dig`:

```bash
dig @127.0.0.1 -p 2053 example.com
```

Query a specific record type:

```bash
dig @127.0.0.1 -p 2053 example.com AAAA
```

## Testing

Run the test suite with:

```bash
ctest --test-dir build --output-on-failure
```

## Future Work

- TTL-aware cache expiration
- performance benchmarking
- additional DNS record types
- improved logging and observability
- more advanced filtering rules
