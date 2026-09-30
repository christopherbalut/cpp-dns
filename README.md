# cpp-dns

A DNS server written in modern C++ with support for DNS packet parsing and serialization, UDP networking, concurrent request handling, caching, filtering, configuration, and persistent data storage.

The project is built primarily as a systems programming project for exploring networking protocols, resource management, concurrency, and server architecture in C++.

---

## Features

- DNS packet encoding and decoding
- DNS name compression parsing
- UDP-based DNS server
- Stub resolver for forwarding DNS queries
- Support for common DNS record types
- Multithreaded request handling with a thread pool
- Thread-safe DNS cache
- Domain blocklist and allowlist filtering
- Runtime server statistics
- Configuration file support
- Graceful server shutdown
- PostgreSQL integration
- RAII-based socket management
- GoogleTest unit test suite

---

## Architecture

A DNS request moves through the server roughly as follows:

```text
Client
  │
  │ DNS Query
  ▼
┌─────────────────┐
│    DnsServer    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Thread Pool   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Packet Parsing  │
│   DnsPacket     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Filtering       │
│ Block / Allow   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      Cache      │
└────────┬────────┘
         │ miss
         ▼
┌─────────────────┐
│  Stub Resolver  │
│ Upstream DNS    │
└────────┬────────┘
         │
         ▼
      Response
```

The project separates DNS protocol logic from networking and server infrastructure so that packet parsing, caching, filtering, and request handling can be developed and tested independently.

---

## DNS Protocol Support

The DNS implementation provides structured C++ representations of DNS packets and their components.

### Packet handling

- `PacketBuffer`
- DNS header parsing and serialization
- DNS question parsing
- DNS record parsing
- DNS packet encoding and decoding
- compressed domain-name decoding
- DNS response construction

### Record types

Support includes common DNS record types such as:

- `A`
- `AAAA`
- `NS`
- `CNAME`
- `MX`

Unknown record types can also be represented without breaking packet decoding.

---

## Server Components

### `DnsServer`

Responsible for:

- binding the UDP socket
- receiving DNS queries
- dispatching requests
- constructing DNS responses
- sending responses back to clients

### `StubResolver`

Forwards DNS queries to an upstream DNS resolver when a result cannot be answered locally.

### `ThreadPool`

Provides concurrent query processing using a fixed pool of worker threads rather than creating a new thread for every request.

### `Cache`

Stores previously resolved DNS responses to avoid unnecessary upstream queries.

The cache is designed to support concurrent access from server worker threads.

### Filtering

The server supports domain filtering through:

- blocklists
- allowlists

This allows the DNS server to act as a basic DNS filtering service.

### Server Statistics

Runtime statistics can be collected for server activity, allowing query handling behavior to be observed while the server is running.

---

## Project Structure

```text
cpp-dns/
├── apps/              # Executable entry points
├── docs/              # Design notes and documentation
├── include/
│   └── dns/           # Public headers
├── scripts/           # Build and helper scripts
├── src/
│   └── dns/           # Implementations
├── tests/             # GoogleTest test suite
└── CMakeLists.txt
```

Some of the major components include:

```text
buffer
packet
header
question
record
domain_name

server
stub_resolver
socket_utils

thread_pool
cache
server_stats

blocklist
allowlist

config_parser
config_file
shutdown
```

---

## Requirements

The project uses:

- C++20
- CMake 3.20+
- a C++20-compatible compiler
- GoogleTest
- PostgreSQL
- libpqxx

On Linux, GCC or Clang can be used.

---

## Building

The project includes helper scripts for configuring and building the server.

Configure the build:

```bash
./scripts/configure.sh
```

Build the project:

```bash
./scripts/build.sh
```

Alternatively, the project can be built directly with CMake:

```bash
cmake -S . -B build
cmake --build build
```

---

## Running

After building the project, run the DNS server executable from the build directory.

The server binds to the configured IP address and UDP port and begins accepting DNS queries.

For local development, a non-privileged port such as `2053` can be used.

A query can then be sent using `dig`:

```bash
dig @127.0.0.1 -p 2053 example.com
```

For a specific record type:

```bash
dig @127.0.0.1 -p 2053 example.com A
```

```bash
dig @127.0.0.1 -p 2053 example.com AAAA
```

---

## Testing

The project uses GoogleTest for automated testing.

Run the test suite with:

```bash
ctest --test-dir build --output-on-failure
```

Tests cover components such as:

- packet buffers
- DNS headers
- DNS questions
- DNS records
- DNS packets
- domain-name parsing
- result codes
- caching
- filtering
- server utilities

---

## Design Goals

The project is intentionally structured around several systems-programming concepts.

### Protocol parsing

DNS packets are parsed directly from their wire representation rather than relying on a high-level DNS library.

This includes handling variable-length fields and compressed domain names.

### Resource management

Operating-system resources such as sockets are managed using RAII so that ownership and cleanup follow normal C++ object lifetimes.

### Concurrency

DNS requests can be processed concurrently through a worker thread pool.

Shared components such as the cache and statistics system are designed with concurrent access in mind.

### Separation of concerns

Protocol representation, networking, request handling, caching, filtering, and configuration are kept as separate components.

This keeps the system easier to test and allows individual pieces to evolve independently.

---

## Motivation

`cpp-dns` started as a way to understand DNS at the packet level and gradually evolved into a larger systems programming project.

The project is intended to explore areas including:

- network programming
- binary protocol parsing
- modern C++ resource management
- concurrency
- caching
- server architecture
- testing
- persistent storage
- Linux deployment

Rather than using an existing DNS library for the protocol layer, the DNS packet representation and parsing logic are implemented directly in C++.

---

## Future Work

Possible extensions include:

- cache expiration based on DNS TTL values
- additional DNS record types
- improved server observability
- more advanced filtering rules
- persistent query statistics
- performance benchmarking
- load testing
- resolver retry and timeout policies
- IPv6 server support
- additional deployment tooling

---

## License

This project is intended primarily for educational and experimental use.
