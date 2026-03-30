# Packet Parsing

This stage of the project implements the DNS packet-parsing foundation in C++. The goal is to take raw DNS packet bytes and decode them into structured C++ objects that the rest of the project can use safely and predictably. At this point, the focus is only on parsing. Networking, resolver logic, caching, and blocking behavior come later.

The parsing pipeline is built in layers. `PacketBuffer` is the low-level byte reader. It keeps track of the current cursor position, supports bounded reads, and provides helpers for reading single bytes, multi-byte integers, and DNS names. On top of that, `DnsHeader`, `DnsQuestion`, and `DnsRecord` each decode one part of the DNS packet format. `DnsPacket` is the top-level type that ties everything together by decoding the header first, then the questions, answers, authority records, and additional records in order.

`PacketBuffer` is the core utility type in this stage. It is responsible for cursor movement, bounded access, network-byte-order reads, and qname parsing. The qname logic is the most protocol-specific part of the buffer layer because DNS names are not stored as ordinary strings. Instead, they are encoded as length-prefixed labels and may also use compression pointers that jump to earlier parts of the packet. The buffer is therefore not just a byte container; it is the object that makes structured DNS parsing possible.

`DnsHeader` represents the 12-byte DNS header. Its decode logic reads the identifier, unpacks the flag bits, and reads the four section counts. `DnsQuestion` represents a question entry and decodes the qname, the query type, and the class field. `DnsRecord` currently supports `A` records and a generic unknown-record fallback. `A` records are decoded into an IPv4 address and TTL, while unsupported record types are preserved as unknown records so that parsing can still continue correctly. `DnsPacket` is the final orchestration layer and is responsible for decoding an entire message from a buffer into its component sections.

The tests for this stage are organized by parsing layer. The packet-buffer tests cover cursor movement, bounded reads, range access, sparse writes, and multi-byte reads in network byte order. The result-code tests verify the numeric-to-enum mapping used during header decoding. The header tests check default construction, flag decoding, count decoding, and even exhaustively verify all possible 16-bit flag combinations. The question tests cover normal qnames, compressed names, lowercase normalization, and partial input behavior. The record tests check `A` records, unknown records, compressed names, truncation behavior, and payload skipping. The packet tests exercise the full integration path and verify that complete DNS packets are decoded into the correct sections in the correct order.

This stage is intentionally limited. The parser currently supports only a small subset of record types, and the project does not yet write packets, send queries over the network, or act as a resolver or server. Still, this layer is the foundation for everything that comes next. Before the project can forward queries, cache responses, or block domains, it first needs a reliable way to decode DNS packets. That is what this stage provides.

The next step is to build on top of this parsing layer and begin working with real DNS communication rather than only offline packet decoding.

The resources used for this were:

