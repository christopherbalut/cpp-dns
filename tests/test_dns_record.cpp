#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <variant>

#include "dns/buffer.hpp"
#include "dns/record.hpp"
#include "dns/types.hpp"

namespace
{
using dns::ARecord;
using dns::DnsRecord;
using dns::PacketBuffer;
using dns::UnknownRecord;

std::size_t write_u16(PacketBuffer& buffer, std::size_t pos, std::uint16_t value)
{
    buffer.set(pos++, static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer.set(pos++, static_cast<std::uint8_t>(value & 0xFF));
    return pos;
}

std::size_t write_u32(PacketBuffer& buffer, std::size_t pos, std::uint32_t value)
{
    buffer.set(pos++, static_cast<std::uint8_t>((value >> 24) & 0xFF));
    buffer.set(pos++, static_cast<std::uint8_t>((value >> 16) & 0xFF));
    buffer.set(pos++, static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer.set(pos++, static_cast<std::uint8_t>(value & 0xFF));
    return pos;
}

std::size_t write_bytes(PacketBuffer& buffer, std::size_t pos,
                        std::initializer_list<std::uint8_t> bytes)
{
    for (const auto byte : bytes)
    {
        buffer.set(pos++, byte);
    }

    return pos;
}

std::size_t write_pointer(PacketBuffer& buffer, std::size_t pos, std::uint16_t offset)
{
    const std::uint16_t pointer = static_cast<std::uint16_t>(0xC000U | offset);
    return write_u16(buffer, pos, pointer);
}

std::size_t write_qname(PacketBuffer& buffer, std::size_t pos, std::string_view name)
{
    if (name.empty())
    {
        buffer.set(pos++, 0);
        return pos;
    }

    std::size_t label_start = 0;

    while (label_start < name.size())
    {
        const std::size_t dot = name.find('.', label_start);
        const std::size_t label_end = (dot == std::string_view::npos) ? name.size() : dot;
        const std::size_t label_len = label_end - label_start;

        buffer.set(pos++, static_cast<std::uint8_t>(label_len));

        for (std::size_t i = label_start; i < label_end; ++i)
        {
            buffer.set(pos++, static_cast<std::uint8_t>(name[i]));
        }

        if (dot == std::string_view::npos)
        {
            break;
        }

        label_start = dot + 1;
    }

    buffer.set(pos++, 0);
    return pos;
}

std::size_t write_rr_header(PacketBuffer& buffer, std::size_t pos, std::string_view name,
                            std::uint16_t qtype, std::uint16_t qclass, std::uint32_t ttl,
                            std::uint16_t rdlength)
{
    pos = write_qname(buffer, pos, name);
    pos = write_u16(buffer, pos, qtype);
    pos = write_u16(buffer, pos, qclass);
    pos = write_u32(buffer, pos, ttl);
    pos = write_u16(buffer, pos, rdlength);
    return pos;
}

std::size_t write_compressed_rr_header(PacketBuffer& buffer, std::size_t pos,
                                       std::uint16_t name_offset, std::uint16_t qtype,
                                       std::uint16_t qclass, std::uint32_t ttl,
                                       std::uint16_t rdlength)
{
    pos = write_pointer(buffer, pos, name_offset);
    pos = write_u16(buffer, pos, qtype);
    pos = write_u16(buffer, pos, qclass);
    pos = write_u32(buffer, pos, ttl);
    pos = write_u16(buffer, pos, rdlength);
    return pos;
}

std::size_t write_a_record(PacketBuffer& buffer, std::size_t pos, std::string_view name,
                           std::uint32_t ttl, std::initializer_list<std::uint8_t> addr)
{
    pos = write_rr_header(buffer, pos, name, 1, 1, ttl, 4);
    pos = write_bytes(buffer, pos, addr);
    return pos;
}

std::size_t write_a_record_with_explicit_rdlength(PacketBuffer& buffer, std::size_t pos,
                                                  std::string_view name, std::uint32_t ttl,
                                                  std::uint16_t rdlength,
                                                  std::initializer_list<std::uint8_t> rdata)
{
    pos = write_rr_header(buffer, pos, name, 1, 1, ttl, rdlength);
    pos = write_bytes(buffer, pos, rdata);
    return pos;
}

std::size_t write_unknown_record(PacketBuffer& buffer, std::size_t pos, std::string_view name,
                                 std::uint16_t qtype, std::uint32_t ttl,
                                 std::initializer_list<std::uint8_t> rdata)
{
    pos =
        write_rr_header(buffer, pos, name, qtype, 1, ttl, static_cast<std::uint16_t>(rdata.size()));
    pos = write_bytes(buffer, pos, rdata);
    return pos;
}

std::size_t write_compressed_a_record(PacketBuffer& buffer, std::size_t pos,
                                      std::uint16_t name_offset, std::uint32_t ttl,
                                      std::initializer_list<std::uint8_t> addr)
{
    pos = write_compressed_rr_header(buffer, pos, name_offset, 1, 1, ttl, 4);
    pos = write_bytes(buffer, pos, addr);
    return pos;
}
} // namespace
  //

namespace
{

dns::DnsRecord round_trip_record(const dns::DnsRecord& record)
{
    dns::PacketBuffer buffer{};

    const std::size_t bytes_written = dns::write_record(record, buffer);

    EXPECT_TRUE(buffer.ok());
    EXPECT_GT(bytes_written, 0);

    buffer.seek(0);
    EXPECT_TRUE(buffer.ok());

    return dns::decode_record(buffer);
}

} // namespace

TEST(DnsRecordTest, DecodeARecordSingleLabel)
{
    PacketBuffer buffer{};
    const std::size_t end = write_a_record(buffer, 0, "a", 300U, {8, 8, 4, 4});

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<ARecord>(record));
    const auto& a = std::get<ARecord>(record);

    EXPECT_EQ(a.domain, "a");
    EXPECT_EQ(a.addr, (std::array<std::uint8_t, 4>{8, 8, 4, 4}));
    EXPECT_EQ(a.ttl, 300U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, DecodeRootARecord)
{
    PacketBuffer buffer{};
    const std::size_t end = write_a_record(buffer, 0, "", 42U, {127, 0, 0, 1});

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<ARecord>(record));
    const auto& a = std::get<ARecord>(record);

    EXPECT_EQ(a.domain, "");
    EXPECT_EQ(a.addr, (std::array<std::uint8_t, 4>{127, 0, 0, 1}));
    EXPECT_EQ(a.ttl, 42U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, DecodeUnknownRecordPreservesMetadataAndSkipsPayload)
{
    PacketBuffer buffer{};
    const std::size_t end = write_unknown_record(buffer, 0, "a", 28U, 900U, {1, 2, 3, 4, 5, 6});

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(record));
    const auto& unknown = std::get<UnknownRecord>(record);

    EXPECT_EQ(unknown.domain, "a");
    EXPECT_EQ(unknown.qtype, 28U);
    EXPECT_EQ(unknown.data_len, 6U);
    EXPECT_EQ(unknown.ttl, 900U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, DecodeUnknownRecordWithZeroLengthRdata)
{
    PacketBuffer buffer{};
    const std::size_t end = write_unknown_record(buffer, 0, "a", 99U, 1U, {});

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(record));
    const auto& unknown = std::get<UnknownRecord>(record);

    EXPECT_EQ(unknown.domain, "a");
    EXPECT_EQ(unknown.qtype, 99U);
    EXPECT_EQ(unknown.data_len, 0U);
    EXPECT_EQ(unknown.ttl, 1U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, DecodeRecordFromNonZeroOffset)
{
    PacketBuffer buffer{};
    constexpr std::size_t start = 40;
    const std::size_t end =
        write_unknown_record(buffer, start, "a", 65000U, 777U, {0xAA, 0xBB, 0xCC});

    buffer.seek(start);
    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(record));
    const auto& unknown = std::get<UnknownRecord>(record);

    EXPECT_EQ(unknown.domain, "a");
    EXPECT_EQ(unknown.qtype, 65000U);
    EXPECT_EQ(unknown.data_len, 3U);
    EXPECT_EQ(unknown.ttl, 777U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, TruncatedRecordAfterQNameDoesNotAdvancePastAvailableData)
{
    PacketBuffer buffer{};
    const std::size_t qname_end = write_qname(buffer, 0, "a");

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(record));
    const auto& unknown = std::get<UnknownRecord>(record);

    EXPECT_EQ(unknown.domain, "a");
    EXPECT_EQ(unknown.qtype, 0U);
    EXPECT_EQ(unknown.data_len, 0U);
    EXPECT_EQ(unknown.ttl, 0U);
    EXPECT_EQ(buffer.position(), qname_end);
}

/*
 * The next tests are intentional bug-catching tests.
 * They describe the behavior you want from a robust DNS parser.
 * Some of them will likely fail on your current implementation.
 */

TEST(DnsRecordTest, DecodeMultiLabelARecordAndLowercaseDomain)
{
    PacketBuffer buffer{};
    const std::size_t end = write_a_record(buffer, 0, "WWW.Example.COM", 3600U, {1, 2, 3, 4});

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<ARecord>(record));
    const auto& a = std::get<ARecord>(record);

    EXPECT_EQ(a.domain, "www.example.com");
    EXPECT_EQ(a.addr, (std::array<std::uint8_t, 4>{1, 2, 3, 4}));
    EXPECT_EQ(a.ttl, 3600U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, DecodeCompressedNameARecord)
{
    PacketBuffer buffer{};

    constexpr std::size_t name_offset = 20;
    constexpr std::size_t record_offset = 60;

    write_qname(buffer, name_offset, "cache.test");
    const std::size_t end =
        write_compressed_a_record(buffer, record_offset, name_offset, 123U, {9, 9, 9, 9});

    buffer.seek(record_offset);
    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<ARecord>(record));
    const auto& a = std::get<ARecord>(record);

    EXPECT_EQ(a.domain, "cache.test");
    EXPECT_EQ(a.addr, (std::array<std::uint8_t, 4>{9, 9, 9, 9}));
    EXPECT_EQ(a.ttl, 123U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, ARecordShouldConsumeEntireRecordWhenDeclaredLengthIsFive)
{
    PacketBuffer buffer{};
    const std::size_t end =
        write_a_record_with_explicit_rdlength(buffer, 0, "a", 500U, 5U, {10, 20, 30, 40, 50});

    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<ARecord>(record));
    const auto& a = std::get<ARecord>(record);

    EXPECT_EQ(a.domain, "a");
    EXPECT_EQ(a.addr, (std::array<std::uint8_t, 4>{10, 20, 30, 40}));
    EXPECT_EQ(a.ttl, 500U);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsRecordTest, UnknownRecordShouldNeverMovePastEndOfBuffer)
{
    PacketBuffer buffer{};

    constexpr std::size_t start = 501;
    std::size_t pos = start;
    pos = write_qname(buffer, pos, "");
    pos = write_u16(buffer, pos, 28U);
    pos = write_u16(buffer, pos, 1U);
    pos = write_u32(buffer, pos, 55U);
    pos = write_u16(buffer, pos, 10U);

    ASSERT_EQ(pos, PacketBuffer::max_size);

    buffer.seek(start);
    const DnsRecord record = dns::decode_record(buffer);

    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(record));
    EXPECT_LE(buffer.position(), PacketBuffer::max_size);
}

TEST(DnsRecordWriteTest, WriteARecordCorrectly)
{
    dns::PacketBuffer buffer{};

    dns::ARecord arecord{.domain = "example.com", .addr = {1, 2, 3, 4}, .ttl = 0x11223344};

    dns::DnsRecord record{arecord};

    const std::size_t bytes_written = dns::write_record(record, buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(bytes_written, 27u);
    EXPECT_EQ(buffer.position(), 27u);

    // qname: 7 example 3 com 0
    EXPECT_EQ(buffer.get(0), 7u);
    EXPECT_EQ(buffer.get(1), static_cast<std::uint8_t>('e'));
    EXPECT_EQ(buffer.get(2), static_cast<std::uint8_t>('x'));
    EXPECT_EQ(buffer.get(3), static_cast<std::uint8_t>('a'));
    EXPECT_EQ(buffer.get(4), static_cast<std::uint8_t>('m'));
    EXPECT_EQ(buffer.get(5), static_cast<std::uint8_t>('p'));
    EXPECT_EQ(buffer.get(6), static_cast<std::uint8_t>('l'));
    EXPECT_EQ(buffer.get(7), static_cast<std::uint8_t>('e'));

    EXPECT_EQ(buffer.get(8), 3u);
    EXPECT_EQ(buffer.get(9), static_cast<std::uint8_t>('c'));
    EXPECT_EQ(buffer.get(10), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(11), static_cast<std::uint8_t>('m'));
    EXPECT_EQ(buffer.get(12), 0u);

    // type A
    EXPECT_EQ(buffer.get(13), 0x00);
    EXPECT_EQ(buffer.get(14), 0x01);

    // class IN
    EXPECT_EQ(buffer.get(15), 0x00);
    EXPECT_EQ(buffer.get(16), 0x01);

    // ttl = 0x11223344
    EXPECT_EQ(buffer.get(17), 0x11);
    EXPECT_EQ(buffer.get(18), 0x22);
    EXPECT_EQ(buffer.get(19), 0x33);
    EXPECT_EQ(buffer.get(20), 0x44);

    // rdlength = 4
    EXPECT_EQ(buffer.get(21), 0x00);
    EXPECT_EQ(buffer.get(22), 0x04);

    // address bytes
    EXPECT_EQ(buffer.get(23), 1u);
    EXPECT_EQ(buffer.get(24), 2u);
    EXPECT_EQ(buffer.get(25), 3u);
    EXPECT_EQ(buffer.get(26), 4u);
}

TEST(DnsRecordWriteTest, WriteThenDecodeARecordRoundTrip)
{
    dns::PacketBuffer buffer{};

    dns::ARecord written{.domain = "google.com", .addr = {8, 8, 4, 4}, .ttl = 300};

    dns::DnsRecord record{written};

    const std::size_t bytes_written = dns::write_record(record, buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_GT(bytes_written, 0u);

    buffer.seek(0);
    ASSERT_TRUE(buffer.ok());

    dns::DnsRecord decoded_record = dns::decode_record(buffer);

    ASSERT_TRUE(buffer.ok());
    ASSERT_TRUE(std::holds_alternative<dns::ARecord>(decoded_record));

    const dns::ARecord& decoded = std::get<dns::ARecord>(decoded_record);

    EXPECT_EQ(decoded.domain, written.domain);
    EXPECT_EQ(decoded.addr, written.addr);
    EXPECT_EQ(decoded.ttl, written.ttl);
}

TEST(DnsRecordWriteTest, WriteUnknownRecordWritesNothing)
{
    dns::PacketBuffer buffer{};

    dns::UnknownRecord unknown{.domain = "example.com", .qtype = 99, .data_len = 10, .ttl = 123};

    dns::DnsRecord record{unknown};

    const std::size_t bytes_written = dns::write_record(record, buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(bytes_written, 0u);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(DnsRecordChapter3Tests, CNameRecordRoundTrips)
{
    const dns::DnsRecord record = dns::CNameRecord{
        .domain = "www.yahoo.com",
        .host = "me-ycpi-cf-www.g06.yahoodns.net",
        .ttl = 37,
    };

    const dns::DnsRecord decoded = round_trip_record(record);

    ASSERT_TRUE(std::holds_alternative<dns::CNameRecord>(decoded));

    const auto& cname = std::get<dns::CNameRecord>(decoded);

    EXPECT_EQ(cname.domain, "www.yahoo.com");
    EXPECT_EQ(cname.host, "me-ycpi-cf-www.g06.yahoodns.net");
    EXPECT_EQ(cname.ttl, 37);
}

TEST(DnsRecordChapter3Tests, NSRecordRoundTrips)
{
    const dns::DnsRecord record = dns::NSRecord{
        .domain = "example.com",
        .host = "a.iana-servers.net",
        .ttl = 300,
    };

    const dns::DnsRecord decoded = round_trip_record(record);

    ASSERT_TRUE(std::holds_alternative<dns::NSRecord>(decoded));

    const auto& ns = std::get<dns::NSRecord>(decoded);

    EXPECT_EQ(ns.domain, "example.com");
    EXPECT_EQ(ns.host, "a.iana-servers.net");
    EXPECT_EQ(ns.ttl, 300);
}

TEST(DnsRecordChapter3Tests, MXRecordRoundTrips)
{
    const dns::DnsRecord record = dns::MXRecord{
        .domain = "example.com",
        .priority = 10,
        .host = "mail.example.com",
        .ttl = 600,
    };

    const dns::DnsRecord decoded = round_trip_record(record);

    ASSERT_TRUE(std::holds_alternative<dns::MXRecord>(decoded));

    const auto& mx = std::get<dns::MXRecord>(decoded);

    EXPECT_EQ(mx.domain, "example.com");
    EXPECT_EQ(mx.priority, 10);
    EXPECT_EQ(mx.host, "mail.example.com");
    EXPECT_EQ(mx.ttl, 600);
}

TEST(DnsRecordChapter3Tests, AAAARecordRoundTrips)
{
    const dns::DnsRecord record = dns::AAAARecord{
        .domain = "example.com",
        .addr =
            std::array<std::uint16_t, 8>{
                0x2606,
                0x2800,
                0x0220,
                0x0001,
                0x0248,
                0x1893,
                0x25c8,
                0x1946,
            },
        .ttl = 120,
    };

    const dns::DnsRecord decoded = round_trip_record(record);

    ASSERT_TRUE(std::holds_alternative<dns::AAAARecord>(decoded));

    const auto& aaaa = std::get<dns::AAAARecord>(decoded);

    EXPECT_EQ(aaaa.domain, "example.com");
    EXPECT_EQ(aaaa.addr[0], 0x2606);
    EXPECT_EQ(aaaa.addr[1], 0x2800);
    EXPECT_EQ(aaaa.addr[2], 0x0220);
    EXPECT_EQ(aaaa.addr[3], 0x0001);
    EXPECT_EQ(aaaa.addr[4], 0x0248);
    EXPECT_EQ(aaaa.addr[5], 0x1893);
    EXPECT_EQ(aaaa.addr[6], 0x25c8);
    EXPECT_EQ(aaaa.addr[7], 0x1946);
    EXPECT_EQ(aaaa.ttl, 120);
}
