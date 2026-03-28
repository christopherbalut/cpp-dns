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
