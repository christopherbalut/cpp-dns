#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <variant>

#include "dns/packet.hpp"
#include "dns/types.hpp"

namespace
{
using dns::ARecord;
using dns::DnsPacket;
using dns::DnsQuestion;
using dns::DnsRecord;
using dns::PacketBuffer;
using dns::QueryType;
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

std::size_t write_header(PacketBuffer& buffer, std::size_t pos, std::uint16_t id,
                         std::uint16_t flags, std::uint16_t qdcount, std::uint16_t ancount,
                         std::uint16_t nscount, std::uint16_t arcount)
{
    pos = write_u16(buffer, pos, id);
    pos = write_u16(buffer, pos, flags);
    pos = write_u16(buffer, pos, qdcount);
    pos = write_u16(buffer, pos, ancount);
    pos = write_u16(buffer, pos, nscount);
    pos = write_u16(buffer, pos, arcount);
    return pos;
}

std::size_t write_question(PacketBuffer& buffer, std::size_t pos, std::string_view name,
                           std::uint16_t qtype, std::uint16_t qclass = 1)
{
    pos = write_qname(buffer, pos, name);
    pos = write_u16(buffer, pos, qtype);
    pos = write_u16(buffer, pos, qclass);
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

TEST(DnsPacketTest, DecodeEmptyPacketParsesHeaderAndLeavesAllSectionsEmpty)
{
    PacketBuffer buffer{};
    const std::size_t end = write_header(buffer, 0, 0x1234, 0x8180, 0, 0, 0, 0);

    DnsPacket packet{};
    packet.decode_from_buffer(buffer);

    EXPECT_EQ(packet.header.id, 0x1234);
    EXPECT_TRUE(packet.header.response);
    EXPECT_TRUE(packet.header.recursion_desired);
    EXPECT_TRUE(packet.header.recursion_available);
    EXPECT_EQ(packet.header.questions, 0);
    EXPECT_EQ(packet.header.answers, 0);
    EXPECT_EQ(packet.header.authoritative_entries, 0);
    EXPECT_EQ(packet.header.resource_entries, 0);

    EXPECT_TRUE(packet.questions.empty());
    EXPECT_TRUE(packet.answers.empty());
    EXPECT_TRUE(packet.authorities.empty());
    EXPECT_TRUE(packet.resources.empty());

    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsPacketTest, DecodeSingleRootQuestion)
{
    PacketBuffer buffer{};
    std::size_t pos = 0;
    pos = write_header(buffer, pos, 0xBEEF, 0x0100, 1, 0, 0, 0);
    const std::size_t end = write_question(buffer, pos, "", 1, 1);

    DnsPacket packet{};
    packet.decode_from_buffer(buffer);

    ASSERT_EQ(packet.questions.size(), 1U);
    EXPECT_TRUE(packet.answers.empty());
    EXPECT_TRUE(packet.authorities.empty());
    EXPECT_TRUE(packet.resources.empty());

    EXPECT_EQ(packet.header.id, 0xBEEF);
    EXPECT_FALSE(packet.header.response);
    EXPECT_TRUE(packet.header.recursion_desired);
    EXPECT_EQ(packet.header.questions, 1);

    EXPECT_EQ(packet.questions[0].name, "");
    EXPECT_EQ(packet.questions[0].qtype, QueryType::A);

    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsPacketTest, DecodeAllSectionsPreservesCountsOrderAndContents)
{
    PacketBuffer buffer{};
    std::size_t pos = 0;

    pos = write_header(buffer, pos, 0xCAFE, 0x8180, 2, 2, 1, 1);

    pos = write_question(buffer, pos, "", 1, 1);
    pos = write_question(buffer, pos, "", 28, 1);

    pos = write_a_record(buffer, pos, "", 60U, {1, 2, 3, 4});
    pos = write_unknown_record(buffer, pos, "", 65000U, 77U, {0xAA, 0xBB});

    pos = write_unknown_record(buffer, pos, "", 99U, 3U, {});

    const std::size_t end = write_a_record(buffer, pos, "", 120U, {8, 8, 8, 8});

    DnsPacket packet{};
    packet.decode_from_buffer(buffer);

    EXPECT_EQ(packet.header.id, 0xCAFE);
    EXPECT_EQ(packet.header.questions, 2);
    EXPECT_EQ(packet.header.answers, 2);
    EXPECT_EQ(packet.header.authoritative_entries, 1);
    EXPECT_EQ(packet.header.resource_entries, 1);

    ASSERT_EQ(packet.questions.size(), 2U);
    EXPECT_EQ(packet.questions[0].name, "");
    EXPECT_EQ(packet.questions[0].qtype, QueryType::A);
    EXPECT_EQ(packet.questions[1].name, "");
    EXPECT_EQ(packet.questions[1].qtype, QueryType::Unknown);

    ASSERT_EQ(packet.answers.size(), 2U);
    ASSERT_TRUE(std::holds_alternative<ARecord>(packet.answers[0]));
    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(packet.answers[1]));

    const auto& answer_a = std::get<ARecord>(packet.answers[0]);
    EXPECT_EQ(answer_a.domain, "");
    EXPECT_EQ(answer_a.addr, (std::array<std::uint8_t, 4>{1, 2, 3, 4}));
    EXPECT_EQ(answer_a.ttl, 60U);

    const auto& answer_unknown = std::get<UnknownRecord>(packet.answers[1]);
    EXPECT_EQ(answer_unknown.domain, "");
    EXPECT_EQ(answer_unknown.qtype, 65000U);
    EXPECT_EQ(answer_unknown.data_len, 2U);
    EXPECT_EQ(answer_unknown.ttl, 77U);

    ASSERT_EQ(packet.authorities.size(), 1U);
    ASSERT_TRUE(std::holds_alternative<UnknownRecord>(packet.authorities[0]));
    const auto& authority = std::get<UnknownRecord>(packet.authorities[0]);
    EXPECT_EQ(authority.domain, "");
    EXPECT_EQ(authority.qtype, 99U);
    EXPECT_EQ(authority.data_len, 0U);
    EXPECT_EQ(authority.ttl, 3U);

    ASSERT_EQ(packet.resources.size(), 1U);
    ASSERT_TRUE(std::holds_alternative<ARecord>(packet.resources[0]));
    const auto& resource = std::get<ARecord>(packet.resources[0]);
    EXPECT_EQ(resource.domain, "");
    EXPECT_EQ(resource.addr, (std::array<std::uint8_t, 4>{8, 8, 8, 8}));
    EXPECT_EQ(resource.ttl, 120U);

    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsPacketTest, DecodeClearsPreviousStateBeforeReadingNewPacket)
{
    DnsPacket packet{};
    packet.header.id = 9999;
    packet.questions.emplace_back("stale", QueryType::A);
    packet.answers.emplace_back(ARecord{.domain = "stale", .addr = {1, 1, 1, 1}, .ttl = 1});
    packet.authorities.emplace_back(
        UnknownRecord{.domain = "stale", .qtype = 15, .data_len = 2, .ttl = 10});
    packet.resources.push_back(ARecord{.domain = "stale", .addr = {9, 9, 9, 9}, .ttl = 9});

    PacketBuffer buffer{};
    const std::size_t end = write_header(buffer, 0, 0x2222, 0x8180, 0, 0, 0, 0);

    packet.decode_from_buffer(buffer);

    EXPECT_EQ(packet.header.id, 0x2222);
    EXPECT_TRUE(packet.questions.empty());
    EXPECT_TRUE(packet.answers.empty());
    EXPECT_TRUE(packet.authorities.empty());
    EXPECT_TRUE(packet.resources.empty());
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsPacketTest, DecodeWorksFromNonZeroBufferOffset)
{
    PacketBuffer buffer{};
    constexpr std::size_t start = 100;

    std::size_t pos = start;
    pos = write_header(buffer, pos, 0x0A0B, 0x8180, 1, 1, 0, 0);
    pos = write_question(buffer, pos, "", 1, 1);
    const std::size_t end = write_a_record(buffer, pos, "", 444U, {4, 3, 2, 1});

    buffer.seek(start);

    DnsPacket packet{};
    packet.decode_from_buffer(buffer);

    EXPECT_EQ(packet.header.id, 0x0A0B);
    ASSERT_EQ(packet.questions.size(), 1U);
    ASSERT_EQ(packet.answers.size(), 1U);

    EXPECT_EQ(packet.questions[0].name, "");
    EXPECT_EQ(packet.questions[0].qtype, QueryType::A);

    ASSERT_TRUE(std::holds_alternative<ARecord>(packet.answers[0]));
    const auto& answer = std::get<ARecord>(packet.answers[0]);
    EXPECT_EQ(answer.domain, "");
    EXPECT_EQ(answer.addr, (std::array<std::uint8_t, 4>{4, 3, 2, 1}));
    EXPECT_EQ(answer.ttl, 444U);

    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsPacketTest, TruncatedHeaderStillResetsPacketAndDoesNotLeaveStaleSections)
{
    DnsPacket packet{};
    packet.questions.emplace_back("old", QueryType::A);
    packet.answers.emplace_back(ARecord{.domain = "old", .addr = {1, 1, 1, 1}, .ttl = 1});

    PacketBuffer buffer{};
    std::size_t pos = 0;
    pos = write_u16(buffer, pos, 0xABCD);
    pos = write_u16(buffer, pos, 0x8180);

    packet.decode_from_buffer(buffer);

    EXPECT_EQ(packet.header.id, 0xABCD);
    EXPECT_TRUE(packet.questions.empty());
    EXPECT_TRUE(packet.answers.empty());
    EXPECT_TRUE(packet.authorities.empty());
    EXPECT_TRUE(packet.resources.empty());

    EXPECT_EQ(packet.header.questions, 0);
    EXPECT_EQ(packet.header.answers, 0);
    EXPECT_EQ(packet.header.authoritative_entries, 0);
    EXPECT_EQ(packet.header.resource_entries, 0);

    EXPECT_EQ(buffer.position(), pos);
}

TEST(DnsPacketTest, DecodeQuestionAndCompressedAnswerName)
{
    PacketBuffer buffer{};
    std::size_t pos = 0;

    pos = write_header(buffer, pos, 0x3333, 0x8180, 1, 1, 0, 0);

    constexpr std::size_t question_name_offset = 12;
    pos = write_question(buffer, pos, "example.com", 1, 1);
    const std::size_t end =
        write_compressed_a_record(buffer, pos, question_name_offset, 99U, {7, 7, 7, 7});

    DnsPacket packet{};
    packet.decode_from_buffer(buffer);

    ASSERT_EQ(packet.questions.size(), 1U);
    ASSERT_EQ(packet.answers.size(), 1U);

    EXPECT_EQ(packet.questions[0].name, "example.com");
    EXPECT_EQ(packet.questions[0].qtype, QueryType::A);

    ASSERT_TRUE(std::holds_alternative<ARecord>(packet.answers[0]));
    const auto& answer = std::get<ARecord>(packet.answers[0]);
    EXPECT_EQ(answer.domain, "example.com");
    EXPECT_EQ(answer.addr, (std::array<std::uint8_t, 4>{7, 7, 7, 7}));
    EXPECT_EQ(answer.ttl, 99U);

    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsPacketWriteTest, WriteQueryPacketCorrectly)
{
    dns::DnsPacket packet{};
    dns::PacketBuffer buffer{};

    packet.header.id = 0x1234;
    packet.header.recursion_desired = true;
    packet.questions.emplace_back("google.com", dns::QueryType::A);

    packet.write_to_buffer(buffer); // use packet.write(buffer) if that is your name

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.position(), 28u);

    // Header
    EXPECT_EQ(buffer.get(0), 0x12);
    EXPECT_EQ(buffer.get(1), 0x34);

    // top flags byte: RD = 1
    EXPECT_EQ(buffer.get(2), 0x01);
    EXPECT_EQ(buffer.get(3), 0x00);

    EXPECT_EQ(buffer.get(4), 0x00); // questions = 1
    EXPECT_EQ(buffer.get(5), 0x01);

    EXPECT_EQ(buffer.get(6), 0x00); // answers = 0
    EXPECT_EQ(buffer.get(7), 0x00);

    EXPECT_EQ(buffer.get(8), 0x00); // authorities = 0
    EXPECT_EQ(buffer.get(9), 0x00);

    EXPECT_EQ(buffer.get(10), 0x00); // resources = 0
    EXPECT_EQ(buffer.get(11), 0x00);

    // Question: google.com, type A, class IN
    EXPECT_EQ(buffer.get(12), 6u);
    EXPECT_EQ(buffer.get(13), static_cast<std::uint8_t>('g'));
    EXPECT_EQ(buffer.get(14), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(15), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(16), static_cast<std::uint8_t>('g'));
    EXPECT_EQ(buffer.get(17), static_cast<std::uint8_t>('l'));
    EXPECT_EQ(buffer.get(18), static_cast<std::uint8_t>('e'));

    EXPECT_EQ(buffer.get(19), 3u);
    EXPECT_EQ(buffer.get(20), static_cast<std::uint8_t>('c'));
    EXPECT_EQ(buffer.get(21), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(22), static_cast<std::uint8_t>('m'));
    EXPECT_EQ(buffer.get(23), 0u);

    EXPECT_EQ(buffer.get(24), 0x00); // qtype A
    EXPECT_EQ(buffer.get(25), 0x01);
    EXPECT_EQ(buffer.get(26), 0x00); // qclass IN
    EXPECT_EQ(buffer.get(27), 0x01);
}

TEST(DnsPacketWriteTest, WriteThenDecodeRepresentativePacketRoundTrip)
{
    dns::DnsPacket written{};
    dns::PacketBuffer buffer{};

    written.header.id = 0xBEEF;
    written.header.recursion_desired = true;

    written.questions.emplace_back("example.com", dns::QueryType::A);

    written.answers.emplace_back(
        dns::ARecord{.domain = "example.com", .addr = {1, 2, 3, 4}, .ttl = 300});

    written.authorities.emplace_back(
        dns::ARecord{.domain = "ns.example.com", .addr = {5, 6, 7, 8}, .ttl = 400});

    written.resources.emplace_back(
        dns::ARecord{.domain = "cache.example.com", .addr = {9, 10, 11, 12}, .ttl = 500});

    written.write_to_buffer(buffer); // use packet.write(buffer) if that is your name

    ASSERT_TRUE(buffer.ok());

    buffer.seek(0);
    ASSERT_TRUE(buffer.ok());

    dns::DnsPacket decoded{};
    decoded.decode_from_buffer(buffer);

    ASSERT_TRUE(buffer.ok());

    EXPECT_EQ(decoded.header.id, written.header.id);
    EXPECT_TRUE(decoded.header.recursion_desired);

    EXPECT_EQ(decoded.questions.size(), 1u);
    EXPECT_EQ(decoded.answers.size(), 1u);
    EXPECT_EQ(decoded.authorities.size(), 1u);
    EXPECT_EQ(decoded.resources.size(), 1u);

    EXPECT_EQ(decoded.questions[0].name, "example.com");
    EXPECT_EQ(decoded.questions[0].qtype, dns::QueryType::A);

    ASSERT_TRUE(std::holds_alternative<dns::ARecord>(decoded.answers[0]));
    ASSERT_TRUE(std::holds_alternative<dns::ARecord>(decoded.authorities[0]));
    ASSERT_TRUE(std::holds_alternative<dns::ARecord>(decoded.resources[0]));

    const dns::ARecord& answer = std::get<dns::ARecord>(decoded.answers[0]);
    const dns::ARecord& authority = std::get<dns::ARecord>(decoded.authorities[0]);
    const dns::ARecord& resource = std::get<dns::ARecord>(decoded.resources[0]);

    EXPECT_EQ(answer.domain, "example.com");
    EXPECT_EQ(answer.addr, (std::array<std::uint8_t, 4>{1, 2, 3, 4}));
    EXPECT_EQ(answer.ttl, 300u);

    EXPECT_EQ(authority.domain, "ns.example.com");
    EXPECT_EQ(authority.addr, (std::array<std::uint8_t, 4>{5, 6, 7, 8}));
    EXPECT_EQ(authority.ttl, 400u);

    EXPECT_EQ(resource.domain, "cache.example.com");
    EXPECT_EQ(resource.addr, (std::array<std::uint8_t, 4>{9, 10, 11, 12}));
    EXPECT_EQ(resource.ttl, 500u);
}

TEST(DnsPacketWriteTest, WriteSkipsUnknownRecordsWhenSettingCounts)
{
    dns::DnsPacket packet{};
    dns::PacketBuffer buffer{};

    packet.answers.emplace_back(dns::UnknownRecord{
        .domain = "ignored.example.com", .qtype = 99, .data_len = 10, .ttl = 111});

    packet.answers.emplace_back(
        dns::ARecord{.domain = "kept.example.com", .addr = {8, 8, 8, 8}, .ttl = 222});

    packet.write_to_buffer(buffer); // use packet.write(buffer) if that is your name

    ASSERT_TRUE(buffer.ok());

    // ancount should be 1, not 2
    EXPECT_EQ(buffer.get(6), 0x00);
    EXPECT_EQ(buffer.get(7), 0x01);

    buffer.seek(0);
    ASSERT_TRUE(buffer.ok());

    dns::DnsPacket decoded{};
    decoded.decode_from_buffer(buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(decoded.answers.size(), 1u);
    ASSERT_TRUE(std::holds_alternative<dns::ARecord>(decoded.answers[0]));

    const dns::ARecord& answer = std::get<dns::ARecord>(decoded.answers[0]);
    EXPECT_EQ(answer.domain, "kept.example.com");
    EXPECT_EQ(answer.addr, (std::array<std::uint8_t, 4>{8, 8, 8, 8}));
    EXPECT_EQ(answer.ttl, 222u);
}

TEST(DnsPacketTest, DecodeGoogleAResponseFromRawBytes)
{
    const std::array<std::uint8_t, 44> raw_response{
        0x1a, 0x0a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f,
        0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0x8e, 0xfa, 0x45, 0x2e};

    dns::PacketBuffer buffer{};
    std::copy(raw_response.begin(), raw_response.end(), buffer.data());

    buffer.set_size(raw_response.size());
    buffer.seek(0);

    dns::DnsPacket packet{};
    packet.decode_from_buffer(buffer);

    ASSERT_TRUE(buffer.ok());

    EXPECT_EQ(packet.header.id, 6666);
    EXPECT_TRUE(packet.header.response);
    EXPECT_TRUE(packet.header.recursion_desired);
    EXPECT_TRUE(packet.header.recursion_available);
    EXPECT_EQ(packet.header.questions, 1);
    EXPECT_EQ(packet.header.answers, 1);
    EXPECT_EQ(packet.header.authoritative_entries, 0);
    EXPECT_EQ(packet.header.resource_entries, 0);

    ASSERT_EQ(packet.questions.size(), 1);
    EXPECT_EQ(packet.questions[0].name, "google.com");
    EXPECT_EQ(packet.questions[0].qtype, dns::QueryType::A);

    ASSERT_EQ(packet.answers.size(), 1);
    ASSERT_TRUE(std::holds_alternative<dns::ARecord>(packet.answers[0]));

    const auto& answer = std::get<dns::ARecord>(packet.answers[0]);

    EXPECT_EQ(answer.domain, "google.com");
    EXPECT_EQ(answer.ttl, 138);
    EXPECT_EQ(answer.addr[0], 142);
    EXPECT_EQ(answer.addr[1], 250);
    EXPECT_EQ(answer.addr[2], 69);
    EXPECT_EQ(answer.addr[3], 46);
}
