#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "dns/buffer.hpp"
#include "dns/header.hpp"
#include "dns/types.hpp"

namespace
{

constexpr std::size_t kDnsHeaderSize = 12;

void write_u16_at(dns::PacketBuffer& buffer, std::size_t pos, std::uint16_t value)
{
    buffer.set(pos, static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer.set(pos + 1, static_cast<std::uint8_t>(value & 0xFF));
}

void write_header_at(dns::PacketBuffer& buffer, std::size_t offset, std::uint16_t id,
                     std::uint16_t flags, std::uint16_t questions, std::uint16_t answers,
                     std::uint16_t authoritative_entries, std::uint16_t resource_entries)
{
    write_u16_at(buffer, offset + 0, id);
    write_u16_at(buffer, offset + 2, flags);
    write_u16_at(buffer, offset + 4, questions);
    write_u16_at(buffer, offset + 6, answers);
    write_u16_at(buffer, offset + 8, authoritative_entries);
    write_u16_at(buffer, offset + 10, resource_entries);
}

void expect_flags_decoded_correctly(const dns::DnsHeader& header, std::uint16_t flags)
{
    const auto high = static_cast<std::uint8_t>((flags >> 8) & 0xFF);
    const auto low = static_cast<std::uint8_t>(flags & 0xFF);

    EXPECT_EQ(header.recursion_desired, (high & (1u << 0)) != 0u);
    EXPECT_EQ(header.truncated_message, (high & (1u << 1)) != 0u);
    EXPECT_EQ(header.authoritative_answer, (high & (1u << 2)) != 0u);
    EXPECT_EQ(header.opcode, static_cast<std::uint8_t>((high >> 3) & 0x0F));
    EXPECT_EQ(header.response, (high & (1u << 7)) != 0u);

    EXPECT_EQ(header.rescode, dns::to_result_code(static_cast<std::uint8_t>(low & 0x0F)));
    EXPECT_EQ(header.checking_disabled, (low & (1u << 4)) != 0u);
    EXPECT_EQ(header.authed_data, (low & (1u << 5)) != 0u);
    EXPECT_EQ(header.z, (low & (1u << 6)) != 0u);
    EXPECT_EQ(header.recursion_available, (low & (1u << 7)) != 0u);
}

TEST(DnsHeaderTest, DefaultConstructionMatchesRustNewFunction)
{
    dns::DnsHeader header{};

    EXPECT_EQ(header.id, 0u);

    EXPECT_FALSE(header.recursion_desired);
    EXPECT_FALSE(header.truncated_message);
    EXPECT_FALSE(header.authoritative_answer);
    EXPECT_EQ(header.opcode, 0u);
    EXPECT_FALSE(header.response);

    EXPECT_EQ(header.rescode, dns::ResultCode::noerror);
    EXPECT_FALSE(header.checking_disabled);
    EXPECT_FALSE(header.authed_data);
    EXPECT_FALSE(header.z);
    EXPECT_FALSE(header.recursion_available);

    EXPECT_EQ(header.questions, 0u);
    EXPECT_EQ(header.answers, 0u);
    EXPECT_EQ(header.authoritative_entries, 0u);
    EXPECT_EQ(header.resource_entries, 0u);
}

TEST(DnsHeaderTest, DecodeZeroHeaderProducesAllZeroAndFalseFields)
{
    dns::PacketBuffer buffer;
    write_header_at(buffer, 0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);

    dns::DnsHeader header{};
    header.decode(buffer);

    EXPECT_EQ(header.id, 0u);

    EXPECT_FALSE(header.recursion_desired);
    EXPECT_FALSE(header.truncated_message);
    EXPECT_FALSE(header.authoritative_answer);
    EXPECT_EQ(header.opcode, 0u);
    EXPECT_FALSE(header.response);

    EXPECT_EQ(header.rescode, dns::ResultCode::noerror);
    EXPECT_FALSE(header.checking_disabled);
    EXPECT_FALSE(header.authed_data);
    EXPECT_FALSE(header.z);
    EXPECT_FALSE(header.recursion_available);

    EXPECT_EQ(header.questions, 0u);
    EXPECT_EQ(header.answers, 0u);
    EXPECT_EQ(header.authoritative_entries, 0u);
    EXPECT_EQ(header.resource_entries, 0u);

    EXPECT_EQ(buffer.position(), kDnsHeaderSize);
}

TEST(DnsHeaderTest, DecodeReadsIdAndCountFieldsInNetworkByteOrder)
{
    dns::PacketBuffer buffer;

    constexpr std::uint16_t id = 0xABCD;
    constexpr std::uint16_t flags = 0x0000;
    constexpr std::uint16_t questions = 0x0102;
    constexpr std::uint16_t answers = 0x0304;
    constexpr std::uint16_t authoritative_entries = 0x0506;
    constexpr std::uint16_t resource_entries = 0x0708;

    write_header_at(buffer, 0, id, flags, questions, answers, authoritative_entries,
                    resource_entries);

    dns::DnsHeader header{};
    header.decode(buffer);

    EXPECT_EQ(header.id, id);
    EXPECT_EQ(header.questions, questions);
    EXPECT_EQ(header.answers, answers);
    EXPECT_EQ(header.authoritative_entries, authoritative_entries);
    EXPECT_EQ(header.resource_entries, resource_entries);
    EXPECT_EQ(buffer.position(), kDnsHeaderSize);
}

TEST(DnsHeaderTest, DecodeWorksFromNonZeroBufferOffset)
{
    dns::PacketBuffer buffer;

    constexpr std::size_t offset = 19;
    constexpr std::uint16_t id = 0xBEEF;
    constexpr std::uint16_t flags = 0x85B0;
    constexpr std::uint16_t questions = 0x0001;
    constexpr std::uint16_t answers = 0x0002;
    constexpr std::uint16_t authoritative_entries = 0x0003;
    constexpr std::uint16_t resource_entries = 0x0004;

    write_header_at(buffer, offset, id, flags, questions, answers, authoritative_entries,
                    resource_entries);

    buffer.seek(offset);

    dns::DnsHeader header{};
    header.decode(buffer);

    EXPECT_EQ(header.id, id);
    expect_flags_decoded_correctly(header, flags);
    EXPECT_EQ(header.questions, questions);
    EXPECT_EQ(header.answers, answers);
    EXPECT_EQ(header.authoritative_entries, authoritative_entries);
    EXPECT_EQ(header.resource_entries, resource_entries);

    EXPECT_EQ(buffer.position(), offset + kDnsHeaderSize);
}

TEST(DnsHeaderTest, DecodeFullyPopulatedRepresentativeHeader)
{
    dns::PacketBuffer buffer;

    constexpr std::uint16_t id = 0x1234;

    // High byte:
    // bit0 RD = 1
    // bit1 TC = 1
    // bit2 AA = 1
    // opcode = 10
    // bit7 QR = 1
    //
    // Low byte:
    // rcode = 5 (refused)
    // CD = 1
    // AD = 1
    // Z  = 1
    // RA = 1
    constexpr std::uint16_t flags = 0xD7F5;

    constexpr std::uint16_t questions = 7;
    constexpr std::uint16_t answers = 11;
    constexpr std::uint16_t authoritative_entries = 13;
    constexpr std::uint16_t resource_entries = 17;

    write_header_at(buffer, 0, id, flags, questions, answers, authoritative_entries,
                    resource_entries);

    dns::DnsHeader header{};
    header.decode(buffer);

    EXPECT_EQ(header.id, id);

    EXPECT_TRUE(header.recursion_desired);
    EXPECT_TRUE(header.truncated_message);
    EXPECT_TRUE(header.authoritative_answer);
    EXPECT_EQ(header.opcode, 10u);
    EXPECT_TRUE(header.response);

    EXPECT_EQ(header.rescode, dns::ResultCode::refused);
    EXPECT_TRUE(header.checking_disabled);
    EXPECT_TRUE(header.authed_data);
    EXPECT_TRUE(header.z);
    EXPECT_TRUE(header.recursion_available);

    EXPECT_EQ(header.questions, questions);
    EXPECT_EQ(header.answers, answers);
    EXPECT_EQ(header.authoritative_entries, authoritative_entries);
    EXPECT_EQ(header.resource_entries, resource_entries);

    EXPECT_EQ(buffer.position(), kDnsHeaderSize);
}

TEST(DnsHeaderTest, DecodeExhaustivelyChecksAll65536PossibleFlagWords)
{
    constexpr std::uint16_t id = 0xCAFE;
    constexpr std::uint16_t questions = 0x1111;
    constexpr std::uint16_t answers = 0x2222;
    constexpr std::uint16_t authoritative_entries = 0x3333;
    constexpr std::uint16_t resource_entries = 0x4444;

    for (std::uint32_t raw_flags = 0; raw_flags <= 0xFFFFu; ++raw_flags)
    {
        SCOPED_TRACE(::testing::Message() << "flags=0x" << std::hex << raw_flags);

        dns::PacketBuffer buffer;
        write_header_at(buffer, 0, id, static_cast<std::uint16_t>(raw_flags), questions, answers,
                        authoritative_entries, resource_entries);

        dns::DnsHeader header{};
        header.decode(buffer);

        EXPECT_EQ(header.id, id);
        expect_flags_decoded_correctly(header, static_cast<std::uint16_t>(raw_flags));
        EXPECT_EQ(header.questions, questions);
        EXPECT_EQ(header.answers, answers);
        EXPECT_EQ(header.authoritative_entries, authoritative_entries);
        EXPECT_EQ(header.resource_entries, resource_entries);
        EXPECT_EQ(buffer.position(), kDnsHeaderSize);
    }
}

} // namespace
