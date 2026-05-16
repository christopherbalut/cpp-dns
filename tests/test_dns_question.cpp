#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "dns/buffer.hpp"
#include "dns/question.hpp"
#include "dns/types.hpp"

namespace
{
using dns::DnsQuestion;
using dns::PacketBuffer;
using dns::QueryType;

std::size_t write_u16(PacketBuffer& buffer, std::size_t pos, std::uint16_t value)
{
    buffer.set(pos++, static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer.set(pos++, static_cast<std::uint8_t>(value & 0xFF));
    return pos;
}

std::size_t write_pointer(PacketBuffer& buffer, std::size_t pos, std::uint16_t offset)
{
    const auto pointer = static_cast<std::uint16_t>(0xC000U | offset);
    return write_u16(buffer, pos, pointer);
}

std::size_t write_qname(PacketBuffer& buffer, std::size_t pos, std::string_view name)
{
    if (name.empty())
    {
        buffer.set(pos++, 0);
        return pos;
    }

    std::size_t start = 0;

    while (start < name.size())
    {
        const std::size_t dot = name.find('.', start);
        const std::size_t end = (dot == std::string_view::npos) ? name.size() : dot;
        const std::size_t len = end - start;

        buffer.set(pos++, static_cast<std::uint8_t>(len));

        for (std::size_t i = start; i < end; ++i)
        {
            buffer.set(pos++, static_cast<std::uint8_t>(name[i]));
        }

        if (dot == std::string_view::npos)
        {
            break;
        }

        start = dot + 1;
    }

    buffer.set(pos++, 0);
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

std::size_t write_compressed_question(PacketBuffer& buffer, std::size_t pos,
                                      std::uint16_t name_offset, std::uint16_t qtype,
                                      std::uint16_t qclass = 1)
{
    pos = write_pointer(buffer, pos, name_offset);
    pos = write_u16(buffer, pos, qtype);
    pos = write_u16(buffer, pos, qclass);
    return pos;
}

TEST(DnsQuestionWriteTest, WriteMultiLabelQuestionCorrectly)
{
    PacketBuffer buffer{};
    DnsQuestion question{"google.com", QueryType::A};

    question.write(buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.position(), 16u);

    EXPECT_EQ(buffer.get(0), 6u);
    EXPECT_EQ(buffer.get(1), static_cast<std::uint8_t>('g'));
    EXPECT_EQ(buffer.get(2), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(3), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(4), static_cast<std::uint8_t>('g'));
    EXPECT_EQ(buffer.get(5), static_cast<std::uint8_t>('l'));
    EXPECT_EQ(buffer.get(6), static_cast<std::uint8_t>('e'));

    EXPECT_EQ(buffer.get(7), 3u);
    EXPECT_EQ(buffer.get(8), static_cast<std::uint8_t>('c'));
    EXPECT_EQ(buffer.get(9), static_cast<std::uint8_t>('o'));
    EXPECT_EQ(buffer.get(10), static_cast<std::uint8_t>('m'));

    EXPECT_EQ(buffer.get(11), 0u);

    EXPECT_EQ(buffer.get(12), 0x00);
    EXPECT_EQ(buffer.get(13), 0x01);

    EXPECT_EQ(buffer.get(14), 0x00);
    EXPECT_EQ(buffer.get(15), 0x01);
}

TEST(DnsQuestionWriteTest, WriteRootQuestionCorrectly)
{
    PacketBuffer buffer{};
    DnsQuestion question{"", QueryType::A};

    question.write(buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.position(), 5u);

    EXPECT_EQ(buffer.get(0), 0u);
    EXPECT_EQ(buffer.get(1), 0x00);
    EXPECT_EQ(buffer.get(2), 0x01);
    EXPECT_EQ(buffer.get(3), 0x00);
    EXPECT_EQ(buffer.get(4), 0x01);
}

TEST(DnsQuestionWriteTest, WriteThenDecodeRoundTrip)
{
    PacketBuffer buffer{};
    DnsQuestion written{"www.example.com", QueryType::A};

    written.write(buffer);

    ASSERT_TRUE(buffer.ok());

    buffer.seek(0);
    ASSERT_TRUE(buffer.ok());

    DnsQuestion decoded{};
    decoded.decode(buffer);

    ASSERT_TRUE(buffer.ok());
    EXPECT_EQ(decoded.name, written.name);
    EXPECT_EQ(decoded.qtype, written.qtype);
}

} // namespace

TEST(DnsQuestionTest, DefaultConstructorStartsEmptyAndUnknown)
{
    const DnsQuestion question{};

    EXPECT_TRUE(question.name.empty());
    EXPECT_EQ(question.qtype, QueryType::Unknown);
}

TEST(DnsQuestionTest, ValueConstructorStoresProvidedValues)
{
    const DnsQuestion question{"google.com", QueryType::A};

    EXPECT_EQ(question.name, "google.com");
    EXPECT_EQ(question.qtype, QueryType::A);
}

TEST(DnsQuestionTest, DecodeReadsRootDomainQuestion)
{
    PacketBuffer buffer{};
    const std::size_t end = write_question(buffer, 0, "", 1, 1);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsQuestionTest, DecodeReadsUncompressedQuestionAtBufferStart)
{
    PacketBuffer buffer{};
    const std::size_t end = write_question(buffer, 0, "example.com", 1, 1);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "example.com");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsQuestionTest, DecodeLowercasesQNameAndConsumesClassField)
{
    PacketBuffer buffer{};
    const std::size_t end = write_question(buffer, 0, "GoOgLe.CoM", 1, 255);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "google.com");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsQuestionTest, DecodeWorksFromNonZeroOffset)
{
    PacketBuffer buffer{};
    constexpr std::size_t start = 20;
    const std::size_t end = write_question(buffer, start, "www.example.com", 1, 1);

    buffer.seek(start);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "www.example.com");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsQuestionTest, DecodeMapsUnknownNumericTypeToUnknown)
{
    PacketBuffer buffer{};
    const std::size_t end = write_question(buffer, 0, "example.com", 28, 1);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "example.com");
    EXPECT_EQ(question.qtype, QueryType::Unknown);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsQuestionTest, DecodeReadsCompressedQuestionName)
{
    PacketBuffer buffer{};

    constexpr std::size_t name_offset = 12;
    constexpr std::size_t question_offset = 40;

    write_qname(buffer, name_offset, "example.com");
    const std::size_t end = write_compressed_question(buffer, question_offset, name_offset, 1, 1);

    buffer.seek(question_offset);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "example.com");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), end);
}

TEST(DnsQuestionTest, DecodeWithMissingTypeLeavesTypeUnknownAndDoesNotAdvancePastQName)
{
    PacketBuffer buffer{};
    const std::size_t qname_end = write_qname(buffer, 0, "example.com");

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "example.com");
    EXPECT_EQ(question.qtype, QueryType::Unknown);
    EXPECT_EQ(buffer.position(), qname_end);
}

TEST(DnsQuestionTest, DecodeWithMissingClassStillKeepsDecodedType)
{
    PacketBuffer buffer{};
    std::size_t pos = 0;
    pos = write_qname(buffer, pos, "example.com");
    const std::size_t after_type = write_u16(buffer, pos, 1);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "example.com");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), after_type);
}

TEST(DnsQuestionTest, DecodeIgnoresQuestionClassButStillConsumesIt)
{
    PacketBuffer buffer{};
    const std::size_t end = write_question(buffer, 0, "example.com", 1, 42);

    DnsQuestion question{};
    question.decode(buffer);

    EXPECT_EQ(question.name, "example.com");
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(buffer.position(), end);
}
