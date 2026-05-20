#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include "dns/buffer.hpp"

using dns::BufferError;
using dns::PacketBuffer;

namespace
{

TEST(PacketBufferTest, StartsAtPositionZero)
{
    dns::PacketBuffer buffer;
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, StepByZeroKeepsPositionUnchangedOnEmptyBuffer)
{
    dns::PacketBuffer buffer;
    buffer.step(0);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, StepPastValidDataDoesNotAdvancePosition)
{
    dns::PacketBuffer buffer;
    buffer.step(5);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, StepWithinValidDataAdvancesPosition)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x11);
    buffer.set(1, 0x22);
    buffer.set(2, 0x33);
    buffer.set(3, 0x44);
    buffer.set(4, 0x55);

    buffer.step(3);

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, StepCanAdvanceExactlyToEndOfValidData)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xAA);
    buffer.set(1, 0xBB);
    buffer.set(2, 0xCC);

    buffer.step(3);

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, StepPastEndAfterMovingDoesNotAdvanceFurther)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xAA);
    buffer.set(1, 0xBB);
    buffer.set(2, 0xCC);

    buffer.step(2);
    buffer.step(2);

    EXPECT_EQ(buffer.position(), 2u);
}

TEST(PacketBufferTest, SeekToZeroWorksOnFreshBuffer)
{
    dns::PacketBuffer buffer;
    buffer.seek(0);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, SeekPastValidDataOnFreshBufferDoesNotMove)
{
    dns::PacketBuffer buffer;
    buffer.seek(12);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, SeekMovesToExactValidPosition)
{
    dns::PacketBuffer buffer;
    buffer.set(12, 0xAB);

    buffer.seek(12);

    EXPECT_EQ(buffer.position(), 12u);
}

TEST(PacketBufferTest, SeekCanMoveBackwardWithinValidData)
{
    dns::PacketBuffer buffer;
    buffer.set(20, 0xEF);

    buffer.seek(20);
    buffer.seek(3);

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, SeekToLastValidByteWorksWhenThatByteExists)
{
    dns::PacketBuffer buffer;
    buffer.set(dns::PacketBuffer::max_size - 1, 0x7F);

    buffer.seek(dns::PacketBuffer::max_size - 1);

    EXPECT_EQ(buffer.position(), dns::PacketBuffer::max_size - 1);
}

TEST(PacketBufferTest, SeekToEndOfValidDataWorks)
{
    dns::PacketBuffer buffer;
    buffer.set(4, 0x99);

    buffer.seek(5);

    EXPECT_EQ(buffer.position(), 5u);
}

TEST(PacketBufferTest, SeekPastEndOfValidDataDoesNotMove)
{
    dns::PacketBuffer buffer;
    buffer.set(4, 0x99);

    buffer.seek(6);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, GetAtBeginningReturnsZeroForFreshBuffer)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.get(0), 0u);
}

TEST(PacketBufferTest, GetAtUnwrittenIndexReturnsZero)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x12);
    buffer.set(1, 0x34);

    EXPECT_EQ(buffer.get(10), 0u);
}

TEST(PacketBufferTest, GetAtWrittenIndexReturnsStoredByte)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x12);
    buffer.set(1, 0x34);
    buffer.set(2, 0x56);

    EXPECT_EQ(buffer.get(0), 0x12u);
    EXPECT_EQ(buffer.get(1), 0x34u);
    EXPECT_EQ(buffer.get(2), 0x56u);
}

TEST(PacketBufferTest, GetDoesNotChangeCursorPosition)
{
    dns::PacketBuffer buffer;
    buffer.set(10, 0xAB);
    buffer.seek(10);

    const auto before = buffer.position();
    (void)buffer.get(3);

    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, ReadSingleByteFromFreshBufferReturnsZeroAndDoesNotAdvance)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_single_byte(), 0u);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, ReadSingleByteReturnsStoredValueAndAdvances)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xAB);

    EXPECT_EQ(buffer.read_single_byte(), 0xABu);
    EXPECT_EQ(buffer.position(), 1u);
}

TEST(PacketBufferTest, RepeatedSingleByteReadsAdvanceSequentiallyOverValidData)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x10);
    buffer.set(1, 0x20);
    buffer.set(2, 0x30);

    EXPECT_EQ(buffer.read_single_byte(), 0x10u);
    EXPECT_EQ(buffer.read_single_byte(), 0x20u);
    EXPECT_EQ(buffer.read_single_byte(), 0x30u);
    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, ReadSingleByteAtLastValidByteAdvancesToEnd)
{
    dns::PacketBuffer buffer;
    buffer.set(4, 0xEE);
    buffer.seek(4);

    const std::uint8_t value = buffer.read_single_byte();

    EXPECT_EQ(value, 0xEEu);
    EXPECT_EQ(buffer.position(), 5u);
}

TEST(PacketBufferTest, ReadSingleByteAtEndReturnsZeroAndDoesNotAdvanceFurther)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xAB);

    EXPECT_EQ(buffer.read_single_byte(), 0xABu);
    EXPECT_EQ(buffer.position(), 1u);

    EXPECT_EQ(buffer.read_single_byte(), 0u);
    EXPECT_EQ(buffer.position(), 1u);
}

TEST(PacketBufferTest, GetRangeFromFreshBufferIsEmpty)
{
    dns::PacketBuffer buffer;
    const auto bytes = buffer.get_range(0, 4);

    EXPECT_TRUE(bytes.empty());
}

TEST(PacketBufferTest, GetRangeFromBeginningReturnsRequestedLengthWhenDataExists)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x11);
    buffer.set(1, 0x22);
    buffer.set(2, 0x33);
    buffer.set(3, 0x44);

    const auto bytes = buffer.get_range(0, 4);

    ASSERT_EQ(bytes.size(), 4u);
    EXPECT_EQ(bytes[0], 0x11u);
    EXPECT_EQ(bytes[1], 0x22u);
    EXPECT_EQ(bytes[2], 0x33u);
    EXPECT_EQ(bytes[3], 0x44u);
}

TEST(PacketBufferTest, GetRangeDoesNotChangeCursorPosition)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x11);
    buffer.set(1, 0x22);
    buffer.set(2, 0x33);
    buffer.set(25, 0x44);
    buffer.seek(25);

    const auto before = buffer.position();
    const auto bytes = buffer.get_range(0, 3);

    ASSERT_EQ(bytes.size(), 3u);
    EXPECT_EQ(bytes[0], 0x11u);
    EXPECT_EQ(bytes[1], 0x22u);
    EXPECT_EQ(bytes[2], 0x33u);
    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, GetRangeCanReadSingleByteAtLastValidIndex)
{
    dns::PacketBuffer buffer;
    buffer.set(dns::PacketBuffer::max_size - 1, 0xCD);

    const auto bytes = buffer.get_range(dns::PacketBuffer::max_size - 1, 1);

    ASSERT_EQ(bytes.size(), 1u);
    EXPECT_EQ(bytes[0], 0xCDu);
}

TEST(PacketBufferTest, GetRangeBeyondValidDataIsEmpty)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x11);
    buffer.set(1, 0x22);

    const auto bytes = buffer.get_range(0, 3);

    EXPECT_TRUE(bytes.empty());
}

TEST(PacketBufferTest, GetRangeStartingPastValidDataIsEmpty)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x11);

    const auto bytes = buffer.get_range(5, 1);

    EXPECT_TRUE(bytes.empty());
}

TEST(PacketBufferTest, ReadU16FromFreshBufferReturnsZeroAndDoesNotAdvance)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_u16(), 0u);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, ReadU16WithOnlyOneAvailableByteReturnsZeroAndDoesNotAdvance)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x12);

    EXPECT_EQ(buffer.read_u16(), 0u);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, ReadU16AdvancesPositionByTwo)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x12);
    buffer.set(1, 0x34);

    EXPECT_EQ(buffer.read_u16(), 0x1234u);
    EXPECT_EQ(buffer.position(), 2u);
}

TEST(PacketBufferTest, ReadU16UsesNetworkByteOrder)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xAB);
    buffer.set(1, 0xCD);

    EXPECT_EQ(buffer.read_u16(), 0xABCDu);
}

TEST(PacketBufferTest, ReadU32FromFreshBufferReturnsZeroAndDoesNotAdvance)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_u32(), 0u);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, ReadU32WithPartialDataReturnsZeroAndDoesNotAdvance)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x12);
    buffer.set(1, 0x34);
    buffer.set(2, 0x56);

    EXPECT_EQ(buffer.read_u32(), 0u);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, ReadU32AdvancesPositionByFour)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0x12);
    buffer.set(1, 0x34);
    buffer.set(2, 0x56);
    buffer.set(3, 0x78);

    EXPECT_EQ(buffer.read_u32(), 0x12345678u);
    EXPECT_EQ(buffer.position(), 4u);
}

TEST(PacketBufferTest, ReadU32UsesNetworkByteOrder)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xDE);
    buffer.set(1, 0xAD);
    buffer.set(2, 0xBE);
    buffer.set(3, 0xEF);

    EXPECT_EQ(buffer.read_u32(), 0xDEADBEEFu);
}

TEST(PacketBufferTest, MixedReadsAdvanceByTotalBytesConsumed)
{
    dns::PacketBuffer buffer;
    buffer.set(0, 0xAA);
    buffer.set(1, 0x01);
    buffer.set(2, 0x02);
    buffer.set(3, 0x10);
    buffer.set(4, 0x20);
    buffer.set(5, 0x30);
    buffer.set(6, 0x40);

    EXPECT_EQ(buffer.read_single_byte(), 0xAAu);
    EXPECT_EQ(buffer.read_u16(), 0x0102u);
    EXPECT_EQ(buffer.read_u32(), 0x10203040u);

    EXPECT_EQ(buffer.position(), 7u);
}

TEST(PacketBufferTest, SetCanCreateSparseValidPrefix)
{
    dns::PacketBuffer buffer;
    buffer.set(4, 0x99);

    EXPECT_EQ(buffer.get(0), 0u);
    EXPECT_EQ(buffer.get(1), 0u);
    EXPECT_EQ(buffer.get(2), 0u);
    EXPECT_EQ(buffer.get(3), 0u);
    EXPECT_EQ(buffer.get(4), 0x99u);

    buffer.seek(4);
    EXPECT_EQ(buffer.read_single_byte(), 0x99u);
    EXPECT_EQ(buffer.position(), 5u);
}

constexpr std::size_t packet_buffer_capacity = 512;

std::uint8_t u8(char ch)
{
    return static_cast<std::uint8_t>(static_cast<unsigned char>(ch));
}

void fill_buffer(PacketBuffer& buffer, std::size_t count, std::uint8_t value = 0xEE)
{
    for (std::size_t i = 0; i < count; ++i)
    {
        buffer.write(value);
        ASSERT_EQ(buffer.last_error(), BufferError::none);
    }
}

void expect_bytes_at(PacketBuffer& buffer, std::size_t offset,
                     std::initializer_list<std::uint8_t> expected)
{
    std::size_t i = 0;
    for (std::uint8_t byte : expected)
    {
        EXPECT_EQ(buffer.get(offset + i), byte) << "Mismatch at byte " << (offset + i);
        ++i;
    }
}

std::string repeated_label_domain(std::size_t label_count)
{
    std::string out;
    for (std::size_t i = 0; i < label_count; ++i)
    {
        if (i > 0)
        {
            out.push_back('.');
        }
        out.push_back('a');
    }
    return out;
}

} // namespace

TEST(PacketBufferWriteTests, WriteStoresByteAndAdvancesPosition)
{
    PacketBuffer buffer{};

    buffer.write(0xAB);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 1u);
    EXPECT_EQ(buffer.get(0), 0xAB);
}

TEST(PacketBufferWriteTests, WriteFailsAtEndOfBuffer)
{
    PacketBuffer buffer{};
    fill_buffer(buffer, packet_buffer_capacity);

    const std::size_t before = buffer.position();

    buffer.write(0xCD);

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::end_of_buffer);
    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferWriteTests, WriteU8MatchesWrite)
{
    PacketBuffer buffer{};

    buffer.write_u8(0x7F);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.position(), 1u);
    EXPECT_EQ(buffer.get(0), 0x7F);
}

TEST(PacketBufferWriteTests, WriteU16WritesBigEndian)
{
    PacketBuffer buffer{};

    buffer.write_u16(0xABCD);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 2u);
    expect_bytes_at(buffer, 0, {0xAB, 0xCD});
}

TEST(PacketBufferWriteTests, WriteU16FailsCleanlyWhenOnlyOneByteRemains)
{
    PacketBuffer buffer{};
    fill_buffer(buffer, packet_buffer_capacity - 1);

    const std::size_t before = buffer.position();

    buffer.write_u16(0x1234);

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::end_of_buffer);
    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferWriteTests, WriteU32WritesBigEndian)
{
    PacketBuffer buffer{};

    buffer.write_u32(0x1234ABCD);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 4u);
    expect_bytes_at(buffer, 0, {0x12, 0x34, 0xAB, 0xCD});
}

TEST(PacketBufferWriteTests, WriteU32FailsCleanlyWhenNotEnoughSpaceRemains)
{
    PacketBuffer buffer{};
    fill_buffer(buffer, packet_buffer_capacity - 3);

    const std::size_t before = buffer.position();

    buffer.write_u32(0x12345678);

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::end_of_buffer);
    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferQNameTests, WriteQNameEmptyStringWritesRootLabel)
{
    PacketBuffer buffer{};

    buffer.write_qname("");

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 1u);
    expect_bytes_at(buffer, 0, {0x00});
}

TEST(PacketBufferQNameTests, WriteQNameSingleDotWritesRootLabel)
{
    PacketBuffer buffer{};

    buffer.write_qname(".");

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 1u);
    expect_bytes_at(buffer, 0, {0x00});
}

TEST(PacketBufferQNameTests, WriteQNameSingleLabelEncodesCorrectly)
{
    PacketBuffer buffer{};

    buffer.write_qname("localhost");

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 11u);
    expect_bytes_at(
        buffer, 0,
        {9, u8('l'), u8('o'), u8('c'), u8('a'), u8('l'), u8('h'), u8('o'), u8('s'), u8('t'), 0});
}

TEST(PacketBufferQNameTests, WriteQNameMultiLabelEncodesCorrectly)
{
    PacketBuffer buffer{};

    buffer.write_qname("www.example.com");

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 17u);
    expect_bytes_at(buffer, 0,
                    {3, u8('w'), u8('w'), u8('w'), 7, u8('e'), u8('x'), u8('a'), u8('m'), u8('p'),
                     u8('l'), u8('e'), 3, u8('c'), u8('o'), u8('m'), 0});
}

TEST(PacketBufferQNameTests, WriteQNameRejectsDoubleDot)
{
    PacketBuffer buffer{};

    buffer.write_qname("a..b");

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::invalid_qname);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferQNameTests, WriteQNameRejectsLeadingDot)
{
    PacketBuffer buffer{};

    buffer.write_qname(".abc");

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::invalid_qname);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferQNameTests, WriteQNameTrailingDotShouldEncodeSameAsWithoutTrailingDot)
{
    PacketBuffer a{};
    PacketBuffer b{};

    a.write_qname("example.com");
    b.write_qname("example.com.");

    ASSERT_EQ(a.last_error(), BufferError::none);
    ASSERT_EQ(b.last_error(), BufferError::none);

    EXPECT_EQ(b.position(), a.position());

    for (std::size_t i = 0; i < a.position(); ++i)
    {
        EXPECT_EQ(b.get(i), a.get(i)) << "Mismatch at byte " << i;
    }
}

TEST(PacketBufferQNameTests, WriteQNameAcceptsLabelOfLengthSixtyThree)
{
    PacketBuffer buffer{};
    const std::string label(63, 'a');

    buffer.write_qname(label);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), 65u);
    EXPECT_EQ(buffer.get(0), 63);
    EXPECT_EQ(buffer.get(64), 0);
}

TEST(PacketBufferQNameTests, WriteQNameRejectsLabelLongerThanSixtyThree)
{
    PacketBuffer buffer{};
    const std::string label(64, 'a');

    buffer.write_qname(label);

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::label_too_long);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferQNameTests, WriteQNameRejectsNamesWhoseWireFormatExceedsTwoHundredFiftyFiveBytes)
{
    PacketBuffer buffer{};
    const std::string domain = repeated_label_domain(128); // 128 one-char labels => wire length 257

    buffer.write_qname(domain);

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::qname_too_long);
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferQNameTests, WriteQNameSucceedsWhenRemainingSpaceExactlyMatchesActualEncodedLength)
{
    PacketBuffer buffer{};

    // "a.b" encodes to: 1 'a' 1 'b' 0  => 5 bytes total
    fill_buffer(buffer, packet_buffer_capacity - 5);

    buffer.write_qname("a.b");

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), BufferError::none);
    EXPECT_EQ(buffer.position(), packet_buffer_capacity);
    expect_bytes_at(buffer, packet_buffer_capacity - 5, {1, u8('a'), 1, u8('b'), 0});
}

TEST(PacketBufferTest, DataReturnsPointerToWrittenBytes)
{
    dns::PacketBuffer buffer{};

    buffer.write_u8(0xAB);

    ASSERT_TRUE(buffer.ok());
    ASSERT_NE(buffer.data(), nullptr);
    EXPECT_EQ(buffer.data()[0], 0xAB);
}

TEST(PacketBufferTest, SetSizeUpdatesSizeButKeepsPosition)
{
    dns::PacketBuffer buffer{};

    buffer.set_size(44);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.size(), 44);
    EXPECT_EQ(buffer.position(), 0);
}

TEST(PacketBufferTest, SetSizeAllowsMaxSize)
{
    dns::PacketBuffer buffer{};

    buffer.set_size(dns::PacketBuffer::max_size);

    EXPECT_TRUE(buffer.ok());
    EXPECT_EQ(buffer.size(), dns::PacketBuffer::max_size);
}

TEST(PacketBufferTest, SetSizeRejectsTooLargeSize)
{
    dns::PacketBuffer buffer{};

    buffer.set_size(dns::PacketBuffer::max_size + 1);

    EXPECT_FALSE(buffer.ok());
    EXPECT_EQ(buffer.last_error(), dns::BufferError::end_of_buffer);
    EXPECT_EQ(buffer.size(), 0);
}
