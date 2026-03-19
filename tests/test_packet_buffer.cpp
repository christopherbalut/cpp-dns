#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "dns/buffer.hpp"

namespace
{

TEST(PacketBufferTest, StartsAtPositionZero)
{
    dns::PacketBuffer buffer;
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, StartsInGoodState)
{
    dns::PacketBuffer buffer;
    EXPECT_TRUE(buffer.good());
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, StepAdvancesPosition)
{
    dns::PacketBuffer buffer;
    buffer.step(5);

    EXPECT_EQ(buffer.position(), 5u);
}

TEST(PacketBufferTest, StepByZeroKeepsPositionUnchanged)
{
    dns::PacketBuffer buffer;
    buffer.step(0);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, SeekMovesToExactPosition)
{
    dns::PacketBuffer buffer;
    buffer.seek(12);

    EXPECT_EQ(buffer.position(), 12u);
}

TEST(PacketBufferTest, SeekCanMoveBackward)
{
    dns::PacketBuffer buffer;
    buffer.step(20);
    buffer.seek(3);

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, SeekToLastValidByteWorks)
{
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size - 1);

    EXPECT_EQ(buffer.position(), dns::PacketBuffer::max_size - 1);
}

TEST(PacketBufferTest, GetAtBeginningReturnsZeroForFreshBuffer)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.get(0), 0u);
}

TEST(PacketBufferTest, GetAtLastValidIndexReturnsZeroForFreshBuffer)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.get(dns::PacketBuffer::max_size - 1), 0u);
}

TEST(PacketBufferTest, GetDoesNotChangeCursorPosition)
{
    dns::PacketBuffer buffer;
    buffer.seek(10);

    const auto before = buffer.position();
    (void)buffer.get(3);

    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, GetDoesNotChangeErrorStateWhenBufferIsFresh)
{
    dns::PacketBuffer buffer;
    (void)buffer.get(0);

    EXPECT_TRUE(buffer.good());
    EXPECT_EQ(buffer.last_error(), dns::BufferError::none);
}

TEST(PacketBufferTest, ReadFromFreshBufferReturnsZero)
{
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_single_byte(), 0u);
}

TEST(PacketBufferTest, ReadAdvancesPositionByOneOnSuccess)
{
    dns::PacketBuffer buffer;
    (void)buffer.read_single_byte();

    EXPECT_EQ(buffer.position(), 1u);
}

TEST(PacketBufferTest, RepeatedReadsAdvanceSequentially)
{
    dns::PacketBuffer buffer;

    (void)buffer.read_single_byte();
    (void)buffer.read_single_byte();
    (void)buffer.read_single_byte();

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, SuccessfulReadKeepsBufferInGoodState)
{
    dns::PacketBuffer buffer;
    (void)buffer.read_single_byte();

    EXPECT_TRUE(buffer.good());
    EXPECT_EQ(buffer.last_error(), dns::BufferError::none);
}

TEST(PacketBufferTest, ReadAtLastValidByteSucceeds)
{
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size - 1);

    const std::uint8_t value = buffer.read_single_byte();

    EXPECT_EQ(value, 0u);
    EXPECT_EQ(buffer.position(), dns::PacketBuffer::max_size);
    EXPECT_TRUE(buffer.good());
    EXPECT_EQ(buffer.last_error(), dns::BufferError::none);
}

TEST(PacketBufferTest, ReadAtEndReturnsFallbackByte)
{
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size);

    const std::uint8_t value = buffer.read_single_byte();

    EXPECT_EQ(value, 0u);
}

TEST(PacketBufferTest, ReadAtEndSetsEndOfBufferError)
{
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size);

    (void)buffer.read_single_byte();

    EXPECT_FALSE(buffer.good());
    EXPECT_EQ(buffer.last_error(), dns::BufferError::end_of_buffer);
}

TEST(PacketBufferTest, FailedReadDoesNotAdvancePosition)
{
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size);

    const auto before = buffer.position();
    (void)buffer.read_single_byte();

    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, BufferCanRecoverAfterFailedReadIfNextReadSucceeds)
{
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size);
    (void)buffer.read_single_byte();

    ASSERT_FALSE(buffer.good());
    ASSERT_EQ(buffer.last_error(), dns::BufferError::end_of_buffer);

    buffer.seek(0);
    const std::uint8_t value = buffer.read_single_byte();

    EXPECT_EQ(value, 0u);
    EXPECT_TRUE(buffer.good());
    EXPECT_EQ(buffer.last_error(), dns::BufferError::none);
}

TEST(PacketBufferTest, GetRangeFromBeginningReturnsRequestedLength)
{
    dns::PacketBuffer buffer;
    const auto bytes = buffer.get_range(0, 4);

    EXPECT_EQ(bytes.size(), 4u);
    for (std::uint8_t byte : bytes) {
        EXPECT_EQ(byte, 0u);
    }
}

TEST(PacketBufferTest, GetRangeDoesNotChangeCursorPosition)
{
    dns::PacketBuffer buffer;
    buffer.seek(25);

    const auto before = buffer.position();
    const auto bytes = buffer.get_range(0, 3);

    EXPECT_EQ(bytes.size(), 3u);
    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, GetRangeCanReadSingleByteAtLastValidIndex)
{
    dns::PacketBuffer buffer;
    const auto bytes = buffer.get_range(dns::PacketBuffer::max_size - 1, 1);

    ASSERT_EQ(bytes.size(), 1u);
    EXPECT_EQ(bytes[0], 0u);
}

} // namespace
