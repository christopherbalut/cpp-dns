#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "dns/buffer.hpp"

namespace {

TEST(PacketBufferTest, StartsAtPositionZero) {
    dns::PacketBuffer buffer;
    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, StepAdvancesPosition) {
    dns::PacketBuffer buffer;
    buffer.step(5);

    EXPECT_EQ(buffer.position(), 5u);
}

TEST(PacketBufferTest, StepByZeroKeepsPositionUnchanged) {
    dns::PacketBuffer buffer;
    buffer.step(0);

    EXPECT_EQ(buffer.position(), 0u);
}

TEST(PacketBufferTest, SeekMovesToExactPosition) {
    dns::PacketBuffer buffer;
    buffer.seek(12);

    EXPECT_EQ(buffer.position(), 12u);
}

TEST(PacketBufferTest, SeekCanMoveBackward) {
    dns::PacketBuffer buffer;
    buffer.step(20);
    buffer.seek(3);

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, SeekToLastValidByteWorks) {
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size - 1);

    EXPECT_EQ(buffer.position(), dns::PacketBuffer::max_size - 1);
}

TEST(PacketBufferTest, GetAtBeginningReturnsZeroForFreshBuffer) {
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.get(0), 0u);
}

TEST(PacketBufferTest, GetAtLastValidIndexReturnsZeroForFreshBuffer) {
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.get(dns::PacketBuffer::max_size - 1), 0u);
}

TEST(PacketBufferTest, GetDoesNotChangeCursorPosition) {
    dns::PacketBuffer buffer;
    buffer.seek(10);

    const auto before = buffer.position();
    (void)buffer.get(3);

    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, ReadSingleByteFromFreshBufferReturnsZero) {
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_single_byte(), 0u);
}

TEST(PacketBufferTest, ReadSingleByteAdvancesPositionByOne) {
    dns::PacketBuffer buffer;
    (void)buffer.read_single_byte();

    EXPECT_EQ(buffer.position(), 1u);
}

TEST(PacketBufferTest, RepeatedSingleByteReadsAdvanceSequentially) {
    dns::PacketBuffer buffer;

    (void)buffer.read_single_byte();
    (void)buffer.read_single_byte();
    (void)buffer.read_single_byte();

    EXPECT_EQ(buffer.position(), 3u);
}

TEST(PacketBufferTest, ReadAtLastValidByteAdvancesToEnd) {
    dns::PacketBuffer buffer;
    buffer.seek(dns::PacketBuffer::max_size - 1);

    const std::uint8_t value = buffer.read_single_byte();

    EXPECT_EQ(value, 0u);
    EXPECT_EQ(buffer.position(), dns::PacketBuffer::max_size);
}

TEST(PacketBufferTest, GetRangeFromBeginningReturnsRequestedLength) {
    dns::PacketBuffer buffer;
    const auto bytes = buffer.get_range(0, 4);

    EXPECT_EQ(bytes.size(), 4u);
    for (std::uint8_t byte : bytes) {
        EXPECT_EQ(byte, 0u);
    }
}

TEST(PacketBufferTest, GetRangeDoesNotChangeCursorPosition) {
    dns::PacketBuffer buffer;
    buffer.seek(25);

    const auto before = buffer.position();
    const auto bytes = buffer.get_range(0, 3);

    EXPECT_EQ(bytes.size(), 3u);
    EXPECT_EQ(buffer.position(), before);
}

TEST(PacketBufferTest, GetRangeCanReadSingleByteAtLastValidIndex) {
    dns::PacketBuffer buffer;
    const auto bytes = buffer.get_range(dns::PacketBuffer::max_size - 1, 1);

    ASSERT_EQ(bytes.size(), 1u);
    EXPECT_EQ(bytes[0], 0u);
}

TEST(PacketBufferTest, ReadU16FromFreshBufferReturnsZero) {
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_u16(), 0u);
}

TEST(PacketBufferTest, ReadU16AdvancesPositionByTwo) {
    dns::PacketBuffer buffer;
    (void)buffer.read_u16();

    EXPECT_EQ(buffer.position(), 2u);
}

TEST(PacketBufferTest, ReadU32FromFreshBufferReturnsZero) {
    dns::PacketBuffer buffer;

    EXPECT_EQ(buffer.read_u32(), 0u);
}

TEST(PacketBufferTest, ReadU32AdvancesPositionByFour) {
    dns::PacketBuffer buffer;
    (void)buffer.read_u32();

    EXPECT_EQ(buffer.position(), 4u);
}

TEST(PacketBufferTest, MixedReadsAdvanceByTotalBytesConsumed) {
    dns::PacketBuffer buffer;

    (void)buffer.read_single_byte(); // +1
    (void)buffer.read_u16();         // +2
    (void)buffer.read_u32();         // +4

    EXPECT_EQ(buffer.position(), 7u);
}

} // namespace
