#include "dns/cache.hpp"

#include <gtest/gtest.h>

namespace dns
{
namespace
{

DnsPacket make_packet_with_a_answer(std::uint32_t ttl)
{
    DnsPacket packet{};

    packet.answers.push_back(ARecord{
        .domain = "google.com",
        .addr = {142, 250, 69, 110},
        .ttl = ttl,
    });

    return packet;
}

TEST(DnsCacheTest, EmptyCacheReturnsNullopt)
{
    DnsCache cache{};

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::A)};

    EXPECT_FALSE(result.has_value());
}

TEST(DnsCacheTest, InsertThenLookupReturnsPacket)
{
    DnsCache cache{};

    cache.insert("google.com", QueryType::A, make_packet_with_a_answer(300));

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::A)};

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->answers.size(), 1U);
}

TEST(DnsCacheTest, DifferentQueryTypesDoNotCollide)
{
    DnsCache cache{};

    cache.insert("google.com", QueryType::A, make_packet_with_a_answer(300));

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::AAAA)};

    EXPECT_FALSE(result.has_value());
}

TEST(DnsCacheTest, NormalizesDomainNames)
{
    DnsCache cache{};

    cache.insert("Google.COM.", QueryType::A, make_packet_with_a_answer(300));

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::A)};

    EXPECT_TRUE(result.has_value());
}

TEST(DnsCacheTest, ZeroTtlDoesNotCache)
{
    DnsCache cache{};

    cache.insert("google.com", QueryType::A, make_packet_with_a_answer(0));

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::A)};

    EXPECT_FALSE(result.has_value());
}

} // namespace
} // namespace dns
