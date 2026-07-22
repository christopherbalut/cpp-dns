#include "dns/cache.hpp"

#include <gtest/gtest.h>

namespace dns
{
namespace
{

DnsPacket make_packet_with_a_answer(std::uint32_t ttl)
{
    DnsPacket packet{};

    packet.answers.emplace_back(ARecord{
        .domain = "google.com",
        .addr = {142, 250, 69, 110},
        .ttl = ttl,
    });

    return packet;
}

std::uint32_t record_ttl(const DnsRecord& record)
{
    return std::visit([](const auto& actual_record) -> std::uint32_t { return actual_record.ttl; },
                      record);
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

TEST(DnsCacheTest, LookupReturnsRemainingTtl)
{
    DnsCache cache{};

    cache.insert("google.com", QueryType::A, make_packet_with_a_answer(3));

    std::this_thread::sleep_for(std::chrono::milliseconds{1100});

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::A)};

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->answers.size(), 1U);

    const std::uint32_t ttl{record_ttl(result->answers.front())};

    EXPECT_LT(ttl, 3U);
    EXPECT_GT(ttl, 0U);
}

TEST(DnsCacheTest, ExpiredEntryReturnsNullopt)
{
    DnsCache cache{};

    cache.insert("google.com", QueryType::A, make_packet_with_a_answer(1));

    std::this_thread::sleep_for(std::chrono::milliseconds{1100});

    const std::optional<DnsPacket> result{cache.lookup("google.com", QueryType::A)};

    EXPECT_FALSE(result.has_value());
}

} // namespace
} // namespace dns
