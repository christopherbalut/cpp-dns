#include "dns/server_stats.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <thread>
#include <vector>

namespace dns
{

TEST(ServerStatsCounterTest, StartsAtZero)
{
    ServerStatsCounter counter{};

    const ServerStats stats = counter.snapshot();

    EXPECT_EQ(stats.queries_received, 0U);
    EXPECT_EQ(stats.queries_forwarded, 0U);
    EXPECT_EQ(stats.upstream_failures, 0U);
    EXPECT_EQ(stats.formerr_responses, 0U);
    EXPECT_EQ(stats.servfail_responses, 0U);
}

TEST(ServerStatsCounterTest, RecordsStats)
{
    ServerStatsCounter counter{};

    counter.record_query_received();
    counter.record_query_received();
    counter.record_query_forwarded();
    counter.record_upstream_failure();
    counter.record_formerr_response();
    counter.record_servfail_response();

    const ServerStats stats = counter.snapshot();

    EXPECT_EQ(stats.queries_received, 2U);
    EXPECT_EQ(stats.queries_forwarded, 1U);
    EXPECT_EQ(stats.upstream_failures, 1U);
    EXPECT_EQ(stats.formerr_responses, 1U);
    EXPECT_EQ(stats.servfail_responses, 1U);
}

TEST(ServerStatsCounterTest, HandlesConcurrentQueryReceivedUpdates)
{
    ServerStatsCounter counter{};

    constexpr int thread_count{8};
    constexpr int increments_per_thread{10'000};

    std::vector<std::thread> threads{};
    threads.reserve(thread_count);

    for (int i = 0; i < thread_count; ++i)
    {
        threads.emplace_back(
            [&counter]
            {
                for (int j = 0; j < increments_per_thread; ++j)
                {
                    counter.record_query_received();
                }
            });
    }

    for (std::thread& thread : threads)
    {
        thread.join();
    }

    const ServerStats stats = counter.snapshot();

    EXPECT_EQ(stats.queries_received,
              static_cast<std::uint64_t>(thread_count * increments_per_thread));
}

TEST(ServerStatsCounterTest, HandlesConcurrentMixedUpdates)
{
    ServerStatsCounter counter{};

    constexpr int thread_count{8};
    constexpr int iterations_per_thread{5'000};

    std::vector<std::thread> threads{};
    threads.reserve(thread_count);

    for (int i = 0; i < thread_count; ++i)
    {
        threads.emplace_back(
            [&counter]
            {
                for (int j = 0; j < iterations_per_thread; ++j)
                {
                    counter.record_query_received();
                    counter.record_query_forwarded();
                    counter.record_upstream_failure();
                    counter.record_formerr_response();
                    counter.record_servfail_response();
                }
            });
    }

    for (std::thread& thread : threads)
    {
        thread.join();
    }

    const ServerStats stats = counter.snapshot();

    const auto expected = static_cast<std::uint64_t>(thread_count * iterations_per_thread);

    EXPECT_EQ(stats.queries_received, expected);
    EXPECT_EQ(stats.queries_forwarded, expected);
    EXPECT_EQ(stats.upstream_failures, expected);
    EXPECT_EQ(stats.formerr_responses, expected);
    EXPECT_EQ(stats.servfail_responses, expected);
}

} // namespace dns
