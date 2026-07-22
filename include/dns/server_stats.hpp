#pragma once

#include <cstdint>
#include <mutex>

namespace dns
{
struct ServerStats
{
    std::uint64_t queries_received{};
    std::uint64_t queries_forwarded{};
    std::uint64_t upstream_failures{};
    std::uint64_t formerr_responses{};
    std::uint64_t servfail_responses{};
    std::uint64_t blocked_queries{};
    std::uint64_t cache_hits{};
    std::uint64_t cache_misses{};
};

class ServerStatsCounter
{

  public:
    void record_query_received();
    void record_query_forwarded();
    void record_upstream_failure();
    void record_formerr_response();
    void record_servfail_response();
    void record_blocked_queries();
    void record_cache_hit();
    void record_cache_miss();

    [[nodiscard]] ServerStats snapshot() const;

  private:
    mutable std::mutex mutex_;
    ServerStats stats_{};
};
} // namespace dns
