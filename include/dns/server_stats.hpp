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
};

class ServerStatsCounter
{

  public:
    void record_query_received();
    void record_query_forwarded();
    void record_upstream_failure();
    void record_formerr_response();
    void record_servfail_response();

    [[nodiscard]] ServerStats snapshot() const;

  private:
    mutable std::mutex mutex_;
    ServerStats stats_{};
};
} // namespace dns
