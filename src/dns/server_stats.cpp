#include "dns/server_stats.hpp"

#include <mutex>

namespace dns
{

void ServerStatsCounter::record_query_received()
{
    std::lock_guard<std::mutex> lock{mutex_};
    ++stats_.queries_received;
}

void ServerStatsCounter::record_query_forwarded()
{
    std::lock_guard<std::mutex> lock{mutex_};
    ++stats_.queries_forwarded;
}

void ServerStatsCounter::record_upstream_failure()
{
    std::lock_guard<std::mutex> lock{mutex_};
    ++stats_.upstream_failures;
}

void ServerStatsCounter::record_formerr_response()
{
    std::lock_guard<std::mutex> lock{mutex_};
    ++stats_.formerr_responses;
}

void ServerStatsCounter::record_servfail_response()
{
    std::lock_guard<std::mutex> lock{mutex_};
    ++stats_.servfail_responses;
}

void ServerStatsCounter::record_blocked_queries()
{
    std::lock_guard<std::mutex> lock{mutex_};
    ++stats_.blocked_queries;
}
ServerStats ServerStatsCounter::snapshot() const
{

    std::lock_guard<std::mutex> lock{mutex_};
    return stats_;
}

} // namespace dns
