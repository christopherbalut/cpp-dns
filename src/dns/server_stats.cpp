#include "dns/server_stats.hpp"

namespace dns
{

void ServerStatsCounter::record_query_received()
{
    ++stats_.queries_received;
}

void ServerStatsCounter::record_query_forwarded()
{
    ++stats_.queries_forwarded;
}

void ServerStatsCounter::record_upstream_failure()
{
    ++stats_.upstream_failures;
}

void ServerStatsCounter::record_formerr_response()
{
    ++stats_.formerr_responses;
}

void ServerStatsCounter::record_servfail_response()
{
    ++stats_.servfail_responses;
}

ServerStats ServerStatsCounter::snapshot() const
{
    return stats_;
}

} // namespace dns
