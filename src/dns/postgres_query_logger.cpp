#include "dns/postgres_query_logger.hpp"

#include "dns/query_log_entry.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <pqxx/pqxx>
#include <stdexcept>
#include <string>

namespace dns
{

PostgresQueryLogger::PostgresQueryLogger(const std::string& connection_string)
    : connection_{std::make_unique<pqxx::connection>(connection_string)}
{
    if (!connection_->is_open())
    {
        throw std::runtime_error{"failed to open PostgreSQL connection"};
    }
}

PostgresQueryLogger::~PostgresQueryLogger() = default;

void PostgresQueryLogger::log_query(const QueryLogEntry& entry)
{
    const double timestamp_seconds =
        std::chrono::duration<double>{entry.timestamp.time_since_epoch()}.count();

    const std::scoped_lock lock{connection_mutex_};

    pqxx::work transaction{*connection_};

    transaction
        .exec(
            "INSERT INTO query_logs "
            "(created_at, client_ip, domain, qtype, response_code, blocked, cache_hit, forwarded) "
            "VALUES (to_timestamp($1), $2, $3, $4, $5, $6, $7, $8)",
            pqxx::params{
                timestamp_seconds,
                entry.client_ip,
                entry.domain,
                std::string{to_log_string(entry.qtype)},
                std::string{to_log_string(entry.response_code)},
                entry.blocked,
                entry.cache_hit,
                entry.forwarded,
            })
        .no_rows();

    transaction.commit();
}

} // namespace dns
