#pragma once

#include "dns/query_logger.hpp"

#include <memory>
#include <mutex>
#include <string>

namespace pqxx
{
class connection;
}

namespace dns
{

class PostgresQueryLogger final : public QueryLogger
{
  public:
    explicit PostgresQueryLogger(const std::string& connection_string);
    PostgresQueryLogger(const PostgresQueryLogger&) = delete;
    PostgresQueryLogger(PostgresQueryLogger&&) = delete;
    PostgresQueryLogger& operator=(const PostgresQueryLogger&) = delete;
    PostgresQueryLogger& operator=(PostgresQueryLogger&&) = delete;
    explicit PostgresQueryLogger(std::string connection_string);

    ~PostgresQueryLogger() override;

    void log_query(const QueryLogEntry& entry) override;

  private:
    std::unique_ptr<pqxx::connection> connection_;
    std::mutex connection_mutex_;
};

} // namespace dns
