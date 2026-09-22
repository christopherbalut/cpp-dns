#pragma once

#include "dns/query_log_entry.hpp"

namespace dns
{

// logging interface for the DNS server
class QueryLogger
{
  public:
    QueryLogger() = default;
    virtual ~QueryLogger() =
        default; // allows for polymorphic destruction
                 // derived classes can still survive after destructor this class is called

    QueryLogger(const QueryLogger&) = delete;
    QueryLogger& operator=(const QueryLogger&) = delete;

    QueryLogger(QueryLogger&&) = delete;
    QueryLogger& operator=(QueryLogger&&) = delete;

    virtual void log_query(const QueryLogEntry& entry) = 0;
};

class NoopQueryLogger final : public QueryLogger
{
  public:
    void log_query(const QueryLogEntry& entry) override;
};

} // namespace dns
