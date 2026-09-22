#pragma once

#include "dns/types.hpp"

#include <chrono>
#include <string>
#include <string_view>

namespace dns
{

// stores one DNS query
struct QueryLogEntry
{
    std::chrono::system_clock::time_point timestamp{std::chrono::system_clock::now()};

    std::string client_ip;
    std::string domain;

    QueryType qtype{QueryType::Unknown};
    ResultCode response_code{ResultCode::noerror};

    bool blocked{false};
    bool cache_hit{false};
    bool forwarded{false};
};

std::string_view to_log_string(QueryType qtype);
std::string_view to_log_string(ResultCode result_code);

} // namespace dns
