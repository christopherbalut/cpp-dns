#include "dns/query_log_entry.hpp"

namespace dns
{

std::string_view to_log_string(QueryType qtype)
{
    switch (qtype)
    {
        case QueryType::A:
            return "A";
        case QueryType::NS:
            return "NS";
        case QueryType::CNAME:
            return "CNAME";
        case QueryType::MX:
            return "MX";
        case QueryType::AAAA:
            return "AAAA";
        case QueryType::Unknown:
            return "UNKNOWN";
    }

    return "UNKNOWN";
}

std::string_view to_log_string(ResultCode result_code)
{
    switch (result_code)
    {
        case ResultCode::noerror:
            return "NOERROR";
        case ResultCode::formerr:
            return "FORMERR";
        case ResultCode::servfail:
            return "SERVFAIL";
        case ResultCode::nxdomain:
            return "NXDOMAIN";
        case ResultCode::notimp:
            return "NOTIMP";

        case ResultCode::refused:
            return "REFUSED";
    }

    return "UNKNOWN";
}

} // namespace dns
