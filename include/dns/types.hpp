#pragma once

#include <cstdint>
#include <string_view>

namespace dns
{

enum class ResultCode : std::uint8_t
{
    noerror = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    notimp = 4,
    refused = 5
};

constexpr ResultCode to_result_code(std::uint8_t code)
{
    switch (code)
    {
        case 1:
            return ResultCode::formerr;
        case 2:
            return ResultCode::servfail;
        case 3:
            return ResultCode::nxdomain;
        case 4:
            return ResultCode::notimp;
        case 5:
            return ResultCode::refused;
        case 0:
        default:
            return ResultCode::noerror;
    }
}

enum class QueryType : std::uint8_t
{
    Unknown = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    MX = 15,
    AAAA = 28
};

constexpr std::uint16_t to_code(QueryType type)
{
    switch (type)
    {
        case QueryType::A:
            return 1;
        case QueryType::NS:
            return 2;
        case QueryType::CNAME:
            return 5;
        case QueryType::MX:
            return 15;
        case QueryType::AAAA:
            return 28;
        case QueryType::Unknown:
        default:
            return 0;
    }
}

constexpr QueryType to_query_type(std::uint16_t code)
{
    switch (code)
    {
        case 1:
            return QueryType::A;
        case 2:
            return QueryType::NS;
        case 5:
            return QueryType::CNAME;
        case 15:
            return QueryType::MX;
        case 28:
            return QueryType::AAAA;
        default:
            return QueryType::Unknown;
    }
}

constexpr std::string_view to_string(QueryType qtype)
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
        default:
            return "UNKNOWN";
    }
}

} // namespace dns
