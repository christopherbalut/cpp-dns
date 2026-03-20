#pragma once

#include <cstdint>

enum class ResultCode : std::uint8_t{
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
        case 1: return ResultCode::formerr;
        case 2: return ResultCode::servfail;
        case 3: return ResultCode::nxdomain;
        case 4: return ResultCode::notimp;
        case 5: return ResultCode::refused;
        case 0:
        default:
            return ResultCode::noerror;
    }
}
