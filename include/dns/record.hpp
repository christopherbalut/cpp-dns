#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>

namespace dns
{

enum class RecordType : std::uint16_t
{
    Unknown = 0,
    A = 1
};

struct UnknownRecord
{
    std::string domain{};
    std::uint16_t qtype{0};
    std::uint16_t data_len{0};
    std::uint32_t ttl{0};
};

struct ARecord
{
    std::string domain{};
    std::array<std::uint8_t, 4> addr{};
    std::uint32_t ttl{0};
};

using DnsRecord = std::variant<UnknownRecord, ARecord>;

} // namespace dns
