#pragma once

#include "dns/buffer.hpp"
#include <array>
#include <cstddef>
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

struct NSRecord
{
    std::string domain{};
    std::string host{};
    std::uint32_t ttl{};
};

struct CNameRecord
{
    std::string domain{};
    std::string host{};
    std::uint32_t ttl{};
};

struct MXRecord
{
    std::string domain{};
    std::uint16_t priority{};
    std::string host{};
    std::uint32_t ttl{};
};

struct AAAARecord
{
    std::string domain{};
    std::array<std::uint16_t, 8> addr{};
    std::uint32_t ttl{};
};
using DnsRecord = std::variant<UnknownRecord, ARecord, NSRecord, CNameRecord, MXRecord, AAAARecord>;

DnsRecord decode_record(PacketBuffer& buffer);

std::size_t write_record(
    const DnsRecord& record,
    PacketBuffer& buffer); // take as input an in-memory DNS record, serialize it and write it
} // namespace dns
