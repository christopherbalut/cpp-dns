#include "dns/record.hpp"
#include "dns/buffer.hpp"
#include "dns/question.hpp"
#include "dns/types.hpp"
#include <array>

namespace dns
{
DnsRecord decode_record(PacketBuffer& buffer)
{
    std::string domain{};
    buffer.read_qname(domain);
    std::uint16_t qtype_num = buffer.read_u16();
    const QueryType qtype{to_query_type(qtype_num)};
    static_cast<void>(buffer.read_u16());
    std::uint32_t ttl{buffer.read_u32()};
    std::uint16_t data_length{buffer.read_u16()};

    switch (qtype)
    {
        case QueryType::A:
        {
            const std::uint32_t raw_addr{buffer.read_u32()};

            const std::array<std::uint8_t, 4> addr{
                static_cast<std::uint8_t>((raw_addr >> 24) & 0xFF),
                static_cast<std::uint8_t>((raw_addr >> 16) & 0xFF),
                static_cast<std::uint8_t>((raw_addr >> 8) & 0xFF),
                static_cast<std::uint8_t>(raw_addr & 0xFF)};

            return ARecord{.domain = domain, .addr = addr, .ttl = ttl};
        }

        case QueryType::Unknown:
        default:
        {
            buffer.step(data_length);

            return UnknownRecord{
                .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
        }
    }
}
}; // namespace dns
