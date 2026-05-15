#include "dns/record.hpp"
#include "dns/buffer.hpp"
#include "dns/question.hpp"
#include "dns/types.hpp"
#include <array>
#include <type_traits>
#include <variant>

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
            if (data_length < 4)
            {
                buffer.step(data_length);
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            const std::uint32_t raw_addr{buffer.read_u32()};

            if (data_length > 4)
            {
                buffer.step(static_cast<std::size_t>(data_length - 4));
            }

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

std::size_t write_record(const DnsRecord& record, PacketBuffer& buffer)
{
    if (!buffer.ok())
    {
        return 0;
    }

    auto start_position{buffer.position()};

    std::visit(
        [&](const auto& rec)
        {
            using T = std::decay_t<decltype(rec)>;

            if constexpr (std::is_same_v<T, ARecord>)
            {
                buffer.write_qname(rec.domain);
                if (!buffer.ok())
                    return;

                buffer.write_u16(1);
                if (!buffer.ok())
                    return;

                buffer.write_u16(1);
                if (!buffer.ok())
                    return;

                buffer.write_u32(rec.ttl);
                if (!buffer.ok())
                    return;

                buffer.write_u16(4);
                if (!buffer.ok())
                    return;

                buffer.write_u8(rec.addr[0]);
                if (!buffer.ok())
                    return;

                buffer.write_u8(rec.addr[1]);
                if (!buffer.ok())
                    return;

                buffer.write_u8(rec.addr[2]);
                if (!buffer.ok())
                    return;

                buffer.write_u8(rec.addr[3]);
            }
            else if constexpr (std::is_same_v<T, UnknownRecord>)
            {
                // skip unsupported record types for now
            }
        },
        record);

    return buffer.position() - start_position;
}
}; // namespace dns
