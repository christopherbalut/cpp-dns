#include "dns/record.hpp"
#include "dns/buffer.hpp"
#include "dns/question.hpp"
#include "dns/types.hpp"
#include <array>
#include <ostream>
#include <type_traits>
#include <variant>

namespace dns
{
namespace
{
constexpr std::uint16_t dns_class_in = 1;
constexpr std::uint16_t ipv4_rdata_length = 4;
constexpr std::uint16_t ipv6_rdata_length = 16;
} // namespace
DnsRecord decode_record(PacketBuffer& buffer)
{
    if (!buffer.ok())
    {
        return UnknownRecord{};
    }

    std::string domain{};
    buffer.read_qname(domain);
    if (!buffer.ok())
    {
        return UnknownRecord{};
    }

    const std::uint16_t qtype_num{buffer.read_u16()};
    if (!buffer.ok())
    {
        return UnknownRecord{.domain = domain, .qtype = 0, .data_len = 0, .ttl = 0};
    }

    const QueryType qtype{to_query_type(qtype_num)};

    static_cast<void>(buffer.read_u16()); // class
    if (!buffer.ok())
    {
        return UnknownRecord{.domain = domain, .qtype = qtype_num, .data_len = 0, .ttl = 0};
    }

    const std::uint32_t ttl{buffer.read_u32()};
    if (!buffer.ok())
    {
        return UnknownRecord{

            .domain = domain, .qtype = qtype_num, .data_len = 0, .ttl = 0};
    }

    const std::uint16_t data_length{buffer.read_u16()};
    if (!buffer.ok())
    {
        return UnknownRecord{.domain = domain, .qtype = qtype_num, .data_len = 0, .ttl = ttl};
    }

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
            if (!buffer.ok())
            {
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            if (data_length > 4)
            {
                buffer.step(static_cast<std::size_t>(data_length - 4));
                if (!buffer.ok())
                {
                    return UnknownRecord{
                        .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
                }
            }

            const std::array<std::uint8_t, 4> addr{
                static_cast<std::uint8_t>((raw_addr >> 24) & 0xFF),
                static_cast<std::uint8_t>((raw_addr >> 16) & 0xFF),
                static_cast<std::uint8_t>((raw_addr >> 8) & 0xFF),
                static_cast<std::uint8_t>(raw_addr & 0xFF)};

            return ARecord{.domain = domain, .addr = addr, .ttl = ttl};
        }

        case QueryType::NS:
        {
            std::string host{};
            buffer.read_qname(host);

            if (!buffer.ok())
            {
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            return NSRecord{.domain = domain, .host = host, .ttl = ttl};
        }

        case QueryType::CNAME:
        {
            std::string host{};
            buffer.read_qname(host);

            if (!buffer.ok())
            {
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            return CNameRecord{.domain = domain, .host = host, .ttl = ttl};
        }

        case QueryType::MX:
        {
            if (data_length < 2)
            {
                buffer.step(data_length);
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            const std::uint16_t priority{buffer.read_u16()};
            if (!buffer.ok())
            {
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            std::string host{};
            buffer.read_qname(host);

            if (!buffer.ok())
            {
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            return MXRecord{.domain = domain, .priority = priority, .host = host, .ttl = ttl};
        }

        case QueryType::AAAA:
        {
            if (data_length != 16)
            {
                buffer.step(data_length);
                return UnknownRecord{
                    .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
            }

            std::array<std::uint16_t, 8> addr{};

            for (auto& segment : addr)
            {
                segment = buffer.read_u16();

                if (!buffer.ok())
                {
                    return UnknownRecord{
                        .domain = domain, .qtype = qtype_num, .data_len = data_length, .ttl = ttl};
                }
            }

            return AAAARecord{.domain = domain, .addr = addr, .ttl = ttl};
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
    const std::size_t start_position = buffer.position();

    if (!buffer.ok())
    {
        return 0;
    }

    std::visit(
        [&](const auto& rec)
        {
            using T = std::decay_t<decltype(rec)>;

            if constexpr (std::is_same_v<T, ARecord>)
            {
                buffer.write_qname(rec.domain);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u16(static_cast<std::uint16_t>(QueryType::A));
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u16(dns_class_in);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u32(rec.ttl);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u16(ipv4_rdata_length);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u8(rec.addr[0]);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u8(rec.addr[1]);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u8(rec.addr[2]);
                if (!buffer.ok())
                {
                    return;
                }

                buffer.write_u8(rec.addr[3]);
            }
            else if constexpr (std::is_same_v<T, NSRecord>)
            {
                buffer.write_qname(rec.domain);
                if (!buffer.ok())
                    return;

                buffer.write_u16(static_cast<std::uint16_t>(QueryType::NS));
                if (!buffer.ok())
                    return;

                buffer.write_u16(dns_class_in);
                if (!buffer.ok())
                    return;

                buffer.write_u32(rec.ttl);
                if (!buffer.ok())
                    return;

                const std::size_t length_position = buffer.position();
                buffer.write_u16(0); // placeholder RDLENGTH
                if (!buffer.ok())
                    return;

                const std::size_t data_start = buffer.position();
                buffer.write_qname(rec.host);
                if (!buffer.ok())
                    return;

                const std::size_t data_length = buffer.position() - data_start;
                buffer.set_u16(length_position, static_cast<std::uint16_t>(data_length));
            }
            else if constexpr (std::is_same_v<T, CNameRecord>)
            {
                buffer.write_qname(rec.domain);
                if (!buffer.ok())
                    return;

                buffer.write_u16(static_cast<std::uint16_t>(QueryType::CNAME));
                if (!buffer.ok())
                    return;

                buffer.write_u16(dns_class_in);
                if (!buffer.ok())
                    return;

                buffer.write_u32(rec.ttl);
                if (!buffer.ok())
                    return;

                const std::size_t length_position = buffer.position();
                buffer.write_u16(0); // placeholder RDLENGTH
                if (!buffer.ok())
                    return;

                const std::size_t data_start = buffer.position();
                buffer.write_qname(rec.host);
                if (!buffer.ok())
                    return;

                const std::size_t data_length = buffer.position() - data_start;
                buffer.set_u16(length_position, static_cast<std::uint16_t>(data_length));
            }
            else if constexpr (std::is_same_v<T, MXRecord>)
            {
                buffer.write_qname(rec.domain);
                if (!buffer.ok())
                    return;

                buffer.write_u16(static_cast<std::uint16_t>(QueryType::MX));
                if (!buffer.ok())
                    return;

                buffer.write_u16(dns_class_in);
                if (!buffer.ok())
                    return;

                buffer.write_u32(rec.ttl);
                if (!buffer.ok())
                    return;

                const std::size_t length_position = buffer.position();
                buffer.write_u16(0); // placeholder RDLENGTH
                if (!buffer.ok())
                    return;

                const std::size_t data_start = buffer.position();

                buffer.write_u16(rec.priority);
                if (!buffer.ok())
                    return;

                buffer.write_qname(rec.host);
                if (!buffer.ok())
                    return;

                const std::size_t data_length = buffer.position() - data_start;
                buffer.set_u16(length_position, static_cast<std::uint16_t>(data_length));
            }
            else if constexpr (std::is_same_v<T, AAAARecord>)
            {
                buffer.write_qname(rec.domain);
                if (!buffer.ok())
                    return;

                buffer.write_u16(static_cast<std::uint16_t>(QueryType::AAAA));
                if (!buffer.ok())
                    return;

                buffer.write_u16(dns_class_in);
                if (!buffer.ok())
                    return;

                buffer.write_u32(rec.ttl);
                if (!buffer.ok())
                    return;

                buffer.write_u16(ipv6_rdata_length);
                if (!buffer.ok())
                    return;

                for (const auto segment : rec.addr)
                {
                    buffer.write_u16(segment);
                    if (!buffer.ok())
                        return;
                }
            }
            else if constexpr (std::is_same_v<T, UnknownRecord>)
            {
                // Skip unsupported record types for now.
            }
        },
        record);

    return buffer.position() - start_position;
}

template <typename... Ts> struct Overloaded : Ts...
{
    using Ts::operator()...;
};

template <typename... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;

std::ostream& operator<<(std::ostream& os, const dns::DnsRecord& record)
{
    std::visit(
        Overloaded{
            [&os](const dns::ARecord& rec)
            {
                os << "A {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    addr: " << static_cast<int>(rec.addr[0]) << "."
                   << static_cast<int>(rec.addr[1]) << "." << static_cast<int>(rec.addr[2]) << "."
                   << static_cast<int>(rec.addr[3]) << ",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::NSRecord& rec)
            {
                os << "NS {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    host: \"" << rec.host << "\",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::CNameRecord& rec)
            {
                os << "CNAME {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    host: \"" << rec.host << "\",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::MXRecord& rec)
            {
                os << "MX {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    priority: " << rec.priority << ",\n";
                os << "    host: \"" << rec.host << "\",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::AAAARecord& rec)
            {
                os << "AAAA {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    addr: ";

                for (std::size_t i = 0; i < rec.addr.size(); ++i)
                {
                    if (i != 0)
                    {
                        os << ":";
                    }

                    os << std::hex << rec.addr[i];
                }

                os << std::dec << ",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::UnknownRecord& rec)
            {
                os << "UNKNOWN {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    qtype: " << static_cast<int>(rec.qtype) << ",\n";
                os << "    ttl: " << rec.ttl << ",\n";
                os << "    data_len: " << rec.data_len << "\n";
                os << "}\n";
            },
        },
        record);
    return os;
}
}; // namespace dns
