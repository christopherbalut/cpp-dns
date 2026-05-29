#include "dns/question.hpp"
#include "dns/buffer.hpp"
#include "dns/types.hpp"
#include <ostream>
#include <utility>

namespace dns
{
namespace
{
constexpr std::uint16_t dns_class_in = 1;
} // namespace
DnsQuestion::DnsQuestion(std::string question_name, QueryType question_type)
    : name{std::move(question_name)}, qtype{question_type}
{
}

void DnsQuestion::decode(PacketBuffer& buffer)
{
    if (!buffer.ok())
    {
        return;
    }

    buffer.read_qname(name);
    if (!buffer.ok())
    {
        return;
    }

    const std::uint16_t typenumber(buffer.read_u16());
    if (!buffer.ok())
    {
        return;
    }

    qtype = to_query_type(typenumber);

    static_cast<void>(buffer.read_u16());
    if (!buffer.ok())
    {
        return;
    }
}

void DnsQuestion::write(PacketBuffer& buffer) const
{
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_qname(name);
    if (!buffer.ok())
    {
        return;
    }

    const std::uint16_t typenumber{static_cast<std::uint16_t>(qtype)};
    buffer.write_u16(typenumber);
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_u16(dns_class_in);

    if (!buffer.ok())
    {
        return;
    }
}

std::ostream& operator<<(std::ostream& os, const DnsQuestion& question)
{
    os << "DnsQuestion {\n";
    os << "    name: \"" << question.name << "\",\n";
    os << "    qtype: " << to_string(question.qtype) << '\n';
    os << "}\n";

    return os;
}
}; // namespace dns
