#include "dns/question.hpp"
#include "dns/buffer.hpp"
#include "dns/types.hpp"
#include <memory>
#include <utility>

namespace dns
{
DnsQuestion::DnsQuestion(std::string question_name, QueryType question_type)
    : name{std::move(question_name)}, qtype{question_type}
{
}

void DnsQuestion::decode(PacketBuffer& buffer)
{
    buffer.read_qname(name);
    qtype = to_query_type(buffer.read_u16());
    static_cast<void>(buffer.read_u16());
}

void DnsQuestion::write(PacketBuffer& buffer) const
{
    buffer.write_qname(name);
    const std::uint16_t typenumber{static_cast<std::uint16_t>(qtype)};
    buffer.write_u16(typenumber);
    buffer.write_u16(1);
}
}; // namespace dns
