#include "dns/question.hpp"
#include "dns/buffer.hpp"
#include "dns/types.hpp"
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
}; // namespace dns
