#pragma once

#include <string>
#include "dns/types.hpp"

namespace dns
{

class PacketBuffer;

struct DnsQuestion
{
    std::string name;
    QueryType qtype{QueryType::Unknown};

    DnsQuestion() = default;
    DnsQuestion(std::string question_name, QueryType question_type);

    void decode(PacketBuffer& buffer);
};

} // namespace dns
