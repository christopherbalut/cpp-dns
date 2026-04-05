#pragma once

#include "dns/types.hpp"
#include <string>

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

    void write(PacketBuffer& buffer) const;
};

} // namespace dns
