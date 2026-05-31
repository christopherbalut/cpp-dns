#pragma once

#include <vector>

#include "dns/header.hpp"
#include "dns/question.hpp"
#include "dns/record.hpp"

namespace dns
{

class PacketBuffer;

struct DnsPacket
{
    DnsHeader header{};
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> resources;

    DnsPacket() = default;

    void decode_from_buffer(PacketBuffer& buffer);

    void write_to_buffer(PacketBuffer& buffer);
};

} // namespace dns
