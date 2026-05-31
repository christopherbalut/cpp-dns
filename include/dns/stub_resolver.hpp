#pragma once

#include "dns/packet.hpp"
#include "dns/types.hpp"

#include <string>
#include <string_view>

namespace dns
{

class StubResolver
{
  public:
    StubResolver();

    StubResolver(std::string server_ip, std::string server_port);

    [[nodiscard]] DnsPacket lookup(std::string_view name, QueryType qtype) const;

  private:
    [[nodiscard]] static DnsPacket make_query_packet(std::string name, QueryType qtype);

    std::string server_ip_;
    std::string server_port_;
};

} // namespace dns
