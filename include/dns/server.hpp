#pragma once

#include "dns/stub_resolver.hpp"

#include <cstdint>
#include <string_view>

namespace dns
{

DnsPacket make_base_response(const DnsPacket& request);

DnsPacket make_formerr_response(const DnsPacket& request);

DnsPacket make_servfail_response(const DnsPacket& request, DnsQuestion question);

DnsPacket make_forwarded_response(const DnsPacket& request, DnsQuestion question,
                                  DnsPacket upstream);
class DnsServer
{
  public:
    explicit DnsServer(StubResolver resolver = StubResolver{});

    void run(std::string_view bind_ip = "0.0.0.0", std::uint16_t port = 2053) const;

  private:
    void handle_query(int socket_fd) const;

    StubResolver resolver_;
};
} // namespace dns
