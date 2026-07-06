#pragma once

#include "dns/server_stats.hpp"
#include "dns/stub_resolver.hpp"

#include <cstdint>
#include <string_view>

namespace dns
{

struct ServerConfig
{
    std::string bind_ip{"0.0.0.0"};
    std::uint16_t port{2053};
};

DnsPacket make_base_response(const DnsPacket& request);

DnsPacket make_formerr_response(const DnsPacket& request);

DnsPacket make_servfail_response(const DnsPacket& request, DnsQuestion question);

DnsPacket make_forwarded_response(const DnsPacket& request, DnsQuestion question,
                                  DnsPacket upstream);
class DnsServer
{
  public:
    explicit DnsServer(ServerConfig config = {}, StubResolver resolver = StubResolver{});

    void run() const;
    void run(std::string_view bind_ip, std::uint16_t port) const;

  private:
    void handle_query(int socket_fd) const;

    ServerConfig config_;
    StubResolver resolver_;
    mutable ServerStatsCounter stats_;
};
} // namespace dns
