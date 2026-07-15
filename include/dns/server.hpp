#pragma once

#include "dns/blocklist.hpp"
#include "dns/packet.hpp"
#include "dns/resolver_interface.hpp"
#include "dns/server_stats.hpp"
#include "dns/stub_resolver.hpp"

#include <cstdint>
#include <gtest/gtest_prod.h>
#include <memory>
#include <string_view>

namespace dns
{

inline constexpr std::uint16_t default_server_port{2053};
struct ServerConfig
{
    std::string bind_ip{"0.0.0.0"};
    std::uint16_t port{default_server_port};
    std::string blocklist_path{"blocklist.txt"};
};

DnsPacket make_base_response(const DnsPacket& request);

DnsPacket make_formerr_response(const DnsPacket& request);

DnsPacket make_servfail_response(const DnsPacket& request, DnsQuestion question);

DnsPacket make_forwarded_response(const DnsPacket& request, DnsQuestion question,
                                  DnsPacket upstream);
DnsPacket make_blocked_response(const DnsPacket& request, DnsQuestion question);

class DnsServer
{
  public:
    explicit DnsServer(ServerConfig config = {}, std::shared_ptr<ResolverInterface> resolver =
                                                     std::make_shared<StubResolver>());

    void run() const;
    void run(std::string_view bind_ip, std::uint16_t port) const;

  private:
    DnsPacket make_response_for_request(DnsPacket request) const;
    void handle_query(int socket_fd) const;

    ServerConfig config_;
    std::shared_ptr<ResolverInterface> resolver_;
    Blocklist blocklist_;
    mutable ServerStatsCounter stats_;

    FRIEND_TEST(DnsServerFakeResolverTest, BlockedDomainDoesNotCallResolver);
    FRIEND_TEST(DnsServerFakeResolverTest, UnblockedDomainCallsResolver);
    FRIEND_TEST(DnsServerFakeResolverTest, ResolverFailureReturnsServfail);
};
} // namespace dns
