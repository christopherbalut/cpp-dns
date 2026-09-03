#pragma once

#include "dns/allowlist.hpp"
#include "dns/blocklist.hpp"
#include "dns/cache.hpp"
#include "dns/packet.hpp"
#include "dns/resolver_interface.hpp"
#include "dns/server_stats.hpp"
#include "dns/stub_resolver.hpp"
#include "dns/thread_pool.hpp"

#include <cstdint>
#include <gtest/gtest_prod.h>
#include <memory>
#include <stop_token>
#include <string_view>
#include <vector>

namespace dns
{

inline constexpr std::uint16_t default_server_port{2053};
inline constexpr std::size_t default_worker_count{4};
struct ServerConfig
{
    std::string bind_ip{"0.0.0.0"};
    std::uint16_t port{default_server_port};
    std::vector<std::string> blocklist_paths{"blocklist.txt"};
    std::size_t worker_count{default_worker_count};
    std::string allowlist_path{"allowlist.txt"};
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
    void log_stats_periodically(const std::stop_token& stop_token) const;

    ServerConfig config_;
    std::shared_ptr<ResolverInterface> resolver_;
    Blocklist blocklist_;
    Allowlist allowlist_;

    mutable DnsCache cache_;
    mutable ThreadPool thread_pool_;
    mutable ServerStatsCounter stats_;

    FRIEND_TEST(DnsServerFakeResolverTest, BlockedDomainDoesNotCallResolver);
    FRIEND_TEST(DnsServerFakeResolverTest, UnblockedDomainCallsResolver);
    FRIEND_TEST(DnsServerFakeResolverTest, ResolverFailureReturnsServfail);
    FRIEND_TEST(DnsServerTest, AllowlistOverridesBlocklist);
    FRIEND_TEST(DnsServerTest, BlocklistStillBlocksNonAllowlistedSubdomain);
};
} // namespace dns
