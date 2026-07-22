#pragma once

#include "dns/packet.hpp"
#include "dns/types.hpp"

#include <chrono>
#include <cstddef>
#include <mutex>
#include <unordered_map>

namespace dns
{
class DnsCache
{
  public:
    DnsCache() = default;
    DnsCache(const DnsCache&) = delete;
    DnsCache& operator=(DnsCache&) = delete;
    DnsCache(DnsCache&&) = delete;
    DnsCache& operator=(DnsCache&&) = delete;

    ~DnsCache() = default;

    void insert(std::string_view name, QueryType qtype, DnsPacket packet);

    [[nodiscard]] std::optional<DnsPacket> lookup(std::string_view name, QueryType qtype);

    [[nodiscard]] std::size_t size() const;

  private:
    using TimePoint = std::chrono::steady_clock::time_point;

    struct CacheKey
    {
        std::string name;
        QueryType qtype{QueryType::Unknown};

        bool operator==(const CacheKey& other) const = default;
    };

    struct CacheKeyHash
    {
        std::size_t operator()(const CacheKey& key) const;
    };

    struct CacheEntry
    {
        DnsPacket packet;
        TimePoint expires_at{};
    };

    [[nodiscard]] static CacheKey make_key(std::string_view name, QueryType qtype);

    [[nodiscard]] static std::chrono::seconds minimum_ttl(const DnsPacket& packet);

    [[nodiscard]] static bool is_expired(const CacheEntry& entry, TimePoint now);

    mutable std::mutex mutex_;
    std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> entries_;
};
} // namespace dns
