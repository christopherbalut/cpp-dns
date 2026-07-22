#include "dns/cache.hpp"
#include "dns/domain_name.hpp"
#include "dns/packet.hpp"
#include "dns/record.hpp"
#include "dns/types.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>

namespace dns
{
std::size_t DnsCache::CacheKeyHash::operator()(const CacheKey& key) const
{
    const std::size_t name_hash{std::hash<std::string>{}(key.name)};
    const std::size_t type_hash{std::hash<int>{}(static_cast<int>(key.qtype))};

    return name_hash ^ (type_hash << 1);
}

DnsCache::CacheKey DnsCache::make_key(std::string_view name, QueryType qtype)
{
    return CacheKey{
        .name = normalize_domain(name),
        .qtype = qtype,
    };
}

bool DnsCache::is_expired(const CacheEntry& entry, TimePoint now)
{
    return now >= entry.expires_at;
}

std::chrono::seconds DnsCache::minimum_ttl(const DnsPacket& packet)
{
    if (packet.answers.empty())
    {
        return std::chrono::seconds{0};
    }

    std::uint32_t smallest_ttl{std::numeric_limits<std::uint32_t>::max()};

    for (const DnsRecord& record : packet.answers)
    {
        const std::uint32_t ttl =
            std::visit([](const auto& actual_record) { return actual_record.ttl; }, record);

        smallest_ttl = std::min(ttl, smallest_ttl);
    }

    return std::chrono::seconds{smallest_ttl};
}

void DnsCache::insert(std::string_view name, QueryType qtype, DnsPacket packet)
{
    const std::chrono::seconds ttl{minimum_ttl(packet)};

    if (ttl.count() <= 0)
    {
        return;
    }

    CacheKey key{make_key(name, qtype)};

    if (key.name.empty())
    {
        return;
    }

    CacheEntry entry{
        .packet = std::move(packet),
        .expires_at = std::chrono::steady_clock::now() + ttl,
    };

    std::lock_guard<std::mutex> lock{mutex_};
    entries_[std::move(key)] = std::move(entry);
}

std::optional<DnsPacket> DnsCache::lookup(std::string_view name, QueryType qtype)
{
    CacheKey key{make_key(name, qtype)};
    const TimePoint now{std::chrono::steady_clock::now()};

    std::lock_guard<std::mutex> lock{mutex_};

    auto entry_it = entries_.find(key);

    if (entry_it == entries_.end())
    {
        return std::nullopt;
    }

    if (is_expired(entry_it->second, now))
    {
        entries_.erase(entry_it);
        return std::nullopt;
    }

    return entry_it->second.packet;
}

std::size_t DnsCache::size() const
{
    std::lock_guard<std::mutex> lock{mutex_};
    return entries_.size();
}
} // namespace dns
