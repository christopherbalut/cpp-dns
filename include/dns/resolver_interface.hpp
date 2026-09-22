#pragma once

#include "dns/packet.hpp"
#include "dns/types.hpp"

#include <string_view>

namespace dns
{

class ResolverInterface
{
  public:
    // fixing clang tidy warning
    ResolverInterface() = default;
    ResolverInterface(const ResolverInterface&) = default;
    ResolverInterface& operator=(const ResolverInterface&) = default;
    ResolverInterface(ResolverInterface&&) noexcept = default;
    ResolverInterface& operator=(ResolverInterface&&) noexcept = default;
    virtual ~ResolverInterface() = default;

    [[nodiscard]] virtual DnsPacket lookup(std::string_view name, QueryType qtype) const = 0;
};

} // namespace dns
