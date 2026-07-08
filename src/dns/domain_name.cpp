#include "dns/domain_name.hpp"

#include <cctype>
#include <string>

namespace dns
{
std::string normalize_domain(std::string_view domain)
{
    std::string normalized{};
    normalized.reserve(domain.size());

    for (const char c : domain)
    {
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    while (!normalized.empty() && normalized.back() == '.')
    {
        normalized.pop_back();
    }
    return normalized;
}
} // namespace dns
