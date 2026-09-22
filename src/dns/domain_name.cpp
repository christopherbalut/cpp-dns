#include "dns/domain_name.hpp"

#include <cctype>
#include <string>

namespace dns
{
std::string trim_ascii(std::string_view text)
{
    std::size_t first{0};

    while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first])) != 0)
    {
        ++first;
    }

    std::size_t last{text.size()};

    while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])) != 0)
    {
        --last;
    }

    return std::string{text.substr(first, last - first)};
}

std::string normalize_domain(std::string_view domain)
{
    const std::string trimmed{trim_ascii(domain)};
    std::string normalized{};
    normalized.reserve(trimmed.size());

    for (const char c : trimmed)
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
