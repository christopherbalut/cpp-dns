#include "dns/allowlist.hpp"

#include "dns/domain_name.hpp"

#include <fstream>
#include <string>

namespace dns
{

void Allowlist::add(std::string_view domain)
{
    const std::string normalized = normalize_domain(domain);

    if (!normalized.empty())
    {
        allowed_domains_.insert(normalized);
    }
}

bool Allowlist::contains(std::string_view domain) const
{
    std::string candidate = normalize_domain(domain);

    if (candidate.empty())
    {
        return false;
    }

    while (true)
    {
        if (allowed_domains_.contains(candidate))
        {
            return true;
        }

        const std::size_t dot_position = candidate.find('.');

        if (dot_position == std::string::npos)
        {
            return false;
        }

        candidate.erase(0, dot_position + 1);
    }
}

std::size_t Allowlist::size() const
{
    return allowed_domains_.size();
}

AllowlistLoadResult Allowlist::load_from_file(const std::filesystem::path& path)
{
    AllowlistLoadResult result{};

    std::ifstream file{path};

    if (!file)
    {
        return result;
    }

    std::string line{};

    while (std::getline(file, line))
    {
        const std::string trimmed = trim_ascii(line);

        if (trimmed.empty())
        {
            ++result.lines_skipped;
            continue;
        }

        if (trimmed.front() == '#')
        {
            ++result.lines_skipped;
            continue;
        }

        const std::size_t old_size = allowed_domains_.size();

        add(trimmed);

        if (allowed_domains_.size() > old_size)
        {
            ++result.domains_loaded;
        }
        else
        {
            ++result.lines_skipped;
        }
    }

    return result;
}
} // namespace dns
