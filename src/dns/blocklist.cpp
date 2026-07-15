#include "dns/blocklist.hpp"

#include "dns/domain_name.hpp"

#include <fstream>
#include <string>

namespace dns
{

void Blocklist::add(std::string_view domain)
{
    const std::string normalized = normalize_domain(domain);

    if (!normalized.empty())
    {
        blocked_domains_.insert(normalized);
    }
}

bool Blocklist::contains(std::string_view domain) const
{
    const std::string normalized = normalize_domain(domain);
    return blocked_domains_.contains(normalized);
}

std::size_t Blocklist::size() const
{
    return blocked_domains_.size();
}

BlocklistLoadResult Blocklist::load_from_file(const std::filesystem::path& path)
{
    BlocklistLoadResult result{};

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

        const std::size_t old_size = blocked_domains_.size();

        add(trimmed);

        if (blocked_domains_.size() > old_size)
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
