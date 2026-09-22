#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>

namespace dns
{

struct BlocklistLoadResult
{
    std::size_t domains_loaded{};
    std::size_t lines_skipped{};
};

class Blocklist
{
  public:
    void add(std::string_view domain);
    [[nodiscard]] bool contains(std::string_view domain) const;
    [[nodiscard]] std::size_t size() const;

    BlocklistLoadResult load_from_file(const std::filesystem::path& path);

  private:
    std::unordered_set<std::string> blocked_domains_;
};
} // namespace dns
