#pragma once

#include <filesystem>
#include <string_view>
#include <unordered_set>
namespace dns
{
struct AllowlistLoadResult
{
    std::size_t domains_loaded{};
    std::size_t lines_skipped{};
};

class Allowlist
{
  public:
    void add(std::string_view domain);
    [[nodiscard]] bool contains(std::string_view domain) const;
    [[nodiscard]] std::size_t size() const;
    AllowlistLoadResult load_from_file(const std::filesystem::path& path);

  private:
    std::unordered_set<std::string> allowed_domains_;
};
} // namespace dns
