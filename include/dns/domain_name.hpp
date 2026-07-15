#pragma once

#include <string>
#include <string_view>

namespace dns
{
std::string trim_ascii(std::string_view text);
std::string normalize_domain(std::string_view domain);
} // namespace dns
