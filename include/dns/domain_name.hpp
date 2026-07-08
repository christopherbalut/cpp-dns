#pragma once

#include <string>
#include <string_view>

namespace dns
{
std::string normalize_domain(std::string_view domain);
} // namespace dns
