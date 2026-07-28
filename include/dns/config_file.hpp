#pragma once

#include "dns/server.hpp"
#include <filesystem>

namespace dns
{
ServerConfig load_config_file(const std::filesystem::path& path);
} // namespace dns
