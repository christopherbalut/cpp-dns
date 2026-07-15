#pragma once

#include "dns/server.hpp"

namespace dns
{

ServerConfig parse_server_config(std::span<char*> args);

} // namespace dns
