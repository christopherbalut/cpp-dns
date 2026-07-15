#include "dns/config_parser.hpp"
#include <charconv>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace dns
{
namespace
{
std::uint16_t parse_port(std::string_view text)
{
    unsigned int port{};

    const char* begin{text.data()};
    const char* end{text.data() + text.size()};

    const auto [ptr, error] = std::from_chars(begin, end, port);

    if (error != std::errc{} || ptr != end)
    {
        throw std::invalid_argument{"invalid port: " + std::string{text}};
    }

    if (port == 0 || port > 65535)
    {
        throw std::invalid_argument("port is not inside 1 and 65535");
    }

    return static_cast<std::uint16_t>(port);
}

std::string_view require_value(std::span<char*> args, size_t& index, std::string_view option)
{
    if (index + 1 >= args.size())
    {
        throw std::invalid_argument{"missing value for " + std::string{option}};
    }

    ++index;
    return args[index];
}

} // namespace

ServerConfig parse_server_config(std::span<char*> args)
{
    ServerConfig config{};

    for (std::size_t i{1}; i < args.size(); i++)
    {
        const std::string_view arg{args[i]};

        if (arg == "--bind")
        {
            config.bind_ip = std::string{require_value(args, i, arg)};
        }
        else if (arg == "--port")
        {
            config.port = parse_port(require_value(args, i, arg));
        }
        else if (arg == "--blocklist")
        {
            config.blocklist_path = std::string{require_value(args, i, arg)};
        }
        else
        {
            throw std::invalid_argument{"unknown option: " + std::string{arg}};
        }
    }
    return config;
}

} // namespace dns
