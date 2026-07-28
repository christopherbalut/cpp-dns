#include "dns/config_parser.hpp"
#include "dns/config_file.hpp"
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

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

std::size_t parse_worker_count(std::string_view text)
{
    std::size_t worker_count{}; // this is unsigned so it cannot be less than 0 by default

    const char* begin{text.data()};
    const char* end{text.data() + text.size()};

    const auto [ptr, error] = std::from_chars(begin, end, worker_count);

    if (error != std::errc{} || ptr != end)
    {
        throw std::invalid_argument{"invalid worker count: " + std::string{text}};
    }

    if (worker_count == 0)
    {
        throw std::invalid_argument{"worker_count cannot be less or equal 0"};
    }
    return worker_count;
}

std::string_view require_value(std::span<char*> args, std::size_t& index, std::string_view option)
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

    for (std::size_t i{1}; i < args.size(); ++i)
    {
        const std::string_view arg{args[i]};

        if (arg == "--config")
        {
            const std::string_view config_path{require_value(args, i, arg)};
            config = load_config_file(std::filesystem::path{config_path});
        }
    }

    for (std::size_t i{1}; i < args.size(); ++i)
    {
        const std::string_view arg{args[i]};

        if (arg == "--config")
        {
            require_value(args, i, arg);
        }
        else if (arg == "--bind")
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
        else if (arg == "--workers")
        {
            config.worker_count = parse_worker_count(require_value(args, i, arg));
        }
        else
        {
            throw std::invalid_argument{"unknown option: " + std::string{arg}};
        }
    }

    return config;
}

} // namespace dns
