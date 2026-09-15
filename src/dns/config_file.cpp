#include "dns/config_file.hpp"
#include <cstdint>
#include <fstream>
#include <string_view>

namespace dns
{
namespace
{

std::string_view trim(std::string_view text)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
    {
        text.remove_prefix(1);
    }

    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r'))
    {
        text.remove_suffix(1);
    }
    return text;
}

std::uint16_t parse_port(std::string_view text)
{
    unsigned int port{};

    const char* begin{text.data()};
    const char* end{text.data() + text.size()};

    const auto [ptr, error] = std::from_chars(begin, end, port);

    if (error != std::errc{} || ptr != end)
    {
        throw std::invalid_argument{"invalid port in config file: " + std::string{text}};
    }

    if (port == 0 || port > 65535)
    {
        throw std::invalid_argument{"port must be between 1 and 65535"};
    }

    return static_cast<std::uint16_t>(port);
}

std::size_t parse_worker_count(std::string_view text)
{
    std::size_t workers{};

    const char* begin{text.data()};
    const char* end{text.data() + text.size()};

    const auto [ptr, error] = std::from_chars(begin, end, workers);

    if (error != std::errc{} || ptr != end)
    {
        throw std::invalid_argument{"invalid workers value in config file: " + std::string{text}};
    }

    if (workers == 0)
    {
        throw std::invalid_argument{"workers must be greater than 0"};
    }

    return workers;
}

void apply_config_value(ServerConfig& config, std::string_view key, std::string_view value,
                        bool& saw_blocklist_path)
{
    if (key == "bind_ip")
    {
        config.bind_ip = std::string{value};
    }
    else if (key == "port")
    {
        config.port = parse_port(value);
    }
    else if (key == "blocklist_path")
    {
        if (!saw_blocklist_path)
        {
            config.blocklist_paths.clear();
            saw_blocklist_path = true;
        }

        config.blocklist_paths.emplace_back(std::string{value});
    }
    else if (key == "allowlist_path")
    {
        config.allowlist_path = std::string{value};
    }
    else if (key == "workers")
    {
        config.worker_count = parse_worker_count(value);
    }
    else
    {
        throw std::invalid_argument{"unknown config key: " + std::string{key}};
    }
}
} // namespace

ServerConfig load_config_file(const std::filesystem::path& path)
{
    std::ifstream file{path};

    if (!file.is_open())
    {
        throw std::runtime_error{"failed to open config file: " + path.string()};
    }

    ServerConfig config{};
    bool saw_blocklist_path{false};

    std::string line{};
    std::size_t line_number{0};

    while (std::getline(file, line))
    {
        ++line_number;

        const std::string_view trimmed_line{trim(line)}; // remove trailing / leading whitespace

        if (trimmed_line.empty()) // if line is empty
        {
            continue;
        }

        if (trimmed_line.front() == '#') // if line is a comment
        {
            continue;
        }

        const std::size_t equals_position{
            trimmed_line.find('=')}; // if we find equals, make LHS key, RHS value

        if (equals_position == std::string_view::npos) // no equal sign return invalid argument
        {
            throw std::invalid_argument{"invalid config line " + std::to_string(line_number) +
                                        ": expected key=value"};
        }

        const std::string_view key{trim(trimmed_line.substr(0, equals_position))};
        const std::string_view value{trim(trimmed_line.substr(equals_position + 1))};

        if (key.empty())
        {
            throw std::invalid_argument{"invalid config line " + std::to_string(line_number) +
                                        ": empty key"};
        }

        if (value.empty())
        {
            throw std::invalid_argument{"invalid config line " + std::to_string(line_number) +
                                        ": empty value"};
        }

        apply_config_value(config, key, value, saw_blocklist_path);
    }

    return config;
}

} // namespace dns
