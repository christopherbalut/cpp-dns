#include "dns/config_parser.hpp"

#include <gtest/gtest.h>

#include <array>
#include <span>
#include <stdexcept>
#include <string>

namespace dns
{
namespace
{

template <std::size_t N> std::array<char*, N> make_argv(std::array<std::string, N>& args)
{
    std::array<char*, N> argv{};

    for (std::size_t i{0}; i < N; ++i)
    {
        argv[i] = args[i].data();
    }

    return argv;
}

template <std::size_t N> std::span<char*> make_span(std::array<char*, N>& argv)
{
    return std::span<char*>{argv.data(), argv.size()};
}

} // namespace

TEST(ConfigParserTest, UsesDefaultsWithNoArguments)
{
    std::array<std::string, 1> args{"cpp_dns_app"};
    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    EXPECT_EQ(config.bind_ip, "0.0.0.0");
    EXPECT_EQ(config.port, default_server_port);
    EXPECT_EQ(config.blocklist_path, "blocklist.txt");
}

TEST(ConfigParserTest, ParsesAllOptions)
{
    std::array<std::string, 7> args{"cpp_dns_app", "--bind",      "127.0.0.1", "--port",
                                    "2053",        "--blocklist", "ads.txt"};
    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    EXPECT_EQ(config.bind_ip, "127.0.0.1");
    EXPECT_EQ(config.port, 2053);
    EXPECT_EQ(config.blocklist_path, "ads.txt");
}

TEST(ConfigParserTest, ThrowsOnMissingValue)
{
    std::array<std::string, 2> args{"cpp_dns_app", "--port"};
    auto argv = make_argv(args);

    EXPECT_THROW(parse_server_config(make_span(argv)), std::invalid_argument);
}

TEST(ConfigParserTest, ThrowsOnInvalidPort)
{
    std::array<std::string, 3> args{"cpp_dns_app", "--port", "2053abc"};
    auto argv = make_argv(args);

    EXPECT_THROW(parse_server_config(make_span(argv)), std::invalid_argument);
}

TEST(ConfigParserTest, ThrowsOnUnknownOption)
{
    std::array<std::string, 2> args{"cpp_dns_app", "--bad-option"};
    auto argv = make_argv(args);

    EXPECT_THROW(parse_server_config(make_span(argv)), std::invalid_argument);
}

} // namespace dns
