#include "dns/config_parser.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

namespace dns
{
namespace
{

constexpr std::uint16_t test_server_port{2053};
constexpr std::uint16_t config_file_port{53};
constexpr std::size_t one_blocklist_path{1};
constexpr std::size_t two_blocklist_paths{2};

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

    ASSERT_EQ(config.blocklist_paths.size(), one_blocklist_path);
    EXPECT_EQ(config.blocklist_paths.at(0), "blocklist.txt");

    EXPECT_EQ(config.allowlist_path, "allowlist.txt");
}

TEST(ConfigParserTest, ParsesAllOptions)
{
    std::array<std::string, 9> args{
        "cpp_dns_app", "--bind",  "127.0.0.1",   "--port",        "2053",
        "--blocklist", "ads.txt", "--allowlist", "allowlist.txt",
    };

    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    EXPECT_EQ(config.bind_ip, "127.0.0.1");
    EXPECT_EQ(config.port, test_server_port);

    ASSERT_EQ(config.blocklist_paths.size(), one_blocklist_path);
    EXPECT_EQ(config.blocklist_paths.at(0), "ads.txt");

    EXPECT_EQ(config.allowlist_path, "allowlist.txt");
}

TEST(ConfigParserTest, ParsesMultipleBlocklistOptions)
{
    std::array<std::string, 5> args{
        "cpp_dns_app", "--blocklist", "ads.txt", "--blocklist", "trackers.txt",
    };

    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    ASSERT_EQ(config.blocklist_paths.size(), two_blocklist_paths);
    EXPECT_EQ(config.blocklist_paths.at(0), "ads.txt");
    EXPECT_EQ(config.blocklist_paths.at(1), "trackers.txt");
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

TEST(ConfigParserTest, CommandLineOverridesConfigFile)
{
    const std::filesystem::path path{"test-cpp-dns.conf"};

    {
        std::ofstream file{path};
        file << "bind_ip=0.0.0.0\n";
        file << "port=53\n";
        file << "blocklist_path=config-blocklist.txt\n";
        file << "allowlist_path=config-allowlist.txt\n";
        file << "workers=4\n";
    }

    std::array<std::string, 7> args{
        "cpp_dns_app", "--config", "test-cpp-dns.conf", "--port", "2053", "--workers", "2",
    };

    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    EXPECT_EQ(config.bind_ip, "0.0.0.0");
    EXPECT_EQ(config.port, test_server_port);
    EXPECT_EQ(config.worker_count, 2U);

    ASSERT_EQ(config.blocklist_paths.size(), one_blocklist_path);
    EXPECT_EQ(config.blocklist_paths.at(0), "config-blocklist.txt");

    EXPECT_EQ(config.allowlist_path, "config-allowlist.txt");

    std::filesystem::remove(path);
}

TEST(ConfigParserTest, CommandLineBlocklistOverridesConfigFileBlocklist)
{
    const std::filesystem::path path{"test-cpp-dns.conf"};

    {
        std::ofstream file{path};
        file << "port=53\n";
        file << "blocklist_path=config-blocklist.txt\n";
    }

    std::array<std::string, 5> args{
        "cpp_dns_app", "--config", "test-cpp-dns.conf", "--blocklist", "cli-blocklist.txt",
    };

    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    EXPECT_EQ(config.port, config_file_port);

    ASSERT_EQ(config.blocklist_paths.size(), one_blocklist_path);
    EXPECT_EQ(config.blocklist_paths.at(0), "cli-blocklist.txt");

    std::filesystem::remove(path);
}

TEST(ConfigParserTest, ParsesAllowlistOption)
{
    std::array<std::string, 3> args{
        "cpp_dns_app",
        "--allowlist",
        "allowlist.txt",
    };

    auto argv = make_argv(args);

    const ServerConfig config = parse_server_config(make_span(argv));

    EXPECT_EQ(config.allowlist_path, "allowlist.txt");
}

} // namespace dns
