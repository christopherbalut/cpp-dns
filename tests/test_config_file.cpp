#include "dns/config_file.hpp"

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

namespace
{

std::filesystem::path write_temp_config(std::string_view contents)
{
    const std::filesystem::path path{"test-cpp-dns.conf"};

    std::ofstream file{path};
    file << contents;

    return path;
}

} // namespace

TEST(ConfigFileTest, LoadsBasicConfig)
{
    const std::filesystem::path path = write_temp_config("bind_ip=127.0.0.1\n"
                                                         "port=2053\n"
                                                         "blocklist_path=blocklist.txt\n"
                                                         "workers=4\n");

    const dns::ServerConfig config = dns::load_config_file(path);

    EXPECT_EQ(config.bind_ip, "127.0.0.1");
    EXPECT_EQ(config.port, 2053);
    EXPECT_EQ(config.blocklist_path, "blocklist.txt");
    EXPECT_EQ(config.worker_count, 4U);

    std::filesystem::remove(path);
}

TEST(ConfigFileTest, IgnoresEmptyLinesAndComments)
{
    const std::filesystem::path path = write_temp_config("# cpp-dns config\n"
                                                         "\n"
                                                         "bind_ip = 127.0.0.1\n"
                                                         "port = 2053\n");

    const dns::ServerConfig config = dns::load_config_file(path);

    EXPECT_EQ(config.bind_ip, "127.0.0.1");
    EXPECT_EQ(config.port, 2053);

    std::filesystem::remove(path);
}

TEST(ConfigFileTest, RejectsUnknownKey)
{
    const std::filesystem::path path = write_temp_config("bad_key=value\n");

    EXPECT_THROW(dns::load_config_file(path), std::invalid_argument);

    std::filesystem::remove(path);
}

TEST(ConfigFileTest, RejectsInvalidLine)
{
    const std::filesystem::path path = write_temp_config("port 2053\n");

    EXPECT_THROW(dns::load_config_file(path), std::invalid_argument);

    std::filesystem::remove(path);
}

TEST(ConfigFileTest, RejectsInvalidPort)
{
    const std::filesystem::path path = write_temp_config("port=99999\n");

    EXPECT_THROW(dns::load_config_file(path), std::invalid_argument);

    std::filesystem::remove(path);
}
