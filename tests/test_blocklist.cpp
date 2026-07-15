#include "dns/blocklist.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace dns
{

TEST(BlocklistTest, ContainsAddedDomain)
{
    Blocklist blocklist{};

    blocklist.add("ads.example.com");

    EXPECT_TRUE(blocklist.contains("ads.example.com"));
}

TEST(BlocklistTest, ContainsIsCaseInsensitive)
{
    Blocklist blocklist{};

    blocklist.add("Ads.Example.COM");

    EXPECT_TRUE(blocklist.contains("ads.example.com"));
    EXPECT_TRUE(blocklist.contains("ADS.EXAMPLE.COM"));
}

TEST(BlocklistTest, ContainsIgnoresTrailingDot)
{
    Blocklist blocklist{};

    blocklist.add("ads.example.com");

    EXPECT_TRUE(blocklist.contains("ads.example.com."));
}

TEST(BlocklistTest, DoesNotContainDifferentDomain)
{
    Blocklist blocklist{};

    blocklist.add("ads.example.com");

    EXPECT_FALSE(blocklist.contains("example.com"));
    EXPECT_FALSE(blocklist.contains("google.com"));
}

TEST(BlocklistTest, LoadFromFileIgnoresWhitespaceCommentsAndDuplicates)
{
    const auto path = std::filesystem::temp_directory_path() / "cpp_dns_blocklist_test.txt";

    {
        std::ofstream file{path};
        ASSERT_TRUE(file);

        file << "# comment\n";
        file << "\n";
        file << "   \n";
        file << "   # spaced comment\n";
        file << "   Yahoo.COM.   \n";
        file << "ads.example.com\n";
        file << "yahoo.com\n";
    }

    Blocklist blocklist{};
    blocklist.load_from_file(path);

    EXPECT_TRUE(blocklist.contains("yahoo.com"));
    EXPECT_TRUE(blocklist.contains("YAHOO.COM."));
    EXPECT_TRUE(blocklist.contains("ads.example.com"));

    EXPECT_FALSE(blocklist.contains("google.com"));

    EXPECT_EQ(blocklist.size(), 2U);

    std::filesystem::remove(path);
}

} // namespace dns
