#include "dns/allowlist.hpp"

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

TEST(AllowlistTest, ContainsAddedDomain)
{
    dns::Allowlist allowlist{};

    allowlist.add("mail.yahoo.com");

    EXPECT_TRUE(allowlist.contains("mail.yahoo.com"));
}

TEST(AllowlistTest, ContainsIsCaseInsensitive)
{
    dns::Allowlist allowlist{};

    allowlist.add("MAIL.YAHOO.COM");

    EXPECT_TRUE(allowlist.contains("mail.yahoo.com"));
    EXPECT_TRUE(allowlist.contains("Mail.Yahoo.Com"));
}

TEST(AllowlistTest, ContainsIgnoresTrailingDot)
{
    dns::Allowlist allowlist{};

    allowlist.add("mail.yahoo.com.");

    EXPECT_TRUE(allowlist.contains("mail.yahoo.com"));
    EXPECT_TRUE(allowlist.contains("mail.yahoo.com."));
}

TEST(AllowlistTest, ContainsSubdomainOfAllowedDomain)
{
    dns::Allowlist allowlist{};

    allowlist.add("mail.yahoo.com");

    EXPECT_TRUE(allowlist.contains("mail.yahoo.com"));
    EXPECT_TRUE(allowlist.contains("images.mail.yahoo.com"));
    EXPECT_TRUE(allowlist.contains("static.images.mail.yahoo.com"));
}

TEST(AllowlistTest, DoesNotContainDifferentDomain)
{
    dns::Allowlist allowlist{};

    allowlist.add("mail.yahoo.com");

    EXPECT_FALSE(allowlist.contains("ads.yahoo.com"));
    EXPECT_FALSE(allowlist.contains("yahoo.com"));
    EXPECT_FALSE(allowlist.contains("google.com"));
}

TEST(AllowlistTest, DoesNotMatchPartialSuffix)
{
    dns::Allowlist allowlist{};

    allowlist.add("yahoo.com");

    EXPECT_FALSE(allowlist.contains("notyahoo.com"));
    EXPECT_FALSE(allowlist.contains("fake-yahoo.com"));
}

TEST(AllowlistTest, LoadFromFileIgnoresWhitespaceCommentsAndDuplicates)
{
    const std::filesystem::path path{"test-allowlist.txt"};

    {
        std::ofstream file{path};
        file << "\n";
        file << "# comment\n";
        file << " mail.yahoo.com \n";
        file << "MAIL.YAHOO.COM\n";
        file << "github.com\n";
    }

    dns::Allowlist allowlist{};

    const dns::AllowlistLoadResult result{allowlist.load_from_file(path)};

    EXPECT_EQ(result.domains_loaded, 2U);
    EXPECT_EQ(result.lines_skipped, 3U);

    EXPECT_TRUE(allowlist.contains("mail.yahoo.com"));
    EXPECT_TRUE(allowlist.contains("images.mail.yahoo.com"));
    EXPECT_TRUE(allowlist.contains("github.com"));

    std::filesystem::remove(path);
}
