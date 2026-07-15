#include "dns/domain_name.hpp"

#include <gtest/gtest.h>

namespace dns
{

TEST(DomainNameTest, LeavesLowercaseDomainUnchanged)
{
    EXPECT_EQ(normalize_domain("yahoo.com"), "yahoo.com");
}

TEST(DomainNameTest, LowercasesDomain)
{
    EXPECT_EQ(normalize_domain("Yahoo.COM"), "yahoo.com");
}

TEST(DomainNameTest, RemovesTrailingDot)
{
    EXPECT_EQ(normalize_domain("yahoo.com."), "yahoo.com");
}

TEST(DomainNameTest, LowercasesAndRemovesTrailingDot)
{
    EXPECT_EQ(normalize_domain("Yahoo.COM."), "yahoo.com");
}

TEST(DomainNameTest, HandlesEmptyDomain)
{
    EXPECT_EQ(normalize_domain(""), "");
}

TEST(DomainNameTest, TrimsAsciiWhitespace)
{
    EXPECT_EQ(trim_ascii("   yahoo.com   "), "yahoo.com");
    EXPECT_EQ(trim_ascii("\tyahoo.com\n"), "yahoo.com");
    EXPECT_EQ(trim_ascii(""), "");
    EXPECT_EQ(trim_ascii("   "), "");
}

TEST(DomainNameTest, NormalizeDomainTrimsWhitespace)
{
    EXPECT_EQ(normalize_domain("   Yahoo.COM.   "), "yahoo.com");
}
} // namespace dns
