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

} // namespace dns
