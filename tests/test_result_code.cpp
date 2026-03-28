#include <cstdint>
#include <gtest/gtest.h>

#include "dns/types.hpp"
using dns::ResultCode;

namespace
{

TEST(ResultCodeTest, MapsZeroToNoError)
{
    EXPECT_EQ(dns::to_result_code(0), ResultCode::noerror);
}

TEST(ResultCodeTest, MapsOneToFormErr)
{
    EXPECT_EQ(dns::to_result_code(1), ResultCode::formerr);
}

TEST(ResultCodeTest, MapsTwoToServFail)
{
    EXPECT_EQ(dns::to_result_code(2), ResultCode::servfail);
}

TEST(ResultCodeTest, MapsThreeToNxDomain)
{
    EXPECT_EQ(dns::to_result_code(3), ResultCode::nxdomain);
}

TEST(ResultCodeTest, MapsFourToNotImp)
{
    EXPECT_EQ(dns::to_result_code(4), ResultCode::notimp);
}

TEST(ResultCodeTest, MapsFiveToRefused)
{
    EXPECT_EQ(dns::to_result_code(5), ResultCode::refused);
}

TEST(ResultCodeTest, MapsUnknownCodeToNoError)
{
    EXPECT_EQ(dns::to_result_code(42), ResultCode::noerror);
}
}; // namespace
