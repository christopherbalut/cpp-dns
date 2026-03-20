#include <gtest/gtest.h>
#include <cstdint>

#include "dns/types.hpp"

namespace {

TEST(ResultCodeTest, MapsZeroToNoError) {
    EXPECT_EQ(to_result_code(0), ResultCode::noerror);
}

TEST(ResultCodeTest, MapsOneToFormErr) {
    EXPECT_EQ(to_result_code(1), ResultCode::formerr);
}

TEST(ResultCodeTest, MapsTwoToServFail) {
    EXPECT_EQ(to_result_code(2), ResultCode::servfail);
}

TEST(ResultCodeTest, MapsThreeToNxDomain) {
    EXPECT_EQ(to_result_code(3), ResultCode::nxdomain);
}

TEST(ResultCodeTest, MapsFourToNotImp) {
    EXPECT_EQ(to_result_code(4), ResultCode::notimp);
}

TEST(ResultCodeTest, MapsFiveToRefused) {
    EXPECT_EQ(to_result_code(5), ResultCode::refused);
}

TEST(ResultCodeTest, MapsUnknownCodeToNoError) {
    EXPECT_EQ(to_result_code(42), ResultCode::noerror);
}

} // namespace
