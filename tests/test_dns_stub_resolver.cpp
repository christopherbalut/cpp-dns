#include "dns/record.hpp"
#include "dns/stub_resolver.hpp"
#include "dns/types.hpp"

#include <cstdlib>
#include <stdexcept>
#include <variant>

#include <gtest/gtest.h>

TEST(StubResolverTests, RejectsInvalidQNameBeforeNetworkCall)
{
    dns::StubResolver resolver{};

    EXPECT_THROW(static_cast<void>(resolver.lookup("google..com", dns::QueryType::A)),
                 std::runtime_error);
}

TEST(StubResolverNetworkTests, LookupGoogleARecordReturnsResponse)
{
    if (std::getenv("RUN_DNS_NETWORK_TESTS") == nullptr)
    {
        GTEST_SKIP() << "Skipping live DNS network test";
    }

    dns::StubResolver resolver{};
    dns::DnsPacket response = resolver.lookup("google.com", dns::QueryType::A);

    EXPECT_EQ(response.header.id, 6666);
    EXPECT_TRUE(response.header.response);
    EXPECT_TRUE(response.header.recursion_desired);
    EXPECT_TRUE(response.header.recursion_available);

    ASSERT_EQ(response.questions.size(), 1);
    EXPECT_EQ(response.questions[0].name, "google.com");
    EXPECT_EQ(response.questions[0].qtype, dns::QueryType::A);

    ASSERT_FALSE(response.answers.empty());

    bool found_a_record = false;

    for (const auto& record : response.answers)
    {
        if (std::holds_alternative<dns::ARecord>(record))
        {
            const auto& answer = std::get<dns::ARecord>(record);

            if (answer.domain == "google.com")
            {
                found_a_record = true;
            }
        }
    }

    EXPECT_TRUE(found_a_record);
}
