#include "dns/postgres_query_logger.hpp"
#include "dns/query_log_entry.hpp"

#include <cstdlib>
#include <string>

#include <gtest/gtest.h>

TEST(PostgresQueryLoggerIntegrationTest, InsertsQueryLog)
{
    const char* connection_string_env = std::getenv("CPP_DNS_TEST_DATABASE_URL");

    if (connection_string_env == nullptr)
    {
        GTEST_SKIP() << "CPP_DNS_TEST_DATABASE_URL is not set";
    }

    const std::string connection_string{connection_string_env};

    dns::PostgresQueryLogger logger{connection_string};

    dns::QueryLogEntry entry{};
    entry.client_ip = "127.0.0.1";
    entry.domain = "example.com";
    entry.qtype = dns::QueryType::A;
    entry.response_code = dns::ResultCode::noerror;
    entry.blocked = false;
    entry.cache_hit = false;
    entry.forwarded = true;

    EXPECT_NO_THROW(logger.log_query(entry));
}
