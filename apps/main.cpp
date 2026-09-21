#include "dns/config_parser.hpp"
#include "dns/postgres_query_logger.hpp"
#include "dns/query_logger.hpp"
#include "dns/server.hpp"
#include "dns/shutdown.hpp"
#include "dns/stub_resolver.hpp"

#include <cstddef>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <span>

int main(int argc, char* argv[])
{
    try
    {
        dns::install_shutdown_signal_handlers();

        const dns::ServerConfig config =
            dns::parse_server_config(std::span<char*>{argv, static_cast<std::size_t>(argc)});

        std::shared_ptr<dns::QueryLogger> query_logger{std::make_shared<dns::NoopQueryLogger>()};

        if (const char* database_url = std::getenv("CPP_DNS_DATABASE_URL"); database_url != nullptr)
        {
            try
            {
                query_logger = std::make_shared<dns::PostgresQueryLogger>(database_url);

                std::cout << "PostgreSQL query logging enabled\n";
            }
            catch (const std::exception& error)
            {
                std::cerr << "Failed to enable PostgreSQL query logging: " << error.what() << '\n';

                std::cerr << "Continuing without database logging\n";
            }
        }

        dns::DnsServer server{config, std::make_shared<dns::StubResolver>(), query_logger};

        server.run();
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }

    return 0;
}
