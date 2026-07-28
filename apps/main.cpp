#include "dns/config_parser.hpp"
#include "dns/server.hpp"
#include "dns/shutdown.hpp"
#include <exception>
#include <iostream>

int main(int argc, char* argv[])
{
    try
    {
        dns::install_shutdown_signal_handlers();

        const dns::ServerConfig config =
            dns::parse_server_config(std::span<char*>{argv, static_cast<std::size_t>(argc)});

        dns::DnsServer server{config};
        server.run();
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        return 1;
    }
    return 0;
}
