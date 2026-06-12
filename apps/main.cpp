#include "dns/server.hpp"
#include <exception>
#include <iostream>

int main()
{
    try
    {
        dns::DnsServer server{};
        server.run();
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        return 1;
    }
    return 0;
}
