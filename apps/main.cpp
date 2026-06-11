#include "dns/server.hpp"
#include <exception>
#include <iostream>

int main()
{
    try
    {
        dns::DnsServer server{};
        server.run("0.0.0.0", 2053);
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        return 1;
    }
    return 0;
}
