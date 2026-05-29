#include "dns/packet.hpp"
#include "dns/stub_resolver.hpp"
#include "dns/types.hpp"

#include <exception>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h> // sockaddr_in, htons()
#include <sys/socket.h> // socket(), AF_INET, SOCK_DGRAM
#include <unistd.h>     // close()

int main()
{
    try
    {
        dns::StubResolver resolver{};
        dns::DnsPacket response_packet = resolver.lookup("www.yahoo.com", dns::QueryType::A);

        std::cout << (response_packet.header);

        for (const auto& question : response_packet.questions)
        {
            std::cout << (question);
        }

        for (const auto& record : response_packet.answers)
        {
            std::cout << record;
        }

        for (const auto& record : response_packet.authorities)
        {
            std::cout << record;
        }

        for (const auto& record : response_packet.resources)
        {
            std::cout << record;
        }
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
