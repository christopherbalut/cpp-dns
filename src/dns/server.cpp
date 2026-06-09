#include "dns/server.hpp"
#include "dns/socket_utils.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>

namespace dns
{
DnsServer::DnsServer(StubResolver resolver) : resolver_{std::move(resolver)} {}

void DnsServer::run(std::string_view bind_ip, std::uint16_t port) const
{
    // create UDP Socket
    UniqueSocket socketfd{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    if (socketfd.get() < 0)
    {
        throw_errno_error("socket () failed, please  try again");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    const std::string bind_ip_string{bind_ip};

    if (inet_pton(AF_INET, bind_ip_string.c_str(), &server_addr.sin_addr) != 1)
    {
        throw std::runtime_error{"Invalid bind ip address"};
    }
    // bind socket to IP and port
    if

    // loop call handle_query
}

void DnsServer::handle_query(int socket_fd) const
{
    (void)socket_fd;
    // recieve packet
    // decode packet
    // build response
    // send response
}
} // namespace dns
