#include "dns/server.hpp"
#include "dns/socket_utils.hpp"

#include <netinet/ip.h>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>

namespace dns
{
DnsServer::DnsServer(StubResolver resolver) : resolver_{std::move(resolver)} {}

void DnsServer::run(std::string_view bind_ip, std::uint16_t port) const
{
    (void)bind_ip;
    (void)port;
    // setup socket
    // bind socket
    // loop forever
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
