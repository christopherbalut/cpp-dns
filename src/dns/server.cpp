#include "dns/server.hpp"
#include "dns/buffer.hpp"
#include "dns/packet.hpp"
#include "dns/socket_utils.hpp"
#include "dns/types.hpp"

#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>

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
    if (bind(socketfd.get(), reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) <
        0)
    {
        throw_errno_error("bind() failed");
    }

    std::cout << "DNS Server listening on " << bind_ip << ':' << port << "\n";

    // loop call handle_query
    while (true)
    {
        try
        {
            handle_query(socketfd.get());
        }
        catch (const std::exception& error)
        {
            std::cerr << "An error occurred while handle query: " << error.what() << "\n";
        }
    }
}

void DnsServer::handle_query(int socket_fd) const
{
    // recieve packet
    // prepare empty storage for packet bytes
    PacketBuffer request_packet{};
    // prepare empty storage for client address
    sockaddr_storage client_addr{};
    // block/wait until a UDP DNS query arrives
    socklen_t client_addr_len = sizeof(client_addr);
    // recvfrom() fills the packet buffer with the bytes
    const ssize_t bytes_recieved =
        recvfrom(socket_fd, request_packet.data(), PacketBuffer::max_size, 0,
                 reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    // recvfrom() fills the client_addr with the senders address
    // check for recieve errors
    if (bytes_recieved < 0)
    {
        throw_errno_error("recvfrom() failed...");
    }
    // tell PacketBuffer how many bytes are valid
    request_packet.set_size(static_cast<std::size_t>(bytes_recieved));
    // reset cursor to the beginning
    request_packet.seek(0);
    // now packet is ready to decode
    // decode packet
    DnsPacket request{};
    request.decode_from_buffer(request_packet);
    // build response
    //
    // create empty DNS response packet
    DnsPacket response{};
    // make id match the clients request id
    response.header.id = request.header.id;
    response.header.response = true;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = true;
    // mark it as the response
    // if request is malformed: return FORMERR
    if (!request_packet.ok())
    {
        response.header.rescode = ResultCode::formerr;
    }
    else if (request.questions.empty())
    {
        response.header.rescode = ResultCode::formerr;
    }
    else
    {
        DnsQuestion question = std::move(request.questions.back());
        request.questions.pop_back();

        std::cout << "Recieved query: " << question.name << "\n";

        response.questions.emplace_back(question);

        try
        {
            DnsPacket result = resolver_.lookup(question.name, question.qtype);

            response.header.rescode = result.header.rescode;
            response.answers = std::move(result.answers);
            response.authorities = std::move(result.authorities);
            response.resources = std::move(result.resources);
        }
        catch (const std::exception& error)
        {
            std::cerr << "Upstream lookup failed: " << error.what() << "\n";
            response.header.rescode = ResultCode::servfail;
        }
    }

    PacketBuffer response_buffer{};
    response.write_to_buffer(response_buffer);

    if (!response_buffer.ok())
    {
        throw std::runtime_error{"failed to write DNS reponse packet"};
    }

    // if request has a question, foward it upstream
    // copy upstream answers in reponse
    // if upstream fails. return SERVFAIL
    // serialize response into bytes
    // send response
    const std::size_t bytes_to_send{response_buffer.position()};

    const ssize_t bytes_sent{sendto(socket_fd, response_buffer.data(), bytes_to_send, 0,
                                    reinterpret_cast<const sockaddr*>(&client_addr),
                                    client_addr_len)};
    if (bytes_sent < 0)
    {
        throw_errno_error("sendto() failed");
    }

    if (static_cast<std::size_t>(bytes_sent) != bytes_to_send)
    {
        throw std::runtime_error{"sendto() sent fewer bytes than expected"};
    }
}
} // namespace dns
