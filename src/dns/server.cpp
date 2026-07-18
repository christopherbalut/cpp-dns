#include "dns/server.hpp"
#include "dns/blocklist.hpp"
#include "dns/buffer.hpp"
#include "dns/packet.hpp"
#include "dns/server_stats.hpp"
#include "dns/socket_utils.hpp"
#include "dns/types.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <exception>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <utility>

namespace dns
{

DnsPacket make_base_response(const DnsPacket& request)
{
    DnsPacket response{};

    response.header.id = request.header.id;
    response.header.response = true;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = true;

    return response;
}

DnsPacket make_formerr_response(const DnsPacket& request)
{
    DnsPacket response = make_base_response(request);
    response.header.rescode = ResultCode::formerr;
    return response;
}

DnsPacket make_servfail_response(const DnsPacket& request, DnsQuestion question)
{
    DnsPacket response = make_base_response(request);

    response.header.rescode = ResultCode::servfail;
    response.questions.emplace_back(std::move(question));

    return response;
}

DnsPacket make_forwarded_response(const DnsPacket& request, DnsQuestion question,
                                  DnsPacket upstream)
{
    DnsPacket response = make_base_response(request);

    response.questions.emplace_back(std::move(question));
    response.header.rescode = upstream.header.rescode;

    response.answers = std::move(upstream.answers);
    response.authorities = std::move(upstream.authorities);
    response.resources = std::move(upstream.resources);

    return response;
}

DnsPacket make_blocked_response(const DnsPacket& request, DnsQuestion question)
{
    DnsPacket response = make_base_response(request);

    response.header.rescode = ResultCode::nxdomain;
    response.questions.emplace_back(std::move(question));

    return response;
}

DnsServer::DnsServer(ServerConfig config, std::shared_ptr<ResolverInterface> resolver)
    : config_{std::move(config)}, resolver_{std::move(resolver)}
{
    if (resolver_ == nullptr)
    {
        throw std::invalid_argument("resolver cannot be null");
    }
    const BlocklistLoadResult result{blocklist_.load_from_file(config_.blocklist_path)};

    std::cout << "Loaded " << result.domains_loaded << " blocked domains, skipped "
              << result.lines_skipped << " lines\n";
}

void DnsServer::run() const
{
    run(config_.bind_ip, config_.port);
}

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

    std::jthread stats_logger{[this](std::stop_token stop_token)
                              { log_stats_periodically(stop_token); }};

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

void DnsServer::log_stats_periodically(const std::stop_token& stop_token) const
{
    while (!stop_token.stop_requested())
    {
        std::this_thread::sleep_for(std::chrono::seconds{5});

        const ServerStats stats = stats_.snapshot();

        std::cout << "[stats] received=" << stats.queries_received
                  << " forwarded=" << stats.queries_forwarded
                  << " blocked=" << stats.blocked_queries << "\n";
    }
}

DnsPacket DnsServer::make_response_for_request(DnsPacket request) const
{
    if (request.questions.empty())
    {
        stats_.record_formerr_response();
        return make_formerr_response(request);
    }

    DnsQuestion question = std::move(request.questions.back());
    request.questions.pop_back();

    std::cout << "Received query: " << question.name << "\n";

    if (blocklist_.contains(question.name))
    {
        stats_.record_blocked_queries();
        return make_blocked_response(request, std::move(question));
    }

    try
    {
        // if request has a question, forward it upstream
        stats_.record_query_forwarded();

        DnsPacket result = resolver_->lookup(question.name, question.qtype);

        // copy upstream answers in response
        return make_forwarded_response(request, std::move(question), std::move(result));
    }
    catch (const std::exception& error)
    {
        std::cerr << "Upstream lookup failed: " << error.what() << "\n";

        stats_.record_servfail_response();
        stats_.record_upstream_failure();

        // if upstream fails, return SERVFAIL
        return make_servfail_response(request, std::move(question));
    }
}

void DnsServer::handle_query(int socket_fd) const
{
    // receive packet
    // prepare empty storage for packet bytes
    PacketBuffer request_packet{};

    // prepare empty storage for client address
    sockaddr_storage client_addr{};

    // block/wait until a UDP DNS query arrives
    socklen_t client_addr_len = sizeof(client_addr);

    // recvfrom() fills the packet buffer with the bytes
    const ssize_t bytes_received =
        recvfrom(socket_fd, request_packet.data(), PacketBuffer::max_size, 0,
                 reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);

    // recvfrom() fills the client_addr with the sender's address
    // check for receive errors
    if (bytes_received < 0)
    {
        throw_errno_error("recvfrom() failed...");
    }

    stats_.record_query_received();

    // tell PacketBuffer how many bytes are valid
    request_packet.set_size(static_cast<std::size_t>(bytes_received));

    // reset cursor to the beginning
    request_packet.seek(0);

    // process the query on a separate worker thread
    std::thread worker{
        [this, socket_fd, request_packet = std::move(request_packet), client_addr,
         client_addr_len]() mutable
        {
            try
            {
                // decode packet
                DnsPacket request{};
                request.decode_from_buffer(request_packet);

                // build response
                DnsPacket response{};

                // if request is malformed: return formerr
                if (!request_packet.ok())
                {
                    stats_.record_formerr_response();
                    response = make_formerr_response(request);
                }
                else
                {
                    response = make_response_for_request(std::move(request));
                }

                // serialize response into bytes
                PacketBuffer response_buffer{};
                response.write_to_buffer(response_buffer);

                if (!response_buffer.ok())
                {
                    throw std::runtime_error{"failed to write DNS response packet"};
                }

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
            catch (const std::exception& error)
            {
                std::cerr << "Failed to process query: " << error.what() << "\n";
            }
        }};

    worker.detach();
}
} // namespace dns
