#include "dns/buffer.hpp"
#include "dns/packet.hpp"
#include "dns/record.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <variant>

#include <arpa/inet.h> // inet_pton()
#include <iomanip>
#include <netdb.h>
#include <netinet/in.h> // sockaddr_in, htons()
#include <sys/socket.h> // socket(), AF_INET, SOCK_DGRAM
#include <unistd.h>     // close()

std::string bool_string(bool value)
{
    return value ? "true" : "false";
}

std::string query_type_string(dns::QueryType qtype)
{
    switch (qtype)
    {
        case dns::QueryType::A:
            return "A";
        default:
            return "UNKNOWN";
    }
}

void print_question(const dns::DnsQuestion& question)
{
    std::cout << "DnsQuestion {\n";
    std::cout << "    name: \"" << question.name << "\",\n";
    std::cout << "    qtype: " << query_type_string(question.qtype) << '\n';
    std::cout << "}\n";
}

void print_header(const dns::DnsHeader& header)
{
    std::cout << "DnsHeader {\n";
    std::cout << "    id: " << header.id << ",\n";
    std::cout << "    recursion_desired: " << bool_string(header.recursion_desired) << ",\n";
    std::cout << "    truncated_message: " << bool_string(header.truncated_message) << ",\n";
    std::cout << "    authoritative_answer: " << bool_string(header.authoritative_answer) << ",\n";
    std::cout << "    opcode: " << static_cast<int>(header.opcode) << ",\n";
    std::cout << "    response: " << bool_string(header.response) << ",\n";
    std::cout << "    rescode: " << static_cast<int>(header.rescode) << ",\n";
    std::cout << "    checking_disabled: " << bool_string(header.checking_disabled) << ",\n";
    std::cout << "    authed_data: " << bool_string(header.authed_data) << ",\n";
    std::cout << "    z: " << bool_string(header.z) << ",\n";
    std::cout << "    recursion_available: " << bool_string(header.recursion_available) << ",\n";
    std::cout << "    questions: " << header.questions << ",\n";
    std::cout << "    answers: " << header.answers << ",\n";
    std::cout << "    authoritative_entries: " << header.authoritative_entries << ",\n";
    std::cout << "    resource_entries: " << header.resource_entries << "\n";
    std::cout << "}\n";
}

void print_record(const dns::DnsRecord& record)
{
    std::visit(
        [](const auto& rec)
        {
            using T = std::decay_t<decltype(rec)>;

            if constexpr (std::is_same_v<T, dns::ARecord>)
            {
                std::cout << "A {\n";
                std::cout << "    domain: \"" << rec.domain << "\",\n";
                std::cout << "    addr: " << static_cast<int>(rec.addr[0]) << "."
                          << static_cast<int>(rec.addr[1]) << "." << static_cast<int>(rec.addr[2])
                          << "." << static_cast<int>(rec.addr[3]) << ",\n";
                std::cout << "    ttl: " << rec.ttl << "\n";
                std::cout << "}\n";
            }
            else if constexpr (std::is_same_v<T, dns::UnknownRecord>)
            {
                std::cout << "UNKNOWN {\n";
                std::cout << "    domain: \"" << rec.domain << "\",\n";
                std::cout << "    qtype: " << static_cast<int>(rec.qtype) << ",\n";
                std::cout << "    ttl: " << rec.ttl << ",\n";
                std::cout << "    data_len: " << rec.data_len << "\n";
                std::cout << "}\n";
            }
        },
        record);
}

int main()
{
    // create DNS Packet and fill header
    dns::DnsPacket packet{}; // create empty dns packet
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;

    dns::DnsQuestion question{};
    question.name = "google.com";
    question.qtype = dns::QueryType::A;

    packet.questions.emplace_back(question);
    packet.header.questions = static_cast<std::uint16_t>(packet.questions.size());

    // write packet into PacketBuffer
    dns::PacketBuffer request_buffer{};
    packet.write_to_buffer(request_buffer);

    if (!request_buffer.ok())
    {
        std::cerr << "failed to write DNS request packet\n";
        return 1;
    }

    std::cout << "Request Buffer size: " << request_buffer.position() << " bytes\n";

    for (std::size_t i{}; i < request_buffer.position(); ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(request_buffer.data()[i]) << ' ';
    }

    std::cout << std::dec << "\n";

    // send buffer through UDP socket
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        std::cerr << "socket() failed: " << std::strerror(errno) << '\n';
        return 1;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* server_info = nullptr;

    const int status = getaddrinfo("8.8.8.8", "53", &hints, &server_info);

    if (status != 0)
    {
        std::cerr << "getaddrinfo() failed: " << gai_strerror(status) << '\n';
        close(socketfd);
        return 1;
    }

    const std::size_t bytes_to_send = request_buffer.position();
    const ssize_t bytes_sent = sendto(socketfd, request_buffer.data(), bytes_to_send, 0,
                                      server_info->ai_addr, server_info->ai_addrlen);

    if (bytes_sent < 0)
    {
        std::cerr << "sendto() failed: " << std::strerror(errno) << '\n';
        freeaddrinfo(server_info);
        close(socketfd);
        return 1;
    }

    if (static_cast<std::size_t>(bytes_sent) != bytes_to_send)
    {
        std::cerr << "sendto() sent fewer bytes than expected\n";
        freeaddrinfo(server_info);
        close(socketfd);
        return 1;
    }

    std::cout << "Sent " << bytes_sent << " bytes\n";

    freeaddrinfo(server_info);

    // receive response bytes
    dns::PacketBuffer response_buffer{};

    std::cout << "Before recvfrom(): position = " << response_buffer.position()
              << ", size = " << response_buffer.size() << '\n';

    const ssize_t bytes_received = recvfrom(socketfd, response_buffer.data(),
                                            dns::PacketBuffer::max_size, 0, nullptr, nullptr);

    if (bytes_received < 0)
    {
        std::cerr << "recvfrom() failed: " << std::strerror(errno) << '\n';
        close(socketfd);
        return 1;
    }

    std::cout << "After recvfrom(): position = " << response_buffer.position()
              << ", size = " << response_buffer.size() << '\n';

    std::cout << "Received " << bytes_received << " bytes\n";

    response_buffer.set_size(static_cast<std::size_t>(bytes_received));
    response_buffer.seek(0);

    std::cout << "After set_size(): position = " << response_buffer.position()
              << ", size = " << response_buffer.size() << '\n';

    // decode into dns packet
    dns::DnsPacket response_packet{};
    response_packet.decode_from_buffer(response_buffer);

    if (!response_buffer.ok())
    {
        std::cerr << "response buffer error after decode\n";
        close(socketfd);
        return 1;
    }

    print_header(response_packet.header);

    for (const auto& question : response_packet.questions)
    {
        print_question(question);
    }

    for (const auto& record : response_packet.answers)
    {
        print_record(record);
    }

    for (const auto& record : response_packet.authorities)
    {
        print_record(record);
    }

    for (const auto& record : response_packet.resources)
    {
        print_record(record);
    }
    close(socketfd);

    return 0;
}
