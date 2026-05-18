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

#include <arpa/inet.h>  // inet_pton()
#include <netinet/in.h> // sockaddr_in, htons()
#include <sys/socket.h> // socket(), AF_INET, SOCK_DGRAM
#include <unistd.h>     // close()

namespace
{

void load_file_into_packet_buffer(const std::string& path, dns::PacketBuffer& buffer)
{
    std::ifstream input(path, std::ios::binary); // open file and read raw bytes
    if (!input)
    {
        throw std::runtime_error("Runtime Error, failed to open file " + path + ", exiting...\n");
    }

    std::array<char, dns::PacketBuffer::max_size> bytes{}; // array of char
    input.read(bytes.data(), static_cast<std::streamsize>(
                                 bytes.size())); // read up to bytes.size() number of bytes in file
    const std::streamsize count{input.gcount()}; // store the actual number of bytes used

    if (count <= 0)
    {
        throw std::runtime_error("Runtime Error, path file is empty: " + path);
    }

    if (input.bad())
    {
        throw std::runtime_error("Runtime Error, failed while reading file: " + path);
    }

    for (std::size_t i{}; i < static_cast<std::size_t>(count); ++i)
    {
        buffer.set(i, static_cast<std::uint8_t>(bytes[i])); // copy one byte into temp file
    }

    buffer.seek(0); // reset PacketBuffer to restart decoding
}

void print_record(const dns::DnsRecord& record)
{
    std::visit(             // visit the value storred in std::variant
        [](const auto& rec) // lambda function used be whichever record type inside the variant
        {
            using T = std::decay_t<decltype(rec)>; // extract type of rec and remove reference /
                                                   // const qualifiers

            if constexpr (std::is_same_v<T, dns::ARecord>) // compiled when branch rec is ARecord
            {
                std::cout << "ARecord {\n";
                std::cout << "  domain: " << rec.domain << "\n";
                std::cout << "  addr: " << static_cast<unsigned>(rec.addr[0]) << "."
                          << static_cast<unsigned>(rec.addr[1]) << "."
                          << static_cast<unsigned>(rec.addr[2]) << "."
                          << static_cast<unsigned>(rec.addr[3]) << "\n";
                std::cout << "  ttl: " << rec.ttl << "\n";
                std::cout << "}\n";
            }
            else if constexpr (std::is_same_v<T, dns::UnknownRecord>) // same as other constexpry
                                                                      // branch
            {
                std::cout << "UnknownRecord {\n";
                std::cout << "  domain: " << rec.domain << "\n";
                std::cout << "  qtype: " << rec.qtype << "\n";
                std::cout << "  data_len: " << rec.data_len << "\n";
                std::cout << "  ttl: " << rec.ttl << "\n";
                std::cout << "}\n";
            }
        },
        record);
}

void print_packet(const dns::DnsPacket& packet)
{
    std::cout << "Header\n";
    std::cout << "  id: " << packet.header.id << "\n";
    std::cout << "  questions: " << packet.header.questions << "\n";
    std::cout << "  answers: " << packet.header.answers << "\n";
    std::cout << "  authoritative_entries: " << packet.header.authoritative_entries << "\n";
    std::cout << "  resource_entries: " << packet.header.resource_entries << "\n";
    std::cout << "  response: " << packet.header.response << "\n";
    std::cout << "  recursion_desired: " << packet.header.recursion_desired << "\n";
    std::cout << "  recursion_available: " << packet.header.recursion_available << "\n";
    std::cout << "\n";

    std::cout << "Questions\n";
    for (const auto& question : packet.questions)
    {
        std::cout << "  name: " << question.name
                  << ", qtype: " << static_cast<unsigned>(question.qtype) << "\n";
    }
    std::cout << "\n";

    std::cout << "Answers\n";
    for (const auto& answer : packet.answers)
    {
        print_record(answer);
    }
    std::cout << "\n";

    std::cout << "Authorities\n";
    for (const auto& authority : packet.authorities)
    {
        print_record(authority);
    }
    std::cout << "\n";

    std::cout << "Resources\n";
    for (const auto& resource : packet.resources)
    {
        print_record(resource);
    }
    std::cout << "\n";
}
} // namespace

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

    // send buffer through UDP socket
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        std::cerr << "socket() failed: " << std::strerror(errno) << '\n';
        return 1;
    }

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(53);

    // receive response bytes

    // decode into dns packet

    return 0;
}
