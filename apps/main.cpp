#include "dns/buffer.hpp"
#include "dns/packet.hpp"
#include "dns/record.hpp"
#include "dns/stub_resolver.hpp"

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
    try
    {
        dns::StubResolver resolver{};
        dns::DnsPacket response_packet = resolver.lookup("google.com", dns::QueryType::A);

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
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
