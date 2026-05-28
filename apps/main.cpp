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
#include <utility>
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
        case dns::QueryType::NS:
            return "NS";
        case dns::QueryType::CNAME:
            return "CNAME";
        case dns::QueryType::MX:
            return "MX";
        case dns::QueryType::AAAA:
            return "AAAA";
        default:
            return "UNKNOWN";
    }
}

template <typename... Ts> struct Overloaded : Ts...
{
    using Ts::operator()...;
};

template <typename... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;

std::ostream& operator<<(std::ostream& os, const dns::DnsQuestion& question)
{
    os << "DnsQuestion {\n";
    os << "    name: \"" << question.name << "\",\n";
    os << "    qtype: " << query_type_string(question.qtype) << '\n';
    os << "}\n";
    return os;
}

std::ostream& operator<<(std::ostream& os, const dns::DnsHeader& header)
{
    os << "DnsHeader {\n";
    os << "    id: " << header.id << ",\n";
    os << "    recursion_desired: " << bool_string(header.recursion_desired) << ",\n";
    os << "    truncated_message: " << bool_string(header.truncated_message) << ",\n";
    os << "    authoritative_answer: " << bool_string(header.authoritative_answer) << ",\n";
    os << "    opcode: " << static_cast<int>(header.opcode) << ",\n";
    os << "    response: " << bool_string(header.response) << ",\n";
    os << "    rescode: " << static_cast<int>(header.rescode) << ",\n";
    os << "    checking_disabled: " << bool_string(header.checking_disabled) << ",\n";
    os << "    authed_data: " << bool_string(header.authed_data) << ",\n";
    os << "    z: " << bool_string(header.z) << ",\n";
    os << "    recursion_available: " << bool_string(header.recursion_available) << ",\n";
    os << "    questions: " << header.questions << ",\n";
    os << "    answers: " << header.answers << ",\n";
    os << "    authoritative_entries: " << header.authoritative_entries << ",\n";
    os << "    resource_entries: " << header.resource_entries << "\n";
    os << "}\n";

    return os;
}

std::ostream& operator<<(std::ostream& os, const dns::DnsRecord& record)
{
    std::visit(
        Overloaded{
            [&os](const dns::ARecord& rec)
            {
                os << "A {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    addr: " << static_cast<int>(rec.addr[0]) << "."
                   << static_cast<int>(rec.addr[1]) << "." << static_cast<int>(rec.addr[2]) << "."
                   << static_cast<int>(rec.addr[3]) << ",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::NSRecord& rec)
            {
                os << "NS {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    host: \"" << rec.host << "\",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::CNameRecord& rec)
            {
                os << "CNAME {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    host: \"" << rec.host << "\",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::MXRecord& rec)
            {
                os << "MX {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    priority: " << rec.priority << ",\n";
                os << "    host: \"" << rec.host << "\",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::AAAARecord& rec)
            {
                os << "AAAA {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    addr: ";

                for (std::size_t i = 0; i < rec.addr.size(); ++i)
                {
                    if (i != 0)
                    {
                        os << ":";
                    }

                    os << std::hex << rec.addr[i];
                }

                os << std::dec << ",\n";
                os << "    ttl: " << rec.ttl << "\n";
                os << "}\n";
            },

            [&os](const dns::UnknownRecord& rec)
            {
                os << "UNKNOWN {\n";
                os << "    domain: \"" << rec.domain << "\",\n";
                os << "    qtype: " << static_cast<int>(rec.qtype) << ",\n";
                os << "    ttl: " << rec.ttl << ",\n";
                os << "    data_len: " << rec.data_len << "\n";
                os << "}\n";
            },
        },
        record);
    return os;
}

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
