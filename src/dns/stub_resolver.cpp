#include "dns/stub_resolver.hpp"

#include "dns/buffer.hpp"
#include "dns/question.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace
{

class UniqueSocket // wrapper class to own socket file descriptor
{
  public:
    explicit UniqueSocket(int fd)
        : fd_{fd} {} // explicit constructor to now allow conversion from int to UniqueSocket

    ~UniqueSocket() // destructor for class
    {
        if (fd_ >= 0)
        {
            close(fd_);
        }
    }

    UniqueSocket(const UniqueSocket&) = delete;            // disable copy constructor
    UniqueSocket& operator=(const UniqueSocket&) = delete; // disable copy assignment

    UniqueSocket(UniqueSocket&& other) noexcept
        : fd_{std::exchange(other.fd_, -1)} {} // move constructor between two sockets

    UniqueSocket& operator=(UniqueSocket&& other) noexcept // move assignment
    {
        if (this != &other) // removes weird s1 = move(s1)
        {
            if (fd_ >= 0)
            {
                close(fd_);
            }

            fd_ = std::exchange(other.fd_, -1);
        }

        return *this;
    }

    [[nodiscard]] int get() const // getter
    {
        return fd_;
    }

  private:
    int fd_{-1}; // initialize by default the fd to -1 i.e. no ownership
};

struct AddrInfoDeleter
{
    void operator()(addrinfo* info) const
    {
        if (info != nullptr)
        {
            freeaddrinfo(info);
        }
    }
};

using AddrInfoPtr = std::unique_ptr<addrinfo, AddrInfoDeleter>;

[[noreturn]] void throw_errno_error(const char* message)
{
    throw std::runtime_error(std::string{message} + ": " + std::strerror(errno));
}

} // namespace

namespace dns
{

StubResolver::StubResolver() : StubResolver{"8.8.8.8", "53"} {}

StubResolver::StubResolver(std::string server_ip, std::string server_port)
    : server_ip_{std::move(server_ip)}, server_port_{std::move(server_port)}
{
}

DnsPacket StubResolver::make_query_packet(std::string name, QueryType qtype)
{
    DnsPacket packet{};
    packet.header.id = 6666;
    packet.header.recursion_desired = true;

    DnsQuestion question{};
    question.name = std::move(name);
    question.qtype = qtype;

    packet.questions.emplace_back(std::move(question));
    packet.header.questions = static_cast<std::uint16_t>(packet.questions.size());

    return packet;
}

DnsPacket StubResolver::lookup(std::string_view name, QueryType qtype) const
{
    DnsPacket request_packet = make_query_packet(std::string{name}, qtype);

    PacketBuffer request_buffer{};
    request_packet.write_to_buffer(request_buffer);

    if (!request_buffer.ok())
    {
        throw std::runtime_error{"failed to write DNS request packet"};
    }

    UniqueSocket socketfd{socket(AF_INET, SOCK_DGRAM, 0)};

    if (socketfd.get() < 0)
    {
        throw_errno_error("socket() failed");
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* raw_server_info = nullptr;

    const int status =
        getaddrinfo(server_ip_.c_str(), server_port_.c_str(), &hints, &raw_server_info);

    if (status != 0)
    {
        throw std::runtime_error{std::string{"getaddrinfo() failed: "} + gai_strerror(status)};
    }

    AddrInfoPtr server_info{raw_server_info};

    const std::size_t bytes_to_send = request_buffer.position();

    const ssize_t bytes_sent = sendto(socketfd.get(), request_buffer.data(), bytes_to_send, 0,
                                      server_info->ai_addr, server_info->ai_addrlen);

    if (bytes_sent < 0)
    {
        throw_errno_error("sendto() failed");
    }

    if (static_cast<std::size_t>(bytes_sent) != bytes_to_send)
    {
        throw std::runtime_error{"sendto() sent fewer bytes than expected"};
    }

    PacketBuffer response_buffer{};

    const ssize_t bytes_received = recvfrom(socketfd.get(), response_buffer.data(),
                                            PacketBuffer::max_size, 0, nullptr, nullptr);

    if (bytes_received < 0)
    {
        throw_errno_error("recvfrom() failed");
    }

    response_buffer.set_size(static_cast<std::size_t>(bytes_received));
    response_buffer.seek(0);

    DnsPacket response_packet{};
    response_packet.decode_from_buffer(response_buffer);

    if (!response_buffer.ok())
    {
        throw std::runtime_error{"response buffer error after decode"};
    }

    return response_packet;
}

} // namespace dns
