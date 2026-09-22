#include "dns/socket_utils.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>

namespace dns
{

UniqueSocket::UniqueSocket(int fd)
    : fd_{fd} // explicit constructor to not allow accidental conversion from int to UniqueSocket
{
}

UniqueSocket::~UniqueSocket() // destructor for class
{
    if (fd_ >= 0)
    {
        close(fd_);
    }
}

UniqueSocket::UniqueSocket(UniqueSocket&& other) noexcept
    : fd_{std::exchange(other.fd_, -1)} // move constructor between two sockets
{
}

UniqueSocket& UniqueSocket::operator=(UniqueSocket&& other) noexcept // move assignment
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

int UniqueSocket::get() const // getter
{
    return fd_;
}

void throw_errno_error(const char* message)
{
    throw std::runtime_error{std::string{message} + ": " + std::strerror(errno)};
}

} // namespace dns
