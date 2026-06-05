#pragma once

namespace dns
{
class UniqueSocket
{
  public:
    explicit UniqueSocket(int fd);

    ~UniqueSocket(); // destructor for class

    UniqueSocket(const UniqueSocket&) = delete;            // disable copy constructor
    UniqueSocket& operator=(const UniqueSocket&) = delete; // disable copy assignment

    UniqueSocket(UniqueSocket&& other) noexcept;
    UniqueSocket& operator=(UniqueSocket&& other) noexcept; // move assignment

    [[nodiscard]] int get() const;

  private:
    int fd_{-1}; // initialize by default the fd to -1 i.e. no ownership
};
void throw_errno_error(const char* message);
} // namespace dns
