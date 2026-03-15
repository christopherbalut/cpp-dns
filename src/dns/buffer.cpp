#include "dns/buffer.hpp"
#include <cstddef>

namespace dns {
    PacketBuffer::PacketBuffer() = default;

    std::size_t PacketBuffer::position() const
    {
        return position_;
    }

    void PacketBuffer::step(std::size_t steps)
    {
        position_ += steps;
    }

    void PacketBuffer::seek(std::size_t position)
    {
        position_ = position;
    }

    std::uint8_t PacketBuffer::read()
    {
        return 0;
    }

};
