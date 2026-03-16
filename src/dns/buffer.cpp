#include "dns/buffer.hpp"
#include <cstddef>
#include <iostream>

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
        if (position() > max_size)
        {
            std::cout << "The position of the byte is greater than 512, exiting...\n";

           // ReadByteResult result{};
//            result.value = 0;
//            result.error = BufferError::end_of_buffer;
//            std::cout << "Buffer Error value is " << result.value << ", Buffer Error error is " << result.error << "\n";
//            return static_cast<uint8_t>(result);
            return 0;
        }
        std::uint8_t current_byte = buffer_[position()];
        ++position_;
        return current_byte;
    }
    std::uint8_t PacketBuffer::get(std::size_t position) const
    {
        // check for bounds to do later
        return buffer_[position];
    }

    std::span<const std::uint8_t> PacketBuffer::get_range(std::size_t start, std::size_t length) const
    {
        if (start > max_size)
        {
            return {};
        }

        if (length + start > max_size)
        {
            return {};
        }

        std::span<const std::uint8_t> full_view{buffer_};
        return full_view.subspan(start, length);
    }


    std::uint16_t read_u16()
    {
        return 0;
    }
            std::uint32_t read_u32();
};
