#include "dns/buffer.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <unistd.h>

namespace dns {
    PacketBuffer::PacketBuffer() = default;

    std::size_t PacketBuffer::position() const
    {
        return position_;
    }

    void PacketBuffer::step(std::size_t steps)
    {
        if (steps > max_size - position_)
        {
            std::cout << "position out of bounds in step method of PacketBuffer\n";
            last_error_ = BufferError::position_out_of_bounds;
        }
        position_ += steps;
        last_error_ = BufferError::none;
    }

    void PacketBuffer::seek(std::size_t position)
    {
        if (position > max_size)
        {
            std::cout << "position out of bounds in seek method of PacketBuffer\n";
            last_error_ = BufferError::position_out_of_bounds;
        }
        position_ = position;
        last_error_ = BufferError::none;
    }

    std::uint8_t PacketBuffer::read_single_byte()
    {
        if (position_ >= max_size)
        {
            std::cout << "The position of the byte is greater than 512, exiting...\n";
            return 0;
        }

        std::uint8_t current_byte = buffer_[position()];
        ++position_;
        return current_byte;
    }

    std::uint8_t PacketBuffer::get(std::size_t position) const
    {
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


    std::uint16_t PacketBuffer::read_u16()
    {
        if (position_ > max_size || 2 > (max_size - position_))
        {
            last_error_ = BufferError::end_of_buffer;
            return 0;
        }

        last_error_ = BufferError::none;

        const auto first_byte = static_cast<std::uint16_t>(read_single_byte()); // read first byte as the upper byte
        const auto second_byte = static_cast<std::uint16_t>(read_single_byte()); // read second as the lower byte

        return static_cast<std::uint16_t>((first_byte << 8 | second_byte));
    }
    std::uint32_t PacketBuffer::read_u32() 
    {
        if (position_ > max_size || 4 > (max_size - position_))
        {
            last_error_ = BufferError::end_of_buffer;
            return 0;
        }

        last_error_ = BufferError::none;

        const auto first_byte = static_cast<std::uint32_t>(read_single_byte());
        const auto second_byte = static_cast<std::uint32_t>(read_single_byte());
        const auto third_byte = static_cast<std::uint32_t>(read_single_byte());
        const auto fourth_byte = static_cast<std::uint32_t>(read_single_byte());

        return static_cast<std::uint32_t>(((first_byte << 24) | (second_byte << 16) | (third_byte << 8) | fourth_byte));
    }

    void PacketBuffer::read_qname(std::string& out)
    {
        std::cout << out << "\n";
    }
};
