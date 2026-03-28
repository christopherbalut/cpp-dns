#include "dns/buffer.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <unistd.h>

namespace dns
{
PacketBuffer::PacketBuffer() = default;

void PacketBuffer::set(std::size_t pos, std::uint8_t value)
{
    if (pos >= max_size)
    {
        return;
    }

    buffer_[pos] = value;
}

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
        return;
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
        return;
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

    const auto first_byte =
        static_cast<std::uint16_t>(read_single_byte()); // read first byte as the upper byte
    const auto second_byte =
        static_cast<std::uint16_t>(read_single_byte()); // read second as the lower byte

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

    return static_cast<std::uint32_t>(
        ((first_byte << 24) | (second_byte << 16) | (third_byte << 8) | fourth_byte));
}

void PacketBuffer::read_qname(std::string& out)
{
    out.clear();

    std::size_t pos{position_};
    bool jumped{false};
    constexpr std::size_t max_jump{5};
    std::size_t jumps_performed{};

    std::string delimiter;

    while (true)
    {
        if (jumps_performed > max_jump)
        {
            std::cout << "read_qname(): position out of bounds\n";
            return;
        }

        const std::uint8_t length{get(pos)};

        if (length == 0)
        {
            ++pos;
            break;
        }

        if ((length & 0xC0) == 0xC0)
        {
            if (jumps_performed >= max_jump) // jump protection
            {
                std::cout << "read_qname() has too many compression jumps, exiting ...\n";
                return;
            }
            if (pos + 1 >= max_size)
            {
                std::cout << "qname() has an incomplete compression pointer\n";
                return;
            }
            const std::uint8_t second_byte{get(pos + 1)};
            const std::uint16_t offset{
                static_cast<std::uint16_t>(((length ^ 0xC0) << 8) | second_byte)};

            if (!jumped)
            {
                seek(pos + 2);
            }

            pos = offset;
            jumped = true;
            ++jumps_performed;
            continue;
        }

        ++pos;

        if (pos + length > max_size)
        {
            std::cout << "read_qname(): label extends past end of buffer\n";
            return;
        }

        out += delimiter;

        const auto label_bytes{get_range(pos, length)};
        for (const auto byte : label_bytes)
        {
            out += static_cast<char>(std::tolower(static_cast<unsigned char>(byte)));
        }
        delimiter = ".";
        pos += length;
    }

    if (!jumped)
    {
        seek(pos);
    }
    std::cout << out << "\n";
}
}; // namespace dns
