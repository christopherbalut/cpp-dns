#include "dns/buffer.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>

namespace dns
{
PacketBuffer::PacketBuffer() = default;

void PacketBuffer::set(std::size_t pos, std::uint8_t value)
{
    if (pos >= max_size)
    {
        last_error_ = BufferError::position_out_of_bounds;
        return;
    }

    buffer_[pos] = value;

    size_ = std::max(pos + 1, size_);

    last_error_ = BufferError::none;
}

std::size_t PacketBuffer::position() const
{
    return position_;
}

void PacketBuffer::step(std::size_t steps)
{
    if (position_ > size_ || steps > (size_ - position_))
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
    if (position > size_)
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
    if (position_ >= size_)
    {
        std::cout << "read_single_byte(): reached end of valid buffer data\n";
        last_error_ = BufferError::end_of_buffer;
        return 0;
    }

    const std::uint8_t current_byte = buffer_[position_];
    ++position_;
    last_error_ = BufferError::none;
    return current_byte;
}

std::uint8_t PacketBuffer::get(std::size_t position) const
{
    if (position >= size_)
    {
        return 0;
    }

    return buffer_[position];
}

std::span<const std::uint8_t> PacketBuffer::get_range(std::size_t start, std::size_t length) const
{
    if (start > size_)
    {
        return {};
    }

    if (length > (size_ - start))
    {
        return {};
    }

    std::span<const std::uint8_t> full_view{buffer_.data(), size_};
    return full_view.subspan(start, length);
}

std::uint16_t PacketBuffer::read_u16()
{
    if (position_ > size_ || 2 > (size_ - position_))
    {
        last_error_ = BufferError::end_of_buffer;
        return 0;
    }

    const auto first_byte = static_cast<std::uint16_t>(read_single_byte());
    const auto second_byte = static_cast<std::uint16_t>(read_single_byte());

    if (last_error_ != BufferError::none)
    {
        return 0;
    }

    last_error_ = BufferError::none;
    return static_cast<std::uint16_t>((first_byte << 8) | second_byte);
}

std::uint32_t PacketBuffer::read_u32()
{
    if (position_ > size_ || 4 > (size_ - position_))
    {
        last_error_ = BufferError::end_of_buffer;
        return 0;
    }

    const auto first_byte = static_cast<std::uint32_t>(read_single_byte());
    const auto second_byte = static_cast<std::uint32_t>(read_single_byte());
    const auto third_byte = static_cast<std::uint32_t>(read_single_byte());
    const auto fourth_byte = static_cast<std::uint32_t>(read_single_byte());

    if (last_error_ != BufferError::none)
    {
        return 0;
    }

    last_error_ = BufferError::none;
    return static_cast<std::uint32_t>((first_byte << 24) | (second_byte << 16) | (third_byte << 8) |
                                      fourth_byte);
}

void PacketBuffer::read_qname(std::string& out)
{
    out.clear();

    std::size_t pos{position_};
    bool jumped{false};
    constexpr std::size_t max_jumps{5};
    std::size_t jumps_performed{0};

    std::string delimiter;

    while (true)
    {
        if (pos >= size_)
        {
            std::cout << "read_qname(): position out of bounds\n";
            last_error_ = BufferError::end_of_buffer;
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
            if (jumps_performed >= max_jumps)
            {
                std::cout << "read_qname(): too many compression jumps\n";
                last_error_ = BufferError::position_out_of_bounds;
                return;
            }

            if (pos + 1 >= size_)
            {
                std::cout << "read_qname(): incomplete compression pointer\n";
                last_error_ = BufferError::end_of_buffer;
                return;
            }

            const std::uint8_t second_byte{get(pos + 1)};
            const std::uint16_t offset = static_cast<std::uint16_t>(
                ((static_cast<std::uint16_t>(length) & 0x3FU) << 8) | second_byte);

            if (offset >= size_)
            {
                std::cout << "read_qname(): compression pointer out of bounds\n";
                last_error_ = BufferError::position_out_of_bounds;
                return;
            }

            if (!jumped)
            {
                seek(pos + 2);
                if (last_error_ != BufferError::none)
                {
                    return;
                }
            }

            pos = offset;
            jumped = true;
            ++jumps_performed;
            continue;
        }

        ++pos;

        if (pos + length > size_)
        {
            std::cout << "read_qname(): label extends past end of valid buffer data\n";
            last_error_ = BufferError::end_of_buffer;
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
        if (last_error_ != BufferError::none)
        {
            return;
        }
    }

    last_error_ = BufferError::none;
}
} // namespace dns
