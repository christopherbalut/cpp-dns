#include "dns/buffer.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

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
                last_error_ = BufferError::position_out_of_bounds;
                return;
            }

            if (pos + 1 >= size_)
            {
                last_error_ = BufferError::end_of_buffer;
                return;
            }

            const std::uint8_t second_byte{get(pos + 1)};
            const auto offset = static_cast<std::uint16_t>(
                ((static_cast<std::uint16_t>(length) & 0x3FU) << 8) | second_byte);

            if (offset >= size_)
            {
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

namespace
{
constexpr std::size_t dns_max_label_length = 63;
constexpr std::size_t dns_max_name_wire_length = 255;
} // namespace

[[nodiscard]] bool PacketBuffer::can_write(std::size_t byte_count) const
{
    return position_ <= max_size && byte_count <= (max_size - position_);
}

void PacketBuffer::update_size_after_write()
{
    size_ = std::max(size_, position_);
}

bool PacketBuffer::ok() const
{
    return last_error_ == BufferError::none;
}

BufferError PacketBuffer::last_error() const
{
    return last_error_;
}

void PacketBuffer::clear_error()
{
    last_error_ = BufferError::none;
}

void PacketBuffer::write(std::uint8_t value)
{
    if (!ok())
    {
        return;
    }

    if (!can_write(1))
    {
        last_error_ = BufferError::end_of_buffer;
        return;
    }

    buffer_[position_] = value;
    ++position_;
    update_size_after_write();
}

void PacketBuffer::write_u8(std::uint8_t value)
{
    write(value);
}

void PacketBuffer::write_u16(std::uint16_t value)
{
    if (!ok())
    {
        return;
    }

    if (!can_write(2))
    {
        last_error_ = BufferError::end_of_buffer;
        return;
    }

    buffer_[position_] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    position_++;

    buffer_[position_] = static_cast<std::uint8_t>(value & 0xFF);
    position_++;

    update_size_after_write();
}

void PacketBuffer::write_u32(std::uint32_t value)
{
    if (!ok())
    {
        return;
    }

    if (!can_write(4))
    {
        last_error_ = BufferError::end_of_buffer;
        return;
    }

    buffer_[position_] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    position_++;

    buffer_[position_] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    position_++;

    buffer_[position_] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    position_++;

    buffer_[position_] = static_cast<std::uint8_t>(value & 0xFF);
    position_++;

    update_size_after_write();
}

void PacketBuffer::write_qname(std::string_view qname)
{
    if (!ok())
    {
        return;
    }
    // check if we can write
    if (qname.empty() || qname == ".")
    {
        write_u8(0);
        return;
    }
    // trailing dot is ok
    if (!qname.empty() && qname.back() == '.')
    {
        qname.remove_suffix(1);
    }
    // check if empty
    if (qname.empty())
    {
        write_u8(0);
        return;
    }
    // validate and compute encoded size
    std::size_t encoded_size{1};
    std::size_t current_label_length{0};

    for (char ch : qname)
    {
        if (ch == '.') // we hit a dot, we reset everything now
        {
            if (current_label_length == 0) // edge case
            {
                last_error_ = BufferError::invalid_qname;
                return;
            }

            encoded_size += 1 + current_label_length; // not edge case
            current_label_length = 0;
            continue;
        }

        ++current_label_length; // increase cur len until we hit a dot or we surpass the max length
        if (current_label_length > dns_max_label_length)
        {
            last_error_ = BufferError::label_too_long;
            return;
        }
    }
    // check capcity
    if (current_label_length == 0) // check whether the last label used was empty
    {
        last_error_ = BufferError::invalid_qname; // ended in invalid way
        return;
    }
    encoded_size += 1 + current_label_length;    // add final label position
    if (encoded_size > dns_max_name_wire_length) // we stop if the size is too large
    {
        last_error_ = BufferError::qname_too_long;
        return;
    }
    // encode and write
    if (!can_write(encoded_size))
    {
        last_error_ = BufferError::end_of_buffer;
        return;
    }

    std::size_t label_start{};
    for (std::size_t i{}; i <= qname.size(); ++i)
    {
        const bool at_end = (i == qname.size());
        const bool at_dot = (!at_end && qname[i] == '.');
        if (!at_end && !at_dot)
        {
            continue;
        }
        const std::size_t label_length = i - label_start;
        buffer_[position_] = static_cast<std::uint8_t>(label_length);
        position_++;
        for (std::size_t j = label_start; j < i; ++j)
        {
            buffer_[position_] = static_cast<std::uint8_t>(static_cast<unsigned char>(qname[j]));
            position_++;
        }
        label_start = i + 1;
    }
    buffer_[position_] = 0;
    ++position_;
    update_size_after_write();
}

} // namespace dns
