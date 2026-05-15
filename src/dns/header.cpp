#include "dns/header.hpp"
#include "dns/buffer.hpp"
#include "dns/types.hpp"
#include <cstdint>

namespace dns
{
namespace
{
constexpr std::uint8_t low_nibble_mask = 0x0F;

constexpr std::uint8_t recursion_desired_bit = 0;
constexpr std::uint8_t truncated_message_bit = 1;
constexpr std::uint8_t authoritative_answer_bit = 2;
constexpr std::uint8_t opcode_shift = 3;
constexpr std::uint8_t response_bit = 7;

constexpr std::uint8_t checking_disabled_bit = 4;
constexpr std::uint8_t authed_data_bit = 5;
constexpr std::uint8_t z_bit = 6;
constexpr std::uint8_t recursion_available_bit = 7;
} // namespace

void DnsHeader::decode(PacketBuffer& buffer)
{
    if (!buffer.ok())
    {
        return;
    }

    id = buffer.read_u16();
    if (!buffer.ok())
    {
        return;
    }

    const std::uint16_t flag{buffer.read_u16()};
    if (!buffer.ok())
    {
        return;
    }

    const std::uint8_t top_8_bytes{static_cast<std::uint8_t>(flag >> 8)};
    const std::uint8_t bottom_8_bytes{static_cast<std::uint8_t>(flag & 0xFF)};

    recursion_desired = (top_8_bytes & (1U << recursion_desired_bit)) != 0;
    truncated_message = (top_8_bytes & (1U << truncated_message_bit)) != 0;
    authoritative_answer = (top_8_bytes & (1U << authoritative_answer_bit)) != 0;
    opcode = static_cast<std::uint8_t>((top_8_bytes >> opcode_shift) & low_nibble_mask);
    response = (top_8_bytes & (1U << response_bit)) != 0;

    rescode = to_result_code(static_cast<std::uint8_t>(bottom_8_bytes & low_nibble_mask));
    checking_disabled = (bottom_8_bytes & (1U << checking_disabled_bit)) != 0;
    authed_data = (bottom_8_bytes & (1U << authed_data_bit)) != 0;
    z = (bottom_8_bytes & (1U << z_bit)) != 0;
    recursion_available = (bottom_8_bytes & (1U << recursion_available_bit)) != 0;

    questions = buffer.read_u16();
    if (!buffer.ok())
    {
        return;
    }

    answers = buffer.read_u16();
    if (!buffer.ok())
    {
        return;
    }

    authoritative_entries = buffer.read_u16();
    if (!buffer.ok())
    {
        return;
    }

    resource_entries = buffer.read_u16();
}

void DnsHeader::write(PacketBuffer& buffer) const
{
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_u16(id);
    if (!buffer.ok())
    {
        return;
    }

    std::uint8_t top_8_bits{0};
    top_8_bits |= static_cast<std::uint8_t>(recursion_desired ? (1U << recursion_desired_bit) : 0U);
    top_8_bits |= static_cast<std::uint8_t>(truncated_message ? (1U << truncated_message_bit) : 0U);
    top_8_bits |=
        static_cast<std::uint8_t>(authoritative_answer ? (1U << authoritative_answer_bit) : 0U);
    top_8_bits |= static_cast<std::uint8_t>((opcode & low_nibble_mask) << opcode_shift);
    top_8_bits |= static_cast<std::uint8_t>(response ? (1U << response_bit) : 0U);

    buffer.write_u8(top_8_bits);
    if (!buffer.ok())
    {
        return;
    }

    std::uint8_t bottom_8_bits{0};
    bottom_8_bits |=
        static_cast<std::uint8_t>(static_cast<std::uint8_t>(rescode) & low_nibble_mask);
    bottom_8_bits |=
        static_cast<std::uint8_t>(checking_disabled ? (1U << checking_disabled_bit) : 0U);
    bottom_8_bits |= static_cast<std::uint8_t>(authed_data ? (1U << authed_data_bit) : 0U);
    bottom_8_bits |= static_cast<std::uint8_t>(z ? (1U << z_bit) : 0U);
    bottom_8_bits |=
        static_cast<std::uint8_t>(recursion_available ? (1U << recursion_available_bit) : 0U);

    buffer.write_u8(bottom_8_bits);
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_u16(questions);
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_u16(answers);
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_u16(authoritative_entries);
    if (!buffer.ok())
    {
        return;
    }

    buffer.write_u16(resource_entries);
}

} // namespace dns
