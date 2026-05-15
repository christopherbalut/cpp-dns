#include "dns/header.hpp"
#include "dns/buffer.hpp"
#include "dns/types.hpp"
#include <cstdint>

namespace dns
{
void DnsHeader::decode(PacketBuffer& buffer)
{
    id = buffer.read_u16();

    const std::uint16_t flag{buffer.read_u16()};
    const std::uint8_t top_8_bytes{static_cast<std::uint8_t>(flag >> 8)};
    const std::uint8_t bottom_8_bytes{static_cast<std::uint8_t>(flag & 0xFF)};

    recursion_desired = (top_8_bytes & (1U << 0)) != 0;
    truncated_message = (top_8_bytes & (1U << 1)) != 0;
    authoritative_answer = (top_8_bytes & (1U << 2)) != 0;
    opcode = static_cast<std::uint8_t>((top_8_bytes >> 3) & 0x0F);
    response = (top_8_bytes & (1U << 7)) != 0;

    rescode = to_result_code(static_cast<std::uint8_t>(bottom_8_bytes & 0x0F));
    checking_disabled = (bottom_8_bytes & (1U << 4)) != 0;
    authed_data = (bottom_8_bytes & (1U << 5)) != 0;
    z = (bottom_8_bytes & (1U << 6)) != 0;
    recursion_available = (bottom_8_bytes & (1U << 7)) != 0;

    questions = buffer.read_u16();
    answers = buffer.read_u16();
    authoritative_entries = buffer.read_u16();
    resource_entries = buffer.read_u16();
}

void DnsHeader::write(PacketBuffer& buffer) const
{
    if (!buffer.ok())
    {
        return;
    }
    buffer.write_u16(id); // put header id in first two bytes
    if (!buffer.ok())
    {
        return;
    }
    std::uint8_t top_8_bits{0}; // create upper 8 bits of 0's so we can write in them after
    top_8_bits |= static_cast<std::uint8_t>(recursion_desired ? (1U << 0) : 0U);    // bit 0
    top_8_bits |= static_cast<std::uint8_t>(truncated_message ? (1U << 1) : 0U);    // bit 1
    top_8_bits |= static_cast<std::uint8_t>(authoritative_answer ? (1U << 2) : 0U); // bit 2
    top_8_bits |= static_cast<std::uint8_t>((opcode & 0x0F) << 3);                  // bits 3-4-5-6
    top_8_bits |= static_cast<std::uint8_t>(response ? (1U << 7) : 0U);             // bit 7

    buffer.write_u8(top_8_bits); // after assigning, we actually write the 8 bits/ 1 byte
    if (!buffer.ok())
    {
        return;
    }

    std::uint8_t bottom_8_bits{0}; // initialize the bottom 8 byte
    bottom_8_bits |=
        static_cast<std::uint8_t>(static_cast<std::uint8_t>(rescode) & 0x0F);         // bits 0-3
    bottom_8_bits |= static_cast<std::uint8_t>(checking_disabled ? (1U << 4) : 0U);   // bit 4
    bottom_8_bits |= static_cast<std::uint8_t>(authed_data ? (1U << 5) : 0U);         // bit 5
    bottom_8_bits |= static_cast<std::uint8_t>(z ? (1U << 6) : 0U);                   // bit 6
    bottom_8_bits |= static_cast<std::uint8_t>(recursion_available ? (1U << 7) : 0U); // bit 7

    buffer.write_u8(bottom_8_bits); // write the bottom 8 bits or 1 byte
    if (!buffer.ok())
    {
        return;
    }
    // write 2 bytes of all the header table of contents
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
