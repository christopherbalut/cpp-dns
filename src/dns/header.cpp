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
} // namespace dns
