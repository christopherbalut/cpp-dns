#pragma once

#include <cstdint>

#include "dns/buffer.hpp"
#include "dns/types.hpp"

namespace dns
{
struct DnsHeader // represents the first 12 bytes of the DnsPacket
{
    std::uint16_t id{0}; // 16 bits

    bool recursion_desired{false};
    bool truncated_message{false};
    bool authoritative_answer{false};
    std::uint8_t opcode{0};
    bool response{false};

    ResultCode rescode{ResultCode::noerror};
    bool checking_disabled{false};
    bool authed_data{false};
    bool z{false};
    bool recursion_available{false};

    std::uint16_t questions{0};
    std::uint16_t answers{0};
    std::uint16_t authoritative_entries{0};
    std::uint16_t resource_entries{0};

    void decode(PacketBuffer& buffer);

    void write(PacketBuffer& buffer)
        const; // turn fields of in the header into bytes so they appear at the start of th
};
} // namespace dns
