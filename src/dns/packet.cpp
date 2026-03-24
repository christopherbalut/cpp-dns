#include "dns/packet.hpp"
#include "dns/header.hpp"
#include "dns/record.hpp"

namespace dns
{
void DnsPacket::decode_from_buffer(PacketBuffer& buffer)
{
    header = DnsHeader{};

    questions.clear();
    answers.clear();
    authorities.clear();
    resources.clear();

    header.decode(buffer);

    const std::size_t question_count{static_cast<std::size_t>(header.questions)};
    const std::size_t answer_count{static_cast<std::size_t>(header.answers)};
    const std::size_t authority_count{static_cast<std::size_t>(header.authoritative_entries)};
    const std::size_t resource_count{static_cast<std::size_t>(header.resource_entries)};

    questions.reserve(question_count);
    answers.reserve(answer_count);
    authorities.reserve(authority_count);
    resources.reserve(resource_count);

    for (std::size_t i{0}; i < question_count; ++i)
    {
        DnsQuestion question{};
        question.decode(buffer);
        questions.emplace_back(question);
    }

    for (std::size_t i{0}; i < answer_count; ++i)
    {
        answers.emplace_back(decode_record(buffer));
    }

    for (std::size_t i{0}; i < authority_count; ++i)
    {
        authorities.emplace_back(decode_record(buffer));
    }

    for (std::size_t i{0}; i < resource_count; ++i)
    {
        resources.emplace_back(decode_record(buffer));
    }
}
}; // namespace dns
