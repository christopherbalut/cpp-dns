#include "dns/packet.hpp"
#include "dns/buffer.hpp"
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

void DnsPacket::write_from_buffer(PacketBuffer& buffer)
{
    // Update header count to match the current entries
    header.questions = static_cast<std::uint16_t>(questions.size());
    header.answers = static_cast<std::uint16_t>(answers.size());
    header.authoritative_entries = static_cast<std::uint16_t>(authorities.size());
    header.resource_entries = static_cast<std::uint16_t>(resources.size());

    header.write(buffer); // write 12 byte header first

    for (const DnsQuestion& question : questions) // write every question
    {
        question.write(buffer);
    }

    for (const DnsRecord& record : answers) // write every answer
    {
        static_cast<void>(
            write_record(record, buffer)); // we don't need return value, so we cast to void
    }

    for (const DnsRecord& record :
         authorities) // write every authority record in authoriryt section
    {
        static_cast<void>(write_record(record, buffer));
    }

    for (const DnsRecord& record :
         resources) // write every additional resource record in additional section
    {
        static_cast<void>(write_record(record, buffer));
    }
}
}; // namespace dns
