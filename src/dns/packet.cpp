#include "dns/packet.hpp"
#include "dns/buffer.hpp"
#include "dns/header.hpp"
#include "dns/record.hpp"
#include <algorithm>
#include <cstdint>
#include <variant>

namespace dns
{
namespace
{
bool is_writable_record(const DnsRecord& record)
{
    return !std::holds_alternative<UnknownRecord>(record);
}
} // namespace
void DnsPacket::decode_from_buffer(PacketBuffer& buffer)
{
    header = DnsHeader{};

    questions.clear();
    answers.clear();
    authorities.clear();
    resources.clear();

    if (!buffer.ok())
    {
        return;
    }

    header.decode(buffer);
    if (!buffer.ok())
    {
        return;
    }

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
        if (!buffer.ok())
        {
            return;
        }
        questions.emplace_back(std::move(question));
    }

    for (std::size_t i{0}; i < answer_count; ++i)
    {
        DnsRecord record{decode_record(buffer)};
        if (!buffer.ok())
        {
            return;
        }
        answers.emplace_back(std::move(record));
    }

    for (std::size_t i{0}; i < authority_count; ++i)
    {
        DnsRecord record{decode_record(buffer)};
        if (!buffer.ok())
        {
            return;
        }
        authorities.emplace_back(std::move(record));
    }

    for (std::size_t i{0}; i < resource_count; ++i)
    {
        DnsRecord record{decode_record(buffer)};
        if (!buffer.ok())
        {
            return;
        }
        resources.emplace_back(std::move(record));
    }
}
void DnsPacket::write_to_buffer(PacketBuffer& buffer)
{
    auto count_writable = [](const auto& records) -> std::uint16_t
    {
        return static_cast<std::uint16_t>(
            std::count_if(records.begin(), records.end(), is_writable_record));
    };

    if (!buffer.ok())
    {
        return;
    }
    // Update header count to match the current entries
    header.questions = static_cast<std::uint16_t>(questions.size());
    header.answers = count_writable(answers);
    header.authoritative_entries = count_writable(authorities);
    header.resource_entries = count_writable(resources);

    header.write(buffer); // write 12 byte header first
    if (!buffer.ok())
    {
        return;
    }

    for (const DnsQuestion& question : questions) // write every question
    {
        question.write(buffer);
        if (!buffer.ok())
        {
            return;
        }
    }

    for (const DnsRecord& record : answers)
    {
        if (!is_writable_record(record))
        {
            continue;
        }
        static_cast<void>(write_record(record, buffer));
        if (!buffer.ok())
        {
            return;
        }
    }

    for (const DnsRecord& record : authorities)
    {
        if (!is_writable_record(record))
        {
            continue;
        }
        static_cast<void>(write_record(record, buffer));
        if (!buffer.ok())
        {
            return;
        }
    }

    for (const DnsRecord& record : resources)
    {
        if (!is_writable_record(record))
        {
            continue;
        }
        static_cast<void>(write_record(record, buffer));
        if (!buffer.ok())
        {
            return;
        }
    }
}
}; // namespace dns
