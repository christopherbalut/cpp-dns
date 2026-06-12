#include "dns/server.hpp"
#include "dns/socket_utils.hpp"

#include "dns/packet.hpp"
#include "dns/question.hpp"
#include "dns/record.hpp"
#include "dns/types.hpp"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <netinet/in.h>
#include <sys/socket.h>

namespace dns
{

TEST(DnsServerTest, MakeBaseResponsePreservesClientIdAndSetsResponseFlags)
{
    DnsPacket request{};
    request.header.id = 0xBEEF;
    request.header.recursion_desired = true;

    const DnsPacket response = make_base_response(request);

    EXPECT_EQ(response.header.id, 0xBEEF);
    EXPECT_TRUE(response.header.response);
    EXPECT_TRUE(response.header.recursion_desired);
    EXPECT_TRUE(response.header.recursion_available);

    EXPECT_TRUE(response.questions.empty());
    EXPECT_TRUE(response.answers.empty());
    EXPECT_TRUE(response.authorities.empty());
    EXPECT_TRUE(response.resources.empty());
}

TEST(DnsServerTest, MakeFormerrResponsePreservesClientIdAndSetsFormerr)
{
    DnsPacket request{};
    request.header.id = 1234;
    request.header.recursion_desired = true;

    const DnsPacket response = make_formerr_response(request);

    EXPECT_EQ(response.header.id, 1234);
    EXPECT_TRUE(response.header.response);
    EXPECT_TRUE(response.header.recursion_desired);
    EXPECT_TRUE(response.header.recursion_available);
    EXPECT_EQ(response.header.rescode, ResultCode::formerr);

    EXPECT_TRUE(response.questions.empty());
    EXPECT_TRUE(response.answers.empty());
}

TEST(DnsServerTest, MakeServfailResponseKeepsQuestionAndSetsServfail)
{
    DnsPacket request{};
    request.header.id = 2222;
    request.header.recursion_desired = true;

    DnsQuestion question{};
    question.name = "example.com";
    question.qtype = QueryType::A;

    const DnsPacket response = make_servfail_response(request, std::move(question));

    EXPECT_EQ(response.header.id, 2222);
    EXPECT_TRUE(response.header.response);
    EXPECT_EQ(response.header.rescode, ResultCode::servfail);

    ASSERT_EQ(response.questions.size(), 1U);
    EXPECT_EQ(response.questions[0].name, "example.com");
    EXPECT_EQ(response.questions[0].qtype, QueryType::A);

    EXPECT_TRUE(response.answers.empty());
    EXPECT_TRUE(response.authorities.empty());
    EXPECT_TRUE(response.resources.empty());
}

TEST(DnsServerTest, MakeForwardedResponsePreservesClientIdButCopiesUpstreamRecords)
{
    DnsPacket request{};
    request.header.id = 9999;
    request.header.recursion_desired = true;

    DnsQuestion question{};
    question.name = "example.com";
    question.qtype = QueryType::A;

    DnsPacket upstream{};
    upstream.header.id = 6666;
    upstream.header.rescode = ResultCode::noerror;

    ARecord answer{};
    answer.domain = "example.com";
    answer.addr = std::array<std::uint8_t, 4>{93, 184, 216, 34};
    answer.ttl = 300;

    upstream.answers.emplace_back(answer);

    DnsPacket response = make_forwarded_response(request, std::move(question), std::move(upstream));

    EXPECT_EQ(response.header.id, 9999);
    EXPECT_NE(response.header.id, 6666);
    EXPECT_TRUE(response.header.response);
    EXPECT_TRUE(response.header.recursion_available);
    EXPECT_EQ(response.header.rescode, ResultCode::noerror);

    ASSERT_EQ(response.questions.size(), 1U);
    EXPECT_EQ(response.questions[0].name, "example.com");
    EXPECT_EQ(response.questions[0].qtype, QueryType::A);

    ASSERT_EQ(response.answers.size(), 1U);
    EXPECT_TRUE(response.authorities.empty());
    EXPECT_TRUE(response.resources.empty());
}

TEST(DnsServerTest, RunThrowsOnInvalidBindIp)
{
    DnsServer server{};

    EXPECT_THROW(server.run("not-an-ip", 2053), std::runtime_error);
}

TEST(DnsServerTest, RunThrowsWhenPortAlreadyInUse)
{
    UniqueSocket existing_socket{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    ASSERT_GE(existing_socket.get(), 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);

    ASSERT_EQ(bind(existing_socket.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)),
              0);

    sockaddr_in bound_addr{};
    socklen_t bound_addr_len = sizeof(bound_addr);

    ASSERT_EQ(getsockname(existing_socket.get(), reinterpret_cast<sockaddr*>(&bound_addr),
                          &bound_addr_len),
              0);

    const std::uint16_t used_port = ntohs(bound_addr.sin_port);

    DnsServer server{};

    EXPECT_THROW(server.run("127.0.0.1", used_port), std::runtime_error);
}
} // namespace dns
