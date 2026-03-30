#include "dns/buffer.hpp"
#include "dns/packet.hpp"
#include "dns/record.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <variant>

void load_file_into_packet_buffer(const std::string& path, dns::PacketBuffer& buffer)
{
    std::ifstream input(path, std::ios::binary); // open file and read raw bytes
    if (!input)
    {
        throw std::runtime_error("Runtime Error, failed to open file " + path + ", exiting...\n");
    }

    std::array<char, dns::PacketBuffer::max_size> bytes{}; // array of char
    input.read(bytes.data(), static_cast<std::streamsize>(
                                 bytes.size())); // read up to bytes.size() number of bytes in file
    const std::streamsize count{input.gcount()}; // store the actual number of bytes used

    if (count <= 0)
    {
        throw std::runtime_error("Runtime Error, path file is empty: " + path);
    }

    if (input.bad())
    {
        throw std::runtime_error("Runtime Error, failed while reading file: " + path);
    }

    for (std::size_t i{}; i < static_cast<std::size_t>(count); ++i)
    {
        buffer.set(i, static_cast<std::uint8_t>(bytes[i])); // copy one byte into temp file
    }

    buffer.seek(0); // reset PacketBuffer to restart decoding
}

int main()
{
    try
    {
        // create empty packetbuffer
        // open the file
        // read the file into temporary storage
        //
        // for each byte read from the file:
        // write that byte into packetbuffer using set(index, byte)
        //
        // reset packetbuffer cursor to begining
        // create Empty DnsPacket
        // decode the packet from packetbuffer
        // print the header
        // print each question
        // print each answer
        // print each authoriy asnwer
        // print each resource used
        dns::PacketBuffer buffer{};
        load_file_into_packet_buffer("response_packet.txt", buffer);

        dns::DnsPacket packet{};
        packet.decode_from_buffer(buffer);

        print_packet(packet);
    }
    catch (const std::exception& exception)
    {
        std::cerr << "error code: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}
