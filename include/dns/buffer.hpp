#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <span>

namespace dns {
    class PacketBuffer {
        public:
            static constexpr std::size_t max_size = 512;
            
            PacketBuffer();

            std::size_t position() const;
            void step(std::size_t steps);
            void seek(std::size_t position);

            std::uint8_t read();
            std::uint8_t get(std::size_t position) const;
            std::span<const std::uint8_t> get_range(std::size_t start, std::size_t length) const;

            std::uint16_t read_u16();
            std::uint32_t read_u32();

            void read_qname(std::string& out);

        private:
            std::array<std::uint8_t, max_size> buffer_{};
            std::size_t position_{0};
    };

};
