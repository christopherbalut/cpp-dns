#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <span>

namespace dns {

    enum class BufferError : std::uint8_t {
        none,
        end_of_buffer,
        position_out_of_bounds
    };

    struct ReadByteResult {
        std::uint8_t value{};
        BufferError error{BufferError::none};
    };

    class PacketBuffer {
        public:
            static constexpr std::size_t max_size = 512;
            
            PacketBuffer();

            [[nodiscard]] std::size_t position() const;
            void step(std::size_t steps);
            void seek(std::size_t position);

            std::uint8_t read_single_byte();
            [[nodiscard]] std::uint8_t get(std::size_t position) const;
            [[nodiscard]] std::span<const std::uint8_t> get_range(std::size_t start, std::size_t length) const;

            std::uint16_t read_u16();
            std::uint32_t read_u32();

            void read_qname(std::string& out);

        private:
            std::array<std::uint8_t, max_size> buffer_{};
            std::size_t position_{0};
            BufferError last_error_{BufferError::none};
    };
};
