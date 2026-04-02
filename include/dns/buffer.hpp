#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace dns
{

enum class BufferError : std::uint8_t
{
    none,
    end_of_buffer,
    position_out_of_bounds,
    invalid_qname,
    label_too_long,
    qname_too_long

};

class PacketBuffer
{
  public:
    static constexpr std::size_t max_size = 512;

    PacketBuffer();

    void set(std::size_t pos, std::uint8_t value);
    [[nodiscard]] std::size_t position() const;
    void step(std::size_t steps);
    void seek(std::size_t position);

    std::uint8_t read_single_byte();
    [[nodiscard]] std::uint8_t get(std::size_t position) const;
    [[nodiscard]] std::span<const std::uint8_t> get_range(std::size_t start,
                                                          std::size_t length) const;

    std::uint16_t read_u16();
    std::uint32_t read_u32();

    void read_qname(std::string& out);

    void write(std::uint8_t value);
    void write_u8(std::uint8_t value);
    void write_u16(std::uint16_t value);
    void write_u32(std::uint32_t value);
    void write_qname(std::string_view qname);

    [[nodiscard]] bool ok() const;
    [[nodiscard]] BufferError last_error() const;
    void clear_error();

  private:
    [[nodiscard]] bool can_write(std::size_t byte_count) const;
    void update_size_after_write();

    std::array<std::uint8_t, max_size> buffer_{};
    std::size_t position_{0};
    std::size_t size_{0};
    BufferError last_error_{BufferError::none};
};

} // namespace dns
