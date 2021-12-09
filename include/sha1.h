// (c) 2021 Zaur Kadokhti (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#pragma once

#include <string_view>
#include <vector>
#include <array>
#include <cstddef>
#include "interface.h"

namespace stagdog::sha1
{
const std::size_t RESERVED_BIT_SIZE = 64 + 1;
const std::size_t CHUNK_BIT_SIZE = 512;

class encrypter : public IEncrypter
{
 public:
  byte_array encrypt( std::istream &stream ) const override;

 private:
  std::array<uint32_t, 5> encrypt_chunk(
      const char *chunk, const std::array<uint32_t, 5> &H ) const;

  std::array<uint32_t, 5> _base{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                                 0xC3D2E1F0 };
};

uint32_t circular_left_shift( uint32_t data, std::size_t n );

// data - full data, length - full data length
byte_array process_last_chunk( const char *chunk, std::size_t chunk_byte_size,
                               std::size_t all_data_byte_size );

uint32_t f( std::size_t index, uint32_t B, uint32_t C, uint32_t D );

uint32_t get_K_constant( std::size_t index );

}  // namespace stagdog::sha1