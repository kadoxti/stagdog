// (c) 2021 Zaur Kadokhov (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#pragma once

#include <string_view>
#include <vector>
#include <array>
#include <cstddef>
#include "interface.h"

namespace stagdog::sha1
{

class encrypter: public IEncrypter
{
public:
    data encrypt(char* data, std::size_t length) const override;
    
private:
    std::array<uint32_t, 5> process_chunk(const std::array<uint32_t, 16> &chunk, const std::array<uint32_t, 5> &base) const;
    
    bool chunk_fits(std::size_t length) const;

    std::array<uint32_t, 5> _base{
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0};
    
};

uint32_t circular_left_shift(uint32_t data, std::size_t n);

} // namespace stagdog::sha1