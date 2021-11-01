// (c) 2021 Zaur Kadokhov (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#include "sha1.h"

namespace stagdog::sha1
{

uint32_t circular_left_shift(uint32_t data, std::size_t n)
{
    n = n%32;
    return data << n | data >> (32 - n);
}

bool encrypter::chunk_fits(std::size_t length) const
{
    return true;
}

data encrypter::encrypt(char* data, std::size_t length) const
{
    // auto raw = reinterpret_cast<unsigned char*>(data->data());
    
    // std::array<uint32_t, 16> chunk;

    // std::size_t chunk_count = length / 64;
    // std::size_t position = 0;

    // std::array<uint32_t, 5> base = _base;

    // while (chunk_count > 0) {
    //     for (std::size_t i = 0; i < chunk.size(); ++i) {
    //         chunk[i] = reinterpret_cast<uint32_t*>(data)[position];
    //         position += 4;
    //     }
    //     auto temp_base = process_chunk(chunk, base);
    //     for (std::size_t i = 0; i < base.size(); ++i) {
    //         base[i] += temp_base[i];
    //     }

    //     --chunk_count;
    // }
    
    // std::vector<std::byte> encrypted_data;
    // encrypted_data.resize(20);

    // for (int i = 0; i < 20; ++i) {
    //     encrypted_data[i] = reinterpret_cast<std::byte*>(base.data())[i];
    // }

    // return encrypted_data;
    return {};
}

std::array<uint32_t, 5> encrypter::process_chunk(const std::array<uint32_t, 16> &chunk, const std::array<uint32_t, 5> &base) const
{
    // auto [a, b, c, d, e] = base;

    // std::array<uint32_t, 80> bigger_chunk;
    // for (int i = 0; i < bigger_chunk.size(); ++i) {
    //     if (i <= chunk.size()) {
    //         bigger_chunk[i] = chunk[i];
    //     }

    //     bigger_chunk[i] = (chunk[i - 3] ^ chunk[i - 8] ^ chunk[i - 14] ^ chunk[i - 16]) << 1;


    //     uint32_t temp = (a << 1) + e + bigger_chunk[i];

    //     if (i <= 19) {
    //         temp += 0x5A827999;
    //         temp += (b & c) | ((!b) & d);
    //     } else if (i <= 39) {
    //         temp += 0x6ED9EBA1;
    //         temp += b ^ c ^ d;
    //     } else if (i <= 59) {
    //         temp += 0x8F1BBCD;
    //         temp += (b & c) | (b & d) | (c & d);
    //     } else if (i <= 79) {
    //         temp += 0xCA62C1D6;
    //         temp += b ^ c ^ d;
    //     }

    //     e = d;
    //     d = c;
    //     c = b << 30;
    //     b = a;
    //     a = temp;
    // }

    // return {a, b, c, d, e};
    return {};
}

} // namespace stagdog::sha1