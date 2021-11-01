// (c) 2021 Zaur Kadokhov (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#include "sha1.h"
#include <string>

namespace stagdog::sha1
{

uint32_t circular_left_shift(uint32_t data, std::size_t n)
{
    n = n%32;
    return data << n | data >> (32 - n);
}

byte_array process_last_chunk(const char *data, std::size_t length)
{
    if (data == nullptr) {
        throw std::invalid_argument("process_last_chunk: nullptr passed");
    }

    if (length == 0 || length > 512) {
        throw std::invalid_argument("process_last_chunk: " + std::to_string(length) + " is invalid length");
    }
    
    const std::size_t reserved_size = 64 + 1;
    const std::size_t chunk_default_size = 512;
    const std::size_t last_chunk_size = length % chunk_default_size;
    const std::size_t chunk_count = length / chunk_default_size;

    byte_array array;

    if (chunk_default_size >= reserved_size + last_chunk_size) {
        array.data = std::make_unique<char[]>(512);
        array.length = 512;
    } else {
        array.data = std::make_unique<char[]>(1024);
        array.length = 1024;
    }

    auto begin = data + chunk_default_size * chunk_count;

    std::copy(begin, begin + last_chunk_size, array.data.get());
    array.data.get()[length] = 1;
    std::fill(array.data.get() + length + 1, array.data.get() + array.length, 0);
    reinterpret_cast<uint64_t*>(array.data.get())[array.length / 8 - 1] = length;

    return array;
}

bool encrypter::chunk_fits(std::size_t length) const
{
    return true;
}

byte_array encrypter::encrypt(char* data, std::size_t length) const
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