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

bool isLittleEndian()
{
    short int number = 0x1;
    char *numPtr = (char*)&number;
    return (numPtr[0] == 1);
}

byte_array process_last_chunk(const char *data, std::size_t length)
{
    uint64_t bit_count = length * 8;

    if (data == nullptr) {
        throw std::invalid_argument("process_last_chunk: nullptr passed");
    }
    
    const std::size_t last_chunk_byte_size = length % (CHUNK_BIT_SIZE / 8);
    const std::size_t chunk_count = bit_count / CHUNK_BIT_SIZE;

    byte_array array;

    if (CHUNK_BIT_SIZE >= RESERVED_BIT_SIZE + last_chunk_byte_size * 8) {
        array.length = CHUNK_BIT_SIZE / 8; 
    } else {
        array.length = CHUNK_BIT_SIZE * 2 / 8;
    }
    array.data = std::make_unique<char[]>(array.length);

    auto begin = data + CHUNK_BIT_SIZE / 8 * chunk_count;

    std::copy(begin, begin + last_chunk_byte_size, array.data.get());
    array.data.get()[last_chunk_byte_size] = 0b10000000;
    auto beg = array.data.get() + last_chunk_byte_size + 1;
    auto end = array.data.get() + array.length;
    std::fill(array.data.get() + last_chunk_byte_size + 1, array.data.get() + array.length, 0);

    if (isLittleEndian()) {
        std::copy(reinterpret_cast<char*>(&bit_count), reinterpret_cast<char*>(&bit_count) + 8, std::reverse_iterator(array.data.get() + array.length));
    } else {
        *reinterpret_cast<uint64_t*>(array.data.get() + array.length - 8) = bit_count;
    }  
    
    return array;
}

uint32_t f (std::size_t index, uint32_t B, uint32_t C, uint32_t D)
{
    if (index < 20) {
        return (B & C) | ((~B) & D);
    } else if (index < 40) {
        return B ^ C ^ D;
    } else if (index < 60) {
        return (B & C) | (B & D) | (C & D);
    } else if (index < 80) {
        return B ^ C ^ D;
    }

    throw std::invalid_argument("f function invalid index: " + std::to_string(index));
}

uint32_t get_K_constant(std::size_t index)
{
    if (index < 20) {
        return 0x5A827999;
    } else if (index < 40) {
        return 0x6ED9EBA1;
    } else if (index < 60) {
        return 0x8F1BBCDC;
    } else if (index < 80) {
        return 0xCA62C1D6;
    }

    throw std::invalid_argument("K constant function invalid index: " + std::to_string(index));
}

byte_array encrypter::encrypt(const char* data, std::size_t length) const
{
    const char* chunk = data;

    std::size_t chunk_count = length * 8 / CHUNK_BIT_SIZE;
    std::size_t position = 0;

    std::array<uint32_t, 5> H {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    };
    
    while (chunk_count > 0) {
        auto temp_base = encrypt_chunk(chunk + position, H);
        for (std::size_t i = 0; i < H.size(); ++i) {
            H[i] += temp_base[i];
        }
        position += CHUNK_BIT_SIZE / 8;
        --chunk_count;
    }

    auto last_chunk = process_last_chunk(data, length);

    for (int i = 0; i < last_chunk.length * 8 / CHUNK_BIT_SIZE; ++i) {
        auto temp_base = encrypt_chunk(last_chunk.data.get() + i * CHUNK_BIT_SIZE / 8, H);
        for (std::size_t i = 0; i < H.size(); ++i) {
            H[i] += temp_base[i];
        }
    }
    
    byte_array encrypted_data;
    encrypted_data.data = std::make_unique<char[]>(20);
    encrypted_data.length = 20;

    if (isLittleEndian()) {
        for (int i = 0; i < H.size(); ++i) {
            std::copy(reinterpret_cast<char *>(H.data()) + i * 4, reinterpret_cast<char *>(H.data()) + i * 4 + 4, std::reverse_iterator(encrypted_data.data.get() + i * 4 + 4));
        }
    } else {
        std::copy(reinterpret_cast<char *>(H.data()), reinterpret_cast<char *>(H.data()) + 20, encrypted_data.data.get());
    }

    return encrypted_data;
}

std::array<uint32_t, 5> encrypter::encrypt_chunk(const char* chunk, const std::array<uint32_t, 5> &H) const
{
    auto [a, b, c, d, e] = H;

    std::array<uint32_t, 80> bigger_chunk;
    for (int i = 0; i < bigger_chunk.size(); ++i) {
        if (i < 16) {
            if (isLittleEndian()) {
                std::copy(&chunk[i * 4], &chunk[i * 4] + 4, std::reverse_iterator( reinterpret_cast<char*>(&bigger_chunk[i]) + 4));
            } else {
                bigger_chunk[i] = *reinterpret_cast<const uint32_t*>(chunk + i * 4);
            }
        } else {
            bigger_chunk[i] = circular_left_shift( (bigger_chunk[i - 3] ^ bigger_chunk[i - 8] ^ bigger_chunk[i - 14] ^ bigger_chunk[i - 16]), 1 );
        }

        uint32_t temp = circular_left_shift(a, 5) + f(i, b, c, d) + e + bigger_chunk[i] + get_K_constant(i);

        e = d;
        d = c;
        c = circular_left_shift(b, 30);
        b = a;
        a = temp;
    }

    return {a, b, c, d, e};
}

} // namespace stagdog::sha1