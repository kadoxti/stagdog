#include <iostream>
#include <iomanip>
#include "sha1.h"
#include <catch/catch.hpp>
#include <bitset>
#include <sstream>

using namespace stagdog::sha1;

TEST_CASE("sha1 circular left shift function", "[sha1]")
{
    SECTION("zero shifting number") {
        CHECK(circular_left_shift(0, 0) == 0);
        CHECK(circular_left_shift(0, 2) == 0);
        CHECK(circular_left_shift(0, 4) == 0);
        CHECK(circular_left_shift(0, 8) == 0);
        CHECK(circular_left_shift(0, 16) == 0);
        CHECK(circular_left_shift(0, 32) == 0);
    }

    SECTION("big shift number") {
        CHECK(circular_left_shift(101, 8) == circular_left_shift(101, 40));
        CHECK(circular_left_shift(101, 0) == circular_left_shift(101, 32));
    }

    SECTION("zero shift number") {
        CHECK(circular_left_shift(0, 0) == 0);
        CHECK(circular_left_shift(101, 0) == 101);
        CHECK(circular_left_shift(0b11111111111111111111111111111111, 0) == 0b11111111111111111111111111111111);
    }

    SECTION("normal shift") {
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 1) == 0b00101100000000000000000000000001);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 2) == 0b01011000000000000000000000000010);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 3) == 0b10110000000000000000000000000100);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 4) == 0b01100000000000000000000000001001);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 5) == 0b11000000000000000000000000010010);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 6) == 0b10000000000000000000000000100101);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 7) == 0b00000000000000000000000001001011);
        CHECK(circular_left_shift(0b10010110000000000000000000000000 , 8) == 0b00000000000000000000000010010110);
    }
}

bool isLittleEndian()
{
    short int number = 0x1;
    char *numPtr = (char*)&number;
    return (numPtr[0] == 1);
}

std::string bitstring(const char *data, std::size_t length)
{
    std::ostringstream stream;
    for (int i = 0; i < length; ++i) {
        stream << std::bitset<8>(data[i]);
    }

    return stream.str();
}

TEST_CASE("sha1 process last chunk", "[sha1]")
{
    const char FILLER = 55;
    auto chunk = std::make_unique<char[]>(512);
    std::fill(chunk.get(), chunk.get() + 512, FILLER);

    SECTION("nullptr chunk pointer") {
        CHECK_THROWS_WITH(process_last_chunk(nullptr, 10), "process_last_chunk: nullptr passed");
    }

    auto content_check = [FILLER](char * data, std::size_t init_size, std::size_t chunk_size){
        bool array_check = true;
        for (int i = 0; i < init_size; ++i) {
            array_check &= data[i] == FILLER;
        }
        CHECK(static_cast<unsigned char>(data[init_size]) == 0b10000000);
        array_check = true;
        for (int i = init_size + 1; i < chunk_size - 8; ++i) {
            array_check &= data[i] == 0;
        }
        CHECK(array_check);
        // CHECK(*reinterpret_cast<uint64_t*>(data + chunk_size - 8) == init_size * 8);  cant check because of different endians
    };

    SECTION("last chunk size < 447 (55 bytes - 440 bits)") {
        auto array = process_last_chunk(chunk.get(), 55);
        REQUIRE(array.data != nullptr);
        REQUIRE(array.length == 512/8);
        content_check(array.data.get(), 55, 512/8);
    }

    SECTION("chunk size > 447 (56 bytes - 448 bits)") {
        auto array = process_last_chunk(chunk.get(), 56);
        REQUIRE(array.data != nullptr);
        REQUIRE(array.length == 1024/8);
        content_check(array.data.get(), 56, 1024/8);
    }

    SECTION("rfc example") {
        char message[] = {0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101};
        auto array = process_last_chunk(message, 5);
        REQUIRE(array.data != nullptr);
        REQUIRE(array.length == 512/8);

        CHECK(array.data.get()[0] == 0b01100001);
        CHECK(array.data.get()[1] == 0b01100010);
        CHECK(array.data.get()[2] == 0b01100011);
        CHECK(array.data.get()[3] == 0b01100100);
        CHECK(array.data.get()[4] == 0b01100101);
        CHECK(static_cast<unsigned char>(array.data.get()[5]) == 0b10000000);
        if (isLittleEndian()) {
            CHECK(*reinterpret_cast<uint64_t*>(array.data.get() + 56) == 0x2800000000000000);
        } else {
            CHECK(*reinterpret_cast<uint64_t*>(array.data.get() + 56) == 0x0000000000000028);
        }
    }
}

TEST_CASE("sha1 test f function", "[sha1]")
{
    SECTION("invalid index") {
        CHECK_THROWS_WITH(f(80, 0, 0, 0), "f function invalid index: 80");
        CHECK_THROWS_WITH(f(81, 0, 0, 0), "f function invalid index: 81");
    }

    SECTION("correct indexes") {
        CHECK(f(0, 0b00000001, 0b00000010, 0b00000100) == 0b00000100);
        CHECK(f(19, 0b00000001, 0b00000010, 0b00000100) == 0b00000100);
        CHECK(f(20, 0b00000001, 0b00000010, 0b00000100) == 0b00000111);
        CHECK(f(39, 0b00000001, 0b00000010, 0b00000100) == 0b00000111);
        CHECK(f(40, 0b00000001, 0b00000010, 0b00000100) == 0b00000000);
        CHECK(f(59, 0b00000001, 0b00000010, 0b00000100) == 0b00000000);
        CHECK(f(60, 0b00000001, 0b00000010, 0b00000100) == 0b00000111);
        CHECK(f(79, 0b00000001, 0b00000010, 0b00000100) == 0b00000111);
    }
}

TEST_CASE("sha1 test k constant function", "[sha1]")
{
    SECTION("invalid index") {
        CHECK_THROWS_WITH(get_K_constant(80), "K constant function invalid index: 80");
        CHECK_THROWS_WITH(get_K_constant(81), "K constant function invalid index: 81");
    }

    SECTION("correct indexes") {
        CHECK(get_K_constant(0) == 0x5A827999);
        CHECK(get_K_constant(19) == 0x5A827999);
        CHECK(get_K_constant(20) == 0x6ED9EBA1);
        CHECK(get_K_constant(39) == 0x6ED9EBA1);
        CHECK(get_K_constant(40) == 0x8F1BBCDC);
        CHECK(get_K_constant(59) == 0x8F1BBCDC);
        CHECK(get_K_constant(60) == 0xCA62C1D6);
        CHECK(get_K_constant(79) == 0xCA62C1D6);
    }
}

TEST_CASE("sha1 some test examples", "[sha1]")
{
    encrypter crypter;
    
    CHECK(bitstring(crypter.encrypt("Sha", 3).data.get(), 20) ==  "1011101001111001101110101110101110011111000100001000100101101010010001101010111001110100011100010101001001110001101101111111010110000110111001110100011001000000");
    CHECK(bitstring(crypter.encrypt("sha", 3).data.get(), 20) ==  "1101100011110100010110010000001100100000111000010011010000111010100100010101101101100011100101000001011100000110010100001010100011110011010111010110100100100110");
    CHECK(bitstring(crypter.encrypt("The quick brown fox jumps over the lazy dog", 43).data.get(), 20) ==  "0010111111010100111000011100011001111010001011010010100011111100111011011000010010011110111000011011101101110110111001110011100100011011100100111110101100010010");
    CHECK(bitstring(crypter.encrypt("В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!", 96).data.get(), 20) ==  "1001111000110010001010010101111110000010001001011000000000111011101101101101010111111101111111001100000001100111010001100001011010100100010000010011110000011011");
}