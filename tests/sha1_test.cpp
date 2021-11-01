#include <iostream>
#include "sha1.h"
#include <catch/catch.hpp>

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

TEST_CASE("sha1 process last chunk", "[sha1]")
{
    const char FILLER = 55;
    auto chunk = std::make_unique<char[]>(512);
    std::fill(chunk.get(), chunk.get() + 512, FILLER);

    SECTION("invalid length chunk") {
        CHECK_THROWS_WITH(process_last_chunk(chunk.get(), 0), "process_last_chunk: 0 is invalid length");
        CHECK_THROWS_WITH(process_last_chunk(chunk.get(), 513), "process_last_chunk: 513 is invalid length");
    }

    SECTION("nullptr chunk pointer") {
        CHECK_THROWS_WITH(process_last_chunk(nullptr, 10), "process_last_chunk: nullptr passed");
    }

    auto content_check = [FILLER](char * data, std::size_t init_size, std::size_t chunk_size){
        bool array_check = true;
        for (int i = 0; i < init_size; ++i) {
            array_check &= data[i] == FILLER;
        }
        CHECK(data[init_size] == 1);
        array_check = true;
        for (int i = init_size + 1; i < chunk_size - 64; ++i) {
            array_check &= data[i] == 0;
        }
        CHECK(array_check);
        CHECK(reinterpret_cast<uint64_t*>(data)[chunk_size / 8 - 1] == init_size);
    };

    SECTION("chunk size < 447") {
        auto array = process_last_chunk(chunk.get(), 446);
        REQUIRE(array.data != nullptr);
        REQUIRE(array.length == 512);
        content_check(array.data.get(), 446, 512);
    }

    SECTION("chunk size = 447") {
        auto array = process_last_chunk(chunk.get(), 447);
        REQUIRE(array.data != nullptr);
        REQUIRE(array.length == 512);
        content_check(array.data.get(), 447, 512);
    }

    SECTION("chunk size > 447") {
        auto array = process_last_chunk(chunk.get(), 448);
        REQUIRE(array.data != nullptr);
        REQUIRE(array.length == 1024);
        content_check(array.data.get(), 448, 1024);
    }
}