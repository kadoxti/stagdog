#include <iostream>
#include "sha1.h"
#include <catch/catch.hpp>

using namespace stagdog::sha1;

TEST_CASE("sha1 circular left shift: zero shifting number", "[sha1]")
{
    CHECK(circular_left_shift(0, 0) == 0);
    CHECK(circular_left_shift(0, 2) == 0);
    CHECK(circular_left_shift(0, 4) == 0);
    CHECK(circular_left_shift(0, 8) == 0);
    CHECK(circular_left_shift(0, 16) == 0);
    CHECK(circular_left_shift(0, 32) == 0);
}

TEST_CASE("sha1 circular left shift number", "[sha1]")
{
    SECTION("big shift number") {
        CHECK(circular_left_shift(101, 8) == circular_left_shift(101, 40));
        CHECK(circular_left_shift(101, 0) == circular_left_shift(101, 32));
    }

    SECTION("zero shift number") {
        CHECK(circular_left_shift(0, 0) == 0);
        CHECK(circular_left_shift(101, 0) == 101);
        CHECK(circular_left_shift(0b11111111111111111111111111111111, 0) == 0b11111111111111111111111111111111);
    }
}

TEST_CASE("sha1 circular left shift function", "[sha1]")
{
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 1) == 0b00101100000000000000000000000001);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 2) == 0b01011000000000000000000000000010);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 3) == 0b10110000000000000000000000000100);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 4) == 0b01100000000000000000000000001001);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 5) == 0b11000000000000000000000000010010);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 6) == 0b10000000000000000000000000100101);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 7) == 0b00000000000000000000000001001011);
    CHECK(circular_left_shift(0b10010110000000000000000000000000 , 8) == 0b00000000000000000000000010010110);
}