// (c) 2021 Zaur Kadokhti (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#pragma once

#include <optional>
#include <cstddef>
#include <istream>

namespace stagdog
{

struct byte_array
{
    std::unique_ptr<char[]> data;
    std::size_t length;
};

class IEncrypter
{
public:
    virtual byte_array encrypt(std::istream &stream) const = 0;
};

class IDecrypter
{
public:
    virtual byte_array decrypt(std::istream &stream) const = 0;
};

}// namespace stagdog