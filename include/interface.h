// (c) 2021 Zaur Kadokhov (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#pragma once

#include <optional>
#include <cstddef>

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
    virtual byte_array encrypt(const char* data, std::size_t length) const = 0;
};

class IDecrypter
{
public:
    virtual byte_array decrypt(const char* data, std::size_t length) const = 0;
};

}// namespace stagdog