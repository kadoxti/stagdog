// (c) 2021 Zaur Kadokhov (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

#pragma once

#include <optional>
#include <cstddef>

namespace stagdog
{

struct data
{
    std::unique_ptr<char> data;
    std::size_t length;
};

class IEncrypter
{
public:
    virtual data encrypt(char* data, std::size_t length) const = 0;
};

class IDecrypter
{
public:
    virtual data decrypt(char* data, std::size_t length) const = 0;
};

}// namespace stagdog