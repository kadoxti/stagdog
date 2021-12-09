// (c) 2021 Zaur Kadokhti (kadoxti.github.io)
// This code is licensed under MIT license (see LICENSE file for details)

/**
 * \file
 * @brief File with interfaces for stagdog library
 *
 */

#pragma once

#include <optional>
#include <cstddef>
#include <istream>

namespace stagdog
{
/**
 * @brief Structure is used as a return value
 * for operations like encrypt and decrypt.
 */
struct byte_array {
  std::unique_ptr<char[]> data;  ///< smart pointer to byte array
  std::size_t length;            ///< length of byte array
};

/**
 * @brief IEncrypter is the interface for encrypting data.
 * You must inherit from this interface if you want to
 * implement encryption in your class.
 */
class IEncrypter
{
 public:
  /**
   * @brief Encryption member function
   * you must implement in your class inherited from IEncription.
   * This function must not have any side effects.
   *
   * @param[in] stream raw data stream
   * @return byte_array encryption result
   */
  virtual byte_array encrypt( std::istream &stream ) const = 0;
};

/**
 * @brief IDecrypter is the interface for decrypting previosly encrypted data.
 * You must inherit from this interface if you want to
 * implement decryption in your class.
 */
class IDecrypter
{
 public:
  /**
   * @brief Decryption member function
   * you must implement in your class inherited from IDecription.
   * This function must not have any side effects.
   *
   * @param[in] stream encrypted data stream
   * @return byte_array decryption result
   */
  virtual byte_array decrypt( std::istream &stream ) const = 0;
};

}  // namespace stagdog