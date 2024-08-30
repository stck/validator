#ifndef VALIDATOR_CRYPTO_BECH_H
#define VALIDATOR_CRYPTO_BECH_H

#include <array>
#include <string>
#include <vector>

namespace bech {
  namespace {
    using checksum_t = uint_least64_t;
    inline const char delimiter = '1';
    inline const size_t MAX_SIZE = 90;

    class InvalidSizeException : public std::runtime_error {
    public:
      explicit InvalidSizeException(const size_t& size, const size_t& max = MAX_SIZE):
            std::runtime_error("Invalid length, expected 8 < N < " + std::to_string(max) + ", given N = " + std::to_string(size)) {}
      using std::runtime_error::runtime_error;
    };

    class NoSeparatorException : public std::runtime_error {
    public:
      explicit NoSeparatorException():
            std::runtime_error("No separator found in given input") {}
      using std::runtime_error::runtime_error;
    };

    class InvalidCharacterException : public std::runtime_error {
    public:
      explicit InvalidCharacterException(const size_t& position):
            std::runtime_error("Invalid character at position" + std::to_string(position)) {}
      using std::runtime_error::runtime_error;
    };

    class InvalidCaseException : public std::runtime_error {
    public:
      explicit InvalidCaseException():
            std::runtime_error("Given string should be all-lowercase nor all-uppercase") {}
      using std::runtime_error::runtime_error;
    };

    inline constexpr std::array<int8_t, 75> DECODE_TABLE = {
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2
    };

    inline constexpr auto polymod_bech(const checksum_t& i) -> checksum_t {
      return (((i & 0x1ffffff) << 5) ^
              (-((i >> 25) & 1) & 0x3b6a57b2) ^
              (-((i >> 26) & 1) & 0x26508e6d) ^
              (-((i >> 27) & 1) & 0x1ea119fa) ^
              (-((i >> 28) & 1) & 0x3d4233dd) ^
              (-((i >> 29) & 1) & 0x2a1462b3));
    }

    inline constexpr auto polymod_blech(const checksum_t& i) -> checksum_t {
      return (((i & 0x7FFFFFFFFFFFFF) << 5) ^
              (-((i >> 55) & 1) & 0x7d52fba40bd886) ^
              (-((i >> 56) & 1) & 0x5e8dbf1a03950c) ^
              (-((i >> 57) & 1) & 0x1c3a3c74072a18) ^
              (-((i >> 58) & 1) & 0x385d72fa0e5139) ^
              (-((i >> 59) & 1) & 0x7093e5a608865b));
    }

    inline constexpr auto prefix_checksum(const std::string& prefix, const std::function<checksum_t(checksum_t)>& polymod = polymod_bech) -> checksum_t {
      checksum_t checksum = 1;
      for (auto c : prefix) {
        if (c < 33 || c > 126) {
          throw InvalidCharacterException{prefix.rfind(c)};
        }
        checksum = polymod(checksum) ^ (c >> 5);
      }

      checksum = polymod_bech(checksum);
      for (auto c : prefix) {
        checksum = polymod(checksum) ^ (c & 0x1f);
      }

      return checksum;
    }
  }  // namespace

  auto decode(
      const std::string& input,
      const int64_t& enc_constant = 1,
      const size_t& max = MAX_SIZE,
      const std::function<checksum_t(checksum_t)>& polymod = polymod_bech) -> std::pair<std::string, bool> {
    if (input.size() < 8 || input.size() > max) {
      throw InvalidSizeException(input.size(), max);
    }

    size_t pos = input.rfind(delimiter);

    if (pos == std::string::npos) {
      throw NoSeparatorException();
    }

    std::string prefix = input.substr(0, pos);
    checksum_t checksum = prefix_checksum(prefix, polymod);

    for (size_t i = 0; i < input.size() - 1 - pos; ++i) {
      auto c = input[i + pos + 1];

      if (c < 48 || c > 122) {
        throw InvalidCharacterException{i + pos + 1};
      }

      int8_t rev = DECODE_TABLE.at(c - 48);

      if (rev == -1) {
        throw InvalidCharacterException{i + pos + 1};
      }

      checksum = polymod(checksum) ^ rev;
    }

    return { prefix, checksum == enc_constant };
  }
}  // namespace bech

#endif // VALIDATOR_CRYPTO_BECH_H