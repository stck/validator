#ifndef VALIDATOR_CRYPTO_BASE_H
#define VALIDATOR_CRYPTO_BASE_H

#include <algorithm>
#include <array>
#include <cmath>
#include <string>

namespace base {

  namespace {
    class InvalidCharacterException : public std::runtime_error {
    public:
      explicit InvalidCharacterException(const int8_t& c)
          : std::runtime_error("Non-dictionary character met: " + std::to_string(c)) {}
      using std::runtime_error::runtime_error;
    };

    constexpr auto is_zero(int i) {
      return i == 0;
    }
  }  // namespace

  auto decode(
      const std::string&             input,
      const int&                     base,
      const float&                   factor,
      const std::array<int, 256> table) -> std::string {
    if (input.empty()) return std::string{};

    auto length    = 0;
    auto mean_size = static_cast<float>(input.length());
    auto size      = static_cast<size_t>(std::ceil(mean_size * factor + 1));
    auto result    = std::vector<uint8_t>(size);

    for (const auto& c : input) {
      auto carry = table[c];
      if (carry == -1) throw InvalidCharacterException(c);

      auto i = 0;
      for (auto j = size - 1; (carry != 0 || i < length) && (j != -1); i++, j--) {
        carry       = carry + ((base * result[j]) >> 0);
        result[j] = (carry % 256) >> 0;
        carry       = (carry / 256) >> 0;
      }

      length = i;
    }

    auto it   = find_if_not(result.begin(), result.end(), is_zero);
    auto first_nonzero_idx = std::distance(result.begin(), it);

    return std::string{result.begin() + first_nonzero_idx, result.end()};
  }

}  // namespace base

#endif  // VALIDATOR_CRYPTO_BASE_H