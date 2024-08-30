#ifndef VALIDATOR_CRYPTO_BECH_BLECH32_H
#define VALIDATOR_CRYPTO_BECH_BLECH32_H

#include "bech.hpp"

namespace bech::blech32 {
  namespace {
    inline constexpr int64_t ENCODING_CONST = 1;
    inline constexpr int32_t MAX_SIZE = 150;
  }  // namespace

  auto decode(const std::string& input) {
    return bech::decode(input, ENCODING_CONST, MAX_SIZE, bech::polymod_blech);
  }
}  // namespace bech::blech32

#endif  // VALIDATOR_CRYPTO_BECH_BLECH32_H
