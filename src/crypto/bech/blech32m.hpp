#ifndef VALIDATOR_CRYPTO_BECH_BLECH32M_H
#define VALIDATOR_CRYPTO_BECH_BLECH32M_H

#include "bech.hpp"

namespace bech::blech32m {
  namespace {
    inline constexpr int64_t ENCODING_CONST = 0x455972a3350f7a1;
    inline constexpr int32_t MAX_SIZE = 150;
  }  // namespace

  auto decrypt(const std::string& input) {
    return bech::decrypt(input, ENCODING_CONST, MAX_SIZE, bech::polymod_blech);
  }
}  // namespace bech::blech32m

#endif  // VALIDATOR_CRYPTO_BECH_BLECH32M_H
