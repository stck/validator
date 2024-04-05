#ifndef VALIDATOR_CRYPTO_BECH_BECH32_H
#define VALIDATOR_CRYPTO_BECH_BECH32_H

#include "bech.hpp"

namespace bech::bech32 {
  namespace {
    inline constexpr int64_t ENCODING_CONST = 1;
  }  // namespace

  auto decrypt(const std::string& input) {
    return bech::decrypt(input, ENCODING_CONST);
  }
}  // namespace bech::bech32

#endif  // VALIDATOR_CRYPTO_BECH_BECH32_H
