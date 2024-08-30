#ifndef VALIDATOR_CRYPTO_BECH_BECH32M_H
#define VALIDATOR_CRYPTO_BECH_BECH32M_H

#include "bech.hpp"

namespace bech::bech32m {
  namespace {
    inline constexpr int64_t ENCODING_CONST = 0x2bc830a3;
  }  // namespace

  auto decode(const std::string& input) {
    return bech::decode(input, ENCODING_CONST);
  }
}

#endif // VALIDATOR_CRYPTO_BECH_BECH32M_H