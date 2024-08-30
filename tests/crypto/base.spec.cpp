#include <vector>
#include <string>
#include <iostream>
#include "../../src/crypto/base/base.hpp"
#include "../../src/crypto/base/base64.hpp"



namespace base {
  namespace base58 {

  }

  namespace base64 {
    auto test_base64_positive() {
      std::vector<std::pair<std::string, std::string>> suite{
        {"SGVsbG8gV29ybGQh", "Hello World!"},
        {"0L/RgNC40LLQtdGC", "привет"}
      };

      for(const auto& [input, expected_result] : suite) {
        auto result = base::base64::decode(input);
std::cout <<result << " - " << expected_result << std::endl;
        assert(result == expected_result);

      }
    }
  }  // namespace base64
}  // namespace base

auto test_positive() -> void {
  base::base64::test_base64_positive();
}

auto main() -> int {
  test_positive();

  return 0;
};