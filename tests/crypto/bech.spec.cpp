#include "../../src/crypto/bech/bech32.hpp"
#include "../../src/crypto/bech/bech32m.hpp"
#include "../../src/crypto/bech/blech32.hpp"
#include "../../src/crypto/bech/blech32m.hpp"
#include <cassert>

namespace bech {
    auto test_prefix_checksum() -> void {
      std::vector<std::tuple<std::string, std::pair<checksum_t, checksum_t>>> suite = {
          {"bc", {36798531, 36798531}},
          {"cro", {81608438, 37684776527}},
          {"terra", {54786043, 34541946538216001}},
          {"ltc", {81592890, 37684785795}},
      };

      for(const auto& [prefix, expected_checksum] : suite) {
        auto [expected_checksum_bech, expected_checksum_blech] = expected_checksum;
        auto checksum = bech::prefix_checksum(prefix);
        auto checksum_bech = bech::prefix_checksum(prefix, bech::polymod_bech);
        auto checksum_blech = bech::prefix_checksum(prefix, bech::polymod_blech);


        assert(checksum == expected_checksum_bech);
        assert(checksum_bech == expected_checksum_bech);
        assert(checksum_blech == expected_checksum_blech);
      }
    }

    auto test_prefix_negative() -> void {
      std::vector<std::string> suite = {
        "bc ",
        "e\nl"
      };

      for(const auto& test : suite) {
        bool is_err = false;
        try{
          bech::prefix_checksum(test);
        } catch (std::runtime_error& err) {
          is_err = true;

          assert(typeid(err).name() == typeid(InvalidCharacterException).name());
        }

        assert(is_err == true);
      }
    }

    auto test_size_negative() -> void {
      std::vector<std::string> suite = {
          "bcassd",
          "zxyuasdashasdnanbefjwefnw"
      };

      for(const auto& test : suite) {
        bool is_err = false;
        try{
          bech::decrypt(test, 1, 10);
        } catch (std::runtime_error& err) {
          is_err = true;

          assert(typeid(err).name() == typeid(InvalidSizeException).name());
        }

        assert(is_err == true);
      }
    }

    auto test_separator_negative() -> void {
      std::vector<std::string> suite = {
          "bcassdasasd",
          "zxyuasdashasdnanbefjwefnw"
      };

      for(const auto& test : suite) {
        bool is_err = false;
        try{
          bech::decrypt(test);
        } catch (std::runtime_error& err) {
          is_err = true;

          assert(typeid(err).name() == typeid(NoSeparatorException).name());
        }

        assert(is_err == true);
      }
    }

    auto test_value_negative() -> void {
      std::vector<std::string> suite = {
          "bc1a ssdasasd",
          "zx1yuasdashbsdnanbefjwefnw"
      };

      for(const auto& test : suite) {
        bool is_err = false;
        try{
          bech::decrypt(test);
        } catch (std::runtime_error& err) {
          is_err = true;

          assert(typeid(err).name() == typeid(InvalidCharacterException).name());
        }

        assert(is_err == true);
      }
    }

    auto test_polymod_bech() -> void {
      std::vector<std::pair<int32_t , int32_t>> suite = {
          {0, 0},
          {1, 32},
          {2, 64},
          {3, 96},
          {4, 128},
          {136, 4352},
          {810, 25920},
          {999, 31968},
      };

      for(const auto& [prefix, expected] : suite) {
        auto result = bech::polymod_bech(prefix);

        assert(result == expected);
      }
    }

    auto test_polymod_blech() -> void {
      std::vector<std::pair<bech::checksum_t, bech::checksum_t>> suite = {
          // input               ,     result
          {36798636,           1177556352},
          {271881476507082877, 613260432816957490},
          {37681803264,        1205817704448},
          {146637959731788213, 72889297154350264}

      };

      for(const auto& [prefix, expected] : suite) {
        auto result = bech::polymod_blech(prefix);

        assert(result == expected);
      }
    }

    namespace bech32 {
      auto test_bech32_positive() -> void {
        std::vector<std::string> suite = {
            "bc1qg8qch0yyctftgvxddy2knyequwgsrechdchdfh76x7pzq0pr0w8sqzw4qk",
        };

        for (const auto& test : suite) {
          auto [prefix, valid] = bech::bech32::decrypt(test);

          assert(prefix == "bc");
          assert(valid == true);
        }
      }
    }  // namespace bech32

    namespace bech32m {
      auto test_bech32m_positive() -> void {
        std::vector<std::string> suite = {
            "bc1peu5hzzyj8cnqm05le6ag7uwry0ysmtf3v4uuxv3v8hqhvsatca8ss2vuwx",
            "bc1pal05wfej2a4rt36yvjz3gqvlne02ty69yvwafzh9flvpm2gq0z2ske2vsv",
            "bc1p2jdgr8sx323r6kzk2u5pdetxckj8wnxmp8yx3qgk5spva6z4g2aqtfxyzp",
            "bc1pgzvpjcts4f07z4guc0kscnjs4zxm4yc6uywpsygf86g943gyjd6qfzpj4g",
            "bc1p6ncfk3j053jvcpp364d4ndkt04jkjean9ds4n6pklp6jvxf3skps3dzph2",
        };

        for (const auto& test : suite) {
          auto [prefix, valid] = bech::bech32m::decrypt(test);

          assert(prefix == "bc");
          assert(valid == true);
        }
      }
  }  // namespace bech32m

  namespace blech32{
    auto test_blech32_positive() -> void {
      std::vector<std::string> suite = {
          "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd"
      };

      for (const auto& test : suite) {
        auto [prefix, valid] = bech::blech32::decrypt(test);

        assert(prefix == "el");
        assert(valid == true);
      }
    }
  }  // namespace blech32

  namespace blech32m{
    auto test_blech32m_positive() -> void {
      std::vector<std::string> suite = {
        "el1pqt2ggkpvrffw5t5zw4mpu23f8kppcw3mr258cpy8nhcnwdmle20g9uda2jsjhgvv6nvg600v68slq6044k5z4v3cwk5252k8whkzkc0kcu6mzca78auu"
      };

      for (const auto& test : suite) {
        auto [prefix, valid] = bech::blech32m::decrypt(test);

        assert(prefix == "el");
        assert(valid == true);
      }
    }
  }  // namespace blech32m
}  // namespace bech


auto test_polymod() {
  bech::test_polymod_bech();
  bech::test_polymod_blech();
}

auto test_positive() {
  bech::bech32::test_bech32_positive();
  bech::bech32m::test_bech32m_positive();
  bech::blech32::test_blech32_positive();
  bech::blech32m::test_blech32m_positive();
}

auto test_prefix() {
  bech::test_prefix_checksum();
  bech::test_prefix_negative();
}

auto test_negative() {
  bech::test_size_negative();
  bech::test_separator_negative();
  bech::test_value_negative();
}

auto main() -> int {
  test_prefix();

  test_polymod();
  test_positive();

  test_negative();

  return 0;
};