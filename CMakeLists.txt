cmake_minimum_required(VERSION 3.10)
if (CMAKE_BINARY_DIR STREQUAL CMAKE_SOURCE_DIR)
    message(FATAL_ERROR "Building in-source is not supported! Create a build dir and remove ${CMAKE_SOURCE_DIR}/CMakeCache.txt")
endif ()

option(test "Build all tests." ON)
project(validator VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)

SET(BASE_LIB
    src/crypto/base/base.hpp
        src/crypto/base/base64.hpp
)

SET(BECH_LIB
    src/crypto/bech/bech.hpp
    src/crypto/bech/bech32.hpp
    src/crypto/bech/bech32m.hpp
    src/crypto/bech/blech32.hpp
    src/crypto/bech/blech32m.hpp
)

SET(CRYPTO_LIB ${BASE_LIB} ${BECH_LIB})

add_executable(validator src/main.cpp
        ${CRYPTO_LIB})

enable_testing()
add_subdirectory(./tests)
