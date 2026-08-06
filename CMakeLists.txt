cmake_minimum_required(VERSION 3.16)

project(
    PUFToken
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(
    puftoken_test

    test/main.cc

    dev_protocol/puftoken_dev.cc
    ps_protocol/puftoken_ps.cc
    crypto/puftoken_crypto.cc
    setup/puftoken_setup.cc
)

target_include_directories(
    puftoken_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/dev_protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/ps_protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/setup
)

if(MSVC)
    target_compile_options(puftoken_test PRIVATE /W4)
else()
    target_compile_options(
        puftoken_test
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )
endif()