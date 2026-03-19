cmake_minimum_required(VERSION 3.20)

project(cpp_dns LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(cpp_dns
    src/dns/buffer.cpp
    src/dns/header.cpp
    src/dns/packet.cpp
    src/dns/question.cpp
    src/dns/record.cpp
)

target_include_directories(cpp_dns
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(cpp_dns
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
)

add_executable(cpp_dns_app
    apps/main.cpp
)

target_link_libraries(cpp_dns_app
    PRIVATE
        cpp_dns
)

include(CTest)

if (BUILD_TESTING)
    find_package(GTest REQUIRED)

    add_executable(dns_packet_tests
        tests/test_sanity_check.cpp
        tests/test_packet_buffer.cpp
    )

    target_link_libraries(dns_packet_tests
        PRIVATE
            cpp_dns
            GTest::gtest_main
    )

    target_compile_options(dns_packet_tests
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
    )

    include(GoogleTest)
    gtest_discover_tests(dns_packet_tests)
endif()
