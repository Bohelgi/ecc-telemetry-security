cmake_minimum_required(VERSION 3.16)
project(ecc_telemetry_security CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TELEMETRY_BUILD_TESTS "Build the crypto/protocol test suite" ON)

include(FetchContent)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.9.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(mbedtls)

add_library(telemetry_core STATIC
    src/support.cpp
    src/crypto_primitives.cpp
    src/protocol_messages.cpp
    src/protocol_agents.cpp
    src/tcp_socket.cpp
)
target_include_directories(telemetry_core PUBLIC include)
target_link_libraries(telemetry_core PUBLIC mbedtls mbedx509 mbedcrypto)
if(WIN32)
    target_link_libraries(telemetry_core PUBLIC ws2_32)
endif()

if(MSVC)
    target_compile_definitions(telemetry_core PUBLIC _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(device_simulator apps/device_simulator.cpp)
target_link_libraries(device_simulator PRIVATE telemetry_core)

set(HTTPLIB_HEADER "${CMAKE_BINARY_DIR}/_deps/httplib/httplib.h")
if(NOT EXISTS "${HTTPLIB_HEADER}")
    file(DOWNLOAD
        "https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.58.0/httplib.h"
        "${HTTPLIB_HEADER}"
        TLS_VERIFY ON
    )
endif()

target_include_directories(device_simulator PRIVATE "${CMAKE_BINARY_DIR}/_deps/httplib")
if(WIN32)
    target_compile_definitions(device_simulator PRIVATE _WIN32_WINNT=0x0A00)
endif()

add_executable(gateway_verifier apps/gateway_verifier.cpp apps/dashboard_state.cpp)
target_link_libraries(gateway_verifier PRIVATE telemetry_core)
target_include_directories(gateway_verifier PRIVATE "${CMAKE_BINARY_DIR}/_deps/httplib")
target_compile_definitions(gateway_verifier PRIVATE DASHBOARD_WEB_DIR="${CMAKE_SOURCE_DIR}/web")
if(WIN32)
    target_compile_definitions(gateway_verifier PRIVATE _WIN32_WINNT=0x0A00)
endif()

if(TELEMETRY_BUILD_TESTS)
    add_executable(crypto_tests tests/test_protocol.cpp)
    target_link_libraries(crypto_tests PRIVATE telemetry_core)
endif()

add_executable(security_demo apps/security_demo.cpp)
target_link_libraries(security_demo PRIVATE telemetry_core)
