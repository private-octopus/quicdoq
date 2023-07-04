cmake_minimum_required(VERSION 3.13)
project(quicdoq C CXX)
find_package (Threads REQUIRED)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Werror -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

if(DISABLE_DEBUG_PRINTF)
    set(CMAKE_C_FLAGS "-DDISABLE_DEBUG_PRINTF ${CMAKE_C_FLAGS}")
endif()

project(quicdoq
        VERSION 1.0.0.0
        DESCRIPTION "quicdoq library and demo app"
        LANGUAGES C CXX)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakePushCheckState)

if(ENABLE_ASAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
    check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
    check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
        message(FATAL_ERROR "ENABLE_ASAN was requested, but not supported!")
    endif()
    set(CMAKE_C_FLAGS "-fsanitize=address ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")
endif()

if(ENABLE_UBSAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=undefined")
    check_c_compiler_flag(-fsanitize=undefined C__fsanitize_undefined_VALID)
    check_cxx_compiler_flag(-fsanitize=undefined CXX__fsanitize_undefined_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_undefined_VALID OR NOT CXX__fsanitize_undefined_VALID)
        message(FATAL_ERROR "ENABLE_UBSAN was requested, but not supported!")
    endif()
    set(CMAKE_C_FLAGS "-fsanitize=undefined ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-fsanitize=undefined ${CMAKE_CXX_FLAGS}")

    # Ease detecting of "Runtime errors". If such an error is found, print a verbose
    # error report and exit the program
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fno-sanitize-recover")
    check_c_compiler_flag(-fno-sanitize-recover C__fnosanitize_recover_VALID)
    check_cxx_compiler_flag(-fno-sanitize-recover CXX__fnosanitize_recover_VALID)
    cmake_pop_check_state()
    if(NOT C__fnosanitize_recover_VALID OR NOT CXX__fnosanitize_recover_VALID)
        message(FATAL_ERROR "ENABLE_UBSAN was requested, but fno-sanitize-recover is not supported!")
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-sanitize-recover")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-sanitize-recover")
endif()

set(QUICDOQ_LIBRARY_FILES
    quicdoq/quicdoq.c
    quicdoq/quicdoq_util.c
    quicdoq/udp_relay.c
)

set(QUICDOQ_TEST_LIBRARY_FILES
    quicdoq_test/dnscode_test.c
    quicdoq_test/network_test.c
)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Picoquic REQUIRED)
message(STATUS "Picoquic/include: ${Picoquic_INCLUDE_DIRS}" )
message(STATUS "Picoquic library: ${Picoquic_LIBRARIES}" )

find_package(PTLS REQUIRED)
message(STATUS "picotls/include: ${PTLS_INCLUDE_DIRS}" )
message(STATUS "picotls libraries: ${PTLS_LIBRARIES}" )

find_package(OpenSSL REQUIRED)
message(STATUS "root: ${OPENSSL_ROOT_DIR}")
message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")

include_directories(quicdoq quicdoq_test 
    ${Picoquic_INCLUDE_DIRS} ${PTLS_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

add_library(quicdoq-core
    ${QUICDOQ_LIBRARY_FILES}
)

add_executable(quicdoq_app
    quicdoq_cli_app/quicdoq_app.c
)

target_link_libraries(quicdoq_app
    quicdoq-core
    ${Picoquic_LIBRARIES}
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

set(TEST_EXES quicdoq_t)

add_executable(quicdoq_t
    quicdoq_cli_test/quicdoq_t.c
    ${QUICDOQ_TEST_LIBRARY_FILES}
)

target_link_libraries(quicdoq_t
    quicdoq-core
    ${Picoquic_LIBRARIES}
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

set(TEST_EXES quicdoq_t)

# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)

# Adds clangformat as target that formats all source files
add_custom_target(
    clangformat
    COMMAND clang-format
    -style=Webkit
    -i
    ${CLANG_FORMAT_SOURCE_FILES}
)
