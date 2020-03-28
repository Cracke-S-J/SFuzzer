cmake_minimum_required(VERSION 2.8)

project(SFuzzer C CXX ASM)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -D_GNU_SOURCE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(wrapper)
# add_subdirectory(fuzzer)
# add_subdirectory(tests)
