cmake_minimum_required(VERSION 3.10)
project(leak_detector CXX)

# Match the standard and optimization level of the hand-written g++ build.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -Wall -Wextra -pedantic")

add_executable(leak_detector leak_detector.cpp trace_reader.cpp)
add_executable(merger merger.cpp)

# Install target
install(TARGETS leak_detector merger
        DESTINATION $ENV{HOME}/.local/dynamorio)
