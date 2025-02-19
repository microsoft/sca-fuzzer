cmake_minimum_required(VERSION 3.13)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# add all C++ files in the current directory
file(GLOB MAIN_SOURCES "*.cpp")
file(GLOB TRACERS "tracers/*.cpp")
add_library(dr_model SHARED ${MAIN_SOURCES} ${TRACERS})

# add `include` directory to the include path
target_include_directories(dr_model PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

configure_DynamoRIO_client(dr_model)
use_DynamoRIO_extension(dr_model drmgr)
use_DynamoRIO_extension(dr_model drreg)
use_DynamoRIO_extension(dr_model drutil)
use_DynamoRIO_extension(dr_model drx)
use_DynamoRIO_extension(dr_model drwrap)
use_DynamoRIO_extension(dr_model drsyms)
