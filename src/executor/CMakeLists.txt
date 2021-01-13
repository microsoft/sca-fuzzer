# This file is only for CLion code completion
# Don't try to use it for building the project
cmake_minimum_required(VERSION 3.7)
set(CMAKE_C_STANDARD 11)

project(x86-executor)

FILE(GLOB SRC x86/measurement.c x86/main.c x86/templates.c x86/x86-executor.h)
set(SOURCE_FILES ${SRC})
add_compile_definitions(__KERNEL__)
add_compile_definitions(PAGE_KERNEL_EXEC)
add_compile_definitions(PAGE_SIZE=4096)
add_compile_definitions(MODULE_LICENSE)
add_compile_definitions(MODULE_AUTHOR)
include_directories(${LINUX_PATH}/include ${LINUX_PATH}/arch/x86/include/)

add_executable(executor-x86 ${SOURCE_FILES})