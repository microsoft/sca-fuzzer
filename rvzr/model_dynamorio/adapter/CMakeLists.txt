cmake_minimum_required(VERSION 3.10)
project(adapter)

# Set compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")

# Define source files
set(SRC_FILES
    main.c
    parser.c
    test_case_entry.c
    sandbox.c
)

# Create executable
add_executable(adapter ${SRC_FILES})
target_include_directories(adapter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(adapter rt)

# Install target
install(TARGETS adapter
        DESTINATION $ENV{HOME}/.local/dynamorio)