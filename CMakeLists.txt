cmake_minimum_required(VERSION 3.12)
project(worm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# --- Main Library build ---
add_library(worm SHARED  elfw.c elfw.h injectw.c injectw.h worm.h listw.c listw.h)
add_library(worm_s STATIC elfw.c elfw.h injectw.c injectw.h worm.h listw.c listw.h)

set_target_properties(worm
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )

# --- Tests building ----
link_directories(cmake-build-debug/lib)
add_executable(test_data_infect tests/test_data_infect.c)
target_link_libraries(test_data_infect libworm.so)
add_executable(test_utils tests/test_utils.c)
target_link_libraries(test_utils libworm.so)

set_target_properties(test_data_infect test_utils
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        )

