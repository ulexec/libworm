cmake_minimum_required(VERSION 3.12)
project(libx C)

set(CMAKE_C_STANDARD 99)
set(SOURCE_FILES main.c elfx.c listx.c)
add_executable(libx main.c elfx.c elfx.h listx.h cmake-build-debug/libx.h libx.h listx.c inject.c inject.h)