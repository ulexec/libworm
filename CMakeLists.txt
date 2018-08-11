cmake_minimum_required(VERSION 3.12)
project(libx C)

set(CMAKE_C_STANDARD 99)

add_executable(libx main.c elfx.h listx.h cmake-build-debug/libx.h libx.h)