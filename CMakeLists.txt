cmake_minimum_required(VERSION 3.5)
project(hamming_benchmark C)

set(CMAKE_C_STANDARD 11)

add_executable(hamming_benchmark main.c)

find_package(OpenSSL REQUIRED)
target_link_libraries(hamming_benchmark OpenSSL::SSL uuid)