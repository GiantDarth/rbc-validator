cmake_minimum_required(VERSION 3.5)
project(hamming_benchmark C)

set(CMAKE_C_STANDARD 11)

add_executable(hamming_benchmark new_main.c)

find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)
target_link_libraries(hamming_benchmark OpenSSL::SSL OpenMP::OpenMP_C uuid gmp)