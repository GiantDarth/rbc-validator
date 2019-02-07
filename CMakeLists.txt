cmake_minimum_required(VERSION 3.5)
project(hamming_benchmark C)

set(CMAKE_C_STANDARD 11)

add_executable(hamming_benchmark hamming_benchmark.c gmp_key_iter.c gmp_key_iter.h)
add_executable(lookupwork lookupwork.c)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)
find_package(SQLite3 MODULE REQUIRED)

target_link_libraries(hamming_benchmark OpenSSL::SSL OpenMP::OpenMP_C uuid gmp)

include_directories(${SQLITE3_INCLUDE_DIRS})
target_link_libraries(lookupwork ${SQLITE3_LIBRARIES})