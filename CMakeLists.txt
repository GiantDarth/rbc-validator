cmake_minimum_required(VERSION 3.9)
project(hamming_benchmark C)

set(CMAKE_C_STANDARD 11)

add_executable(hamming_benchmark hamming_benchmark.c gmp_key_iter.c gmp_key_iter.h util.c util.h)
add_executable(hamming_validator hamming_validator.c gmp_key_iter.c gmp_key_iter.h util.c util.h)
add_executable(lookupwork lookupwork.c)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Append expected search paths for Monsoon
list(APPEND CMAKE_PREFIX_PATH /packages/openssl/1.1.1 /packages/gmp/6.1.2 /packages/sqlite/3.27.1)
# Append expected search paths for Mac OS X via Homebrew
# TODO: Append these by using some sort of brew command, e.g.: brew list openssl@1.1
list(APPEND CMAKE_PREFIX_PATH /usr/local/Cellar/openssl@1.1/1.1.1a /usr/local/Cellar/libomp/7.0.0
        /usr/local/Cellar/ossp-uuid/1.6.2_2 /usr/local/Cellar/gmp/6.1.2_2 /usr/local/Cellar/sqlite/3.27.1)

find_package(OpenSSL 1.1 REQUIRED)
find_package(OpenMP REQUIRED)
find_package(GMP 6.0.0 MODULE REQUIRED)
find_package(SQLite3 MODULE REQUIRED)
find_package(UUID MODULE REQUIRED)

include_directories(${SQLITE3_INCLUDE_DIRS})
include_directories(${GMP_INCLUDES})
include_directories(${UUID_INCLUDE_DIRS})

target_link_libraries(hamming_benchmark OpenSSL::SSL OpenMP::OpenMP_C ${UUID_LIBRARIES} ${GMP_LIBRARIES})
target_link_libraries(hamming_validator OpenSSL::SSL OpenMP::OpenMP_C ${UUID_LIBRARIES} ${GMP_LIBRARIES})

target_link_libraries(lookupwork ${SQLITE3_LIBRARIES})