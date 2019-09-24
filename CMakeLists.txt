# libomp can only be found on Mac OS X if using CMake 3.12+
if(APPLE)
    cmake_minimum_required(VERSION 3.12)
# Otherwise, we need at least CMake 3.9 to utilize OpenMP::OpenMP_C
else(APPLE)
    cmake_minimum_required(VERSION 3.9)
endif(APPLE)
project(hamming_benchmark C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx -maes")

set(SOURCE_FILES src/uint256_t.c src/uint256_t.h src/iter/uint256_key_iter.c src/iter/uint256_key_iter.h
        src/util.c src/util.h src/aes256-ni.c src/aes256-ni.h)

# note micro-ecc from https://github.com/kmackay/micro-ecc.git 
add_executable(ecc_validator src/ecc_validator.c ../micro-ecc/uECC.c ../micro-ecc/uECC.h
        src/iter/uint256_key_iter.h src/iter/uint256_key_iter.c
        src/uint256_t.h src/uint256_t.c
        src/util.h src/util.c
        )

add_executable(hamming_validator src/hamming_validator.c ${SOURCE_FILES})
add_executable(hamming_validator_mpi src/hamming_validator_mpi.c ${SOURCE_FILES})

add_executable(aes256_test src/aes256_test.c src/aes256-ni.c src/aes256-ni.h)
# note micro-ecc from https://github.com/kmackay/micro-ecc.git 
add_executable(ecc256_test src/ecc256_test.c ../micro-ecc/uECC.c ../micro-ecc/uECC.h)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Append expected search paths for Monsoon
list(APPEND CMAKE_PREFIX_PATH /packages/gmp/6.1.2 /packages/sqlite/3.27.1 /packages/openssl/1.1.1)
# Append expected search paths for Mac OS X via Homebrew
list(APPEND CMAKE_PREFIX_PATH /usr/local/opt/libomp /usr/local/opt/open-mpi /usr/local/opt/ossp-uuid
        /usr/local/opt/gmp /usr/local/opt/openssl@1.1)

set(CMAKE_THREAD_PREFER_PTHREAD ON)

find_package(OpenMP REQUIRED)
find_package(MPI REQUIRED)
find_package(Threads REQUIRED)
find_package(GMP 6.0.0 MODULE REQUIRED)
find_package(UUID MODULE REQUIRED)
find_package(Argp MODULE REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)

include_directories(${GMP_INCLUDES})
include_directories(${UUID_INCLUDE_DIRS})
include_directories(${ARGP_INCLUDE_DIR})

target_link_libraries(ecc_validator OpenMP::OpenMP_C ${UUID_LIBRARIES} ${GMP_LIBRARIES} ${ARGP_LIBRARIES})
target_link_libraries(hamming_validator OpenMP::OpenMP_C ${UUID_LIBRARIES} ${GMP_LIBRARIES} ${ARGP_LIBRARIES})
target_link_libraries(hamming_validator_mpi MPI::MPI_C Threads::Threads ${UUID_LIBRARIES} ${GMP_LIBRARIES} ${ARGP_LIBRARIES})

install(TARGETS ecc_validator RUNTIME DESTINATION bin)
install(TARGETS hamming_validator RUNTIME DESTINATION bin)
install(TARGETS hamming_validator_mpi RUNTIME DESTINATION bin)
