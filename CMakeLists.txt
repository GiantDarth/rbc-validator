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
        src/util.c src/util.h)
# note micro-ecc from https://github.com/kmackay/micro-ecc.git
set(uECC_FILES lib/micro-ecc/uECC.c lib/micro-ecc/uECC.h)
set(AES_FILES src/crypto/aes256-ni_enc.c src/crypto/aes256-ni_enc.h)

add_executable(aes256_test src/aes256_test.c ${AES_FILES})
add_executable(ecc256_test src/ecc256_test.c ${SOURCE_FILES} ${uECC_FILES})

add_executable(rbc_validator src/rbc_validator.c ${SOURCE_FILES} ${AES_FILES} ${uECC_FILES})

if(NOT CYGWIN)
    add_executable(aes_validator_mpi src/aes_validator_mpi.c ${SOURCE_FILES} ${AES_FILES})
    add_executable(ecc_validator_mpi src/ecc_validator_mpi.c ${SOURCE_FILES} ${uECC_FILES})
endif(NOT CYGWIN)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Append expected search paths for Monsoon
list(APPEND CMAKE_PREFIX_PATH /packages/gmp/6.1.2 /packages/sqlite/3.27.1)
# Append expected search paths for Mac OS X via Homebrew
list(APPEND CMAKE_PREFIX_PATH /usr/local/opt/libomp /usr/local/opt/open-mpi /usr/local/opt/ossp-uuid
        /usr/local/opt/gmp)

find_package(OpenMP REQUIRED)
if(NOT CYGWIN)
    find_package(MPI REQUIRED)
endif(NOT CYGWIN)
find_package(GMP 6.0.0 MODULE REQUIRED)
find_package(UUID MODULE REQUIRED)
find_package(Argp MODULE REQUIRED)

include_directories(${GMP_INCLUDES})
include_directories(${UUID_INCLUDE_DIRS})
include_directories(${ARGP_INCLUDE_DIR})

target_link_libraries(ecc256_test ${GMP_LIBRARIES})

target_link_libraries(rbc_validator OpenMP::OpenMP_C ${UUID_LIBRARIES} ${GMP_LIBRARIES} ${ARGP_LIBRARIES})

if(NOT CYGWIN)
    target_link_libraries(aes_validator_mpi MPI::MPI_C ${UUID_LIBRARIES} ${GMP_LIBRARIES} ${ARGP_LIBRARIES})
    target_link_libraries(ecc_validator_mpi MPI::MPI_C ${UUID_LIBRARIES} ${GMP_LIBRARIES} ${ARGP_LIBRARIES})
endif(NOT CYGWIN)

install(TARGETS rbc_validator RUNTIME DESTINATION bin)

if(NOT CYGWIN)
    install(TARGETS aes_validator_mpi RUNTIME DESTINATION bin)
    install(TARGETS ecc_validator_mpi RUNTIME DESTINATION bin)
endif(NOT CYGWIN)
