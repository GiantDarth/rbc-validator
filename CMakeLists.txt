# libomp can only be found on Mac OS X if using CMake 3.12+
if(APPLE)
    cmake_minimum_required(VERSION 3.12)
# Otherwise, we need at least CMake 3.9 to utilize OpenMP::OpenMP_C
else(APPLE)
    cmake_minimum_required(VERSION 3.9)
endif(APPLE)
project(rbc_validator C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes -mtune=generic")
# Equivalent to OpenSSL 1.1.1
set(OPENSSL_API_COMPAT 10101)

set(SOURCE_FILES src/gmp_seed_iter.c src/gmp_seed_iter.h
        src/util.c src/util.h)
set(EC_FILES src/crypto/ec.c src/crypto/ec.h)
set(AES_FILES src/crypto/aes256-ni_enc.c src/crypto/aes256-ni_enc.h)
set(VALIDATOR_FILES src/validator.c src/validator.h)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Append expected search paths for Monsoon
list(APPEND CMAKE_PREFIX_PATH /packages/gmp/6.1.2 /packages/sqlite/3.27.1 /packages/openssl/1.1.1)
# Append expected search paths for Mac OS X via Homebrew
list(APPEND CMAKE_PREFIX_PATH /usr/local/opt/libomp /usr/local/opt/open-mpi /usr/local/opt/ossp-uuid
        /usr/local/opt/gmp /usr/local/opt/openssl@1.1)

add_executable(aes256_test src/aes256_test.c ${AES_FILES})
add_executable(ecc_test src/ecc_test.c ${EC_FILES})

add_executable(rbc_validator src/rbc_validator.c ${VALIDATOR_FILES} ${SOURCE_FILES}
        ${AES_FILES} ${EC_FILES})

if(NOT CYGWIN)
    add_executable(rbc_validator_mpi src/rbc_validator.c ${VALIDATOR_FILES} ${SOURCE_FILES}
            ${AES_FILES} ${EC_FILES})
endif(NOT CYGWIN)

find_package(OpenSSL 1.1.1 REQUIRED)
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

target_compile_definitions(ecc_test PUBLIC OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
        PUBLIC OPENSSL_NO_DEPRECATED)
target_compile_definitions(rbc_validator PUBLIC OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
        PUBLIC OPENSSL_NO_DEPRECATED)

if(NOT CYGWIN)
    target_compile_definitions(rbc_validator_mpi PUBLIC USE_MPI OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
            PUBLIC OPENSSL_NO_DEPRECATED)
endif(NOT CYGWIN)

target_link_libraries(ecc_test OpenSSL::Crypto)
target_link_libraries(rbc_validator OpenMP::OpenMP_C OpenSSL::Crypto ${UUID_LIBRARIES} ${GMP_LIBRARIES}
        ${ARGP_LIBRARIES})

if(NOT CYGWIN)
    target_link_libraries(rbc_validator_mpi MPI::MPI_C OpenSSL::Crypto ${UUID_LIBRARIES} ${GMP_LIBRARIES}
            ${ARGP_LIBRARIES})
endif(NOT CYGWIN)

install(TARGETS rbc_validator RUNTIME DESTINATION bin)

if(NOT CYGWIN)
    install(TARGETS rbc_validator_mpi RUNTIME DESTINATION bin)
endif(NOT CYGWIN)
