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

# If not using Cygwin, Windows, or Travis-based OS X, default to MPI_ENABLED ON
# Otherwise default to OFF
if(UNIX AND NOT CYGWIN AND NOT APPLE)
    set(MPI_ENABLED ON CACHE BOOL "Enable support for compiling an MPI version as well.")
else(UNIX AND NOT CYGWIN AND NOT APPLE)
    set(MPI_ENABLED OFF CACHE BOOL "Enable support for compiling an MPI version as well.")
endif(UNIX AND NOT CYGWIN AND NOT APPLE)

set(SOURCE_FILES src/gmp_seed_iter.c src/gmp_seed_iter.h
        src/util.c src/util.h)
set(AES_FILES src/crypto/aes256-ni_enc.c src/crypto/aes256-ni_enc.h)
set(CIPHER_FILES src/crypto/cipher.c src/crypto/cipher.h)
set(EC_FILES src/crypto/ec.c src/crypto/ec.h)
set(QTESLA_FILES lib/qtesla/ref/qTesla_p_I/api.h lib/qtesla/ref/qTesla_p_I/CDT32.h
        lib/qtesla/ref/qTesla_p_I/consts.c lib/qtesla/ref/qTesla_p_I/params.h
        lib/qtesla/ref/qTesla_p_I/gauss.c lib/qtesla/ref/qTesla_p_I/gauss.h
        lib/qtesla/ref/qTesla_p_I/pack.c lib/qtesla/ref/qTesla_p_I/pack.h
        lib/qtesla/ref/qTesla_p_I/poly.c lib/qtesla/ref/qTesla_p_I/poly.h
        lib/qtesla/ref/qTesla_p_I/sample.c lib/qtesla/ref/qTesla_p_I/sample.h
        lib/qtesla/ref/qTesla_p_I/sign.c
        lib/qtesla/ref/qTesla_p_I/random/random.c lib/qtesla/ref/qTesla_p_I/random/random.h
        lib/qtesla/ref/qTesla_p_I/sha3/fips202.c lib/qtesla/ref/qTesla_p_I/sha3/fips202.h)
set(DILITHIUM_FILES lib/dilithium/ref/api.h lib/dilithium/ref/params.h lib/dilithium/ref/sign.c
        lib/dilithium/ref/sign.h lib/dilithium/ref/packing.c lib/dilithium/ref/packing.h
        lib/dilithium/ref/polyvec.c lib/dilithium/ref/polyvec.h lib/dilithium/ref/poly.c
        lib/dilithium/ref/poly.h lib/dilithium/ref/ntt.c lib/dilithium/ref/ntt.h
        lib/dilithium/ref/reduce.c lib/dilithium/ref/reduce.h lib/dilithium/ref/rounding.c
        lib/dilithium/ref/rounding.h lib/dilithium/ref/fips202.c lib/dilithium/ref/fips202.h
        lib/dilithium/ref/symmetric-shake.c lib/dilithium/ref/symmetric.h)
set(VALIDATOR_FILES src/validator.c src/validator.h)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Append expected search paths for Monsoon
list(APPEND CMAKE_PREFIX_PATH /packages/gmp/6.1.2 /packages/sqlite/3.27.1 /packages/openssl/1.1.1)
# Append expected search paths for Mac OS X via Homebrew
list(APPEND CMAKE_PREFIX_PATH /usr/local/opt/libomp /usr/local/opt/open-mpi /usr/local/opt/ossp-uuid
        /usr/local/opt/gmp /usr/local/opt/openssl@1.1)

add_executable(aes256_test src/aes256_test.c ${AES_FILES})
add_executable(cipher_test src/cipher_test.c ${CIPHER_FILES})
add_executable(ecc_test src/ecc_test.c ${EC_FILES})
add_executable(hash_test src/hash_test.c ${HASH_FILES})

add_executable(rbc_validator src/rbc_validator.c ${VALIDATOR_FILES} ${SOURCE_FILES}
        ${CIPHER_FILES} ${AES_FILES} ${EC_FILES} ${HASH_FILES})

if(MPI_ENABLED)
    add_executable(rbc_validator_mpi src/rbc_validator.c ${VALIDATOR_FILES} ${SOURCE_FILES}
            ${CIPHER_FILES} ${AES_FILES} ${EC_FILES} ${HASH_FILES})
endif(MPI_ENABLED)

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(OpenMP REQUIRED)
if(MPI_ENABLED)
    find_package(MPI REQUIRED)
endif(MPI_ENABLED)
find_package(GMP 6.0.0 MODULE REQUIRED)
find_package(UUID MODULE REQUIRED)
find_package(Argp MODULE REQUIRED)

include_directories(${GMP_INCLUDES})
include_directories(${UUID_INCLUDE_DIRS})
include_directories(${ARGP_INCLUDE_DIR})

target_compile_definitions(cipher_test PUBLIC OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
        OPENSSL_NO_DEPRECATED)
target_compile_definitions(ecc_test PUBLIC OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
        PUBLIC OPENSSL_NO_DEPRECATED)
target_compile_definitions(hash_test PUBLIC OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
        PUBLIC OPENSSL_NO_DEPRECATED)
target_compile_definitions(rbc_validator PUBLIC OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
        PUBLIC OPENSSL_NO_DEPRECATED)

if(MPI_ENABLED)
    target_compile_definitions(rbc_validator_mpi PUBLIC USE_MPI OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
            PUBLIC OPENSSL_NO_DEPRECATED)
endif(MPI_ENABLED)

target_link_libraries(cipher_test OpenSSL::Crypto)
target_link_libraries(ecc_test OpenSSL::Crypto)
target_link_libraries(hash_test OpenSSL::Crypto)
target_link_libraries(rbc_validator OpenMP::OpenMP_C OpenSSL::Crypto ${UUID_LIBRARIES} ${GMP_LIBRARIES}
        ${ARGP_LIBRARIES})

if(MPI_ENABLED)
    target_link_libraries(rbc_validator_mpi MPI::MPI_C OpenSSL::Crypto ${UUID_LIBRARIES} ${GMP_LIBRARIES}
            ${ARGP_LIBRARIES})
endif(MPI_ENABLED)

install(TARGETS rbc_validator RUNTIME DESTINATION bin)

if(MPI_ENABLED)
    install(TARGETS rbc_validator_mpi RUNTIME DESTINATION bin)
endif(MPI_ENABLED)
