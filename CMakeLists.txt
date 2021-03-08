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

set(ALWAYS_EVP_AES OFF CACHE BOOL "Force AES to use OpenSSL's EVP system instead of a custom implementation.")
set(ALWAYS_EVP_HASH OFF CACHE BOOL "Force MD5, SHA1, and SHA2 to use OpenSSL's EVP system instead.")
set(ALWAYS_EVP_SHA3 OFF CACHE BOOL "Force all SHA-3 algorithms to use OpenSSL's EVP over XKCP.")

set(SOURCE_FILES src/seed_iter.c src/seed_iter.h src/perm.c src/perm.h)
set(UTIL_FILES src/util.c src/util.h)
set(AES_FILES src/crypto/aes256-ni_enc.c src/crypto/aes256-ni_enc.h)
set(CIPHER_FILES src/crypto/cipher.c src/crypto/cipher.h)
set(EC_FILES src/crypto/ec.c src/crypto/ec.h)
set(HASH_FILES src/crypto/hash.c src/crypto/hash.h)
set(VALIDATOR_FILES src/validator.c src/validator.h)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
# Append expected search paths for Monsoon
list(APPEND CMAKE_PREFIX_PATH /packages/gmp/6.1.2-aqy3gvy /packages/openssl/1.1.1i-5uny3qr)
# Append expected search paths for Mac OS X via Homebrew
list(APPEND CMAKE_PREFIX_PATH /usr/local/opt/libomp /usr/local/opt/open-mpi /usr/local/opt/ossp-uuid
        /usr/local/opt/gmp /usr/local/opt/openssl@1.1)

add_executable(aes256_test src/aes256_test.c ${AES_FILES} ${UTIL_FILES})
add_executable(cipher_test src/cipher_test.c ${CIPHER_FILES} ${UTIL_FILES})
add_executable(ecc_test src/ecc_test.c ${EC_FILES})
add_executable(hash_test src/hash_test.c ${HASH_FILES})

add_executable(rbc_validator src/rbc_validator.c ${VALIDATOR_FILES} ${SOURCE_FILES} ${UTIL_FILES}
        ${CIPHER_FILES} ${AES_FILES} ${EC_FILES} ${HASH_FILES})

if(MPI_ENABLED)
    add_executable(rbc_validator_mpi src/rbc_validator.c ${VALIDATOR_FILES} ${SOURCE_FILES} ${UTIL_FILES}
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

find_library(XKCP_LIBRARIES NAMES XKCP PATHS ~/.local/lib)

include_directories(~/.local/include)
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

if(ALWAYS_EVP_AES)
    target_compile_definitions(rbc_validator PUBLIC ALWAYS_EVP_AES)
endif(ALWAYS_EVP_AES)

if(ALWAYS_EVP_HASH)
    target_compile_definitions(rbc_validator PUBLIC ALWAYS_EVP_HASH)
endif(ALWAYS_EVP_HASH)

if(ALWAYS_EVP_SHA3)
    target_compile_definitions(rbc_validator PUBLIC ALWAYS_EVP_SHA3)
endif(ALWAYS_EVP_SHA3)

if(MPI_ENABLED)
    target_compile_definitions(rbc_validator_mpi PUBLIC USE_MPI OPENSSL_API_COMPAT=${OPENSSL_API_COMPAT}
            PUBLIC OPENSSL_NO_DEPRECATED)

    if(ALWAYS_EVP_AES)
        target_compile_definitions(rbc_validator PUBLIC ALWAYS_EVP_AES)
    endif(ALWAYS_EVP_AES)

    if(ALWAYS_EVP_HASH)
        target_compile_definitions(rbc_validator PUBLIC ALWAYS_EVP_HASH)
    endif(ALWAYS_EVP_HASH)

    if(ALWAYS_EVP_SHA3)
        target_compile_definitions(rbc_validator_mpi PUBLIC ALWAYS_EVP_SHA3)
    endif(ALWAYS_EVP_SHA3)
endif(MPI_ENABLED)

target_link_libraries(cipher_test OpenSSL::Crypto)
target_link_libraries(ecc_test OpenSSL::Crypto)
target_link_libraries(hash_test OpenSSL::Crypto ${XKCP_LIBRARIES})
target_link_libraries(rbc_validator OpenMP::OpenMP_C OpenSSL::Crypto ${UUID_LIBRARIES} ${GMP_LIBRARIES}
        ${ARGP_LIBRARIES} ${XKCP_LIBRARIES})

if(MPI_ENABLED)
    target_link_libraries(rbc_validator_mpi MPI::MPI_C OpenSSL::Crypto ${UUID_LIBRARIES} ${GMP_LIBRARIES}
            ${ARGP_LIBRARIES} ${XKCP_LIBRARIES})
endif(MPI_ENABLED)

install(TARGETS rbc_validator RUNTIME DESTINATION bin)

if(MPI_ENABLED)
    install(TARGETS rbc_validator_mpi RUNTIME DESTINATION bin)
endif(MPI_ENABLED)
